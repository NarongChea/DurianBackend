import os
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError

app = FastAPI(title="Durian Farm (MongoDB)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))[os.getenv("MONGO_DB", "durian_farm")]
db.trees.create_index("code", unique=True)

def next_id(name):
    r = db.counters.find_one_and_update({"_id": name}, {"$inc": {"seq": 1}}, upsert=True, return_document=ReturnDocument.AFTER)
    return r["seq"]

COLS = {
  "trees": ["code", "note"],
  "categories": ["name"],
  "types": ["category_id", "name"],
  "spendings": ["date", "tree_id", "category_id", "type_id", "kg", "price_per_kg", "amount", "note"],
  "logs": ["date", "tree_id", "kind", "sickness", "medicine", "fruit_count", "weight_kg", "note"],
}
ORDER = {"spendings": [("date", -1), ("id", -1)], "logs": [("date", -1), ("id", -1)]}

def clean(name, d):
    d = {c: (d.get(c) if d.get(c) != "" else None) for c in COLS[name]}
    if name == "spendings" and d["amount"] is None and d["kg"] and d["price_per_kg"]:
        d["amount"] = d["kg"] * d["price_per_kg"]
    return d

def register(name):
    col = db[name]
    @app.get(f"/api/{name}", name=f"list_{name}")
    def lst(): return list(col.find({}, {"_id": 0}).sort(ORDER.get(name, [("id", 1)])))
    @app.post(f"/api/{name}", name=f"add_{name}")
    def add(body: dict):
        d = clean(name, body); d["id"] = next_id(name)
        try: col.insert_one(d)
        except DuplicateKeyError: return {"error": "duplicate"}
        return {"id": d["id"]}
    @app.put(f"/api/{name}/{{id}}", name=f"edit_{name}")
    def edit(id: int, body: dict):
        col.update_one({"id": id}, {"$set": clean(name, body)}); return {"ok": True}
    @app.delete(f"/api/{name}/{{id}}", name=f"del_{name}")
    def delete(id: int):
        if name == "categories": db.types.delete_many({"category_id": id})
        col.delete_one({"id": id}); return {"ok": True}

for n in COLS: register(n)

@app.post("/api/trees-bulk")
def bulk(body: dict):
    n = 0
    for i in range(int(body["start"]), int(body["end"]) + 1):
        try:
            db.trees.insert_one({"id": next_id("trees"), "code": f"{body.get('prefix','')}{i}", "note": None}); n += 1
        except DuplicateKeyError: pass
    return {"added": n}

def key(date, period):
    d = datetime.strptime(date[:10], "%Y-%m-%d")
    return {"day": d.strftime("%Y-%m-%d"), "week": d.strftime("%Y-W%W"), "month": d.strftime("%Y-%m"), "year": d.strftime("%Y")}[period]

@app.get("/api/report/spending")
def rep_spending(period: str = "day"):
    if period not in ("day", "week", "month", "year"): period = "day"
    cats = {c["id"]: c["name"] for c in db.categories.find()}
    rows, bycat = {}, {}
    for s in db.spendings.find({"date": {"$ne": None}}):
        p = key(s["date"], period); amt = s.get("amount") or 0
        r = rows.setdefault(p, {"p": p, "total": 0, "kg": 0}); r["total"] += amt; r["kg"] += s.get("kg") or 0
        c = bycat.setdefault((p, s.get("category_id")), {"p": p, "category": cats.get(s.get("category_id"), "-"), "total": 0}); c["total"] += amt
    return {"rows": sorted(rows.values(), key=lambda r: r["p"], reverse=True),
            "by_category": sorted(bycat.values(), key=lambda r: r["p"], reverse=True)}

@app.get("/api/report/fruit")
def rep_fruit():
    codes = {t["id"]: t["code"] for t in db.trees.find()}
    per = {}
    for l in db.logs.find({"kind": "fruit"}):
        if l.get("tree_id") in codes:
            r = per.setdefault(l["tree_id"], {"code": codes[l["tree_id"]], "count": 0, "kg": 0})
            r["count"] += l.get("fruit_count") or 0; r["kg"] += l.get("weight_kg") or 0
    trees = [per[k] for k in sorted(per)]
    cnt = sum(r["count"] for r in trees); kg = sum(r["kg"] for r in trees)
    return {"trees": trees, "total_count": cnt, "total_kg": kg, "avg_kg": (kg / cnt if cnt else 0)}

@app.get("/api/price")
def get_price():
    r = db.settings.find_one({"_id": "price"}); return {"price": r["v"] if r else 0}

@app.put("/api/price")
def set_price(body: dict):
    db.settings.update_one({"_id": "price"}, {"$set": {"v": float(body.get("price") or 0)}}, upsert=True); return {"ok": True}