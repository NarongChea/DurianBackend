import os, re, time, json, hmac, hashlib, secrets, smtplib, urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import bcrypt, jwt
from fastapi import FastAPI, APIRouter, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError

app = FastAPI(title="Durian Farm (MongoDB)")

DEFAULT_ORIGINS = [
    "https://narongchea.github.io",
    "http://localhost:5173", "http://127.0.0.1:5173",
]
ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()] or DEFAULT_ORIGINS
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["*"], allow_headers=["*"])

db = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))[os.getenv("MONGO_DB", "durian_farm")]
db.trees.create_index("code", unique=True)
db.users.create_index("username", unique=True)

# one-time: give old trees (like "D1") a numeric "no"
for t in db.trees.find({"no": {"$exists": False}}):
    d = re.sub(r"\D", "", t.get("code", ""))
    n = int(d) if d else 0
    try: db.trees.update_one({"_id": t["_id"]}, {"$set": {"no": n, "code": str(n) if n else t["code"]}})
    except DuplicateKeyError: pass

# MUST be set on Render, otherwise everybody is logged out on every restart
SECRET = os.getenv("SECRET_KEY") or secrets.token_hex(32)

# ---------- security helpers ----------
def hash_pw(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_pw(pw, h):
    try: return bcrypt.checkpw(pw.encode()[:72], h.encode())
    except Exception: return False
DUMMY = hash_pw("dummy-password-for-timing")

def strong(pw, username=""):
    """Return an error text, or None if the password is strong."""
    if not (12 <= len(pw) <= 64): return "length 12-64"
    if not re.search(r"[A-Z]", pw): return "capital letter"
    if not re.search(r"[a-z]", pw): return "small letter"
    if not re.search(r"\d", pw): return "number"
    if not re.search(r"[^A-Za-z0-9]", pw): return "symbol"
    if username and username.lower() in pw.lower(): return "contains username"
    return None

def sha(s): return hashlib.sha256((SECRET + s).encode()).hexdigest()
def make_token(username, pv):
    return jwt.encode({"sub": username, "pv": pv, "exp": datetime.now(timezone.utc) + timedelta(days=7)}, SECRET, algorithm="HS256")

def auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "auth")
    try: p = jwt.decode(authorization[7:], SECRET, algorithms=["HS256"])
    except jwt.PyJWTError: raise HTTPException(401, "auth")
    u = db.users.find_one({"username": p.get("sub")})
    if not u or p.get("pv") != u.get("pv", 0): raise HTTPException(401, "auth")
    return u

def send_mail(to, subject, body):
    key = os.getenv("RESEND_API_KEY")
    if key:  # works on Render (HTTPS)
        req = urllib.request.Request("https://api.resend.com/emails",
            data=json.dumps({"from": os.getenv("MAIL_FROM", "Durian Farm <onboarding@resend.dev>"),
                             "to": [to], "subject": subject, "text": body}).encode(),
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": "durian-farm/1.0"})
        urllib.request.urlopen(req, timeout=15); return
    if os.getenv("SMTP_USER"):  # Gmail app password (local use; Render free blocks SMTP)
        m = EmailMessage(); m["From"] = os.environ["SMTP_USER"]; m["To"] = to; m["Subject"] = subject; m.set_content(body)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"]); s.send_message(m)
        return
    print(f"\n=== DEV MODE (no email configured) ===\nTo: {to}\n{body}\n")

FAILS = {}  # key -> [count, locked_until]

# ---------- public routes ----------
@app.get("/")
def root(): return {"status": "ok", "app": "Durian Farm API"}

@app.post("/api/login")
def login(body: dict):
    name = str(body.get("username", "")).strip().lower()
    f = FAILS.get(name, [0, 0])
    if f[1] > time.time(): raise HTTPException(429, "locked")
    u = db.users.find_one({"username": name})
    ok = check_pw(str(body.get("password", "")), u["hash"] if u else DUMMY)
    if not (u and ok):
        f[0] += 1
        if f[0] >= 5: f = [0, time.time() + 600]
        FAILS[name] = f
        raise HTTPException(401, "bad_login")
    FAILS.pop(name, None)
    return {"token": make_token(name, u.get("pv", 0)), "username": name}

# ---------- protected routes ----------
api = APIRouter(prefix="/api", dependencies=[Depends(auth)])

@api.get("/me")
def me(u: dict = Depends(auth)):
    e = u.get("email", "")
    return {"username": u["username"], "email": (e[0] + "***" + e[e.index("@"):]) if "@" in e else ""}

@api.post("/password/request-otp")
def request_otp(u: dict = Depends(auth)):
    old = db.otps.find_one({"_id": u["username"]})
    if old and time.time() - old.get("sent", 0) < 60: raise HTTPException(429, "wait")
    code = f"{secrets.randbelow(1000000):06d}"
    db.otps.update_one({"_id": u["username"]}, {"$set": {"h": sha(code), "exp": time.time() + 600, "tries": 0, "sent": time.time()}}, upsert=True)
    try: send_mail(u["email"], "Durian Farm - password change code", f"Your code is {code}\nIt expires in 10 minutes.\nIf you did not ask for it, ignore this email.")
    except Exception as e:
        print("MAIL ERROR:", e); db.otps.delete_one({"_id": u["username"]}); raise HTTPException(502, "mail_fail")
    return {"ok": True}

@api.post("/password/change")
def change_password(body: dict, u: dict = Depends(auth)):
    o = db.otps.find_one({"_id": u["username"]})
    if not o or o["exp"] < time.time() or o["tries"] >= 5: raise HTTPException(400, "otp_expired")
    if not hmac.compare_digest(o["h"], sha(str(body.get("otp", "")).strip())):
        db.otps.update_one({"_id": u["username"]}, {"$inc": {"tries": 1}}); raise HTTPException(400, "otp_wrong")
    if not check_pw(str(body.get("old_password", "")), u["hash"]): raise HTTPException(400, "old_wrong")
    new = str(body.get("new_password", ""))
    if strong(new, u["username"]): raise HTTPException(400, "weak")
    db.users.update_one({"username": u["username"]}, {"$set": {"hash": hash_pw(new)}, "$inc": {"pv": 1}})
    db.otps.delete_one({"_id": u["username"]})
    return {"token": make_token(u["username"], u.get("pv", 0) + 1)}

# ---------- farm data ----------
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
    @api.get(f"/{name}", name=f"list_{name}")
    def lst(): return list(col.find({}, {"_id": 0}).sort(ORDER.get(name, [("id", 1)])))
    @api.post(f"/{name}", name=f"add_{name}")
    def add(body: dict):
        d = clean(name, body); d["id"] = next_id(name)
        try: col.insert_one(d)
        except DuplicateKeyError: return {"error": "duplicate"}
        return {"id": d["id"]}
    @api.put(f"/{name}/{{id}}", name=f"edit_{name}")
    def edit(id: int, body: dict):
        col.update_one({"id": id}, {"$set": clean(name, body)}); return {"ok": True}
    @api.delete(f"/{name}/{{id}}", name=f"del_{name}")
    def delete(id: int):
        if name == "categories": db.types.delete_many({"category_id": id})
        col.delete_one({"id": id}); return {"ok": True}

for n in COLS:
    if n != "trees": register(n)   # trees have their own protected routes below

# ---------- trees: numbered 1,2,3... ----------
def tree_numbers():
    return sorted(t["no"] for t in db.trees.find({}, {"no": 1}) if t.get("no"))

def tree_gaps():
    nums = tree_numbers(); have = set(nums)
    return [i for i in range(1, (nums[-1] if nums else 0) + 1) if i not in have]

def need_password(u, pw):
    k = "pw:" + u["username"]
    f = FAILS.get(k, [0, 0])
    if f[1] > time.time(): raise HTTPException(429, "locked")
    if not check_pw(str(pw or ""), u["hash"]):
        f[0] += 1
        if f[0] >= 5: f = [0, time.time() + 600]
        FAILS[k] = f
        raise HTTPException(403, "pw_wrong")
    FAILS.pop(k, None)

@api.get("/trees")
def list_trees(): return list(db.trees.find({}, {"_id": 0}).sort([("no", 1)]))

@api.get("/trees-info")
def trees_info():
    nums = tree_numbers()
    return {"max": nums[-1] if nums else 0, "total": len(nums), "gaps": tree_gaps()}

@api.post("/trees-add")
def trees_add(body: dict, u: dict = Depends(auth)):
    need_password(u, body.get("password"))
    count = int(body.get("count") or 0)
    if not 1 <= count <= 500: raise HTTPException(400, "count")
    fill = sorted(set(int(x) for x in body.get("fill_gaps", [])) & set(tree_gaps()))[:count]
    nums = tree_numbers(); start = (nums[-1] if nums else 0) + 1
    new = fill + list(range(start, start + count - len(fill)))
    for n in new:
        db.trees.insert_one({"id": next_id("trees"), "no": n, "code": str(n), "note": None})
    return {"added": new}

@api.put("/trees/{id}")
def edit_tree(id: int, body: dict):
    db.trees.update_one({"id": id}, {"$set": {"note": body.get("note") or None}}); return {"ok": True}

@api.post("/trees/{id}/delete")
def delete_tree(id: int, body: dict, u: dict = Depends(auth)):
    need_password(u, body.get("password"))
    db.trees.delete_one({"id": id}); return {"ok": True}

# ---------- reports ----------
def key(date, period):
    d = datetime.strptime(date[:10], "%Y-%m-%d")
    return {"day": d.strftime("%Y-%m-%d"), "week": d.strftime("%Y-W%W"), "month": d.strftime("%Y-%m"), "year": d.strftime("%Y")}[period]

@api.get("/report/spending")
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

@api.get("/report/fruit")
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

@api.get("/price")
def get_price():
    r = db.settings.find_one({"_id": "price"}); return {"price": r["v"] if r else 0}

@api.put("/price")
def set_price(body: dict):
    db.settings.update_one({"_id": "price"}, {"$set": {"v": float(body.get("price") or 0)}}, upsert=True); return {"ok": True}

app.include_router(api)   # keep this line LAST