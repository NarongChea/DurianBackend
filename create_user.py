import argparse, getpass, sys
from main import db, hash_pw, strong

ap = argparse.ArgumentParser()
ap.add_argument("--username", default="admin")
ap.add_argument("--email", default="senghern013@gmail.com")
a = ap.parse_args()
name = a.username.strip().lower()

pw = getpass.getpass("New password (hidden): ")
if pw != getpass.getpass("Repeat password: "): sys.exit("Passwords do not match")
err = strong(pw, name)
if err: sys.exit(f"Weak password: needs 12-64 characters, capital, small, number, symbol, not your username ({err})")

db.users.update_one({"username": name},
    {"$set": {"username": name, "email": a.email, "hash": hash_pw(pw)}, "$inc": {"pv": 1}}, upsert=True)
print(f"OK: account '{name}' saved. OTP codes will be sent to {a.email}")