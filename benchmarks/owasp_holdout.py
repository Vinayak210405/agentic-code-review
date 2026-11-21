"""Held-out OWASP cases written AFTER the rules were finished, using idioms
not present in owasp_cases.py. Rules were NOT tuned on these; results are
reported as-is to give a less optimistic estimate."""

CASES = [
    {"id": "h-a01-django-view", "owasp": "A01", "vulnerable": True, "filename": "shop/api.py", "code": '''
from fastapi import FastAPI
app = FastAPI()

@app.patch("/accounts/{account_id}/limits")
async def raise_limit(account_id: str, new_limit: int):
    return await store.update(account_id, new_limit)
'''},
    {"id": "h-a01-pathlib-traversal", "owasp": "A01", "vulnerable": True, "filename": "assets.py", "code": '''
from pathlib import Path
from flask import request

def read_asset():
    rel = request.args["p"]
    return Path("/var/www/assets", rel).read_text()
'''},
    {"id": "h-a02-sha1-password", "owasp": "A02", "vulnerable": True, "filename": "legacy_auth.py", "code": '''
from hashlib import sha1

def store_password(user, pw):
    user.pw_hash = sha1(pw.encode()).hexdigest()
'''},
    {"id": "h-a02-random-otp", "owasp": "A02", "vulnerable": True, "filename": "otp.py", "code": '''
import random

def send_otp(phone):
    otp = random.randrange(100000, 999999)
    sms.send(phone, otp)
'''},
    {"id": "h-a03-sqli-concat-var", "owasp": "A03", "vulnerable": True, "filename": "report_repo.py", "code": '''
def monthly(cursor, month):
    base = "SELECT sum(total) FROM orders WHERE month = '"
    sql = base + month + "'"
    cursor.execute(sql)
'''},
    {"id": "h-a03-cmd-call-shell", "owasp": "A03", "vulnerable": True, "filename": "backup.py", "code": '''
import subprocess

def backup(db_name):
    cmd = "pg_dump " + db_name + " > /backups/out.sql"
    subprocess.call(cmd, shell=True)
'''},
    {"id": "h-a03-exec-template", "owasp": "A03", "vulnerable": True, "filename": "plugin.py", "code": '''
def run_plugin(source_code):
    namespace = {}
    exec(source_code, namespace)
    return namespace
'''},
    {"id": "h-a03-render-template-string", "owasp": "A03", "vulnerable": True, "filename": "hello.py", "code": '''
from flask import request, render_template_string

def hello():
    return render_template_string("<p>Hi " + request.args.get("n", "") + "</p>")
'''},
    {"id": "h-a04-discount-from-body", "owasp": "A04", "vulnerable": True, "filename": "cart.py", "code": '''
from flask import request

def apply():
    body = request.get_json()
    return finalize(total=body["total"])
'''},
    {"id": "h-a05-cors-flask", "owasp": "A05", "vulnerable": True, "filename": "wsgi.py", "code": '''
from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app, supports_credentials=True)
'''},
    {"id": "h-a05-lxml-entities", "owasp": "A05", "vulnerable": True, "filename": "svg.py", "code": '''
from lxml import etree

def parse_svg(data):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)
'''},
    {"id": "h-a06-old-flask-werkzeug", "owasp": "A06", "vulnerable": True, "filename": "requirements/base.txt", "code": '''
Flask==2.0.3
Werkzeug==2.0.3
'''},
    {"id": "h-a07-secret-dict", "owasp": "A07", "vulnerable": True, "filename": "settings_local.py", "code": '''
STRIPE = {"api_key": "rk_live_51Habcdefghijklmno", "timeout": 10}
'''},
    {"id": "h-a07-github-token-yaml", "owasp": "A07", "vulnerable": True, "filename": ".github/workflows/release.yml", "code": '''
env:
  GH_TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123456789
'''},
    {"id": "h-a07-jwt-alg-none", "owasp": "A07", "vulnerable": True, "filename": "sso.py", "code": '''
import jwt

def read(token, key):
    return jwt.decode(token, key, algorithms=["HS256", "none"])
'''},
    {"id": "h-a08-joblib", "owasp": "A08", "vulnerable": True, "filename": "ml/serve.py", "code": '''
import joblib

def load(path_from_user):
    return joblib.load(path_from_user)
'''},
    {"id": "h-a08-marshal", "owasp": "A08", "vulnerable": True, "filename": "rpc.py", "code": '''
import marshal

def decode(blob):
    return marshal.loads(blob)
'''},
    {"id": "h-a09-print-card", "owasp": "A09", "vulnerable": True, "filename": "payments.py", "code": '''
def charge(card_number, amount):
    print("charging", card_number, amount)
'''},
    {"id": "h-a10-session-get", "owasp": "A10", "vulnerable": True, "filename": "importer.py", "code": '''
import requests
from flask import request

def import_feed():
    feed = request.json.get("feed")
    with requests.Session() as session:
        return session.get(feed, timeout=10).text
'''},
    {"id": "h-a10-aiohttp", "owasp": "A10", "vulnerable": True, "filename": "thumbs.py", "code": '''
import httpx

async def thumbnail(image_url: str):
    async with httpx.AsyncClient() as client:
        return await client.get(image_url)
'''},
    # ---- safe
    {"id": "h-safe-orm", "owasp": "A03", "vulnerable": False, "filename": "orm_repo.py", "code": '''
from sqlalchemy import select

def by_email(session, email):
    return session.execute(select(User).where(User.email == email)).scalar_one_or_none()
'''},
    {"id": "h-safe-shlex", "owasp": "A03", "vulnerable": False, "filename": "safe_backup.py", "code": '''
import subprocess

def backup(db_name: str) -> None:
    subprocess.run(["pg_dump", "--dbname", db_name, "--file", "/backups/out.sql"], check=True)
'''},
    {"id": "h-safe-secret-from-vault", "owasp": "A07", "vulnerable": False, "filename": "vault_cfg.py", "code": '''
from app.vault import read_secret

API_KEY = read_secret("payments/api_key")
password_field_label = "Password"
'''},
    {"id": "h-safe-public-route", "owasp": "A01", "vulnerable": False, "filename": "status.py", "code": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"ok": True}
'''},
    {"id": "h-safe-allowlisted-fetch", "owasp": "A10", "vulnerable": False, "filename": "safe_fetch.py", "code": '''
import requests

ALLOWED = {"https://cdn.example.com/feed.xml"}

def fetch_feed(name: str):
    url = "https://cdn.example.com/" + name + ".xml"
    if url not in ALLOWED:
        raise ValueError("not allowed")
    return requests.get("https://cdn.example.com/feed.xml", timeout=5).text
'''},
    {"id": "h-safe-blake2", "owasp": "A02", "vulnerable": False, "filename": "etag.py", "code": '''
import hashlib

def etag(body: bytes) -> str:
    return hashlib.blake2b(body, digest_size=16).hexdigest()
'''},
    {"id": "h-safe-logging-redacted", "owasp": "A09", "vulnerable": False, "filename": "audit_ok.py", "code": '''
import logging
log = logging.getLogger("audit")

def on_login(user_id: int, success: bool) -> None:
    log.info("login user_id=%s success=%s", user_id, success)
'''},
    {"id": "h-safe-modern-reqs", "owasp": "A06", "vulnerable": False, "filename": "requirements.txt", "code": '''
Flask==3.0.3
Werkzeug==3.0.6
PyJWT==2.9.0
'''},
]
