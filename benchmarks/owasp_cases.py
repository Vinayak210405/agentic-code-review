"""Labelled OWASP Top 10 (2021) detection corpus.

Each vulnerable case must be detected in its category; each safe case is the
secure counterpart and must produce no MEDIUM-or-higher finding.  The corpus
was written by the project author alongside the rules, so it is a
*regression* benchmark, not an independent evaluation — see README.
"""

CASES = [
    # ------------------------------------------------------------- A01
    {"id": "a01-route-no-auth", "owasp": "A01", "vulnerable": True, "filename": "api/admin.py", "code": '''
from fastapi import APIRouter
router = APIRouter()

@router.delete("/admin/users/{user_id}")
def remove_user(user_id: int):
    return {"deleted": user_id}
'''},
    {"id": "a01-flask-no-auth", "owasp": "A01", "vulnerable": True, "filename": "web/views.py", "code": '''
from flask import Flask
app = Flask(__name__)

@app.route("/invoices/<invoice_id>", methods=["GET", "PUT"])
def update_invoice(invoice_id):
    return {"ok": invoice_id}
'''},
    {"id": "a01-path-traversal", "owasp": "A01", "vulnerable": True, "filename": "files.py", "code": '''
import os
from flask import request, send_file

def download():
    name = request.args.get("file")
    return send_file(os.path.join("/srv/uploads", name))
'''},
    {"id": "a01-open-redirect", "owasp": "A01", "vulnerable": True, "filename": "auth_views.py", "code": '''
from flask import redirect, request

def after_login():
    target = request.args.get("next")
    return redirect(target)
'''},
    {"id": "a01-safe-auth-dep", "owasp": "A01", "vulnerable": False, "filename": "api/safe_admin.py", "code": '''
from fastapi import APIRouter, Depends
from app.auth import get_current_admin
router = APIRouter()

@router.delete("/admin/users/{user_id}")
def remove_user(user_id: int, admin=Depends(get_current_admin)):
    return {"deleted": user_id}
'''},
    {"id": "a01-safe-decorator", "owasp": "A01", "vulnerable": False, "filename": "web/safe_views.py", "code": '''
from flask import Flask
from app.security import require_auth
app = Flask(__name__)

@app.route("/invoices/<invoice_id>")
@require_auth
def show_invoice(invoice_id):
    return {"ok": invoice_id}
'''},
    # ------------------------------------------------------------- A02
    {"id": "a02-md5-password", "owasp": "A02", "vulnerable": True, "filename": "crypto_utils.py", "code": '''
import hashlib

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
'''},
    {"id": "a02-sha1-new", "owasp": "A02", "vulnerable": True, "filename": "sig.py", "code": '''
import hashlib

def signature(payload):
    return hashlib.new("sha1", payload).hexdigest()
'''},
    {"id": "a02-random-token", "owasp": "A02", "vulnerable": True, "filename": "tokens.py", "code": '''
import random
import string

def create_session_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(32))
'''},
    {"id": "a02-ecb", "owasp": "A02", "vulnerable": True, "filename": "enc.py", "code": '''
from Crypto.Cipher import AES

def encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)
'''},
    {"id": "a02-safe-secrets", "owasp": "A02", "vulnerable": False, "filename": "safe_tokens.py", "code": '''
import hashlib
import secrets

def create_session_token():
    return secrets.token_urlsafe(32)

def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
'''},
    {"id": "a02-safe-random-nonsecurity", "owasp": "A02", "vulnerable": False, "filename": "shuffle.py", "code": '''
import random

def shuffle_playlist(songs):
    picked = random.sample(songs, k=len(songs))
    return picked
'''},
    # ------------------------------------------------------------- A03
    {"id": "a03-sqli-fstring", "owasp": "A03", "vulnerable": True, "filename": "repo.py", "code": '''
def find_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()
'''},
    {"id": "a03-sqli-format", "owasp": "A03", "vulnerable": True, "filename": "repo2.py", "code": '''
def orders_for(conn, customer_id):
    sql = "SELECT * FROM orders WHERE customer_id = {}".format(customer_id)
    return conn.execute(sql).fetchall()
'''},
    {"id": "a03-sqli-percent", "owasp": "A03", "vulnerable": True, "filename": "repo3.py", "code": '''
def delete_item(cur, item_id):
    cur.execute("DELETE FROM items WHERE id = %s" % item_id)
'''},
    {"id": "a03-sqli-sqlalchemy-text", "owasp": "A03", "vulnerable": True, "filename": "repo4.py", "code": '''
from sqlalchemy import text

def search(session, term):
    return session.execute(text("SELECT * FROM products WHERE name LIKE '%" + term + "%'"))
'''},
    {"id": "a03-cmd-subprocess-shell", "owasp": "A03", "vulnerable": True, "filename": "ops.py", "code": '''
import subprocess

def ping(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
'''},
    {"id": "a03-cmd-popen", "owasp": "A03", "vulnerable": True, "filename": "ops2.py", "code": '''
import os

def disk_usage(path):
    return os.popen("du -sh " + path).read()
'''},
    {"id": "a03-eval", "owasp": "A03", "vulnerable": True, "filename": "calc.py", "code": '''
def calculate(expression):
    return eval(expression)
'''},
    {"id": "a03-xss-markup", "owasp": "A03", "vulnerable": True, "filename": "render.py", "code": '''
from markupsafe import Markup

def greeting(name):
    return Markup(f"<h1>Hello {name}</h1>")
'''},
    {"id": "a03-js-sqli", "owasp": "A03", "vulnerable": True, "filename": "server/users.js", "code": '''
app.get("/users", (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
});
'''},
    {"id": "a03-js-innerhtml", "owasp": "A03", "vulnerable": True, "filename": "web/comment.js", "code": '''
function showComment(comment) {
  document.getElementById("out").innerHTML = comment.body;
}
'''},
    {"id": "a03-safe-param-sql", "owasp": "A03", "vulnerable": False, "filename": "safe_repo.py", "code": '''
def find_user(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cursor.fetchone()
'''},
    {"id": "a03-safe-subprocess-list", "owasp": "A03", "vulnerable": False, "filename": "safe_ops.py", "code": '''
import subprocess

def ping(host: str):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)
'''},
    {"id": "a03-safe-literal-eval", "owasp": "A03", "vulnerable": False, "filename": "safe_calc.py", "code": '''
import ast

def parse_list(text):
    return ast.literal_eval(text)
'''},
    # ------------------------------------------------------------- A04
    {"id": "a04-client-price", "owasp": "A04", "vulnerable": True, "filename": "checkout.py", "code": '''
from flask import request

def checkout():
    amount = request.json.get("price")
    return charge_card(amount)
'''},
    {"id": "a04-client-role", "owasp": "A04", "vulnerable": True, "filename": "signup.py", "code": '''
from flask import request

def register():
    role = request.form["role"]
    return create_user(role=role)
'''},
    {"id": "a04-assert-auth", "owasp": "A04", "vulnerable": True, "filename": "perm.py", "code": '''
def delete_project(user, project):
    assert user.is_admin, "admins only"
    project.delete()
'''},
    {"id": "a04-safe-server-price", "owasp": "A04", "vulnerable": False, "filename": "safe_checkout.py", "code": '''
from flask import request

def checkout(catalog):
    sku = request.json.get("sku")
    amount = catalog.price_for(sku)
    return charge_card(amount)
'''},
    {"id": "a04-safe-explicit-check", "owasp": "A04", "vulnerable": False, "filename": "safe_perm.py", "code": '''
def delete_project(user, project):
    if not user.is_admin:
        raise PermissionError("admins only")
    project.delete()
'''},
    # ------------------------------------------------------------- A05
    {"id": "a05-flask-debug", "owasp": "A05", "vulnerable": True, "filename": "run.py", "code": '''
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=True)
'''},
    {"id": "a05-django-debug", "owasp": "A05", "vulnerable": True, "filename": "settings.py", "code": '''
DEBUG = True
ALLOWED_HOSTS = ["*"]
'''},
    {"id": "a05-cors-wildcard-creds", "owasp": "A05", "vulnerable": True, "filename": "app_factory.py", "code": '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
'''},
    {"id": "a05-xxe", "owasp": "A05", "vulnerable": True, "filename": "xml_import.py", "code": '''
import xml.etree.ElementTree as ET

def import_feed(body):
    return ET.fromstring(body)
'''},
    {"id": "a05-yaml-config-debug", "owasp": "A05", "vulnerable": True, "filename": "config/prod.yaml", "code": '''
server:
  port: 8080
debug: true
'''},
    {"id": "a05-safe-cors", "owasp": "A05", "vulnerable": False, "filename": "safe_factory.py", "code": '''
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(debug=os.getenv("DEBUG") == "1")
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
'''},
    {"id": "a05-safe-defusedxml", "owasp": "A05", "vulnerable": False, "filename": "safe_xml.py", "code": '''
import defusedxml.ElementTree as DET

def import_feed(body):
    return DET.fromstring(body)
'''},
    # ------------------------------------------------------------- A06
    {"id": "a06-old-pyyaml", "owasp": "A06", "vulnerable": True, "filename": "requirements.txt", "code": '''
fastapi==0.110.0
PyYAML==5.3.1
'''},
    {"id": "a06-old-requests", "owasp": "A06", "vulnerable": True, "filename": "requirements.txt", "code": '''
requests==2.25.1
'''},
    {"id": "a06-old-pyjwt", "owasp": "A06", "vulnerable": True, "filename": "requirements-prod.txt", "code": '''
PyJWT==2.3.0
gunicorn==20.1.0
'''},
    {"id": "a06-safe-pinned", "owasp": "A06", "vulnerable": False, "filename": "requirements.txt", "code": '''
requests==2.32.3
PyYAML==6.0.2
flask==3.0.3
'''},
    # ------------------------------------------------------------- A07
    {"id": "a07-hardcoded-password", "owasp": "A07", "vulnerable": True, "filename": "db.py", "code": '''
import psycopg2

DB_PASSWORD = "pr0d-p@ssw0rd"

def connect():
    return psycopg2.connect(host="db", user="app", password=DB_PASSWORD)
'''},
    {"id": "a07-hardcoded-kwarg", "owasp": "A07", "vulnerable": True, "filename": "mailer.py", "code": '''
import smtplib

def send(msg):
    server = smtplib.SMTP("smtp.example.com")
    server.login(user="noreply", password="hunter2hunter2")
    server.send_message(msg)
'''},
    {"id": "a07-jwt-noverify", "owasp": "A07", "vulnerable": True, "filename": "jwt_auth.py", "code": '''
import jwt

def current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]
'''},
    {"id": "a07-tls-verify-false", "owasp": "A07", "vulnerable": True, "filename": "client.py", "code": '''
import requests

def fetch_rates():
    return requests.get("https://rates.internal/api", verify=False, timeout=5).json()
'''},
    {"id": "a07-aws-key", "owasp": "A07", "vulnerable": True, "filename": "deploy/config.js", "code": '''
const s3 = new S3Client({ accessKeyId: "AKIAIOSFODNN7EXAMPLE", region: "us-east-1" });
'''},
    {"id": "a07-safe-env-secret", "owasp": "A07", "vulnerable": False, "filename": "safe_db.py", "code": '''
import os
import psycopg2

DB_PASSWORD = os.environ["DB_PASSWORD"]

def connect():
    return psycopg2.connect(host="db", user="app", password=DB_PASSWORD)
'''},
    {"id": "a07-safe-jwt", "owasp": "A07", "vulnerable": False, "filename": "safe_jwt.py", "code": '''
import os
import jwt

def current_user(token):
    claims = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
    return claims["sub"]
'''},
    # ------------------------------------------------------------- A08
    {"id": "a08-pickle", "owasp": "A08", "vulnerable": True, "filename": "cache.py", "code": '''
import pickle

def load_cart(cookie_value):
    return pickle.loads(cookie_value)
'''},
    {"id": "a08-yaml-load", "owasp": "A08", "vulnerable": True, "filename": "cfg_loader.py", "code": '''
import yaml

def load(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.Loader)
'''},
    {"id": "a08-torch-load", "owasp": "A08", "vulnerable": True, "filename": "model_loader.py", "code": '''
import torch

def load_model(path):
    return torch.load(path)
'''},
    {"id": "a08-curl-bash", "owasp": "A08", "vulnerable": True, "filename": "Dockerfile", "code": '''
FROM python:3.12-slim
RUN curl -sSL https://install.example.com/setup.sh | bash
'''},
    {"id": "a08-safe-yaml", "owasp": "A08", "vulnerable": False, "filename": "safe_cfg.py", "code": '''
import json
import yaml

def load(path):
    with open(path) as fh:
        return yaml.safe_load(fh)

def load_cart(cookie_value):
    return json.loads(cookie_value)
'''},
    # ------------------------------------------------------------- A09
    {"id": "a09-log-password", "owasp": "A09", "vulnerable": True, "filename": "login.py", "code": '''
import logging
logger = logging.getLogger(__name__)

def login(username, password):
    logger.debug(f"login user={username} password={password}")
'''},
    {"id": "a09-log-token", "owasp": "A09", "vulnerable": True, "filename": "oauth.py", "code": '''
import logging

def store(access_token):
    logging.info("received token %s", access_token)
'''},
    {"id": "a09-swallow", "owasp": "A09", "vulnerable": True, "filename": "audit.py", "code": '''
def record_failed_login(audit, user):
    try:
        audit.write(user)
    except Exception:
        pass
'''},
    {"id": "a09-safe-logging", "owasp": "A09", "vulnerable": False, "filename": "safe_login.py", "code": '''
import logging
logger = logging.getLogger(__name__)

def login(username, password_hash):
    logger.info("login attempt for user=%s", username)
    try:
        return verify(username, password_hash)
    except ValueError:
        logger.exception("verification failed for %s", username)
        raise
'''},
    # ------------------------------------------------------------- A10
    {"id": "a10-requests-user-url", "owasp": "A10", "vulnerable": True, "filename": "preview.py", "code": '''
import requests
from flask import request

def link_preview():
    target = request.args.get("url")
    return requests.get(target, timeout=3).text
'''},
    {"id": "a10-webhook-param", "owasp": "A10", "vulnerable": True, "filename": "webhook.py", "code": '''
import httpx

def deliver(webhook_url, event):
    return httpx.post(webhook_url, json=event, timeout=5)
'''},
    {"id": "a10-urlopen", "owasp": "A10", "vulnerable": True, "filename": "fetcher.py", "code": '''
from urllib.request import urlopen
from flask import request

def fetch_avatar():
    return urlopen(request.form["avatar_url"]).read()
'''},
    {"id": "a10-js-ssrf", "owasp": "A10", "vulnerable": True, "filename": "server/proxy.js", "code": '''
app.get("/proxy", async (req, res) => {
  const r = await axios.get(req.query.target);
  res.send(r.data);
});
'''},
    {"id": "a10-safe-fixed-url", "owasp": "A10", "vulnerable": False, "filename": "safe_rates.py", "code": '''
import requests

RATES_URL = "https://api.exchangerate.example.com/latest"

def fetch_rates():
    return requests.get(RATES_URL, timeout=5).json()
'''},
]
