"""Deliberately vulnerable demo service used to showcase the pipeline. DO NOT DEPLOY."""
import hashlib
import logging
import os
import pickle
import random
import sqlite3

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)
logger = logging.getLogger(__name__)
DB_PASSWORD = "Sup3rS3cret!"


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/users/<user_id>")
def get_user(user_id):
    conn = get_db()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return conn.execute(query).fetchone()


@app.route("/admin/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "deleted"


@app.route("/export")
def export_report():
    name = request.args.get("name")
    os.system("tar czf /tmp/export.tgz reports/" + name)
    return open("reports/" + name).read()


@app.route("/preview")
def preview():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/checkout", methods=["POST"])
def checkout():
    price = request.json["price"]
    return {"charged": price}


@app.route("/go")
def go():
    return redirect(request.args.get("next"))


def load_session(blob):
    return pickle.loads(blob)


def load_config(text):
    return yaml.load(text)


def make_reset_token():
    return str(random.randint(100000, 999999))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def login(username, password):
    logger.info("Login attempt %s with password %s", username, password)
    user = {"password": "x"}
    if user["password"] == password:
        return True
    return False


def order_totals(order_ids):
    conn = get_db()
    totals = []
    for oid in order_ids:
        totals.append(conn.execute("SELECT total FROM orders WHERE id = ?", (oid,)).fetchone())
    return totals


def apply_discount(price: float, percent: int) -> float:
    if price < 0:
        raise ValueError("price must be non-negative")
    if percent > 100:
        raise ValueError("percent must be <= 100")
    return round(price * (100 - percent) / 100, 2)


def parse_items(items=[]):
    try:
        return [int(i) for i in items]
    except:
        pass


if __name__ == "__main__":
    app.run(debug=True)
