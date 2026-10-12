"""Исправленная (безопасная) версия API."""
import os
import re
import sqlite3
from flask import Flask, request, jsonify
from markupsafe import escape

app = Flask(__name__)
app.config["DB"] = os.environ.get("USERS_DB", "users.db")
EMAIL_RE = re.compile(r"^[^@\s<>'\"]+@[^@\s<>'\"]+\.[^@\s<>'\"]+$")
NAME_RE = re.compile(r"^[\w .\-]{1,64}$", re.UNICODE)


def db():
    conn = sqlite3.connect(app.config["DB"])
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)")
    return conn


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'"
    return resp


@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}
    name, email = data.get("name", ""), data.get("email", "")
    if not (isinstance(name, str) and NAME_RE.match(name)) or not (isinstance(email, str) and EMAIL_RE.match(email)):
        return jsonify({"error": "invalid input"}), 400
    conn = db()
    cur = conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    conn.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "email": email}), 201


@app.route("/api/users", methods=["GET"])
def list_users():
    name = request.args.get("name", "")
    rows = db().execute("SELECT id, name, email FROM users WHERE name LIKE ?", (f"%{name}%",)).fetchall()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    conn = db()
    cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    return jsonify({"status": "deleted"})


@app.route("/hello")
def hello():
    return jsonify({"message": "Hello, " + str(escape(request.args.get("name", "")))})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
