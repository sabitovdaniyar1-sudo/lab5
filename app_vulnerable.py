"""УЯЗВИМАЯ версия API (только для лабораторной, НЕ использовать в проде)."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB = "users_vuln.db"


def db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)")
    return conn


@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json(force=True)
    conn = db()
    # A03 Injection: SQL строится конкатенацией строк
    conn.execute("INSERT INTO users (name, email) VALUES ('%s', '%s')" % (data["name"], data["email"]))
    conn.commit()
    return jsonify({"status": "created", "name": data["name"]}), 201


@app.route("/api/users", methods=["GET"])
def list_users():
    name = request.args.get("name", "")
    conn = db()
    # A03 Injection: SQL Injection через параметр name
    rows = conn.execute(f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'").fetchall()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@app.route("/api/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    conn = db()
    # A01/A03: нет авторизации, SQL конкатенацией
    conn.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/calc")
def calc():
    # A03: выполнение произвольного кода
    return jsonify({"result": eval(request.args.get("expr", "0"))})


@app.route("/hello")
def hello():
    # A03 XSS: пользовательский ввод отражается как HTML без экранирования
    return "<h1>Hello, " + request.args.get("name", "") + "</h1>"


if __name__ == "__main__":
    # A05 Security Misconfiguration: debug + доступ со всех интерфейсов
    app.run(host="0.0.0.0", port=5000, debug=True)
