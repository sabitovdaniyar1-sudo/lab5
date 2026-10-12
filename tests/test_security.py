"""API security tests: TC-03 (SQLi), TC-04 (XSS) + доп. проверки.
Каждый тест прогоняется против уязвимой (app_vulnerable) и исправленной (app) версий.
Переменная TARGET=vulnerable|secure; по умолчанию secure (так работает CI).
"""
import importlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = os.environ.get("TARGET", "secure")
SQLI = "' OR '1'='1"
XSS = "<script>alert(1)</script>"


class SecurityTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        if TARGET == "vulnerable":
            self.mod = importlib.import_module("app_vulnerable")
            self.mod.DB = self.path
        else:
            self.mod = importlib.import_module("app")
            self.mod.app.config["DB"] = self.path
        self.mod.app.config["TESTING"] = True
        self.c = self.mod.app.test_client()

    def tearDown(self):
        os.remove(self.path)

    def _seed(self):
        self.c.post("/api/users", json={"name": "alice", "email": "a@x.com"})
        self.c.post("/api/users", json={"name": "bob", "email": "b@x.com"})

    # --- функциональные ---
    def test_crud(self):
        r = self.c.post("/api/users", json={"name": "alice", "email": "a@x.com"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(len(self.c.get("/api/users").get_json()), 1)
        self.assertEqual(self.c.delete("/api/users/1").status_code, 200)
        self.assertEqual(self.c.get("/api/users").get_json(), [])

    # --- TC-03 SQL Injection ---
    def test_tc03_sqli_get_filter(self):
        self._seed()
        r = self.c.get("/api/users", query_string={"name": "zzz" + SQLI + " AND '1'='1"})
        data = r.get_json() if r.is_json else []
        self.assertEqual(data, [], "SQLi: фильтр вернул чужие записи")

    def test_tc03_sqli_delete(self):
        self._seed()
        r = self.c.delete("/api/users/1 OR 1=1")
        self.assertIn(r.status_code, (400, 404), "SQLi: DELETE принял SQL-выражение")
        self.assertEqual(len(self.c.get("/api/users").get_json()), 2)

    def test_tc03_sqli_post(self):
        r = self.c.post("/api/users", json={"name": "x'); DROP TABLE users;--", "email": "e@x.com"})
        self.assertEqual(r.status_code, 400, "SQLi: POST принял вредоносное имя")

    # --- TC-04 XSS ---
    def test_tc04_xss_reflected(self):
        r = self.c.get("/hello", query_string={"name": XSS})
        self.assertNotIn(XSS, r.get_data(as_text=True), "XSS: скрипт отражён без экранирования")

    def test_tc04_xss_stored(self):
        r = self.c.post("/api/users", json={"name": XSS, "email": "e@x.com"})
        self.assertEqual(r.status_code, 400, "XSS: сохранён скрипт")

    # --- A05 Misconfiguration / A03 eval ---
    def test_no_eval_endpoint(self):
        r = self.c.get("/api/calc", query_string={"expr": "1+1"})
        self.assertEqual(r.status_code, 404, "RCE: доступен eval-эндпоинт")

    def test_security_headers(self):
        r = self.c.get("/api/users")
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")


if __name__ == "__main__":
    unittest.main(verbosity=2)
