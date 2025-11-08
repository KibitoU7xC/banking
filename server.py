#!/usr/bin/env python3
"""
server.py - simple dev server for the banking app
Note: for production, use a proper WSGI server + secure session store.
"""

import http.server
import socketserver
import json
import mysql.connector
from urllib.parse import urlparse
import urllib
import uuid, os, hashlib, hmac
from http import cookies
from decimal import Decimal

HOST = "0.0.0.0"
PORT = 8080

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "1234",
    "database": "bank",
    "autocommit": False
}

SESSION_COOKIE = "BANKSESSION"
SESSIONS = {}

def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt + hashed

def verify_password(stored: bytes, provided_plain: str) -> bool:
    salt = stored[:16]
    stored_hash = stored[16:]
    new_hash = hashlib.pbkdf2_hmac("sha256", provided_plain.encode(), salt, 200_000)
    return hmac.compare_digest(stored_hash, new_hash)

def get_db_conn():
    return mysql.connector.connect(**DB_CONFIG)

def write_json(handler, status, data, set_cookie=None):
    payload = json.dumps(data, default=str).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    if set_cookie:
        handler.send_header("Set-Cookie", set_cookie)
    handler.end_headers()
    handler.wfile.write(payload)

def gen_account_number():
    return str(uuid.uuid4()).replace('-', '')[:16]

class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # serve static files from ./static
        if path == "/" or path.startswith("/static/") or path.endswith(".html") or path.endswith(".css") or path.endswith(".js"):
            if path == "/":
                return "static/index.html"
            if path.startswith("/static/"):
                return "." + path
            return "static" + path if path.startswith("/") else "static/" + path
        return super().translate_path(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length > 0 else b''
        content_type = self.headers.get('Content-Type', '')
        data = {}
        try:
            if 'application/json' in content_type:
                data = json.loads(raw.decode() or "{}")
            else:
                tmp = urllib.parse.parse_qs(raw.decode())
                data = {k: v[0] for k, v in tmp.items()}
        except Exception:
            data = {}

        if path == "/api/register":
            return self.api_register(data)
        if path == "/api/login":
            return self.api_login(data)
        if path == "/api/create_account":
            return self.api_create_account(data)
        if path == "/api/accounts":
            return self.api_list_accounts()
        if path == "/api/transaction":
            return self.api_transaction(data)
        if path.startswith("/api/transactions/"):
            account_number = path.split("/")[-1]
            return self.api_get_transactions(account_number)
        if path == "/api/admin/transactions":
            return self.api_admin_transactions(data)
        if path == "/api/admin/stats":
            return self.api_admin_stats()
        if path == "/api/admin/rename_person":
            return self.api_admin_rename_person(data)
        # unknown
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'Not found')

    def get_current_session(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        c = cookies.SimpleCookie()
        c.load(cookie_header)
        if SESSION_COOKIE not in c:
            return None
        sid = c[SESSION_COOKIE].value
        return SESSIONS.get(sid)

    def api_register(self, data):
        name = data.get("name") or ""
        email = data.get("email") or ""
        password = data.get("password") or ""
        if not (name and email and password):
            write_json(self, 400, {"error":"name,email,password required"})
            return
        hashed = hash_password(password)
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO person (user_id,name,email,password_hash,role) VALUES (%s,%s,%s,%s,%s)",
                        (email, name, email, mysql.connector.Binary(hashed), 'customer'))
            pid = cur.lastrowid
            cur.execute("INSERT INTO customer (person_id) VALUES (%s)", (pid,))
            conn.commit()
            write_json(self, 200, {"status":"ok","msg":"registered"})
        except mysql.connector.IntegrityError as e:
            conn.rollback()
            write_json(self, 400, {"error":"user exists", "detail": str(e)})
        except Exception as e:
            conn.rollback()
            write_json(self, 500, {"error":"db error", "detail": str(e)})
        finally:
            cur.close()
            conn.close()

    def api_login(self, data):
        email = data.get("email") or ""
        password = data.get("password") or ""
        if not (email and password):
            write_json(self, 400, {"error":"email,password required"})
            return
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM person WHERE email=%s", (email,))
            user = cur.fetchone()
            if not user:
                write_json(self, 400, {"error":"invalid credentials"})
                return
            stored = user['password_hash']
            if isinstance(stored, memoryview):
                stored = stored.tobytes()
            if not verify_password(stored, password):
                write_json(self, 400, {"error":"invalid credentials"})
                return
            sid = str(uuid.uuid4())
            SESSIONS[sid] = {"user_id": user['user_id'], "person_id": user['id'], "name": user['name']}
            cookie = cookies.SimpleCookie()
            cookie[SESSION_COOKIE] = sid
            cookie[SESSION_COOKIE]["path"] = "/"
            # check admin table now for role
            cur.execute("SELECT 1 FROM admin WHERE person_id=%s LIMIT 1", (user['id'],))
            is_admin = cur.fetchone() is not None
            role = "admin" if is_admin else "customer"
            SESSIONS[sid]["role"] = role
            write_json(self, 200, {"status":"ok","msg":"logged in","role":role}, set_cookie=cookie.output(header='').strip())
        except Exception as e:
            write_json(self, 500, {"error":"db error", "detail": str(e)})
        finally:
            cur.close()
            conn.close()

    def require_auth(self):
        sess = self.get_current_session()
        if not sess:
            write_json(self, 401, {"error":"login required"})
            return None
        return sess

    def require_admin(self):
        sess = self.get_current_session()
        if not sess:
            write_json(self, 401, {"error":"login required"})
            return None
        # verify admin table in DB to be safe
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT 1 FROM admin WHERE person_id=%s LIMIT 1", (sess["person_id"],))
            row = cur.fetchone()
            if not row:
                write_json(self, 403, {"error":"admin only"})
                return None
            return sess
        except Exception as e:
            write_json(self, 500, {"error":"db error", "detail": str(e)})
            return None
        finally:
            cur.close()
            conn.close()

    def api_create_account(self, data):
        sess = self.require_auth()
        if not sess:
            return
        acct_type = data.get("account_type", "savings")
        acct_no = gen_account_number()
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO account (account_number, person_id, account_type, balance) VALUES (%s,%s,%s,%s)",
                        (acct_no, sess['person_id'], acct_type, Decimal("0.00")))
            conn.commit()
            write_json(self, 200, {"status":"ok","account_number":acct_no})
        except Exception as e:
            conn.rollback()
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

    def api_list_accounts(self):
        sess = self.require_auth()
        if not sess:
            return
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT account_number, account_type, balance FROM account WHERE person_id=%s", (sess['person_id'],))
            rows = cur.fetchall()
            write_json(self, 200, {"accounts": rows})
        except Exception as e:
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

    def api_transaction(self, data):
        sess = self.require_auth()
        if not sess:
            return
        acct_no = data.get("account_number")
        ttype = data.get("transaction_type")
        try:
            amount = Decimal(str(data.get("amount", "0")))
        except Exception:
            write_json(self, 400, {"error":"invalid amount"})
            return
        if amount <= 0:
            write_json(self, 400, {"error":"amount must be positive"})
            return

        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM account WHERE account_number=%s FOR UPDATE", (acct_no,))
            src = cur.fetchone()
            if not src:
                write_json(self, 404, {"error":"source account not found"})
                return
            if src['person_id'] != sess['person_id']:
                write_json(self, 403, {"error":"not owner of source account"})
                return

            if ttype == "deposit":
                newbal = Decimal(src['balance']) + amount
                cur.execute("UPDATE account SET balance=%s WHERE id=%s", (newbal, src['id']))
                txid = "TXN-"+str(uuid.uuid4())
                cur.execute("INSERT INTO transaction (transaction_id, account_id, amount, transaction_type, transaction_log) VALUES (%s,%s,%s,%s,%s)",
                            (txid, src['id'], amount, 'deposit', f"Deposit {amount}"))
                conn.commit()
                write_json(self, 200, {"status":"ok","transaction_id":txid})
                return

            elif ttype == "withdrawal":
                if Decimal(src['balance']) < amount:
                    write_json(self, 400, {"error":"insufficient funds"})
                    return
                newbal = Decimal(src['balance']) - amount
                cur.execute("UPDATE account SET balance=%s WHERE id=%s", (newbal, src['id']))
                txid = "TXN-"+str(uuid.uuid4())
                cur.execute("INSERT INTO transaction (transaction_id, account_id, amount, transaction_type, transaction_log) VALUES (%s,%s,%s,%s,%s)",
                            (txid, src['id'], amount, 'withdrawal', f"Withdrawal {amount}"))
                conn.commit()
                write_json(self, 200, {"status":"ok","transaction_id":txid})
                return

            elif ttype == "transfer":
                to_acct_no = data.get("to_account_number")
                if not to_acct_no:
                    write_json(self, 400, {"error":"to_account_number required"})
                    return
                cur.execute("SELECT * FROM account WHERE account_number=%s FOR UPDATE", (to_acct_no,))
                dst = cur.fetchone()
                if not dst:
                    write_json(self, 404, {"error":"destination account not found"})
                    return
                if Decimal(src['balance']) < amount:
                    write_json(self, 400, {"error":"insufficient funds"})
                    return
                new_src = Decimal(src['balance']) - amount
                new_dst = Decimal(dst['balance']) + amount
                cur.execute("UPDATE account SET balance=%s WHERE id=%s", (new_src, src['id']))
                cur.execute("UPDATE account SET balance=%s WHERE id=%s", (new_dst, dst['id']))
                txid = "TXN-"+str(uuid.uuid4())
                cur.execute("INSERT INTO transaction (transaction_id, account_id, amount, transaction_type, to_account_number, transaction_log) VALUES (%s,%s,%s,%s,%s,%s)",
                            (txid, src['id'], amount, 'transfer', to_acct_no, f"Transfer to {to_acct_no}"))
                conn.commit()
                write_json(self, 200, {"status":"ok","transaction_id":txid})
                return
            else:
                write_json(self, 400, {"error":"invalid transaction type"})
                return
        except Exception as e:
            conn.rollback()
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

    def api_get_transactions(self, account_number):
        sess = self.require_auth()
        if not sess:
            return
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT * FROM account WHERE account_number=%s", (account_number,))
            acct = cur.fetchone()
            if not acct:
                write_json(self, 404, {"error":"account not found"})
                return
            if acct['person_id'] != sess['person_id']:
                write_json(self, 403, {"error":"not your account"})
                return
            cur.execute("SELECT transaction_id, amount, transaction_type, to_account_number, transaction_log, created_at FROM transaction WHERE account_id=%s ORDER BY created_at DESC LIMIT 100", (acct['id'],))
            rows = cur.fetchall()
            write_json(self, 200, {"transactions": rows})
        except Exception as e:
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

    # Admin endpoints (require admin table membership)
    def api_admin_transactions(self, data):
        sess = self.require_admin()
        if not sess:
            return
        q = (data.get("q") or "").strip()
        order_by = data.get("order_by") or "created_at"
        direction = (data.get("direction") or "desc").lower()
        limit = int(data.get("limit") or 200)
        if order_by not in ("created_at", "amount", "transaction_type", "name", "account_number"):
            order_by = "created_at"
        if direction not in ("asc","desc"):
            direction = "desc"
        sql_order_field = order_by
        if order_by == "name":
            sql_order_field = "p.name"
        elif order_by == "account_number":
            sql_order_field = "a.account_number"

        base_sql = """
            SELECT t.transaction_id, t.amount, t.transaction_type, t.to_account_number, t.transaction_log, t.created_at,
                   a.account_number, p.id as person_id, p.name, p.email
            FROM transaction t
            JOIN account a ON t.account_id = a.id
            JOIN person p ON a.person_id = p.id
        """
        params = []
        if q:
            base_sql += " WHERE (p.name LIKE %s OR p.email LIKE %s OR a.account_number LIKE %s) "
            likeq = f"%{q}%"
            params.extend([likeq, likeq, likeq])
        base_sql += f" ORDER BY {sql_order_field} {direction} LIMIT %s"
        params.append(limit)

        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(base_sql, tuple(params))
            rows = cur.fetchall()
            write_json(self, 200, {"transactions": rows})
        except Exception as e:
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

    def api_admin_stats(self):
        sess = self.require_admin()
        if not sess:
            return
        conn = get_db_conn()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT transaction_type, AVG(amount) as avg_amount, COUNT(*) as cnt FROM transaction GROUP BY transaction_type")
            rows = cur.fetchall()
            write_json(self, 200, {"stats": rows})
        except Exception as e:
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

    def api_admin_rename_person(self, data):
        sess = self.require_admin()
        if not sess:
            return
        person_id = data.get("person_id")
        new_name = (data.get("new_name") or "").strip()
        if not person_id or not new_name:
            write_json(self, 400, {"error":"person_id and new_name required"})
            return
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            cur.execute("UPDATE person SET name=%s WHERE id=%s", (new_name, person_id))
            if cur.rowcount == 0:
                conn.rollback()
                write_json(self, 404, {"error":"person not found"})
                return
            conn.commit()
            write_json(self, 200, {"status":"ok","msg":"name updated"})
        except Exception as e:
            conn.rollback()
            write_json(self, 500, {"error":"db error", "detail":str(e)})
        finally:
            cur.close()
            conn.close()

if __name__ == "__main__":
    print(f"Starting server at http://{HOST}:{PORT}")
    handler = Handler
    with socketserver.ThreadingTCPServer((HOST, PORT), handler) as httpd:
        httpd.serve_forever()
