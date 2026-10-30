import http.server
import socketserver
import json
import os
import time
import secrets
from urllib.parse import urlparse

import hashlib

PORT = int(os.environ.get("PORT", 8888))
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.json")
CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SECRET_SALT = "AWS_PRO_REALTIME_LICENSE_SECURE_2026"

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    db = {"tokens": []}
    save_db(db)
    return db

def save_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def generate_16char_token():
    return "".join(secrets.choice(CHARS) for _ in range(16))

def is_valid_token_format(token):
    if not isinstance(token, str):
        return False
    trimmed = token.strip()
    return 6 <= len(trimmed) <= 64

class Handler(http.server.BaseHTTPRequestHandler):
    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.end_headers()

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_cors()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)
        return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            return self.send_json(200, {"status": "ok", "time": int(time.time() * 1000)})
        if parsed.path == "/api/tokens":
            db = load_db()
            now = int(time.time() * 1000)
            for t in db.get("tokens", []):
                if t.get("status") == "active" and t.get("expiresAt") and now > t["expiresAt"]:
                    t["status"] = "expired"
            save_db(db)
            return self.send_json(200, {"tokens": db.get("tokens", [])})
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_cors()
            self.end_headers()
            # Serve dashboard HTML from node server equivalent
            html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Saned Admin</title></head><body style="background:#0f172a;color:#fff;padding:2rem;"><h2>Saned Python Server Running on port """ + str(PORT) + """</h2><p>Use Node.js server.js for the complete dashboard UI, or use the API endpoints directly.</p></body></html>"""
            self.wfile.write(html.encode("utf-8"))
            return
        self.send_json(404, {"message": "Not Found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self.read_body()
        db = load_db()
        now = int(time.time() * 1000)

        if parsed.path == "/api/verify":
            token_str = str(body.get("token", "")).strip()
            device_id = str(body.get("device_id", "")).strip()
            if not token_str or not device_id:
                return self.send_json(400, {"unlocked": False, "message": "Missing token or device_id"})
            if not is_valid_token_format(token_str):
                return self.send_json(400, {"unlocked": False, "reason": "invalid_format", "message": "Invalid 16-character token format"})
            found = next((t for t in db["tokens"] if t["token"].lower() == token_str.lower()), None)
            if not found:
                return self.send_json(404, {"unlocked": False, "reason": "not_found", "message": "Token not found"})
            if found.get("status") == "revoked":
                return self.send_json(403, {"unlocked": False, "reason": "revoked", "message": "Token revoked"})
            if found.get("deviceId") and found["deviceId"] != device_id:
                return self.send_json(403, {"unlocked": False, "reason": "device_mismatch", "message": "Bound to another device"})
            if found.get("expiresAt") and now > found["expiresAt"]:
                found["status"] = "expired"
                save_db(db)
                return self.send_json(403, {"unlocked": False, "reason": "expired", "message": "Subscription expired"})
            days_left = max(0, int((found["expiresAt"] - now) / 86400000)) if found.get("expiresAt") else 0
            return self.send_json(200, {"unlocked": True, "token": found["token"], "expires_at": found.get("expiresAt"), "days_left": days_left})

        if parsed.path == "/api/activate":
            token_str = str(body.get("token", "")).strip()
            device_id = str(body.get("device_id", "")).strip()
            if not token_str or not device_id:
                return self.send_json(400, {"success": False, "unlocked": False, "message": "Missing token or device_id"})
            if not is_valid_token_format(token_str):
                return self.send_json(400, {"success": False, "unlocked": False, "reason": "invalid_format", "message": "Invalid 16-character token format"})
            found = next((t for t in db["tokens"] if t["token"].lower() == token_str.lower()), None)
            if not found:
                return self.send_json(404, {"success": False, "unlocked": False, "message": "Invalid 16-character token"})
            if found.get("status") == "revoked":
                return self.send_json(403, {"success": False, "unlocked": False, "message": "Token has been revoked"})
            if found.get("deviceId") and found["deviceId"] != device_id:
                return self.send_json(403, {"success": False, "unlocked": False, "message": "Token already bound to another device"})
            if not found.get("deviceId"):
                found["deviceId"] = device_id
                found["activatedAt"] = now
                found["expiresAt"] = now + (found["periodDays"] * 86400000)
                found["status"] = "active"
                save_db(db)
            elif now > found["expiresAt"]:
                found["status"] = "expired"
                save_db(db)
                return self.send_json(403, {"success": False, "unlocked": False, "message": "Token has expired"})
            days_left = max(0, int((found["expiresAt"] - now) / 86400000))
            return self.send_json(200, {"success": True, "unlocked": True, "token": found["token"], "expires_at": found["expiresAt"], "days_left": days_left})

        if parsed.path == "/api/tokens/generate":
            period_days = int(body.get("period_days", 30))
            note = str(body.get("note", "")).strip()
            token = generate_16char_token()
            while any(t["token"] == token for t in db["tokens"]):
                token = generate_16char_token()
            new_t = {
                "token": token,
                "periodDays": period_days,
                "createdAt": now,
                "activatedAt": None,
                "expiresAt": None,
                "deviceId": None,
                "note": note,
                "status": "available"
            }
            db["tokens"].insert(0, new_t)
            save_db(db)
            return self.send_json(201, {"success": True, "token": new_t})

        self.send_json(404, {"message": "Not Found"})

if __name__ == "__main__":
    print(f"Starting server on port {PORT}...")
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as s:
        s.serve_forever()
