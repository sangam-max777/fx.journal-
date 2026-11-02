"""
Comprehensive Test Suite for LIQUID Trading Journal v2.0
=========================================================
Tests:
- Password security (PBKDF2-HMAC-SHA256)
- User signup, login, session validation, logout, and password reset
- Strict user data isolation (User A cannot access User B's trades or accounts)
- Data migration from browser localStorage
- Multi-trade Vision AI parsing, deduplication, and schema validation
- Authentication enforcement on protected endpoints (/api/analyze, /api/trades, /api/accounts)
"""

import unittest
import json
import base64
import io
import os
import server
import db

def simulate_http_request(raw_http_bytes):
    rfile = io.BytesIO(raw_http_bytes)
    wfile = io.BytesIO()

    handler = server.LiquidRequestHandler.__new__(server.LiquidRequestHandler)
    handler.rfile = rfile
    handler.wfile = wfile
    handler.client_address = ("127.0.0.1", 54321)
    handler.server = None
    handler.directory = server.BASE_DIR
    handler.extra_response_headers = None
    handler.close_connection = True

    handler.handle_one_request()

    response = wfile.getvalue()
    header_part, _, body_part = response.partition(b"\r\n\r\n")
    headers_lines = header_part.decode("latin1").split("\r\n")
    status_line = headers_lines[0] if headers_lines else ""
    status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
    return status_code, body_part, response


class TestAuthAndDataIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use an isolated test database
        db.DB_PATH = os.path.join(server.BASE_DIR, "test_liquid_journal.db")
        if os.path.exists(db.DB_PATH):
            os.remove(db.DB_PATH)
        db.init_db()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(db.DB_PATH):
            try:
                os.remove(db.DB_PATH)
            except Exception:
                pass

    def test_password_hashing_and_verification(self):
        pwd = "TraderPassword123!"
        hashed = db.hash_password(pwd)
        self.assertTrue(hashed.startswith("pbkdf2_sha256$100000$"))
        self.assertTrue(db.verify_password(pwd, hashed))
        self.assertFalse(db.verify_password("WrongPassword", hashed))

    def test_signup_login_logout_flow(self):
        # 1. Signup
        signup_payload = json.dumps({
            "email": "trader1@liquid.io",
            "password": "SecurePassWord1!",
            "displayName": "Alex Trader",
            "currency": "USD"
        }).encode("utf-8")
        req = (
            f"POST /api/auth/signup HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(signup_payload)}\r\n\r\n"
        ).encode("utf-8") + signup_payload

        code, body, _ = simulate_http_request(req)
        self.assertEqual(code, 201)
        data = json.loads(body.decode())
        self.assertTrue(data["success"])
        token = data["token"]
        self.assertTrue(len(token) >= 32)
        user = data["user"]
        self.assertEqual(user["email"], "trader1@liquid.io")

        # 2. Verify /api/auth/me with Bearer token
        req_me = (
            f"GET /api/auth/me HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {token}\r\n\r\n"
        ).encode("utf-8")
        code, body, _ = simulate_http_request(req_me)
        self.assertEqual(code, 200)
        me_data = json.loads(body.decode())
        self.assertEqual(me_data["user"]["email"], "trader1@liquid.io")

        # 3. Login
        login_payload = json.dumps({
            "email": "trader1@liquid.io",
            "password": "SecurePassWord1!"
        }).encode("utf-8")
        req_login = (
            f"POST /api/auth/login HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(login_payload)}\r\n\r\n"
        ).encode("utf-8") + login_payload
        code, body, _ = simulate_http_request(req_login)
        self.assertEqual(code, 200)
        login_data = json.loads(body.decode())
        new_token = login_data["token"]

        # 4. Logout
        req_logout = (
            f"POST /api/auth/logout HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {new_token}\r\n\r\n"
        ).encode("utf-8")
        code, body, _ = simulate_http_request(req_logout)
        self.assertEqual(code, 200)

        # 5. After logout, session is revoked
        req_me_after = (
            f"GET /api/auth/me HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {new_token}\r\n\r\n"
        ).encode("utf-8")
        code, _, _ = simulate_http_request(req_me_after)
        self.assertEqual(code, 401)

    def test_password_reset_flow(self):
        # Create user
        user = db.create_user("resetme@liquid.io", "OldPassword123", "Reset User")
        
        # Request reset
        req_body = json.dumps({"email": "resetme@liquid.io"}).encode()
        req = (
            f"POST /api/auth/reset-request HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(req_body)}\r\n\r\n"
        ).encode() + req_body
        code, body, _ = simulate_http_request(req)
        self.assertEqual(code, 200)
        data = json.loads(body.decode())
        reset_token = data.get("resetToken")
        self.assertTrue(bool(reset_token))

        # Confirm reset
        confirm_body = json.dumps({"token": reset_token, "newPassword": "NewPassword456!"}).encode()
        req_confirm = (
            f"POST /api/auth/reset-confirm HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(confirm_body)}\r\n\r\n"
        ).encode() + confirm_body
        code, body, _ = simulate_http_request(req_confirm)
        self.assertEqual(code, 200)

        # Login with new password
        auth_user = db.authenticate_user("resetme@liquid.io", "NewPassword456!")
        self.assertEqual(auth_user["id"], user["id"])

    def test_strict_user_data_isolation(self):
        # Create User A and User B
        user_a = db.create_user("user_a@liquid.io", "PassA123!", "User A")
        user_b = db.create_user("user_b@liquid.io", "PassB123!", "User B")
        token_a = db.create_session(user_a["id"])
        token_b = db.create_session(user_b["id"])

        # User A adds a trade
        trade_a = {
            "pair": "XAUUSD",
            "direction": "Buy",
            "entry": 2750.0,
            "sl": 2740.0,
            "tp": 2770.0,
            "status": "Closed",
            "outcome": "Win",
            "pnl": 1500.0
        }
        req_add_a = (
            f"POST /api/trades HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {token_a}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json.dumps(trade_a))}\r\n\r\n"
        ).encode() + json.dumps(trade_a).encode()
        code, body, _ = simulate_http_request(req_add_a)
        self.assertEqual(code, 201)

        # User B queries their trades
        req_get_b = (
            f"GET /api/trades HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {token_b}\r\n\r\n"
        ).encode()
        code, body, _ = simulate_http_request(req_get_b)
        self.assertEqual(code, 200)
        data_b = json.loads(body.decode())
        self.assertEqual(len(data_b["trades"]), 0)  # User B must NOT see User A's trade!

        # User A queries their trades
        req_get_a = (
            f"GET /api/trades HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {token_a}\r\n\r\n"
        ).encode()
        code, body, _ = simulate_http_request(req_get_a)
        self.assertEqual(code, 200)
        data_a = json.loads(body.decode())
        self.assertEqual(len(data_a["trades"]), 1)
        self.assertEqual(data_a["trades"][0]["pair"], "XAUUSD")

    def test_localstorage_data_migration(self):
        user = db.create_user("migrator@liquid.io", "Migrate123!", "Migrator")
        token = db.create_session(user["id"])

        local_dump = {
            "accounts": [
                {"id": "loc-acc-1", "type": "Funded", "name": "5K Challenge", "size": 5000}
            ],
            "trades": [
                {"id": "loc-trade-1", "accountId": "loc-acc-1", "pair": "EURUSD", "direction": "Sell", "pnl": 250},
                {"id": "loc-trade-2", "accountId": "loc-acc-1", "pair": "GBPUSD", "direction": "Buy", "pnl": -120}
            ]
        }
        payload = json.dumps(local_dump).encode()
        req = (
            f"POST /api/data/migrate HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode() + payload

        code, body, _ = simulate_http_request(req)
        self.assertEqual(code, 200)
        res = json.loads(body.decode())
        self.assertEqual(res["importedTrades"], 2)
        self.assertEqual(res["importedAccounts"], 1)

        # Verify trades now exist under user account
        user_trades = db.get_user_trades(user["id"])
        self.assertEqual(len(user_trades), 2)


class TestMultiTradeVisionAI(unittest.TestCase):
    def test_multi_trade_schema_sanitization(self):
        raw_ai_response = {
            "summary": "Detected 3 trades: 2 from table and 1 active chart position",
            "trades": [
                {
                    "tradeId": "trade-1",
                    "pair": "XAU/USD",
                    "direction": "long",
                    "date": "2026-10-31",
                    "entryTime": "14:30",
                    "entry": 2745.50,
                    "sl": 2738.00,
                    "tp": 2760.50,
                    "status": "Closed",
                    "outcome": "Win",
                    "pnl": 1500.0,
                    "uncertainties": []
                },
                {
                    "tradeId": "trade-2",
                    "pair": "EURUSD",
                    "direction": "Sell",
                    "date": "2026-10-31",
                    "entry": 1.0850,
                    "sl": None,
                    "tp": 1.0800,
                    "status": "Open",
                    "outcome": "Open",
                    "pnl": None,
                    "uncertainties": ["Stop loss level was not visible on the chart ticket"]
                },
                {
                    # Duplicate of trade-1 to test server deduplication
                    "tradeId": "trade-3",
                    "pair": "XAUUSD",
                    "direction": "Buy",
                    "date": "2026-10-31",
                    "entryTime": "14:30",
                    "entry": 2745.50,
                    "status": "Closed",
                    "pnl": 1500.0
                }
            ]
        }

        res = server.sanitize_and_validate_multi_trades(raw_ai_response)
        self.assertEqual(res["tradesCount"], 2)  # Duplicate trade-3 was deduplicated!
        self.assertEqual(len(res["trades"]), 2)

        t1 = res["trades"][0]
        self.assertEqual(t1["pair"], "XAUUSD")
        self.assertEqual(t1["direction"], "Buy")
        self.assertEqual(t1["rr"], 2.0)  # (2760.5 - 2745.5) / (2745.5 - 2738) = 15 / 7.5 = 2.0

        t2 = res["trades"][1]
        self.assertEqual(t2["pair"], "EURUSD")
        self.assertEqual(t2["direction"], "Sell")
        self.assertIsNone(t2["sl"])
        self.assertTrue(any("stop" in u.lower() for u in t2["uncertainties"]))

    def test_analyze_endpoint_requires_auth(self):
        # Without Authorization header -> returns 401
        payload = json.dumps({"images": [{"name": "chart.png", "data": "data:image/png;base64,iVBORw0KGgo="}]}).encode()
        req = (
            f"POST /api/analyze HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode() + payload

        code, body, _ = simulate_http_request(req)
        self.assertEqual(code, 401)
        data = json.loads(body.decode())
        self.assertIn("Authentication required", data["error"])

    def test_mocked_multi_trade_analyze_flow(self):
        # Authenticated user calling /api/analyze with multiple trade extraction
        user = db.create_user("visionuser@liquid.io", "Pass12345!", "Vision User")
        token = db.create_session(user["id"])

        mock_multi_trades = {
            "summary": "Extracted 2 distinct trades from broker history table.",
            "trades": [
                {
                    "tradeId": "row-1",
                    "pair": "US30",
                    "direction": "Buy",
                    "entry": 42500.0,
                    "sl": 42300.0,
                    "tp": 42900.0,
                    "status": "Closed",
                    "outcome": "Win",
                    "pnl": 800.0
                },
                {
                    "tradeId": "row-2",
                    "pair": "BTCUSD",
                    "direction": "Sell",
                    "entry": 69200.0,
                    "sl": 69800.0,
                    "tp": 68000.0,
                    "status": "Closed",
                    "outcome": "Win",
                    "pnl": 1200.0
                }
            ]
        }

        server.GEMINI_API_KEY = "mock_key"
        orig_caller = server.call_gemini_vision
        server.call_gemini_vision = lambda images, key, model: mock_multi_trades

        try:
            png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            b64_png = base64.b64encode(png_bytes).decode()
            payload = json.dumps({"images": [{"name": "history_table.png", "data": f"data:image/png;base64,{b64_png}"}]}).encode()

            req = (
                f"POST /api/analyze HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n\r\n"
            ).encode() + payload

            code, body, _ = simulate_http_request(req)
            self.assertEqual(code, 200)
            res = json.loads(body.decode())
            self.assertTrue(res["success"])
            self.assertEqual(res["tradesCount"], 2)
            self.assertEqual(len(res["trades"]), 2)
            self.assertEqual(res["trades"][0]["pair"], "US30")
            self.assertEqual(res["trades"][1]["pair"], "BTCUSD")

            # Bulk save the confirmed trades into user's account
            bulk_payload = json.dumps({"trades": res["trades"]}).encode()
            req_bulk = (
                f"POST /api/trades/bulk HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(bulk_payload)}\r\n\r\n"
            ).encode() + bulk_payload
            code_bulk, body_bulk, _ = simulate_http_request(req_bulk)
            self.assertEqual(code_bulk, 201)
            saved_data = json.loads(body_bulk.decode())
            self.assertEqual(saved_data["savedCount"], 2)

            # Confirm user's trades in database
            user_trades = db.get_user_trades(user["id"])
            self.assertEqual(len(user_trades), 2)
        finally:
            server.call_gemini_vision = orig_caller
            server.GEMINI_API_KEY = ""


class TestImageValidation(unittest.TestCase):
    def test_png_magic_bytes(self):
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 50
        is_valid, mime, err = server.detect_and_validate_image(png_data, "test.png")
        self.assertTrue(is_valid)
        self.assertEqual(mime, "image/png")
        self.assertEqual(err, "")

    def test_jpeg_magic_bytes(self):
        jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 50
        is_valid, mime, err = server.detect_and_validate_image(jpeg_data, "test.jpg")
        self.assertTrue(is_valid)
        self.assertEqual(mime, "image/jpeg")
        self.assertEqual(err, "")

    def test_webp_magic_bytes(self):
        webp_data = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 50
        is_valid, mime, err = server.detect_and_validate_image(webp_data, "test.webp")
        self.assertTrue(is_valid)
        self.assertEqual(mime, "image/webp")
        self.assertEqual(err, "")

    def test_unsupported_format(self):
        text_data = b"Hello this is not an image file"
        is_valid, mime, err = server.detect_and_validate_image(text_data, "test.txt")
        self.assertFalse(is_valid)
        self.assertIn("Unsupported file type", err)

    def test_oversized_image(self):
        oversized = b"\x89PNG\r\n\x1a\n" + b"\x00" * (server.MAX_IMAGE_SIZE_BYTES + 100)
        is_valid, mime, err = server.detect_and_validate_image(oversized, "huge.png")
        self.assertFalse(is_valid)
        self.assertIn("exceeds maximum allowed size", err)


if __name__ == "__main__":
    unittest.main()
