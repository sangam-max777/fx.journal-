"""
LIQUID Trading Journal - Database & Authentication Layer
========================================================
SQLite-backed persistence and secure session-based authentication.
Uses standard library hashlib.pbkdf2_hmac with 100,000 iterations for password hashing.
Enforces strict user isolation across all trades, accounts, and journal data.
"""

import sqlite3
import os
import hashlib
import hmac
import secrets
import datetime
import json
import logging

logger = logging.getLogger("liquid-db")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "liquid_journal.db"))
SESSION_DURATION_DAYS = 30
RESET_TOKEN_DURATION_HOURS = 2

def get_connection():
    """Returns a SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes database tables if they do not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            currency TEXT DEFAULT 'USD',
            created_at TEXT NOT NULL
        )
        """)
        
        # 2. Sessions table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """)
        
        # 3. Password Resets table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0
        )
        """)
        
        # 4. Accounts table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            provider TEXT,
            size REAL,
            balance REAL,
            reference TEXT,
            created_at TEXT NOT NULL
        )
        """)
        
        # 5. Trades table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS trades (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            account_id TEXT,
            date TEXT,
            entry_time TEXT,
            exit_time TEXT,
            pair TEXT NOT NULL,
            direction TEXT NOT NULL,
            session TEXT,
            status TEXT NOT NULL,
            outcome TEXT NOT NULL,
            entry REAL,
            sl REAL,
            tp REAL,
            exit_price REAL,
            risk REAL,
            pnl REAL,
            size REAL,
            quality REAL,
            timeframe TEXT,
            reason TEXT,
            liquidity TEXT,
            emotion_before TEXT,
            emotion_during TEXT,
            rules TEXT,
            lesson TEXT,
            tags TEXT,
            images_json TEXT,
            created_at TEXT NOT NULL
        )
        """)
        
        # 6. Rules table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            rule_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        
        conn.commit()
    logger.info(f"Database initialized at: {DB_PATH}")

# ---------------------------------------------------------------------------
# Password Security (PBKDF2-HMAC-SHA256 with 100k rounds)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hashes a password with a unique salt using 100,000 iterations of PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    iterations = 100_000
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    """Constant-time verification of password against stored hash."""
    try:
        parts = hashed.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = bytes.fromhex(parts[3])
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# User Authentication Functions
# ---------------------------------------------------------------------------
def create_user(email: str, password: str, display_name: str, currency: str = "USD") -> dict:
    email = email.strip().lower()
    display_name = display_name.strip() or "Trader"
    if not email or "@" not in email:
        raise ValueError("Valid email address is required.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters.")

    user_id = secrets.token_hex(16)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    pwd_hash = hash_password(password)

    with get_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, display_name, currency, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, email, pwd_hash, display_name, currency, now)
            )
            # Add default rules for new user
            default_rules = [
                "Only trade a confirmed setup",
                "Risk is defined before entry",
                "No setup = no trade",
                "No revenge trading",
                "Respect the daily risk limit"
            ]
            for r in default_rules:
                conn.execute(
                    "INSERT INTO rules (id, user_id, rule_text, created_at) VALUES (?, ?, ?, ?)",
                    (secrets.token_hex(12), user_id, r, now)
                )
            conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError("An account with this email already exists.")

    return get_user_by_id(user_id)

def authenticate_user(email: str, password: str) -> dict:
    email = email.strip().lower()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if not row:
            raise PermissionError("Invalid email or password.")
        if not verify_password(password, row["password_hash"]):
            raise PermissionError("Invalid email or password.")
        return dict(row)

def create_session(user_id: str) -> str:
    token = secrets.token_hex(32)
    session_id = secrets.token_hex(16)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(days=SESSION_DURATION_DAYS)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO sessions (id, user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, user_id, token, now.isoformat(), expires.isoformat())
        )
        conn.commit()
    return token

def get_user_by_token(token: str) -> dict:
    if not token:
        return None
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.email, u.display_name, u.currency, u.created_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token, now))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None

def delete_session(token: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()

def create_password_reset(email: str) -> str:
    email = email.strip().lower()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if not row:
            # Avoid leaking whether email exists
            return None
        user_id = row["id"]
        token = secrets.token_hex(16)
        reset_id = secrets.token_hex(12)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(hours=RESET_TOKEN_DURATION_HOURS)

        conn.execute(
            "INSERT INTO password_resets (id, user_id, token, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)",
            (reset_id, user_id, token, now.isoformat(), expires.isoformat())
        )
        conn.commit()
        return token

def confirm_password_reset(token: str, new_password: str):
    if len(new_password) < 6:
        raise ValueError("Password must be at least 6 characters.")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id FROM password_resets
            WHERE token = ? AND used = 0 AND expires_at > ?
        """, (token, now))
        row = cursor.fetchone()
        if not row:
            raise ValueError("Invalid or expired password reset token.")
        user_id = row["user_id"]
        pwd_hash = hash_password(new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pwd_hash, user_id))
        conn.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (token,))
        # Revoke existing sessions for security
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()

def update_user_preferences(user_id: str, display_name: str, currency: str) -> dict:
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET display_name = ?, currency = ? WHERE id = ?",
            (display_name.strip(), currency.strip(), user_id)
        )
        conn.commit()
    return get_user_by_id(user_id)

def get_user_by_id(user_id: str) -> dict:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, display_name, currency, created_at FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

# ---------------------------------------------------------------------------
# Accounts CRUD (Scoped to user_id)
# ---------------------------------------------------------------------------
def get_user_accounts(user_id: str) -> list:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM accounts WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        return [dict(r) for r in cursor.fetchall()]

def create_account(user_id: str, account_data: dict) -> dict:
    acc_id = account_data.get("id") or secrets.token_hex(16)
    name = (account_data.get("name") or "").strip()
    if not name:
        raise ValueError("Account name is required.")
    acc_type = account_data.get("type") or "Real"
    provider = (account_data.get("provider") or "").strip()
    size = account_data.get("size")
    balance = account_data.get("balance")
    ref = (account_data.get("reference") or "").strip()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO accounts (id, user_id, type, name, provider, size, balance, reference, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (acc_id, user_id, acc_type, name, provider, size, balance, ref, now))
        conn.commit()

    return {
        "id": acc_id,
        "type": acc_type,
        "name": name,
        "provider": provider,
        "size": size,
        "balance": balance,
        "reference": ref,
        "createdAt": now
    }

def delete_account(user_id: str, account_id: str):
    with get_connection() as conn:
        # Unlink trades before removing account
        conn.execute("UPDATE trades SET account_id = '' WHERE user_id = ? AND account_id = ?", (user_id, account_id))
        conn.execute("DELETE FROM accounts WHERE user_id = ? AND id = ?", (user_id, account_id))
        conn.commit()

# ---------------------------------------------------------------------------
# Trades CRUD (Scoped to user_id)
# ---------------------------------------------------------------------------
def get_user_trades(user_id: str) -> list:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM trades WHERE user_id = ? ORDER BY date DESC, entry_time DESC", (user_id,))
        rows = cursor.fetchall()
        trades = []
        for r in rows:
            t = dict(r)
            # Reconstruct field names matching frontend expectations
            trade_obj = {
                "id": t["id"],
                "accountId": t["account_id"] or "",
                "date": t["date"] or "",
                "entryTime": t["entry_time"] or "",
                "exitTime": t["exit_time"] or "",
                "pair": t["pair"],
                "direction": t["direction"],
                "session": t["session"] or "",
                "status": t["status"] or "Closed",
                "outcome": t["outcome"] or "Open",
                "entry": t["entry"],
                "sl": t["sl"],
                "tp": t["tp"],
                "exit": t["exit_price"],
                "risk": t["risk"],
                "pnl": t["pnl"] if t["pnl"] is not None else 0,
                "size": t["size"],
                "quality": t["quality"],
                "timeframe": t["timeframe"] or "",
                "reason": t["reason"] or "",
                "liquidity": t["liquidity"] or "",
                "emotionBefore": t["emotion_before"] or "",
                "emotionDuring": t["emotion_during"] or "",
                "rules": t["rules"] or "yes",
                "lesson": t["lesson"] or "",
                "tags": t["tags"] or "",
                "images": json.loads(t["images_json"]) if t["images_json"] else [],
                "createdAt": t["created_at"]
            }
            trades.append(trade_obj)
        return trades

def create_trade(user_id: str, t: dict) -> dict:
    trade_id = t.get("id") or secrets.token_hex(16)
    pair = (t.get("pair") or "XAUUSD").strip()
    direction = t.get("direction") or "Buy"
    date_val = t.get("date") or datetime.date.today().isoformat()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    images_str = json.dumps(t.get("images", []))

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO trades (
                id, user_id, account_id, date, entry_time, exit_time, pair, direction,
                session, status, outcome, entry, sl, tp, exit_price, risk, pnl, size,
                quality, timeframe, reason, liquidity, emotion_before, emotion_during,
                rules, lesson, tags, images_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            trade_id, user_id, t.get("accountId", ""), date_val, t.get("entryTime", ""), t.get("exitTime", ""),
            pair, direction, t.get("session", ""), t.get("status", "Closed"), t.get("outcome", "Open"),
            t.get("entry"), t.get("sl"), t.get("tp"), t.get("exit"), t.get("risk"), t.get("pnl", 0),
            t.get("size"), t.get("quality"), t.get("timeframe", ""), t.get("reason", ""), t.get("liquidity", ""),
            t.get("emotionBefore", ""), t.get("emotionDuring", ""), t.get("rules", "yes"), t.get("lesson", ""),
            t.get("tags", ""), images_str, now
        ))
        conn.commit()

    return {**t, "id": trade_id}

def create_bulk_trades(user_id: str, trades_list: list) -> list:
    """Inserts multiple verified trades for user in a single transaction."""
    saved = []
    with get_connection() as conn:
        for t in trades_list:
            trade_id = t.get("id") or secrets.token_hex(16)
            pair = (t.get("pair") or "XAUUSD").strip()
            direction = t.get("direction") or "Buy"
            date_val = t.get("date") or datetime.date.today().isoformat()
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            images_str = json.dumps(t.get("images", []))

            conn.execute("""
                INSERT INTO trades (
                    id, user_id, account_id, date, entry_time, exit_time, pair, direction,
                    session, status, outcome, entry, sl, tp, exit_price, risk, pnl, size,
                    quality, timeframe, reason, liquidity, emotion_before, emotion_during,
                    rules, lesson, tags, images_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                trade_id, user_id, t.get("accountId", ""), date_val, t.get("entryTime", ""), t.get("exitTime", ""),
                pair, direction, t.get("session", ""), t.get("status", "Closed"), t.get("outcome", "Open"),
                t.get("entry"), t.get("sl"), t.get("tp"), t.get("exit"), t.get("risk"), t.get("pnl", 0),
                t.get("size"), t.get("quality"), t.get("timeframe", ""), t.get("reason", ""), t.get("liquidity", ""),
                t.get("emotionBefore", ""), t.get("emotionDuring", ""), t.get("rules", "yes"), t.get("lesson", ""),
                t.get("tags", ""), images_str, now
            ))
            saved.append({**t, "id": trade_id})
        conn.commit()
    return saved

def delete_trade(user_id: str, trade_id: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM trades WHERE user_id = ? AND id = ?", (user_id, trade_id))
        conn.commit()

# ---------------------------------------------------------------------------
# Migration / Import of Existing Local Data
# ---------------------------------------------------------------------------
def migrate_local_data(user_id: str, payload: dict) -> dict:
    """
    Safely imports existing browser localStorage data (trades, accounts, rules)
    into the authenticated user's account without overwriting existing data.
    """
    local_trades = payload.get("trades", [])
    local_accounts = payload.get("accounts", [])
    local_rules = payload.get("rules", [])

    imported_trades_count = 0
    imported_accounts_count = 0

    with get_connection() as conn:
        # 1. Import accounts
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM accounts WHERE user_id = ?", (user_id,))
        existing_acc_ids = {r[0] for r in cursor.fetchall()}

        for acc in local_accounts:
            acc_id = acc.get("id") or secrets.token_hex(16)
            if acc_id not in existing_acc_ids:
                conn.execute("""
                    INSERT INTO accounts (id, user_id, type, name, provider, size, balance, reference, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    acc_id, user_id, acc.get("type", "Real"), acc.get("name", "Account"),
                    acc.get("provider", ""), acc.get("size"), acc.get("balance"),
                    acc.get("reference", ""), datetime.datetime.now(datetime.timezone.utc).isoformat()
                ))
                existing_acc_ids.add(acc_id)
                imported_accounts_count += 1

        # 2. Import trades
        cursor.execute("SELECT id FROM trades WHERE user_id = ?", (user_id,))
        existing_trade_ids = {r[0] for r in cursor.fetchall()}

        for t in local_trades:
            tid = t.get("id") or secrets.token_hex(16)
            if tid not in existing_trade_ids:
                images_str = json.dumps(t.get("images", []))
                conn.execute("""
                    INSERT INTO trades (
                        id, user_id, account_id, date, entry_time, exit_time, pair, direction,
                        session, status, outcome, entry, sl, tp, exit_price, risk, pnl, size,
                        quality, timeframe, reason, liquidity, emotion_before, emotion_during,
                        rules, lesson, tags, images_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tid, user_id, t.get("accountId", ""), t.get("date", ""), t.get("entryTime", ""),
                    t.get("exitTime", ""), t.get("pair", "XAUUSD"), t.get("direction", "Buy"),
                    t.get("session", ""), t.get("status", "Closed"), t.get("outcome", "Open"),
                    t.get("entry"), t.get("sl"), t.get("tp"), t.get("exit"), t.get("risk"),
                    t.get("pnl", 0), t.get("size"), t.get("quality"), t.get("timeframe", ""),
                    t.get("reason", ""), t.get("liquidity", ""), t.get("emotionBefore", ""),
                    t.get("emotionDuring", ""), t.get("rules", "yes"), t.get("lesson", ""),
                    t.get("tags", ""), images_str, datetime.datetime.now(datetime.timezone.utc).isoformat()
                ))
                existing_trade_ids.add(tid)
                imported_trades_count += 1

        conn.commit()

    return {
        "success": True,
        "importedTrades": imported_trades_count,
        "importedAccounts": imported_accounts_count
    }

# Initialize tables immediately upon import
init_db()
