import os
import json
import time
import re
import hmac
import hashlib
import secrets
import httpx
import sqlite3
import socket
import psycopg2
from urllib.parse import unquote, urlparse
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="WardenWAF - Enterprise Security")

DB_FILE = "waf_database.db"
DATABASE_URL = os.getenv("DATABASE_URL")
WAF_SECRET = os.getenv("WAF_SECRET", "warden-waf-enterprise-secret-2026")

# --- KONFIGURASI DURASI BLOKIR BERTINGKAT (DETIK) ---
# Pelanggaran ke-1: 5 menit | ke-2: 30 menit | ke-3: 2 jam | ke-4+: 24 jam
BAN_ESCALATION_SECONDS = [300, 1800, 7200, 86400]
TIME_WINDOW = 10

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

USE_POSTGRES = bool(DATABASE_URL)

def get_db():
    if USE_POSTGRES:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_FILE)

def q(query: str) -> str:
    return query.replace("?", "%s") if USE_POSTGRES else query

def get_client_ip(request: Request) -> str:
    """Mengambil IP asli pengunjung meskipun melewati CDN (Cloudflare) atau load balancer Render."""
    for header in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
        val = request.headers.get(header)
        if val:
            return val.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def format_duration_id(seconds: int) -> str:
    """Mengubah detik menjadi teks durasi yang mudah dibaca (misal: 5 menit, 2 jam 10 menit)."""
    seconds = max(1, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if hours > 0:
        parts.append(f"{hours} jam")
    if minutes > 0:
        parts.append(f"{minutes} menit")
    if secs > 0 and hours == 0:
        parts.append(f"{secs} detik")
    return " ".join(parts) if parts else "1 detik"

# --- 1. SETUP & MIGRASI DATABASE ---
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
            domain TEXT PRIMARY KEY,
            origin_server TEXT NOT NULL,
            waf_enabled BOOLEAN NOT NULL,
            rate_limit INTEGER NOT NULL,
            status TEXT NOT NULL,
            owner TEXT NOT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        cursor.execute("INSERT INTO users VALUES ('admin', 'admin123', 'admin') ON CONFLICT (username) DO NOTHING")
        cursor.execute("INSERT INTO users VALUES ('user', 'user123', 'user') ON CONFLICT (username) DO NOTHING")
        cursor.execute('''CREATE TABLE IF NOT EXISTS attack_logs (
            id SERIAL PRIMARY KEY,
            timestamp TEXT,
            ip_address TEXT,
            domain TEXT,
            threat_type TEXT
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS banned_ips (
            ip_address TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            reason TEXT NOT NULL,
            banned_at TEXT NOT NULL,
            banned_until DOUBLE PRECISION,
            ban_count INTEGER NOT NULL DEFAULT 1
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS rate_limit_hits (
            id SERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL,
            hit_time DOUBLE PRECISION NOT NULL
        )''')
        cursor.execute("ALTER TABLE banned_ips ADD COLUMN IF NOT EXISTS banned_until DOUBLE PRECISION")
        cursor.execute("ALTER TABLE banned_ips ADD COLUMN IF NOT EXISTS ban_count INTEGER NOT NULL DEFAULT 1")
    else:
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
            domain TEXT PRIMARY KEY,
            origin_server TEXT NOT NULL,
            waf_enabled BOOLEAN NOT NULL,
            rate_limit INTEGER NOT NULL,
            status TEXT NOT NULL,
            owner TEXT NOT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'admin123', 'admin')")
        cursor.execute("INSERT OR IGNORE INTO users VALUES ('user', 'user123', 'user')")
        cursor.execute('''CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            domain TEXT,
            threat_type TEXT
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS banned_ips (
            ip_address TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            reason TEXT NOT NULL,
            banned_at TEXT NOT NULL,
            banned_until REAL,
            ban_count INTEGER NOT NULL DEFAULT 1
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS rate_limit_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            hit_time REAL NOT NULL
        )''')
        for alter_sql in [
            "ALTER TABLE banned_ips ADD COLUMN banned_until REAL",
            "ALTER TABLE banned_ips ADD COLUMN ban_count INTEGER NOT NULL DEFAULT 1"
        ]:
            try:
                cursor.execute(alter_sql)
            except sqlite3.OperationalError:
                pass
    conn.commit()
    cursor.close()
    conn.close()

init_db()
templates = Jinja2Templates(directory="templates")

class ClientConfig(BaseModel):
    domain: str
    origin_server: Optional[str] = ""
    waf_enabled: bool = True
    rate_limit: int = 20

class ClientUpdateConfig(BaseModel):
    origin_server: str
    waf_enabled: bool
    rate_limit: int
    status: str

class ManualBanData(BaseModel):
    ip_address: str
    domain: Optional[str] = "Semua Domain (Manual)"
    reason: Optional[str] = "Diblokir Manual oleh Admin"
    duration_minutes: Optional[int] = 30

class AuthData(BaseModel):
    username: str
    password: str

class ChallengeVerifyData(BaseModel):
    ts: str
    a: int
    b: int
    ans: int
    sig: str

# --- FUNGSI SESI LOGIN PANEL ADMIN (SERVER-SIDE HTTPONLY COOKIE) ---
def create_admin_session_token(username: str, role: str) -> str:
    exp_ts = str(int(time.time()) + 1800)
    payload = f"{username}:{role}:{exp_ts}"
    sig = hmac.new(
        WAF_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{payload}.{sig}"

def verify_admin_session(request: Request) -> Optional[dict]:
    token = request.cookies.get("warden_admin_session")
    if not token or "." not in token:
        return None
    try:
        payload, sig = token.rsplit(".", 1)
        username, role, exp_ts = payload.split(":", 2)
        if int(time.time()) > int(exp_ts):
            return None
        expected_sig = hmac.new(
            WAF_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return None
        return {"username": username, "role": role}
    except Exception:
        return None

def require_session(request: Request) -> dict:
    session = verify_admin_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Sesi tidak valid atau telah berakhir. Silakan login kembali.")
    return session

# --- FUNGSI HELPER PEMBLOKIRAN TIMER & ESKALASI BERTINGKAT ---
def is_ip_banned(ip: str) -> Optional[dict]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT reason, banned_until, ban_count FROM banned_ips WHERE ip_address=?"), (ip,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        return None

    reason, banned_until, ban_count = row[0], row[1], row[2] or 1
    if banned_until is None:
        return {
            "reason": reason,
            "remaining_seconds": None,
            "ban_count": ban_count,
            "unblock_at": "Permanen"
        }

    now = time.time()
    if now < float(banned_until):
        remaining = max(1, int(float(banned_until) - now))
        unblock_str = datetime.fromtimestamp(float(banned_until)).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "reason": reason,
            "remaining_seconds": remaining,
            "ban_count": ban_count,
            "unblock_at": unblock_str
        }

    return None

def ban_ip_with_escalation(ip: str, domain: str, reason: str, custom_duration_seconds: Optional[int] = None) -> dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT ban_count FROM banned_ips WHERE ip_address=?"), (ip,))
    existing = cursor.fetchone()

    prev_count = (existing[0] or 0) if existing else 0
    new_count = prev_count + 1
    now_ts = time.time()
    now_str = datetime.fromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M:%S")

    if custom_duration_seconds is not None:
        if custom_duration_seconds <= 0:
            banned_until = None
            duration_label = "Permanen"
            remaining_seconds = None
            unblock_at_str = "Permanen"
        else:
            banned_until = now_ts + custom_duration_seconds
            duration_label = format_duration_id(custom_duration_seconds)
            remaining_seconds = custom_duration_seconds
            unblock_at_str = datetime.fromtimestamp(banned_until).strftime("%Y-%m-%d %H:%M:%S")
    else:
        tier_idx = min(new_count - 1, len(BAN_ESCALATION_SECONDS) - 1)
        duration_sec = BAN_ESCALATION_SECONDS[tier_idx]
        banned_until = now_ts + duration_sec
        duration_label = format_duration_id(duration_sec)
        remaining_seconds = duration_sec
        unblock_at_str = datetime.fromtimestamp(banned_until).strftime("%Y-%m-%d %H:%M:%S")

    if USE_POSTGRES:
        cursor.execute(
            """INSERT INTO banned_ips (ip_address, domain, reason, banned_at, banned_until, ban_count)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (ip_address) DO UPDATE SET
                   domain = EXCLUDED.domain,
                   reason = EXCLUDED.reason,
                   banned_at = EXCLUDED.banned_at,
                   banned_until = EXCLUDED.banned_until,
                   ban_count = EXCLUDED.ban_count""",
            (ip, domain, reason, now_str, banned_until, new_count)
        )
    else:
        cursor.execute(
            "INSERT OR REPLACE INTO banned_ips (ip_address, domain, reason, banned_at, banned_until, ban_count) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, domain, reason, now_str, banned_until, new_count)
        )
    cursor.execute(q("DELETE FROM rate_limit_hits WHERE ip_address=?"), (ip,))
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "ban_count": new_count,
        "duration_label": duration_label,
        "remaining_seconds": remaining_seconds,
        "unblock_at_str": unblock_at_str
    }

def check_and_record_rate_limit(ip: str, limit: int) -> bool:
    """
    Mencatat permintaan di database agar konsisten di seluruh worker.
    Mengembalikan True jika jumlah request dalam TIME_WINDOW sudah mencapai batas.
    """
    now = time.time()
    window_start = now - TIME_WINDOW
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("DELETE FROM rate_limit_hits WHERE hit_time < ?"), (window_start,))
    cursor.execute(q("SELECT COUNT(*) FROM rate_limit_hits WHERE ip_address=?"), (ip,))
    count = cursor.fetchone()[0] or 0

    if count >= limit:
        cursor.execute(q("DELETE FROM rate_limit_hits WHERE ip_address=?"), (ip,))
        conn.commit()
        cursor.close()
        conn.close()
        return True

    cursor.execute(q("INSERT INTO rate_limit_hits (ip_address, hit_time) VALUES (?, ?)"), (ip, now))
    conn.commit()
    cursor.close()
    conn.close()
    return False

# --- FUNGSI HELPER JS CHALLENGE ---
def sign_challenge(ts: str, a: int, b: int, ans: int) -> str:
    payload = f"{ts}:{a}:{b}:{ans}".encode("utf-8")
    return hmac.new(WAF_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()

def create_clearance_cookie(user_agent: str) -> str:
    exp_ts = str(int(time.time()) + 1800)
    payload = f"{user_agent}:{exp_ts}".encode("utf-8")
    sig = hmac.new(WAF_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"{exp_ts}.{sig}"

def is_valid_clearance(cookie_val: Optional[str], user_agent: str) -> bool:
    if not cookie_val or "." not in cookie_val:
        return False
    try:
        exp_ts, sig = cookie_val.split(".", 1)
        if int(time.time()) > int(exp_ts):
            return False
        expected_sig = hmac.new(
            WAF_SECRET.encode("utf-8"),
            f"{user_agent}:{exp_ts}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_sig, sig)
    except Exception:
        return False

# --- HALAMAN LOGIN & PANEL WARDEN (WAJIB LOGIN DULU) ---
@app.get("/panel-warden/login", response_class=HTMLResponse)
async def panel_login_ui(request: Request):
    if verify_admin_session(request):
        return RedirectResponse(url="/panel-warden", status_code=302)
    return templates.TemplateResponse(request, "login.html", {})

@app.get("/panel-warden", response_class=HTMLResponse)
async def dashboard_ui(request: Request):
    session = verify_admin_session(request)
    if not session:
        return RedirectResponse(url="/panel-warden/login", status_code=302)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": session["username"],
            "role": session["role"]
        }
    )

# --- ENDPOINT VERIFIKASI JS CHALLENGE ---
@app.post("/__waf_verify")
async def verify_js_challenge(data: ChallengeVerifyData, request: Request):
    client_ip = get_client_ip(request)
    active_ban = is_ip_banned(client_ip)
    if active_ban:
        rem = active_ban["remaining_seconds"]
        sisa_str = format_duration_id(rem) if rem else "Permanen"
        raise HTTPException(
            status_code=403,
            detail=f"IP Anda sedang diblokir sementara karena {active_ban['reason']} (Sisa waktu: {sisa_str})."
        )

    try:
        if abs(int(time.time()) - int(data.ts)) > 300:
            raise HTTPException(status_code=400, detail="Challenge kedaluwarsa")
        expected_sig = sign_challenge(data.ts, data.a, data.b, data.ans)
        if not hmac.compare_digest(expected_sig, data.sig):
            raise HTTPException(status_code=403, detail="Jawaban verifikasi tidak valid")
    except ValueError:
        raise HTTPException(status_code=400, detail="Format tidak valid")

    user_agent = request.headers.get("user-agent", "unknown")
    cookie_token = create_clearance_cookie(user_agent)

    resp = JSONResponse(content={"status": "verified"})
    resp.set_cookie(
        key="warden_waf_clearance",
        value=cookie_token,
        max_age=1800,
        httponly=True,
        samesite="lax"
    )
    return resp

# --- ENDPOINT AUTENTIKASI PANEL ---
@app.post("/api/login")
def login(data: AuthData):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT role FROM users WHERE username=? AND password=?"), (data.username, data.password))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        role = user[0]
        session_token = create_admin_session_token(data.username, role)
        resp = JSONResponse(content={
            "status": "success",
            "role": role,
            "username": data.username,
            "redirect": "/panel-warden"
        })
        resp.set_cookie(
            key="warden_admin_session",
            value=session_token,
            httponly=True,
            samesite="lax"
        )
        return resp
    raise HTTPException(status_code=401, detail="Username atau password salah")

@app.post("/api/register")
def register(data: AuthData):
    clean_user = data.username.strip()
    if len(clean_user) < 3 or len(data.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Username minimal 3 karakter dan password minimal 4 karakter")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT username FROM users WHERE username=?"), (clean_user,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Username sudah dipakai")
    cursor.execute(q("INSERT INTO users (username, password, role) VALUES (?, ?, ?)"), (clean_user, data.password, 'user'))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success", "message": "Akun berhasil dibuat"}

@app.post("/api/logout")
def logout():
    resp = JSONResponse(content={"status": "logged_out"})
    resp.delete_cookie("warden_admin_session")
    return resp

# --- ENDPOINT KHUSUS ADMIN: DAFTAR & HAPUS USER TERDAFTAR ---
@app.get("/admin/api/users")
def get_registered_users(request: Request):
    session = require_session(request)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat melihat daftar user")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, u.role, COUNT(c.domain) AS total_domains
        FROM users u
        LEFT JOIN clients c ON u.username = c.owner
        GROUP BY u.username, u.role
        ORDER BY u.role ASC, u.username ASC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [
        {
            "username": r[0],
            "role": r[1],
            "total_domains": r[2]
        }
        for r in rows
    ]

@app.delete("/admin/api/users/{target_username}")
def delete_registered_user(target_username: str, request: Request):
    session = require_session(request)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat menghapus akun user")
    if target_username in ("admin", session["username"]):
        raise HTTPException(status_code=400, detail="Akun admin utama atau akun yang sedang digunakan tidak dapat dihapus")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("DELETE FROM clients WHERE owner=?"), (target_username,))
    cursor.execute(q("DELETE FROM users WHERE username=?"), (target_username,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success", "message": f"User {target_username} berhasil dihapus"}

# --- ENDPOINT API MANAJEMEN DOMAIN ---
@app.get("/admin/api/domains")
def get_all_domains(request: Request):
    session = require_session(request)
    conn = get_db()
    cursor = conn.cursor()
    if session["role"] == 'admin':
        cursor.execute("SELECT domain, origin_server, waf_enabled, rate_limit, status, owner FROM clients ORDER BY domain ASC")
    else:
        cursor.execute(
            q("SELECT domain, origin_server, waf_enabled, rate_limit, status, owner FROM clients WHERE owner=? ORDER BY domain ASC"),
            (session["username"],)
        )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [
        {
            "domain": r[0],
            "origin_server": r[1],
            "waf_enabled": bool(r[2]),
            "rate_limit": r[3],
            "status": r[4],
            "owner": r[5]
        }
        for r in rows
    ]

@app.post("/admin/api/domains")
def add_domain(config: ClientConfig, request: Request):
    session = require_session(request)
    conn = get_db()
    cursor = conn.cursor()

    clean_domain = config.domain.strip().lower()
    origin = (config.origin_server or "").strip().rstrip("/")
    if not origin:
        try:
            ip_address = socket.gethostbyname(clean_domain)
            origin = f"http://{ip_address}"
        except socket.gaierror:
            origin = "http://127.0.0.1"
    elif not origin.startswith(("http://", "https://")):
        origin = f"https://{origin}"

    status = 'approved' if session["role"] == 'admin' else 'pending'
    waf_status = bool(config.waf_enabled) if session["role"] == 'admin' else False

    if USE_POSTGRES:
        cursor.execute(
            """INSERT INTO clients (domain, origin_server, waf_enabled, rate_limit, status, owner)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (domain) DO UPDATE SET
                   origin_server = EXCLUDED.origin_server,
                   waf_enabled = EXCLUDED.waf_enabled,
                   rate_limit = EXCLUDED.rate_limit,
                   status = EXCLUDED.status,
                   owner = EXCLUDED.owner""",
            (clean_domain, origin, waf_status, config.rate_limit, status, session["username"])
        )
    else:
        cursor.execute(
            "INSERT OR REPLACE INTO clients VALUES (?, ?, ?, ?, ?, ?)",
            (clean_domain, origin, waf_status, config.rate_limit, status, session["username"])
        )
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Pengajuan berhasil"}

@app.put("/admin/api/domains/{target_domain}")
def update_domain(target_domain: str, config: ClientUpdateConfig, request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat mengedit konfigurasi domain")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT domain FROM clients WHERE domain=?"), (target_domain,))
    if not cursor.fetchone():
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Domain tidak ditemukan")

    clean_origin = config.origin_server.strip().rstrip("/")
    if clean_origin and not clean_origin.startswith(("http://", "https://")):
        clean_origin = f"https://{clean_origin}"
    clean_status = config.status if config.status in ("approved", "pending") else "approved"
    waf_val = bool(config.waf_enabled) if clean_status == "approved" else False

    cursor.execute(
        q("UPDATE clients SET origin_server=?, waf_enabled=?, rate_limit=?, status=? WHERE domain=?"),
        (clean_origin, waf_val, max(1, config.rate_limit), clean_status, target_domain)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success", "message": f"Konfigurasi {target_domain} berhasil diperbarui"}

@app.put("/admin/api/domains/{target_domain}/approve")
def approve_domain(target_domain: str, request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Akses ditolak")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("UPDATE clients SET status='approved', waf_enabled=TRUE WHERE domain=?"), (target_domain,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Domain disetujui"}

@app.delete("/admin/api/domains/{target_domain}")
def delete_domain(target_domain: str, request: Request):
    session = require_session(request)
    conn = get_db()
    cursor = conn.cursor()
    if session["role"] == 'admin':
        cursor.execute(q("DELETE FROM clients WHERE domain=?"), (target_domain,))
    else:
        cursor.execute(q("DELETE FROM clients WHERE domain=? AND owner=?"), (target_domain, session["username"]))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Domain dihapus"}

# --- ENDPOINT LOG SERANGAN (SCOPED BY ROLE & OWNER) ---
@app.get("/admin/api/logs")
def get_attack_logs(request: Request):
    session = require_session(request)
    conn = get_db()
    cursor = conn.cursor()
    if session["role"] == "admin":
        cursor.execute("SELECT id, timestamp, ip_address, domain, threat_type FROM attack_logs ORDER BY id DESC LIMIT 100")
    else:
        cursor.execute(
            q("""SELECT a.id, a.timestamp, a.ip_address, a.domain, a.threat_type
                 FROM attack_logs a
                 INNER JOIN clients c ON a.domain = c.domain
                 WHERE c.owner=?
                 ORDER BY a.id DESC LIMIT 100"""),
            (session["username"],)
        )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "ip_address": r[2],
            "domain": r[3],
            "threat_type": r[4]
        }
        for r in rows
    ]

@app.delete("/admin/api/logs/{log_id}")
def delete_single_log(log_id: int, request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat menghapus log serangan")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("DELETE FROM attack_logs WHERE id=?"), (log_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success", "message": "Log serangan berhasil dihapus"}

@app.delete("/admin/api/logs")
def clear_all_logs(request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat membersihkan log serangan")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attack_logs")
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success", "message": "Seluruh log serangan berhasil dibersihkan"}

# --- ENDPOINT DAFTAR, BLOKIR MANUAL & UNBLOKIR IP TIMER ---
@app.get("/admin/api/banned-ips")
def get_banned_ips(request: Request):
    session = require_session(request)
    conn = get_db()
    cursor = conn.cursor()
    if session["role"] == 'admin':
        cursor.execute("SELECT ip_address, domain, reason, banned_at, banned_until, ban_count FROM banned_ips ORDER BY banned_at DESC")
    else:
        cursor.execute(
            q("""SELECT b.ip_address, b.domain, b.reason, b.banned_at, b.banned_until, b.ban_count
                 FROM banned_ips b
                 INNER JOIN clients c ON b.domain = c.domain
                 WHERE c.owner=?
                 ORDER BY b.banned_at DESC"""),
            (session["username"],)
        )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    now = time.time()
    active_bans = []
    for r in rows:
        ip_addr, dom, rsn, b_at, b_until, b_count = r[0], r[1], r[2], r[3], r[4], r[5] or 1
        if b_until is None:
            active_bans.append({
                "ip_address": ip_addr,
                "domain": dom,
                "reason": rsn,
                "banned_at": b_at,
                "unblock_at": "Permanen",
                "remaining_seconds": None,
                "ban_count": b_count
            })
        elif now < float(b_until):
            rem = max(1, int(float(b_until) - now))
            active_bans.append({
                "ip_address": ip_addr,
                "domain": dom,
                "reason": rsn,
                "banned_at": b_at,
                "unblock_at": datetime.fromtimestamp(float(b_until)).strftime("%Y-%m-%d %H:%M:%S"),
                "remaining_seconds": rem,
                "ban_count": b_count
            })
    return active_bans

@app.post("/admin/api/banned-ips")
def manual_ban_ip(data: ManualBanData, request: Request):
    session = require_session(request)
    clean_ip = data.ip_address.strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="Alamat IP tidak boleh kosong")

    target_dom = (data.domain or "").strip()
    if session["role"] != 'admin':
        clean_dom = target_dom.lower()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(q("SELECT 1 FROM clients WHERE domain=? AND owner=?"), (clean_dom, session["username"]))
        owned = cursor.fetchone()
        cursor.close()
        conn.close()
        if not owned:
            raise HTTPException(status_code=403, detail="Anda hanya dapat memblokir IP pada domain milik Anda sendiri")
        target_dom = clean_dom
    else:
        target_dom = target_dom or "Semua Domain (Manual)"

    duration_sec = None
    if data.duration_minutes is not None:
        duration_sec = data.duration_minutes * 60 if data.duration_minutes > 0 else 0

    default_reason = "Diblokir Manual oleh Admin" if session["role"] == "admin" else f"Diblokir oleh Pemilik ({session['username']})"
    ban_info = ban_ip_with_escalation(
        clean_ip,
        target_dom,
        (data.reason or default_reason).strip(),
        custom_duration_seconds=duration_sec
    )
    return {
        "status": "success",
        "message": f"IP {clean_ip} berhasil diblokir pada {target_dom} ({ban_info['duration_label']})"
    }

@app.delete("/admin/api/banned-ips/{target_ip:path}")
def unblock_ip(target_ip: str, request: Request):
    session = require_session(request)
    conn = get_db()
    cursor = conn.cursor()

    if session["role"] != 'admin':
        cursor.execute(
            q("""SELECT b.domain FROM banned_ips b
                 INNER JOIN clients c ON b.domain = c.domain
                 WHERE b.ip_address=? AND c.owner=?"""),
            (target_ip, session["username"])
        )
        owned_ban = cursor.fetchone()
        if not owned_ban:
            cursor.close()
            conn.close()
            raise HTTPException(
                status_code=403,
                detail="Akses ditolak: Anda hanya dapat membuka blokir IP pada domain milik Anda sendiri"
            )

    cursor.execute(q("DELETE FROM banned_ips WHERE ip_address=?"), (target_ip,))
    cursor.execute(q("DELETE FROM rate_limit_hits WHERE ip_address=?"), (target_ip,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success", "message": f"Blokir untuk IP {target_ip} berhasil dibuka & riwayat pelanggaran direset"}

# --- ENGINE KEAMANAN (WAF & RATE LIMIT) ---
WAF_PATTERNS = [
    r"(\%27)|(\')",
    r"((\%3D)|(=))[^\n]*(\%27|\')",
    r"\w*((\%27)|(\'))((-)|(OR|or)|(UNION|union))",
    r"<script[^>]*>[\s\S]*?</script>",
    r"javascript:",
    r"onerror\s*="
]

def is_malicious(text: str):
    decoded = unquote(text)
    return any(re.search(p, text, re.IGNORECASE) or re.search(p, decoded, re.IGNORECASE) for p in WAF_PATTERNS)

def log_attack(ip: str, domain: str, threat: str):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        q("INSERT INTO attack_logs (timestamp, ip_address, domain, threat_type) VALUES (?, ?, ?, ?)"),
        (now, ip, domain, threat)
    )
    conn.commit()
    cursor.close()
    conn.close()

def resolve_proxy_target(request: Request, path: str):
    clean_path = "/" + path.lstrip("/")
    host_header = request.headers.get("host", "").split(":")[0].strip().lower()

    if clean_path == "/p" or clean_path.startswith("/p/"):
        parts = clean_path.split("/", 3)
        if len(parts) >= 3 and parts[2].strip():
            site_name = parts[2].strip().lower()
            forward_path = "/" + parts[3] if len(parts) == 4 else "/"
            return site_name, forward_path, site_name

    if clean_path != "/":
        referer = request.headers.get("referer", "")
        if referer:
            ref_parsed = urlparse(referer)
            if ref_parsed.netloc.split(":")[0].lower() == host_header and ref_parsed.path.startswith("/p/"):
                ref_parts = ref_parsed.path.split("/", 3)
                if len(ref_parts) >= 3 and ref_parts[2].strip():
                    return ref_parts[2].strip().lower(), clean_path, None

        cookie_site = request.cookies.get("warden_site")
        if cookie_site:
            return cookie_site.strip().lower(), clean_path, None

    return host_header, clean_path, None

def inject_spa_subpath_handler(html_bytes: bytes, site_name: str) -> bytes:
    html_text = html_bytes.decode("utf-8", errors="replace")
    prefix_json = json.dumps(f"/p/{site_name}")
    prefix_script = f"""<script>
(function() {{
  var prefix = {prefix_json};
  var origPush = history.pushState;
  var origReplace = history.replaceState;
  function withPrefix(url) {{
    if (typeof url === "string" && url.charAt(0) === "/" && url.indexOf(prefix) !== 0) {{
      return prefix + (url === "/" ? "" : url);
    }}
    return url;
  }}
  function ensurePrefixInBar() {{
    var cur = window.location.pathname;
    if (cur !== prefix && cur.indexOf(prefix + "/") !== 0) {{
      origReplace.call(history, history.state, "", prefix + (cur === "/" ? "" : cur) + window.location.search + window.location.hash);
    }}
  }}
  history.pushState = function(state, title, url) {{
    return origPush.call(history, state, title, withPrefix(url));
  }};
  history.replaceState = function(state, title, url) {{
    return origReplace.call(history, state, title, withPrefix(url));
  }};
  if (window.location.pathname === prefix || window.location.pathname.indexOf(prefix + "/") === 0) {{
    var innerPath = window.location.pathname.slice(prefix.length) || "/";
    origReplace.call(history, history.state, "", innerPath + window.location.search + window.location.hash);
    document.addEventListener("DOMContentLoaded", function() {{
      setTimeout(ensurePrefixInBar, 0);
    }});
    window.addEventListener("load", ensurePrefixInBar);
  }}
  document.addEventListener("click", function(e) {{
    var anchor = e.target && e.target.closest ? e.target.closest("a[href]") : null;
    if (!anchor) return;
    var rawHref = anchor.getAttribute("href");
    if (rawHref && rawHref.charAt(0) === "/" && rawHref.charAt(1) !== "/" && rawHref.indexOf(prefix) !== 0) {{
      anchor.setAttribute("href", withPrefix(rawHref));
    }}
  }}, true);
}})();
</script>"""
    if re.search(r"<head[^>]*>", html_text, re.IGNORECASE):
        html_text = re.sub(r"<head[^>]*>", lambda m: m.group(0) + prefix_script, html_text, count=1, flags=re.IGNORECASE)
    else:
        html_text = prefix_script + html_text
    return html_text.encode("utf-8")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    if str(request.url.path).startswith(("/admin/", "/api/", "/panel-warden")):
        return JSONResponse(status_code=404, content={"error": "Not Found"})

    client_ip = get_client_ip(request)
    host_header = request.headers.get("host", "").split(":")[0].strip().lower()
    target_domain, forward_path, new_site_cookie = resolve_proxy_target(request, path)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT origin_server, waf_enabled, rate_limit, status FROM clients WHERE domain=?"), (target_domain,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        clean_path = "/" + path.lstrip("/")
        cookie_site = (request.cookies.get("warden_site") or "").strip().lower()
        if clean_path == "/" and cookie_site and not new_site_cookie:
            conn_chk = get_db()
            cur_chk = conn_chk.cursor()
            cur_chk.execute(q("SELECT 1 FROM clients WHERE domain=?"), (cookie_site,))
            exists = cur_chk.fetchone()
            cur_chk.close()
            conn_chk.close()
            if exists:
                return RedirectResponse(url=f"/p/{cookie_site}", status_code=302)

        resp_404 = JSONResponse(status_code=404, content={"error": "Domain tidak terdaftar di WardenWAF."})
        if cookie_site and not new_site_cookie:
            resp_404.delete_cookie("warden_site", path="/")
        return resp_404

    client_config = {"origin": row[0], "waf_enabled": bool(row[1]), "rate_limit": row[2], "status": row[3]}

    if client_config["status"] == "pending":
        return JSONResponse(status_code=403, content={"error": "Domain ini sedang menunggu persetujuan Admin."})

    # 1. CEK APAKAH IP SEDANG DALAM MASA BLOKIR TIMER
    active_ban = is_ip_banned(client_ip)
    if active_ban:
        rem = active_ban["remaining_seconds"]
        headers = {"Retry-After": str(rem)} if rem else {}
        sisa_str = format_duration_id(rem) if rem else "Permanen"
        return JSONResponse(
            status_code=403,
            headers=headers,
            content={
                "status": "blocked",
                "firewall": "WardenWAF",
                "offense_count": active_ban["ban_count"],
                "remaining_seconds": rem,
                "unblock_at": active_ban["unblock_at"],
                "reason": f"IP Anda ({client_ip}) diblokir sementara karena {active_ban['reason']}. Otomatis dibuka dalam {sisa_str}."
            }
        )

    # 2. DETEKSI SERANGAN SQL INJECTION / XSS -> BLOKIR TIMER BERTINGKAT
    if client_config["waf_enabled"] and is_malicious(str(request.url)):
        ban_info = ban_ip_with_escalation(client_ip, target_domain, "SQLi/XSS Injection")
        log_attack(client_ip, target_domain, f"SQLi/XSS Injection (Pelanggaran #{ban_info['ban_count']} - {ban_info['duration_label']})")
        return JSONResponse(
            status_code=403,
            headers={"Retry-After": str(ban_info["remaining_seconds"])},
            content={
                "status": "blocked",
                "firewall": "WardenWAF",
                "offense_count": ban_info["ban_count"],
                "ban_duration": ban_info["duration_label"],
                "remaining_seconds": ban_info["remaining_seconds"],
                "unblock_at": ban_info["unblock_at_str"],
                "reason": f"Serangan SQLi/XSS terdeteksi (Pelanggaran ke-{ban_info['ban_count']}). IP diblokir selama {ban_info['duration_label']}."
            }
        )

    # 3. DETEKSI FLOOD / DDOS RATE LIMIT -> BLOKIR TIMER BERTINGKAT (TERCATAT DI DB)
    if check_and_record_rate_limit(client_ip, client_config["rate_limit"]):
        ban_info = ban_ip_with_escalation(client_ip, target_domain, "DDoS / Flood Rate Limit")
        log_attack(client_ip, target_domain, f"DDoS / Flood Rate Limit (Pelanggaran #{ban_info['ban_count']} - {ban_info['duration_label']})")
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(ban_info["remaining_seconds"])},
            content={
                "status": "blocked",
                "firewall": "WardenWAF",
                "offense_count": ban_info["ban_count"],
                "ban_duration": ban_info["duration_label"],
                "remaining_seconds": ban_info["remaining_seconds"],
                "unblock_at": ban_info["unblock_at_str"],
                "reason": f"Terlalu banyak permintaan / DDoS Flood (Pelanggaran ke-{ban_info['ban_count']}). IP diblokir selama {ban_info['duration_label']}."
            }
        )

    # 4. HALAMAN VERIFIKASI BROWSER (JS CHALLENGE)
    if client_config["waf_enabled"]:
        clearance_cookie = request.cookies.get("warden_waf_clearance")
        user_agent = request.headers.get("user-agent", "unknown")
        if not is_valid_clearance(clearance_cookie, user_agent):
            ts = str(int(time.time()))
            num_a = secrets.randbelow(40) + 10
            num_b = secrets.randbelow(40) + 10
            sig = sign_challenge(ts, num_a, num_b, num_a + num_b)
            challenge_resp = templates.TemplateResponse(
                request,
                "challenge.html",
                {
                    "domain": target_domain,
                    "ts": ts,
                    "num_a": num_a,
                    "num_b": num_b,
                    "sig": sig
                }
            )
            if new_site_cookie:
                challenge_resp.set_cookie(
                    key="warden_site",
                    value=new_site_cookie,
                    path="/",
                    httponly=True,
                    samesite="lax"
                )
            return challenge_resp

    async with httpx.AsyncClient(base_url=client_config["origin"]) as client:
        url = httpx.URL(path=forward_path, query=request.url.query.encode("utf-8"))
        try:
            proxy_resp = await client.send(
                client.build_request(
                    request.method,
                    url,
                    content=await request.body(),
                    headers={
                        k: v for k, v in request.headers.items()
                        if k.lower() not in ("host", "content-length", "accept-encoding")
                    }
                ),
                stream=True
            )

            excluded_resp_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
            custom_headers = {
                k: v for k, v in proxy_resp.headers.items()
                if k.lower() not in excluded_resp_headers
            }
            custom_headers["X-Protected-By"] = "WardenWAF - Enterprise Security"
            custom_headers["X-WAF-Status"] = "Active"

            resp_body = await proxy_resp.aread()
            content_type = proxy_resp.headers.get("content-type", "").lower()
            is_subpath_mode = bool(new_site_cookie) or (target_domain != host_header)
            if is_subpath_mode and "text/html" in content_type:
                resp_body = inject_spa_subpath_handler(resp_body, target_domain)

            final_resp = Response(
                content=resp_body,
                status_code=proxy_resp.status_code,
                headers=custom_headers
            )
            if new_site_cookie:
                final_resp.set_cookie(
                    key="warden_site",
                    value=new_site_cookie,
                    path="/",
                    httponly=True,
                    samesite="lax"
                )
            return final_resp
        except httpx.RequestError:
            return JSONResponse(status_code=502, content={"error": "Bad Gateway"})