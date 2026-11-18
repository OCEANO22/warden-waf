import os
import time
import re
import hmac
import hashlib
import secrets
import httpx
import sqlite3
import socket
import psycopg2
from urllib.parse import unquote
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
    """Mengambil IP asli pengunjung meskipun melewati load balancer Render."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# --- 1. SETUP DATABASE ---
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
            banned_at TEXT NOT NULL
        )''')
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
            banned_at TEXT NOT NULL
        )''')
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
    exp_ts = str(int(time.time()) + 1800)  # Sesi aktif 30 menit
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

# --- FUNGSI HELPER PEMBLOKIRAN PERMANEN ---
def is_ip_banned(ip: str) -> Optional[str]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT reason FROM banned_ips WHERE ip_address=?"), (ip,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row[0] if row else None

def ban_ip_permanently(ip: str, domain: str, reason: str):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if USE_POSTGRES:
        cursor.execute(
            """INSERT INTO banned_ips (ip_address, domain, reason, banned_at)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (ip_address) DO UPDATE SET
                   domain = EXCLUDED.domain,
                   reason = EXCLUDED.reason,
                   banned_at = EXCLUDED.banned_at""",
            (ip, domain, reason, now)
        )
    else:
        cursor.execute(
            "INSERT OR REPLACE INTO banned_ips (ip_address, domain, reason, banned_at) VALUES (?, ?, ?, ?)",
            (ip, domain, reason, now)
        )
    conn.commit()
    cursor.close()
    conn.close()

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
    if is_ip_banned(client_ip):
        raise HTTPException(status_code=403, detail="IP Anda diblokir permanen oleh WardenWAF.")

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

# --- ENDPOINT LOG SERANGAN (LIHAT & HAPUS KHUSUS ADMIN) ---
@app.get("/admin/api/logs")
def get_attack_logs(request: Request):
    require_session(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, ip_address, domain, threat_type FROM attack_logs ORDER BY id DESC LIMIT 100")
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

# --- ENDPOINT KHUSUS ADMIN: DAFTAR, BLOKIR MANUAL & UNBLOKIR IP PERMANEN ---
@app.get("/admin/api/banned-ips")
def get_banned_ips(request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat melihat daftar IP terblokir")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, domain, reason, banned_at FROM banned_ips ORDER BY banned_at DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [
        {
            "ip_address": r[0],
            "domain": r[1],
            "reason": r[2],
            "banned_at": r[3]
        }
        for r in rows
    ]

@app.post("/admin/api/banned-ips")
def manual_ban_ip(data: ManualBanData, request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat memblokir IP")
    clean_ip = data.ip_address.strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="Alamat IP tidak boleh kosong")
    ban_ip_permanently(
        clean_ip,
        (data.domain or "Semua Domain (Manual)").strip(),
        (data.reason or "Diblokir Manual oleh Admin").strip()
    )
    return {"status": "success", "message": f"IP {clean_ip} berhasil diblokir permanen"}

@app.delete("/admin/api/banned-ips/{target_ip:path}")
def unblock_ip(target_ip: str, request: Request):
    session = require_session(request)
    if session["role"] != 'admin':
        raise HTTPException(status_code=403, detail="Hanya admin yang dapat membuka blokir IP")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("DELETE FROM banned_ips WHERE ip_address=?"), (target_ip,))
    conn.commit()
    cursor.close()
    conn.close()
    REQUEST_LOGS.pop(target_ip, None)
    return {"status": "success", "message": f"Blokir untuk IP {target_ip} berhasil dibuka"}

# --- ENGINE KEAMANAN (WAF & RATE LIMIT) ---
TIME_WINDOW = 10 
REQUEST_LOGS = {}
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
    """
    Menentukan domain target dan path tujuan:
    1. Jalur instan: /p/<nama_web> atau /p/<nama_web>/sub-halaman
    2. Cookie sesi (warden_site) untuk memuat aset CSS/JS/gambar dari jalur instan
    3. Custom domain penuh berdasarkan header Host
    """
    clean_path = "/" + path.lstrip("/")
    if clean_path == "/p" or clean_path.startswith("/p/"):
        parts = clean_path.split("/", 3)  # ['', 'p', '<nama_web>', '<sisa_path>']
        if len(parts) >= 3 and parts[2].strip():
            site_name = parts[2].strip().lower()
            forward_path = "/" + parts[3] if len(parts) == 4 else "/"
            return site_name, forward_path, site_name

    host_header = request.headers.get("host", "").split(":")[0].strip().lower()
    cookie_site = request.cookies.get("warden_site")
    if cookie_site:
        return cookie_site.strip().lower(), clean_path, None

    return host_header, clean_path, None

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    if str(request.url.path).startswith(("/admin/", "/api/", "/panel-warden")):
        return JSONResponse(status_code=404, content={"error": "Not Found"})

    client_ip = get_client_ip(request)
    target_domain, forward_path, new_site_cookie = resolve_proxy_target(request, path)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(q("SELECT origin_server, waf_enabled, rate_limit, status FROM clients WHERE domain=?"), (target_domain,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        return JSONResponse(status_code=404, content={"error": "Domain tidak terdaftar di WardenWAF."})
    client_config = {"origin": row[0], "waf_enabled": bool(row[1]), "rate_limit": row[2], "status": row[3]}

    if client_config["status"] == "pending":
        return JSONResponse(status_code=403, content={"error": "Domain ini sedang menunggu persetujuan Admin."})

    # 1. CEK APAKAH IP SUDAH TERBLOKIR PERMANEN DI DATABASE
    banned_reason = is_ip_banned(client_ip)
    if banned_reason:
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "firewall": "WardenWAF",
                "reason": f"IP Anda ({client_ip}) diblokir permanen karena {banned_reason}."
            }
        )

    # 2. DETEKSI SERANGAN SQL INJECTION / XSS -> BLOKIR PERMANEN
    if client_config["waf_enabled"] and is_malicious(str(request.url)):
        ban_ip_permanently(client_ip, target_domain, "SQLi/XSS Injection")
        log_attack(client_ip, target_domain, "SQLi/XSS Injection")
        return JSONResponse(status_code=403, content={"status": "blocked", "firewall": "WardenWAF", "reason": "Malicious payload detected - IP Banned Permanently"})

    # 3. DETEKSI FLOOD / DDOS RATE LIMIT -> BLOKIR PERMANEN
    current_time = time.time()
    REQUEST_LOGS.setdefault(client_ip, [])
    REQUEST_LOGS[client_ip] = [t for t in REQUEST_LOGS[client_ip] if current_time - t < TIME_WINDOW]
    if len(REQUEST_LOGS[client_ip]) >= client_config["rate_limit"]:
        ban_ip_permanently(client_ip, target_domain, "DDoS / Flood Rate Limit")
        log_attack(client_ip, target_domain, "DDoS / Flood Rate Limit")
        return JSONResponse(status_code=429, content={"status": "blocked", "firewall": "WardenWAF", "reason": "Too many requests - IP Banned Permanently"})

    REQUEST_LOGS[client_ip].append(current_time)

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

    # 5. SIMPAN COOKIE SITUS & ARAHKAN KE ROOT AGAR ROUTER SPA & ASET TERMUAT UTUH
    if new_site_cookie:
        redirect_url = forward_path
        if request.url.query:
            redirect_url += f"?{request.url.query}"
        redir_resp = RedirectResponse(url=redirect_url, status_code=302)
        redir_resp.set_cookie(
            key="warden_site",
            value=new_site_cookie,
            path="/",
            httponly=True,
            samesite="lax"
        )
        return redir_resp

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

            final_resp = Response(
                content=await proxy_resp.aread(),
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