# -*- coding: utf-8 -*-
"""
PyHost — Python project host + KHPAY billing
Security: no payment bypass, rate limits, webhook verify, server-side payment confirm only
"""
from __future__ import annotations

import os
import re
import io
import ast
import json
import time
import hmac
import hashlib
import zipfile
import secrets
import threading
from collections import defaultdict, deque
from pathlib import Path
from functools import wraps

import requests
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_file,
    Response,
    jsonify,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# Harden session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024)),
)

DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR = DATA_DIR / "projects"
PROJECTS_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
INDEX_FILE = DATA_DIR / "index.json"
PAYMENTS_FILE = DATA_DIR / "payments.json"
AUDIT_FILE = DATA_DIR / "audit.jsonl"

APP_NAME = os.environ.get("APP_NAME", "PyHost")
FREE_TRIAL_SECONDS = int(os.environ.get("FREE_TRIAL_SECONDS", 15 * 60))
MAX_FILES = int(os.environ.get("MAX_FILES", 30))
ALLOW_DEMO_UPGRADE = os.environ.get("ALLOW_DEMO_UPGRADE", "0") == "1"

KHPAY_API_KEY = os.environ.get("KHPAY_API_KEY", "").strip()
KHPAY_BASE = os.environ.get("KHPAY_BASE", "https://khpay.site/api/v1").rstrip("/")
KHPAY_WEBHOOK_SECRET = os.environ.get("KHPAY_WEBHOOK_SECRET", "").strip()

PLAN_LIMITS = {
    "free": {"projects": 2, "files": 10, "max_file": 100_000},
    "starter": {"projects": 10, "files": 30, "max_file": 500_000},
    "pro": {"projects": 50, "files": 50, "max_file": 2_000_000},
    "business": {"projects": 200, "files": 100, "max_file": 5_000_000},
}
PLAN_PRICES = {
    "starter": {"amount": "2.99", "label": "Starter 1 month"},
    "pro": {"amount": "6.99", "label": "Pro 1 month"},
    "business": {"amount": "14.99", "label": "Business 1 month"},
}

# --- Rate limiting (in-memory; use Redis in multi-instance production) ---
_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque] = defaultdict(deque)
_file_lock = threading.RLock()

# limits: (max_requests, window_seconds)
RATE_LIMITS = {
    "default": (120, 60),
    "login": (10, 60),
    "register": (5, 60),
    "upgrade": (8, 60),
    "pay_status": (30, 60),
    "webhook": (60, 60),
    "api": (60, 60),
}


def client_ip() -> str:
    # Render / proxies: trust first X-Forwarded-For hop only if present
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def rate_allow(bucket: str, key: str | None = None) -> bool:
    name = bucket if bucket in RATE_LIMITS else "default"
    limit, window = RATE_LIMITS[name]
    k = f"{name}:{key or client_ip()}"
    now = time.time()
    with _rate_lock:
        q = _rate_buckets[k]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        # prevent unbounded keys
        if len(_rate_buckets) > 20000:
            _rate_buckets.clear()
    return True


def audit(event: str, **fields):
    try:
        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "ip": client_ip(),
            **fields,
        }
        with _file_lock:
            with AUDIT_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _load(path: Path, default):
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path: Path, data):
    with _file_lock:
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(path)


def hash_pw(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    # slow-ish stretch without extra deps
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"{salt}${h.hex()}"


def check_pw(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
        return hmac.compare_digest(hash_pw(password, salt), stored)
    except Exception:
        return False


def get_users():
    return _load(USERS_FILE, {})


def save_users(users):
    _save(USERS_FILE, users)


def get_payments():
    return _load(PAYMENTS_FILE, {})


def save_payments(data):
    _save(PAYMENTS_FILE, data)


def user_plan(email: str):
    users = get_users()
    u = users.get(email) or {}
    plan = (u.get("plan") or "free").lower()
    if plan == "expired":
        return "expired", u
    if plan not in PLAN_LIMITS:
        plan = "free"
    return plan, u


def free_trial_remaining(email: str):
    plan, u = user_plan(email)
    if plan in ("starter", "pro", "business"):
        return None
    if plan == "expired" or u.get("free_expired"):
        return 0
    if plan != "free":
        return None
    started = u.get("free_started_at")
    if not started:
        return FREE_TRIAL_SECONDS
    try:
        left = int(FREE_TRIAL_SECONDS - (time.time() - float(started)))
    except (TypeError, ValueError):
        return FREE_TRIAL_SECONDS
    return max(0, left)


def ensure_free_timer(email: str):
    users = get_users()
    u = users.get(email)
    if not u:
        return
    if (u.get("plan") or "free").lower() != "free":
        return
    if not u.get("free_started_at"):
        u["free_started_at"] = time.time()
        users[email] = u
        save_users(users)


def free_expired(email: str) -> bool:
    left = free_trial_remaining(email)
    expired = left is not None and left <= 0
    if expired:
        users = get_users()
        u = users.get(email)
        if u and not u.get("free_expired"):
            u["free_expired"] = True
            u["plan"] = "expired"
            users[email] = u
            save_users(users)
            audit("free_expired", email=email)
    return expired


def requires_paid(email: str) -> bool:
    plan, u = user_plan(email)
    if plan in ("starter", "pro", "business"):
        return False
    if plan == "expired" or u.get("free_expired"):
        return True
    return free_expired(email)


def activate_plan(email: str, plan: str, payment_id: str | None = None) -> bool:
    """ONLY call after verified payment (or ALLOW_DEMO_UPGRADE)."""
    if plan not in PLAN_PRICES:
        return False
    users = get_users()
    if email not in users:
        return False
    users[email]["plan"] = plan
    users[email]["plan_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    users[email]["free_started_at"] = None
    users[email]["free_expired"] = False
    if payment_id:
        users[email]["last_payment_id"] = payment_id
    save_users(users)
    audit("plan_activated", email=email, plan=plan, payment_id=payment_id)
    return True


def is_paid_status(st: str) -> bool:
    st = (st or "").lower()
    return st in ("paid", "approved", "success", "completed", "confirmed") or "approv" in st


def khpay_headers():
    return {
        "Authorization": f"Bearer {KHPAY_API_KEY}",
        "Content-Type": "application/json",
    }


def khpay_create_qr(amount: str, note: str, metadata: dict):
    if not KHPAY_API_KEY:
        return None, "KHPAY_API_KEY not configured"
    url = f"{KHPAY_BASE}/qr/generate"
    try:
        r = requests.post(
            url,
            headers={**khpay_headers(), "Idempotency-Key": metadata.get("payment_id", secrets.token_hex(8))},
            json={"amount": str(amount), "note": note[:200], "metadata": metadata},
            timeout=30,
        )
        data = r.json()
    except Exception as e:
        return None, str(e)[:200]
    if r.status_code >= 400:
        return None, str(data.get("error") or data.get("message") or data)[:300]
    return data, None


def khpay_check(txn_id: str):
    if not KHPAY_API_KEY or not txn_id:
        return None, "missing"
    try:
        r = requests.get(
            f"{KHPAY_BASE}/qr/check",
            headers=khpay_headers(),
            params={"txn_id": txn_id},
            timeout=20,
        )
        data = r.json()
    except Exception as e:
        return None, str(e)
    if r.status_code >= 400:
        return None, data
    return data, None


def extract_txn(data: dict):
    d = data.get("data") if isinstance(data.get("data"), dict) else {}
    txn_id = data.get("txn_id") or data.get("transaction_id") or data.get("id") or d.get("txn_id")
    qr_string = data.get("qr") or data.get("qr_string") or data.get("khqr") or d.get("qr")
    payment_url = data.get("payment_url") or data.get("checkout_url") or d.get("payment_url")
    qr_image = data.get("qr_image") or data.get("download_qr") or data.get("qr_url") or d.get("qr_image")
    return txn_id, qr_string, payment_url, qr_image


def confirm_payment_server_side(payment_id: str) -> bool:
    """Mark paid + activate only if KHPAY confirms. Never trust client alone."""
    payments = get_payments()
    pay = payments.get(payment_id)
    if not pay or pay.get("status") == "paid":
        return pay.get("status") == "paid" if pay else False
    data, err = khpay_check(pay.get("txn_id") or "")
    if err or not data:
        return False
    st = str(data.get("status") or data.get("action") or (data.get("data") or {}).get("status") or "")
    if not is_paid_status(st):
        return False
    # Optional amount check if API returns amount
    amt = data.get("amount") or (data.get("data") or {}).get("amount")
    if amt is not None:
        try:
            if abs(float(amt) - float(pay.get("amount", 0))) > 0.011:
                audit("amount_mismatch", payment_id=payment_id, expected=pay.get("amount"), got=amt)
                return False
        except (TypeError, ValueError):
            pass
    pay["status"] = "paid"
    pay["paid_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pay["confirm_raw"] = {k: data.get(k) for k in list(data)[:20]} if isinstance(data, dict) else {}
    payments[payment_id] = pay
    save_payments(payments)
    activate_plan(pay["email"], pay["plan"], payment_id)
    return True


def new_id(n=10):
    return secrets.token_urlsafe(n)[:n]


def safe_name(name: str) -> str:
    name = name.replace("\\", "/").strip().lstrip("/")
    parts = [p for p in name.split("/") if p and p not in (".", "..")]
    out = "/".join(parts)
    return out[:180] if out else "file.txt"


def project_dir(pid: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "", pid)[:32]
    d = PROJECTS_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def meta_path(pid: str) -> Path:
    return project_dir(pid) / "_meta.json"


def load_meta(pid: str):
    return _load(meta_path(pid), None)


def save_meta(meta: dict):
    pid = meta["id"]
    _save(meta_path(pid), meta)
    idx = _load(INDEX_FILE, {"projects": []})
    summary = {
        "id": meta["id"],
        "title": meta.get("title"),
        "description": (meta.get("description") or "")[:160],
        "owner": meta.get("owner"),
        "private": bool(meta.get("private")),
        "created": meta.get("created"),
        "updated": meta.get("updated"),
        "file_count": len(meta.get("files") or {}),
        "views": meta.get("views", 0),
    }
    projects = [p for p in idx.get("projects", []) if p.get("id") != pid]
    projects.insert(0, summary)
    idx["projects"] = projects[:300]
    _save(INDEX_FILE, idx)


def write_project_file(pid: str, rel: str, content: str):
    rel = safe_name(rel)
    base = project_dir(pid).resolve()
    path = (base / rel).resolve()
    if not str(path).startswith(str(base)):
        raise ValueError("invalid path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def read_project_file(pid: str, rel: str):
    rel = safe_name(rel)
    base = project_dir(pid).resolve()
    path = (base / rel).resolve()
    if not str(path).startswith(str(base)) or not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def list_files(pid: str):
    meta = load_meta(pid) or {}
    return sorted((meta.get("files") or {}).keys())


def syntax_check_python(code: str):
    try:
        ast.parse(code)
        return True, None
    except SyntaxError as e:
        return False, f"Line {e.lineno}: {e.msg}"


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


@app.context_processor
def inject():
    u = session.get("user")
    trial_left = None
    plan = None
    if u and u.get("email"):
        plan, _ = user_plan(u["email"])
        trial_left = free_trial_remaining(u["email"])
    return {
        "app_name": APP_NAME,
        "user": u,
        "user_plan_name": plan,
        "free_trial_left": trial_left,
        "free_trial_minutes": FREE_TRIAL_SECONDS // 60,
        "khpay_ready": bool(KHPAY_API_KEY),
    }


@app.before_request
def security_gate():
    # Global rate limit
    if not rate_allow("default"):
        audit("rate_limited", path=request.path)
        return jsonify({"error": "Too many requests"}), 429

    ep = request.endpoint
    open_eps = {
        "index", "explore", "login", "register", "logout", "health",
        "view_project", "raw_file", "download_zip", "check_project",
        "static", "pricing", "upgrade_plan", "pay", "pay_status", "khpay_webhook",
    }
    if ep in open_eps or ep is None:
        return None
    u = session.get("user")
    if not u or not u.get("email"):
        return None
    email = u["email"]
    ensure_free_timer(email)
    if requires_paid(email):
        if ep in ("logout", "pricing", "upgrade_plan", "pay", "pay_status"):
            return None
        flash(
            f"Free {FREE_TRIAL_SECONDS // 60} នាទី ផុតហើយ។ ត្រូវបង់លុយទើបប្រើបន្ត។",
            "error",
        )
        return redirect(url_for("pricing"))
    return None


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Basic CSP
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://khpay.site"
    )
    return resp


@app.get("/")
def index():
    idx = _load(INDEX_FILE, {"projects": []})
    public = [p for p in idx.get("projects", []) if not p.get("private")][:12]
    return render_template("index.html", projects=public)


@app.get("/explore")
def explore():
    idx = _load(INDEX_FILE, {"projects": []})
    public = [p for p in idx.get("projects", []) if not p.get("private")]
    return render_template("explore.html", projects=public)


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_project():
    if request.method == "GET":
        return render_template("new.html")
    email = session["user"]["email"]
    plan, _ = user_plan(email)
    limits = PLAN_LIMITS.get(plan) or PLAN_LIMITS["free"]
    idx = _load(INDEX_FILE, {"projects": []})
    owned = sum(1 for p in idx.get("projects", []) if p.get("owner") == email)
    if owned >= limits["projects"]:
        flash("ដល់ដែនកំណត់ project តាម plan", "error")
        return redirect(url_for("pricing"))

    title = (request.form.get("title") or "").strip()[:100] or "Python Project"
    description = (request.form.get("description") or "").strip()[:500]
    private = request.form.get("private") == "1"
    main_code = request.form.get("main_code") or ""
    requirements = request.form.get("requirements") or "Flask>=3.0.0\n"

    pid = new_id()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    files = {}
    max_file = limits["max_file"]

    if main_code.strip():
        if len(main_code) > max_file:
            flash("app.py វែងពេក", "error")
            return redirect(url_for("new_project"))
        ok, err = syntax_check_python(main_code)
        write_project_file(pid, "app.py", main_code)
        files["app.py"] = {"size": len(main_code), "syntax_ok": ok, "syntax_error": err}
    if requirements.strip():
        write_project_file(pid, "requirements.txt", requirements.strip() + "\n")
        files["requirements.txt"] = {"size": len(requirements)}

    for f in request.files.getlist("files"):
        if not f or not f.filename:
            continue
        rel = safe_name(Path(f.filename).name)
        if not rel or len(files) >= limits["files"]:
            continue
        raw = f.read()
        if len(raw) > max_file:
            continue
        try:
            body = raw.decode("utf-8")
        except UnicodeDecodeError:
            body = raw.decode("utf-8", errors="replace")
        info = {"size": len(body)}
        if rel.endswith(".py"):
            ok, err = syntax_check_python(body)
            info["syntax_ok"] = ok
            info["syntax_error"] = err
        write_project_file(pid, rel, body)
        files[rel] = info
    proc = "web: gunicorn app:app --bind 0.0.0.0:$PORT\n"
    write_project_file(pid, "Procfile", proc)
    files["Procfile"] = {"size": len(proc)}
    readme = f"# {title}\n\nHosted on {APP_NAME}\n"
    write_project_file(pid, "README.md", readme)
    files["README.md"] = {"size": len(readme)}

    meta = {
        "id": pid,
        "title": title,
        "description": description,
        "private": private,
        "owner": email,
        "created": now,
        "updated": now,
        "views": 0,
        "files": files,
    }
    save_meta(meta)
    flash("បង្កើត project រួច", "ok")
    return redirect(url_for("view_project", pid=pid))


@app.get("/p/<pid>")
def view_project(pid):
    meta = load_meta(pid)
    if not meta:
        abort(404)
    if meta.get("private"):
        me = (session.get("user") or {}).get("email")
        if meta.get("owner") != me:
            abort(404)
    meta["views"] = int(meta.get("views") or 0) + 1
    save_meta(meta)
    files = list_files(pid)
    current = request.args.get("file") or (files[0] if files else None)
    content = read_project_file(pid, current) if current else ""
    return render_template("project.html", meta=meta, files=files, current=current, content=content or "")


@app.route("/p/<pid>/upload", methods=["POST"])
@login_required
def upload_file(pid):
    """Upload one or many files from device, and/or save pasted text."""
    meta = load_meta(pid)
    if not meta or meta.get("owner") != session["user"]["email"]:
        abort(403)
    plan, _ = user_plan(session["user"]["email"])
    limits = PLAN_LIMITS.get(plan) or PLAN_LIMITS["free"]
    max_files = limits["files"]
    max_file = limits["max_file"]
    saved = []
    errors = []

    def save_one(rel: str, body: str):
        rel = safe_name(rel)
        if not rel:
            errors.append("ឈ្មោះ file មិនត្រឹមត្រូវ")
            return
        if len(meta.get("files") or {}) + (0 if rel in (meta.get("files") or {}) else 1) > max_files:
            errors.append(f"ដល់ដែនកំណត់ files ({max_files})")
            return
        if len(body.encode("utf-8", errors="replace")) > max_file:
            errors.append(f"{rel}: ធំពេក (max {max_file} bytes)")
            return
        info = {"size": len(body)}
        if rel.endswith(".py"):
            ok, err = syntax_check_python(body)
            info["syntax_ok"] = ok
            info["syntax_error"] = err
        write_project_file(pid, rel, body)
        meta.setdefault("files", {})[rel] = info
        saved.append(rel)

    # 1) Multi file upload from <input type=file multiple>
    uploads = request.files.getlist("files") or []
    single = request.files.get("file")
    if single and single.filename and single not in uploads:
        uploads.append(single)

    for f in uploads:
        if not f or not f.filename:
            continue
        # keep relative name only (no path traversal)
        name = Path(f.filename).name
        raw = f.read()
        if len(raw) > max_file:
            errors.append(f"{name}: ធំពេក")
            continue
        try:
            body = raw.decode("utf-8")
        except UnicodeDecodeError:
            body = raw.decode("utf-8", errors="replace")
            # skip obvious binary
            if "\x00" in body[:2000]:
                errors.append(f"{name}: binary មិនទទួល (text តែ)")
                continue
        save_one(name, body)

    # 2) Optional paste path + content
    rel = (request.form.get("path") or request.form.get("filename") or "").strip()
    body = request.form.get("content")
    if rel and body is not None and body != "":
        save_one(rel, body)

    if not saved and not errors:
        flash("រើស file ឬបញ្ចូល path + content", "error")
        return redirect(url_for("view_project", pid=pid))

    meta["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_meta(meta)
    if saved:
        flash("Upload: " + ", ".join(saved[:8]) + ("…" if len(saved) > 8 else ""), "ok")
    for e in errors[:5]:
        flash(e, "error")
    last = saved[-1] if saved else None
    return redirect(url_for("view_project", pid=pid, file=last) if last else url_for("view_project", pid=pid))


@app.post("/p/<pid>/delete-file")
@login_required
def delete_file(pid):
    meta = load_meta(pid)
    if not meta or meta.get("owner") != session["user"]["email"]:
        abort(403)
    rel = safe_name(request.form.get("path") or "")
    base = project_dir(pid).resolve()
    path = (base / rel).resolve()
    if str(path).startswith(str(base)) and path.is_file():
        path.unlink()
    meta.get("files", {}).pop(rel, None)
    meta["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_meta(meta)
    return redirect(url_for("view_project", pid=pid))


@app.get("/p/<pid>/raw/<path:filepath>")
def raw_file(pid, filepath):
    meta = load_meta(pid)
    if not meta:
        abort(404)
    if meta.get("private"):
        me = (session.get("user") or {}).get("email")
        if meta.get("owner") != me:
            abort(404)
    content = read_project_file(pid, filepath)
    if content is None:
        abort(404)
    return Response(content, mimetype="text/plain; charset=utf-8")


@app.get("/p/<pid>/download.zip")
def download_zip(pid):
    meta = load_meta(pid)
    if not meta:
        abort(404)
    if meta.get("private"):
        me = (session.get("user") or {}).get("email")
        if meta.get("owner") != me:
            abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in list_files(pid):
            content = read_project_file(pid, rel)
            if content is not None:
                z.writestr(rel, content)
    buf.seek(0)
    name = re.sub(r"[^\w-]", "_", meta.get("title") or "project")[:40] + ".zip"
    return send_file(buf, as_attachment=True, download_name=name, mimetype="application/zip")


@app.get("/p/<pid>/check")
def check_project(pid):
    if not rate_allow("api"):
        return jsonify({"error": "rate limit"}), 429
    meta = load_meta(pid)
    if not meta:
        abort(404)
    results = []
    for rel in list_files(pid):
        if not rel.endswith(".py"):
            continue
        code = read_project_file(pid, rel) or ""
        ok, err = syntax_check_python(code)
        results.append({"file": rel, "ok": ok, "error": err})
    return jsonify({"results": results})


@app.get("/mine")
@login_required
def mine():
    email = session["user"]["email"]
    idx = _load(INDEX_FILE, {"projects": []})
    mine_list = [p for p in idx.get("projects", []) if p.get("owner") == email]
    return render_template("mine.html", projects=mine_list)


@app.post("/p/<pid>/delete")
@login_required
def delete_project(pid):
    meta = load_meta(pid)
    if not meta or meta.get("owner") != session["user"]["email"]:
        abort(403)
    import shutil
    d = project_dir(pid)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    idx = _load(INDEX_FILE, {"projects": []})
    idx["projects"] = [p for p in idx.get("projects", []) if p.get("id") != pid]
    _save(INDEX_FILE, idx)
    flash("លុប project រួច", "ok")
    return redirect(url_for("mine"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        if not rate_allow("login"):
            error = "សាកច្រើនពេក — រង់ចាំ 1 នាទី"
            return render_template("login.html", error=error)
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        users = get_users()
        u = users.get(email)
        if u and check_pw(password, u["password"]):
            session.clear()
            session["user"] = {
                "email": email,
                "name": u.get("name") or email,
                "plan": u.get("plan") or "free",
            }
            session.permanent = True
            ensure_free_timer(email)
            audit("login_ok", email=email)
            if free_expired(email):
                flash(f"Free trial ផុត — ត្រូវបង់លុយ", "error")
                return redirect(url_for("pricing"))
            return redirect(request.args.get("next") or url_for("index"))
        audit("login_fail", email=email)
        error = "Email ឬ password មិនត្រឹមត្រូវ"
        time.sleep(0.4)  # slow brute force slightly
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        if not rate_allow("register"):
            error = "សាកច្រើនពេក — រង់ចាំបន្តិច"
            return render_template("register.html", error=error)
        name = (request.form.get("name") or "").strip()[:80]
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or len(password) < 6:
            error = "Email + password យ៉ាងតិច 6 តួ"
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            error = "Email មិនត្រឹមត្រូវ"
        else:
            users = get_users()
            if email in users:
                error = "Email មានរួច"
            else:
                users[email] = {
                    "name": name or email.split("@")[0],
                    "password": hash_pw(password),
                    "plan": "free",
                    "free_started_at": None,
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                save_users(users)
                session.clear()
                session["user"] = {"email": email, "name": users[email]["name"], "plan": "free"}
                audit("register", email=email)
                return redirect(url_for("index"))
    return render_template("register.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/pricing")
def pricing():
    return render_template(
        "pricing.html",
        plans=[
            {"id": "free", "name": "Free", "price": "$0", "desc": f"សាក {FREE_TRIAL_SECONDS // 60} នាទី", "features": ["2 projects", f"Trial {FREE_TRIAL_SECONDS // 60} នាទី"]},
            {"id": "starter", "name": "Starter", "price": "$2.99/ខែ", "desc": "Side project", "features": ["10 projects", "Private", "ZIP"]},
            {"id": "pro", "name": "Pro", "price": "$6.99/ខែ", "desc": "Freelance", "features": ["50 projects", "Priority"]},
            {"id": "business", "name": "Business", "price": "$14.99/ខែ", "desc": "Team", "features": ["200 projects", "5 seats"]},
        ],
        trial_minutes=FREE_TRIAL_SECONDS // 60,
        allow_demo=ALLOW_DEMO_UPGRADE,
    )


@app.post("/upgrade")
@login_required
def upgrade_plan():
    if not rate_allow("upgrade", session["user"]["email"]):
        flash("សាកច្រើនពេក", "error")
        return redirect(url_for("pricing"))

    plan = (request.form.get("plan") or "").lower()
    if plan not in PLAN_PRICES:
        flash("Plan មិនត្រឹមត្រូវ", "error")
        return redirect(url_for("pricing"))

    email = session["user"]["email"]
    # Block demo bypass unless explicitly enabled
    if request.form.get("demo") == "1":
        if not ALLOW_DEMO_UPGRADE:
            audit("demo_bypass_blocked", email=email, plan=plan)
            flash("Demo បិទ — ត្រូវបង់តាម KHPAY", "error")
            return redirect(url_for("pricing"))
        activate_plan(email, plan, payment_id="demo")
        session["user"]["plan"] = plan
        flash(f"Demo upgrade {plan}", "ok")
        return redirect(url_for("mine"))

    if not KHPAY_API_KEY:
        flash("Server មិនទាន់ភ្ជាប់ KHPAY_API_KEY", "error")
        return redirect(url_for("pricing"))

    price = PLAN_PRICES[plan]
    payment_id = secrets.token_hex(8)
    meta = {"payment_id": payment_id, "email": email, "plan": plan, "app": APP_NAME}
    data, err = khpay_create_qr(price["amount"], f"PyHost {price['label']} {email}", meta)
    if err:
        audit("khpay_create_fail", email=email, error=str(err)[:200])
        flash(f"KHPAY: {err}", "error")
        return redirect(url_for("pricing"))

    txn_id, qr_string, payment_url, qr_image = extract_txn(data if isinstance(data, dict) else {})
    payments = get_payments()
    payments[payment_id] = {
        "id": payment_id,
        "txn_id": txn_id or payment_id,
        "email": email,
        "plan": plan,
        "amount": price["amount"],
        "status": "pending",
        "qr_string": qr_string,
        "payment_url": payment_url,
        "qr_image": qr_image,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ip": client_ip(),
    }
    save_payments(payments)
    audit("payment_created", email=email, payment_id=payment_id, plan=plan)
    return redirect(url_for("pay", payment_id=payment_id))


@app.get("/pay/<payment_id>")
@login_required
def pay(payment_id):
    payments = get_payments()
    pay = payments.get(payment_id)
    if not pay or pay.get("email") != session["user"]["email"]:
        abort(404)
    return render_template("pay.html", pay=pay)


@app.get("/pay/<payment_id>/status")
@login_required
def pay_status(payment_id):
    if not rate_allow("pay_status", session["user"]["email"]):
        return jsonify({"error": "rate limit"}), 429
    payments = get_payments()
    pay = payments.get(payment_id)
    if not pay or pay.get("email") != session["user"]["email"]:
        return jsonify({"error": "not found"}), 404
    if pay.get("status") == "paid":
        session["user"]["plan"] = pay.get("plan")
        return jsonify({"status": "paid", "plan": pay.get("plan")})
    # Server-side confirm only — client cannot force paid
    ok = confirm_payment_server_side(payment_id)
    payments = get_payments()
    pay = payments.get(payment_id) or pay
    if ok:
        session["user"]["plan"] = pay.get("plan")
    return jsonify({"status": pay.get("status", "pending"), "plan": pay.get("plan")})


@app.post("/webhooks/khpay")
def khpay_webhook():
    if not rate_allow("webhook"):
        return jsonify({"error": "rate limit"}), 429
    # Require secret in production
    if KHPAY_WEBHOOK_SECRET:
        token = (
            request.headers.get("X-Webhook-Secret")
            or request.headers.get("Authorization", "").replace("Bearer ", "")
            or request.args.get("secret")
        )
        if not token or not hmac.compare_digest(token, KHPAY_WEBHOOK_SECRET):
            audit("webhook_unauthorized")
            return jsonify({"error": "unauthorized"}), 401
    elif os.environ.get("REQUIRE_WEBHOOK_SECRET", "1") == "1" and not ALLOW_DEMO_UPGRADE:
        # refuse open webhook if no secret configured in prod posture
        return jsonify({"error": "webhook secret not configured"}), 503

    payload = request.get_json(silent=True) or {}
    event = str(payload.get("event") or payload.get("type") or "").lower()
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    status = str(data.get("status") or data.get("action") or event or "")
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else payload.get("metadata") or {}
    payment_id = meta.get("payment_id")
    txn_id = data.get("txn_id") or data.get("transaction_id") or data.get("id")

    payments = get_payments()
    pay = payments.get(payment_id) if payment_id else None
    if not pay and txn_id:
        for p in payments.values():
            if p.get("txn_id") == txn_id:
                pay = p
                payment_id = p["id"]
                break

    if not pay:
        audit("webhook_unknown_payment", txn_id=txn_id)
        return jsonify({"ok": True, "activated": False})

    # Always re-verify with KHPAY API — do not trust webhook body alone
    if is_paid_status(status) or "payment.paid" in event:
        if confirm_payment_server_side(payment_id):
            return jsonify({"ok": True, "activated": True})
        # If check fails but webhook says paid, still don't activate without API confirm
        audit("webhook_unconfirmed", payment_id=payment_id)
    return jsonify({"ok": True, "activated": False})


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "app": APP_NAME,
        "khpay": bool(KHPAY_API_KEY),
        "demo_upgrade": ALLOW_DEMO_UPGRADE,
    })


@app.errorhandler(404)
def nf(e):
    return render_template("404.html"), 404


@app.errorhandler(429)
def too_many(e):
    return jsonify({"error": "Too many requests"}), 429


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # Never enable debug in production
    app.run(host="0.0.0.0", port=port, debug=False)
