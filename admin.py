#!/usr/bin/env python3
"""
MM Hosting — Professional Admin Dashboard
==========================================
Zero modification to bot.py / security_scanner_free.py / requirements.txt.

Shares the SAME storage the bot uses:
  storage/data/panel_db.json
  storage/data/panel_settings.json
  storage/data/audit.log
  storage/bot_data/*.json

NEW: Bot start/stop, sandbox file editor, live log streaming.

Run:
    python admin_dashboard.py

Env:
    DASH_USER      login user (default: admin)
    DASH_PASS      login password (auto-generated if empty)
    DASH_PORT      port to bind (default: 8080)
    DASH_SECRET    Flask secret (auto-generated if empty)
"""

from __future__ import annotations

import os, sys, json, time, hashlib, secrets, threading, io, shutil
import subprocess, signal
from pathlib import Path
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional

try:
    from flask import (Flask, request, jsonify, session, redirect,
                       url_for, render_template_string, Response)
except ImportError:
    print("[!] Flask required:  pip install flask psutil")
    sys.exit(1)

try:
    import psutil
    _PSUTIL = True
except ImportError:
    psutil = None
    _PSUTIL = False
    print("[!] psutil missing — bot start/stop and system metrics will be limited.")
    print("    Install with:  pip install psutil")


# ═══════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════

BASE_DIR      = Path(__file__).resolve().parent
STORAGE       = BASE_DIR / "storage"
DATA_DIR      = STORAGE / "data"
SANDBOX_DIR   = BASE_DIR / "sandbox"
BOTDATA_DIR   = STORAGE / "bot_data"
BOTLOG_DIR    = DATA_DIR / "bot_logs"
DB_FILE       = DATA_DIR / "panel_db.json"
SETTINGS_FILE = DATA_DIR / "panel_settings.json"
AUDIT_FILE    = DATA_DIR / "audit.log"
AUTH_FILE     = DATA_DIR / "dashboard_auth.json"

BOTLOG_DIR.mkdir(parents=True, exist_ok=True)

DASH_USER   = os.environ.get("DASH_USER", "admin")
DASH_PASS   = os.environ.get("DASH_PASS", "")
DASH_PORT   = int(os.environ.get("DASH_PORT", os.environ.get("PORT", "12549")))
DASH_SECRET = os.environ.get("DASH_SECRET") or secrets.token_hex(32)

SECRET_ENV_NAMES = {
    "BOT_TOKEN", "OWNER_ID", "ERROR_BOT_TOKEN",
    "MONGO_URL", "MONGO_URL_BACKUP",
    "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH", "GITHUB_KEY_REPO",
    "OWNER_IDS", "SESSION_SECRET",
    "DATABASE_URL", "PGDATABASE", "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD",
    "REPLIT_DB_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY",
    "ANNOUNCE_CHANNEL",
}

ENTRY_ORDER = ("bot.py", "main.py", "app.py", "run.py",
               "index.js", "bot.js", "main.js", "app.js")

app = Flask(__name__)
app.secret_key = DASH_SECRET
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["JSON_SORT_KEYS"] = False


# ═══════════════════════════════════════════════════════════════════
#  STORAGE (atomic JSON — same pattern bot.py uses)
# ═══════════════════════════════════════════════════════════════════

_lock = threading.RLock()

def _read_json(p: Path, default: Any) -> Any:
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[read] {p}: {e}", file=sys.stderr)
    return default

def _atomic_write(p: Path, data: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)

_DB_KEYS = (("users", {}), ("bots", {}), ("payments", []), ("admins", {}),
            ("audit", []), ("coupons", {}), ("tickets", {}),
            ("scheduled_broadcasts", []), ("notes", {}),
            ("rate_violations", {}), ("scan_log", []))

def load_db() -> Dict[str, Any]:
    with _lock:
        d = _read_json(DB_FILE, {})
    for k, v in _DB_KEYS:
        d.setdefault(k, v)
    return d

def save_db(d: Dict[str, Any]) -> None:
    with _lock:
        _atomic_write(DB_FILE, d)

def load_settings() -> Dict[str, Any]:
    with _lock:
        return _read_json(SETTINGS_FILE, {})

def save_settings(s: Dict[str, Any]) -> None:
    with _lock:
        _atomic_write(SETTINGS_FILE, s)


# ═══════════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════════

def _hash_pw(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"

def _check_pw(pw: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return secrets.compare_digest(_hash_pw(pw, salt), stored)

def _ensure_auth() -> None:
    auth = _read_json(AUTH_FILE, {})
    if DASH_PASS:
        _atomic_write(AUTH_FILE, {"user": DASH_USER, "hash": _hash_pw(DASH_PASS)})
        return
    if not auth.get("hash"):
        pw = secrets.token_urlsafe(12)
        _atomic_write(AUTH_FILE, {"user": DASH_USER, "hash": _hash_pw(pw),
                                  "auto_generated": True})
        print("=" * 64)
        print("  [!]  DASHBOARD PASSWORD AUTO-GENERATED")
        print(f"       User : {DASH_USER}")
        print(f"       Pass : {pw}")
        print("       Set DASH_PASS env var to lock a permanent password.")
        print("=" * 64)

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("auth"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


# ═══════════════════════════════════════════════════════════════════
#  SYSTEM INFO
# ═══════════════════════════════════════════════════════════════════

def _sysinfo() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "pid": os.getpid(),
        "python": sys.version.split()[0],
        "platform": f"{os.uname().sysname} {os.uname().release}",
        "hostname": os.uname().nodename,
    }
    if _PSUTIL:
        try:
            p = psutil.Process(os.getpid())
            info["rss"]         = p.memory_info().rss
            info["cpu"]         = p.cpu_percent(interval=0.05)
            info["threads"]     = p.num_threads()
            info["cpu_count"]   = psutil.cpu_count()
            info["cpu_pct"]     = psutil.cpu_percent(interval=0.05)
            vm = psutil.virtual_memory()
            info["mem_total"]   = vm.total
            info["mem_used"]    = vm.used
            info["mem_pct"]     = vm.percent
            du = psutil.disk_usage("/")
            info["disk_total"]  = du.total
            info["disk_used"]   = du.used
            info["disk_pct"]    = du.percent
            info["boot_time"]   = psutil.boot_time()
            try:
                info["load"] = list(os.getloadavg())
            except Exception:
                info["load"] = [0.0, 0.0, 0.0]
        except Exception:
            pass
    return info


# ═══════════════════════════════════════════════════════════════════
#  BOT PROCESS MANAGEMENT
#  Finds sandbox bots by scanning process CWDs, plus tracks PIDs
#  stored in the DB by either bot.py or this dashboard.
# ═══════════════════════════════════════════════════════════════════

def _sandbox_pids() -> Dict[str, Dict[str, Any]]:
    """Returns {bot_id: {pid, cmdline, cpu, mem}} for all running bots.
    Matches by CWD under BASE_DIR/sandbox/<uid>_<bid>."""
    out: Dict[str, Dict[str, Any]] = {}
    if not _PSUTIL:
        return out
    sandbox_root = str(SANDBOX_DIR)
    for proc in psutil.process_iter(["pid", "cmdline", "cwd", "create_time"]):
        try:
            cwd = proc.info.get("cwd") or ""
            if not cwd.startswith(sandbox_root):
                continue
            cmdline = " ".join(proc.info.get("cmdline") or [])
            if not (("python" in cmdline.lower()) or ("node" in cmdline.lower())):
                continue
            name = Path(cwd).name
            if "_" not in name:
                continue
            bid = name.rsplit("_", 1)[-1]
            try:
                p = psutil.Process(proc.info["pid"])
                out[bid] = {
                    "pid":        proc.info["pid"],
                    "cmdline":    cmdline[:200],
                    "cpu":        p.cpu_percent(interval=0.0),
                    "mem":        p.memory_info().rss,
                    "started":    proc.info.get("create_time"),
                }
            except Exception:
                out[bid] = {"pid": proc.info["pid"], "cmdline": cmdline[:200]}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    return out


def _detect_entry(bot_dir: Path) -> Optional[str]:
    for name in ENTRY_ORDER:
        if (bot_dir / name).exists():
            return name
    # recursive (skip deps/node_modules)
    for name in ENTRY_ORDER:
        for p in bot_dir.rglob(name):
            if any(x in p.parts for x in (".deps", "node_modules", ".tmp_run",
                                          "__pycache__", ".git")):
                continue
            return str(p.relative_to(bot_dir))
    return None


def _build_env(bot_dir: Path, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV_NAMES}
    env["HOME"]   = str(bot_dir)
    env["TMPDIR"] = str(bot_dir / ".tmp_run")
    env["PATH"]   = "/usr/local/bin:/usr/bin:/bin"
    env.setdefault("NODE_ENV", "production")
    deps = str(bot_dir / ".deps")
    cur_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{deps}:{cur_pp}" if cur_pp else deps
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    Path(deps).mkdir(parents=True, exist_ok=True)
    if extra:
        for k, v in extra.items():
            if k in SECRET_ENV_NAMES:
                continue
            env[str(k)] = str(v)
    return env


def _log_path(bid: str) -> Path:
    return BOTLOG_DIR / f"{bid}.log"


def start_bot(bid: str) -> Dict[str, Any]:
    """Spawn bot process from its sandbox. Writes stdout+stderr to
    storage/data/bot_logs/<bid>.log so we can live-stream."""
    d = load_db()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Bot not found"}
    if b.get("approval_status") == "pending":
        return {"ok": False, "error": "Awaiting admin approval"}
    if b.get("approval_status") == "rejected":
        return {"ok": False, "error": "Bot was rejected"}
    bot_dir = Path(b.get("dir", ""))
    if not bot_dir.exists():
        return {"ok": False, "error": f"Sandbox missing: {bot_dir}"}

    running = _sandbox_pids()
    if bid in running:
        return {"ok": False, "error": f"Already running (pid {running[bid]['pid']})"}

    entry = _detect_entry(bot_dir)
    if not entry:
        return {"ok": False, "error": "No entry file (bot.py/main.py/index.js)"}

    cmd = (["node", entry] if entry.endswith(".js")
           else [sys.executable, "-u", entry])
    env = _build_env(bot_dir, b.get("env") or {})

    log_fh = open(_log_path(bid), "ab", buffering=0)
    try:
        header = f"\n\n──── {datetime.now(timezone.utc).isoformat()} ── START ────\n"
        log_fh.write(header.encode())

        kwargs = {
            "cwd":   str(bot_dir),
            "env":   env,
            "stdout": log_fh,
            "stderr": subprocess.STDOUT,
            "stdin":  subprocess.DEVNULL,
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **kwargs)
    except Exception as e:
        log_fh.close()
        return {"ok": False, "error": f"spawn failed: {e}"}

    d["bots"][bid]["status"]       = "running"
    d["bots"][bid]["pid"]          = proc.pid
    d["bots"][bid]["last_started"] = datetime.now(timezone.utc).isoformat()
    d["bots"][bid]["last_error"]   = ""
    save_db(d)
    return {"ok": True, "pid": proc.pid, "entry": entry, "cmd": " ".join(cmd)}


def stop_bot(bid: str) -> Dict[str, Any]:
    """Kill the bot's process group + all descendants."""
    d = load_db()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Bot not found"}

    killed_pids: List[int] = []
    bot_dir_str = str(Path(b.get("dir", "")).resolve())

    # 1) Kill by tracked PID (from DB, set by bot.py or dashboard)
    tracked_pid = b.get("pid")
    if tracked_pid and _PSUTIL:
        try:
            p = psutil.Process(int(tracked_pid))
            for c in p.children(recursive=True):
                try: c.kill(); killed_pids.append(c.pid)
                except Exception: pass
            p.kill(); killed_pids.append(p.pid)
        except Exception:
            pass

    # 2) Kill anything with CWD == bot_dir
    if _PSUTIL:
        for proc in psutil.process_iter(["pid", "cwd", "cmdline"]):
            try:
                cwd = proc.info.get("cwd") or ""
                if cwd != bot_dir_str:
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if not (("python" in cmdline.lower()) or ("node" in cmdline.lower())):
                    continue
                p = psutil.Process(proc.info["pid"])
                for c in p.children(recursive=True):
                    try: c.kill(); killed_pids.append(c.pid)
                    except Exception: pass
                p.kill(); killed_pids.append(p.pid)
            except Exception:
                continue
    elif os.name == "posix" and tracked_pid:
        try:
            os.killpg(os.getpgid(int(tracked_pid)), signal.SIGTERM)
        except Exception:
            pass

    d["bots"][bid]["status"] = "stopped"
    d["bots"][bid]["pid"]    = None
    save_db(d)

    log_fh = open(_log_path(bid), "ab", buffering=0)
    log_fh.write(f"\n──── STOP ({len(killed_pids)} proc) ────\n".encode())
    log_fh.close()

    return {"ok": True, "killed_pids": killed_pids}


# ═══════════════════════════════════════════════════════════════════
#  SANDBOX FILE BROWSER  (path-traversal safe)
# ═══════════════════════════════════════════════════════════════════

SKIP_DIRS = {".deps", "node_modules", "__pycache__", ".git", "venv", ".venv"}
MAX_EDIT_BYTES = 512 * 1024   # 512 KB cap for editor

def _safe_child(root: Path, rel: str) -> Optional[Path]:
    try:
        rel = (rel or "").lstrip("/")
        target = (root / rel).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            return None
        return target
    except Exception:
        return None


def list_dir(bid: str, rel: str = "") -> Dict[str, Any]:
    d = load_db()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Bot not found"}
    root = Path(b.get("dir", "")).resolve()
    if not root.exists():
        return {"ok": False, "error": "Sandbox missing"}
    target = _safe_child(root, rel)
    if target is None:
        return {"ok": False, "error": "Access denied"}
    if not target.exists():
        return {"ok": False, "error": "Not found"}
    if target.is_file():
        return {"ok": False, "error": "Not a directory"}
    entries: List[Dict[str, Any]] = []
    for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if child.name in SKIP_DIRS:
            continue
        try:
            entries.append({
                "name": child.name,
                "type": "dir" if child.is_dir() else "file",
                "size": 0 if child.is_dir() else child.stat().st_size,
                "editable": child.is_file() and child.stat().st_size <= MAX_EDIT_BYTES,
            })
        except Exception:
            continue
    return {"ok": True, "path": rel, "entries": entries}


def read_file(bid: str, rel: str) -> Dict[str, Any]:
    d = load_db()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Bot not found"}
    root = Path(b.get("dir", "")).resolve()
    target = _safe_child(root, rel)
    if target is None or not target.is_file():
        return {"ok": False, "error": "File not found"}
    size = target.stat().st_size
    if size > MAX_EDIT_BYTES:
        return {"ok": False, "error": f"File too big ({size} bytes > {MAX_EDIT_BYTES})"}
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        return {"ok": True, "path": rel, "content": content, "size": size}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def write_file(bid: str, rel: str, content: str) -> Dict[str, Any]:
    d = load_db()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Bot not found"}
    root = Path(b.get("dir", "")).resolve()
    target = _safe_child(root, rel)
    if target is None:
        return {"ok": False, "error": "Access denied"}
    if len(content.encode("utf-8")) > MAX_EDIT_BYTES:
        return {"ok": False, "error": "Content too large"}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # atomic write
        tmp = target.with_suffix(target.suffix + ".dash.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(target)
        return {"ok": True, "path": rel, "size": len(content)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def delete_path(bid: str, rel: str) -> Dict[str, Any]:
    d = load_db()
    b = d["bots"].get(bid)
    if not b:
        return {"ok": False, "error": "Bot not found"}
    root = Path(b.get("dir", "")).resolve()
    target = _safe_child(root, rel)
    if target is None or not target.exists():
        return {"ok": False, "error": "Not found"}
    if target == root:
        return {"ok": False, "error": "Cannot delete sandbox root"}
    try:
        if target.is_file():
            target.unlink()
        else:
            shutil.rmtree(target, ignore_errors=True)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════
#  AGGREGATED STATS
# ═══════════════════════════════════════════════════════════════════

def _build_stats() -> Dict[str, Any]:
    d = load_db()
    users    = d["users"]
    bots     = d["bots"]
    payments = d["payments"]

    total_users  = len(users)
    total_bots   = len(bots)
    live         = _sandbox_pids()
    running_bots = len(live)

    banned     = sum(1 for u in users.values() if u.get("banned"))
    verified   = sum(1 for u in users.values() if u.get("verified"))
    paid_users = sum(1 for u in users.values() if (u.get("plan") or "free") != "free")

    pending_pay  = sum(1 for p in payments if p.get("status") == "pending")
    approved_pay = [p for p in payments if p.get("status") == "approved"]
    revenue      = sum(int(p.get("amount") or 0) for p in approved_pay)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_signups = sum(1 for u in users.values()
                        if str(u.get("joined", "")).startswith(today))

    plan_dist: Dict[str, int] = {}
    for u in users.values():
        pl = (u.get("plan") or "free")
        plan_dist[pl] = plan_dist.get(pl, 0) + 1

    now = datetime.now(timezone.utc)
    signup_series: List[Dict[str, Any]] = []
    for i in range(13, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        cnt = sum(1 for u in users.values()
                  if str(u.get("joined", "")).startswith(day))
        signup_series.append({"day": day, "count": cnt})

    rev_series: List[Dict[str, Any]] = []
    for i in range(13, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        amt = sum(int(p.get("amount") or 0) for p in approved_pay
                  if str(p.get("ts", "")).startswith(day))
        rev_series.append({"day": day, "amount": amt})

    return {
        "total_users":     total_users,
        "total_bots":      total_bots,
        "running_bots":    running_bots,
        "banned":          banned,
        "verified":        verified,
        "paid_users":      paid_users,
        "pending_pay":     pending_pay,
        "approved_pay":    len(approved_pay),
        "revenue":         revenue,
        "today_signups":   today_signups,
        "plan_dist":       plan_dist,
        "signup_series":   signup_series,
        "revenue_series":  rev_series,
        "system":          _sysinfo(),
        "running_pids":    {k: v["pid"] for k, v in live.items()},
    }


def _recent_activity(limit: int = 20) -> List[Dict[str, Any]]:
    d = load_db()
    items: List[Dict[str, Any]] = []
    for a in d["audit"][-60:]:
        items.append({"kind": "audit", "ts": a.get("ts"), "uid": a.get("uid"),
                      "text": f"{a.get('action')} {a.get('detail','')}".strip()})
    for p in d["payments"][-30:]:
        items.append({"kind": "payment", "ts": p.get("ts"), "uid": p.get("uid"),
                      "text": f"Payment #{p.get('id','?')} · {p.get('plan') or 'topup'} · {p.get('amount')}৳ · {p.get('status')}"})
    for b in list(d["bots"].values())[-20:]:
        items.append({"kind": "bot", "ts": b.get("created"), "uid": b.get("owner"),
                      "text": f"Bot '{b.get('name')}' uploaded"})
    items = [x for x in items if x.get("ts")]
    items.sort(key=lambda x: x["ts"], reverse=True)
    return items[:limit]


# ═══════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        u = (data.get("user") or "").strip()
        p = data.get("pass") or ""
        auth = _read_json(AUTH_FILE, {})
        if u == auth.get("user") and _check_pw(p, auth.get("hash", "")):
            session["auth"] = True
            session.permanent = True
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    return (HTML_LOGIN
            .replace("__CSS__", CSS)
            .replace("__LOGIN_JS__", LOGIN_JS))

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# ── STATS ────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify({"ok": True, "data": _build_stats()})

@app.route("/api/activity")
@login_required
def api_activity():
    return jsonify({"ok": True, "data": _recent_activity(30)})

@app.route("/api/system")
@login_required
def api_system():
    return jsonify({"ok": True, "data": _sysinfo()})


# ── USERS ────────────────────────────────────────────────────────
@app.route("/api/users")
@login_required
def api_users():
    q     = (request.args.get("q") or "").strip().lower()
    limit = int(request.args.get("limit", 200))
    d = load_db()
    bot_counts: Dict[str, int] = {}
    for b in d["bots"].values():
        bot_counts[str(b.get("owner"))] = bot_counts.get(str(b.get("owner")), 0) + 1
    rows: List[Dict[str, Any]] = []
    for uid, u in d["users"].items():
        if q and q not in uid.lower() and q not in str(u.get("name","")).lower() \
           and q not in str(u.get("username","")).lower():
            continue
        rows.append({
            "uid": uid, "name": u.get("name", ""),
            "username": u.get("username", ""),
            "plan": u.get("plan", "free"),
            "plan_expires": u.get("plan_expires"),
            "joined": u.get("joined"), "last_seen": u.get("last_seen"),
            "banned": bool(u.get("banned")), "ban_reason": u.get("ban_reason", ""),
            "wallet": u.get("wallet", 0), "verified": bool(u.get("verified")),
            "bot_count": bot_counts.get(uid, 0), "ref_count": u.get("ref_count", 0),
        })
    rows.sort(key=lambda r: r.get("joined") or "", reverse=True)
    return jsonify({"ok": True, "data": rows[:limit], "total": len(rows)})

@app.route("/api/users/<uid>/ban", methods=["POST"])
@login_required
def api_user_ban(uid: str):
    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "banned from dashboard").strip()
    d = load_db()
    if uid not in d["users"]:
        return jsonify({"ok": False, "error": "User not found"}), 404
    d["users"][uid]["banned"] = True
    d["users"][uid]["ban_reason"] = reason
    save_db(d)
    return jsonify({"ok": True})

@app.route("/api/users/<uid>/unban", methods=["POST"])
@login_required
def api_user_unban(uid: str):
    d = load_db()
    if uid not in d["users"]:
        return jsonify({"ok": False, "error": "User not found"}), 404
    d["users"][uid]["banned"] = False
    d["users"][uid]["ban_reason"] = ""
    save_db(d)
    return jsonify({"ok": True})

@app.route("/api/users/<uid>/plan", methods=["POST"])
@login_required
def api_user_grant_plan(uid: str):
    body = request.get_json(silent=True) or {}
    plan = (body.get("plan") or "").strip()
    days = int(body.get("days") or 0)
    if not plan:
        return jsonify({"ok": False, "error": "plan required"}), 400
    d = load_db()
    if uid not in d["users"]:
        return jsonify({"ok": False, "error": "User not found"}), 404
    u = d["users"][uid]
    u["plan"] = plan
    if plan == "free" or days <= 0:
        u["plan_expires"] = None
    else:
        u["plan_expires"] = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    save_db(d)
    return jsonify({"ok": True})


# ── BOTS ─────────────────────────────────────────────────────────
@app.route("/api/bots")
@login_required
def api_bots():
    d = load_db()
    live = _sandbox_pids()
    rows: List[Dict[str, Any]] = []
    for bid, b in d["bots"].items():
        info = live.get(bid, {})
        rows.append({
            "bid": bid, "name": b.get("name", ""),
            "owner": b.get("owner"), "status": b.get("status", "stopped"),
            "approval": b.get("approval_status", ""),
            "created": b.get("created"), "last_started": b.get("last_started"),
            "last_error": (b.get("last_error") or "")[:300],
            "last_exit_code": b.get("last_exit_code"),
            "running": bid in live,
            "pid": info.get("pid"),
            "cpu": info.get("cpu"),
            "mem": info.get("mem"),
            "dir": b.get("dir"),
        })
    rows.sort(key=lambda r: r.get("created") or "", reverse=True)
    return jsonify({"ok": True, "data": rows})

@app.route("/api/bots/<bid>/start", methods=["POST"])
@login_required
def api_bot_start(bid: str):
    return jsonify(start_bot(bid))

@app.route("/api/bots/<bid>/stop", methods=["POST"])
@login_required
def api_bot_stop(bid: str):
    return jsonify(stop_bot(bid))

@app.route("/api/bots/<bid>/restart", methods=["POST"])
@login_required
def api_bot_restart(bid: str):
    stop_bot(bid)
    time.sleep(1)
    return jsonify(start_bot(bid))


# ── BOT FILES ────────────────────────────────────────────────────
@app.route("/api/bots/<bid>/files")
@login_required
def api_bot_files(bid: str):
    rel = request.args.get("path", "")
    return jsonify(list_dir(bid, rel))

@app.route("/api/bots/<bid>/file", methods=["GET", "POST", "DELETE"])
@login_required
def api_bot_file(bid: str):
    if request.method == "GET":
        rel = request.args.get("path", "")
        return jsonify(read_file(bid, rel))
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        rel = body.get("path", "")
        content = body.get("content", "")
        return jsonify(write_file(bid, rel, content))
    if request.method == "DELETE":
        rel = request.args.get("path", "")
        return jsonify(delete_path(bid, rel))


# ── BOT LOG STREAM (SSE) ─────────────────────────────────────────
@app.route("/api/bots/<bid>/logs/stream")
@login_required
def api_bot_logs_stream(bid: str):
    log_file = _log_path(bid)

    def generate():
        # Emit a snapshot of the tail first
        try:
            if log_file.exists():
                with open(log_file, "r", errors="replace") as f:
                    lines = f.readlines()
                    tail = lines[-300:]
                    for ln in tail:
                        yield f"data: {json.dumps(ln.rstrip())}\n\n"
                    last_pos = f.tell()
            else:
                yield f"data: {json.dumps('[no logs yet]')}\n\n"
                last_pos = 0
        except Exception as e:
            yield f"data: {json.dumps(f'[log error: {e}]')}\n\n"
            last_pos = 0

        # Then keep polling for new bytes
        try:
            while True:
                time.sleep(1.0)
                if not log_file.exists():
                    continue
                try:
                    size = log_file.stat().st_size
                except Exception:
                    continue
                if size < last_pos:
                    last_pos = 0
                if size > last_pos:
                    with open(log_file, "r", errors="replace") as f:
                        f.seek(last_pos)
                        for ln in f:
                            yield f"data: {json.dumps(ln.rstrip())}\n\n"
                        last_pos = f.tell()
        except GeneratorExit:
            return

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

@app.route("/api/bots/<bid>/logs/clear", methods=["POST"])
@login_required
def api_bot_logs_clear(bid: str):
    p = _log_path(bid)
    try:
        if p.exists():
            p.unlink()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── PAYMENTS ─────────────────────────────────────────────────────
@app.route("/api/payments")
@login_required
def api_payments():
    d = load_db()
    status = request.args.get("status")
    rows = list(d["payments"])
    if status:
        rows = [p for p in rows if p.get("status") == status]
    rows.sort(key=lambda p: p.get("ts") or "", reverse=True)
    return jsonify({"ok": True, "data": rows[:300]})

@app.route("/api/payments/<pid>/approve", methods=["POST"])
@login_required
def api_payment_approve(pid: str):
    d = load_db()
    pay = next((x for x in d["payments"] if x.get("id") == pid), None)
    if not pay:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if pay.get("status") != "pending":
        return jsonify({"ok": False, "error": f"Already {pay.get('status')}"}), 400
    pay["status"] = "approved"
    pay["approved_at"] = datetime.now(timezone.utc).isoformat()
    pay["approved_by"] = "dashboard"
    if pay.get("kind") == "wallet_topup":
        u = d["users"].get(str(pay.get("uid")))
        if u:
            u["wallet"] = int(u.get("wallet") or 0) + int(pay.get("amount") or 0)
    elif pay.get("plan"):
        u = d["users"].get(str(pay.get("uid")))
        if u:
            u["plan"] = pay["plan"]
            u["plan_expires"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    save_db(d)
    return jsonify({"ok": True})

@app.route("/api/payments/<pid>/reject", methods=["POST"])
@login_required
def api_payment_reject(pid: str):
    d = load_db()
    pay = next((x for x in d["payments"] if x.get("id") == pid), None)
    if not pay:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if pay.get("status") != "pending":
        return jsonify({"ok": False, "error": f"Already {pay.get('status')}"}), 400
    pay["status"] = "rejected"
    pay["rejected_at"] = datetime.now(timezone.utc).isoformat()
    pay["rejected_by"] = "dashboard"
    save_db(d)
    return jsonify({"ok": True})


# ── COUPONS ──────────────────────────────────────────────────────
@app.route("/api/coupons", methods=["GET", "POST"])
@login_required
def api_coupons():
    d = load_db()
    if request.method == "GET":
        return jsonify({"ok": True, "data": list(d["coupons"].items())})
    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip().upper()
    if not code:
        return jsonify({"ok": False, "error": "code required"}), 400
    d["coupons"][code] = {
        "percent": int(body.get("percent") or 0),
        "uses_left": int(body.get("uses_left") or 1),
        "created": datetime.now(timezone.utc).isoformat(),
    }
    save_db(d)
    return jsonify({"ok": True})

@app.route("/api/coupons/<code>", methods=["DELETE"])
@login_required
def api_coupon_delete(code: str):
    d = load_db()
    d["coupons"].pop(code.upper(), None)
    save_db(d)
    return jsonify({"ok": True})


# ── TICKETS / SCAN LOG / AUDIT / SETTINGS ────────────────────────
@app.route("/api/tickets")
@login_required
def api_tickets():
    d = load_db()
    rows = sorted(d["tickets"].values(),
                  key=lambda t: t.get("opened_at") or "", reverse=True)
    return jsonify({"ok": True, "data": rows})

@app.route("/api/scan-log")
@login_required
def api_scan_log():
    d = load_db()
    return jsonify({"ok": True, "data": list(reversed(d["scan_log"][-200:]))})

@app.route("/api/audit")
@login_required
def api_audit():
    d = load_db()
    return jsonify({"ok": True, "data": list(reversed(d["audit"][-300:]))})

@app.route("/api/audit/file")
@login_required
def api_audit_file():
    if not AUDIT_FILE.exists():
        return jsonify({"ok": True, "data": ""})
    try:
        text = AUDIT_FILE.read_text(encoding="utf-8", errors="replace")
        return jsonify({"ok": True, "data": text[-20000:]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "GET":
        return jsonify({"ok": True, "data": load_settings()})
    body = request.get_json(silent=True) or {}
    s = load_settings()
    for k, v in body.items():
        s[k] = v
    save_settings(s)
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════
#  HTML / CSS / JS
# ═══════════════════════════════════════════════════════════════════

CSS = r"""
:root{
  --bg:#070a0f; --bg-2:#0b0f16; --panel:#10151f; --panel-2:#161c28;
  --border:#1c2333; --border-2:#2b3548; --text:#c9d1d9; --text-dim:#8b949e;
  --text-mute:#5c6570; --accent:#00e5a0; --accent-2:#00b87c;
  --purple:#a855f7; --blue:#58a6ff; --yellow:#f0b429; --red:#ff5470;
  --shadow:0 8px 32px rgba(0,0,0,.45); --glow:0 0 24px rgba(0,229,160,.15);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh}
code,pre,.mono{font-family:'JetBrains Mono','Fira Code',Menlo,monospace}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.app{display:flex;min-height:100vh}
.sidebar{width:250px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.brand{padding:22px 20px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:11px}
.brand-mark{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--purple));display:grid;place-items:center;font-weight:800;color:#061014;font-size:16px;box-shadow:var(--glow)}
.brand-title{font-weight:700;font-size:13.5px}
.brand-sub{font-size:10.5px;color:var(--text-mute);font-family:'JetBrains Mono',monospace}
.nav{padding:14px 10px}
.nav-group-title{font-size:10px;color:var(--text-mute);text-transform:uppercase;letter-spacing:1.2px;padding:14px 10px 6px;font-weight:600}
.nav-item{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:8px;cursor:pointer;color:var(--text-dim);font-weight:500;font-size:13px;transition:all .15s ease;user-select:none;border:1px solid transparent}
.nav-item:hover{background:var(--panel-2);color:var(--text)}
.nav-item.active{background:linear-gradient(90deg,rgba(0,229,160,.08),transparent);color:var(--accent);border-color:rgba(0,229,160,.15)}
.nav-icon{width:17px;height:17px;flex-shrink:0;opacity:.85}
.nav-item.active .nav-icon{opacity:1}
.sidebar-footer{margin-top:auto;padding:14px 16px;border-top:1px solid var(--border);font-size:11px;color:var(--text-mute);font-family:'JetBrains Mono',monospace}
.pulse-dot{width:7px;height:7px;border-radius:50%;background:var(--accent);display:inline-block;margin-right:7px;animation:pulse 1.8s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(0,229,160,.6)}70%{box-shadow:0 0 0 8px rgba(0,229,160,0)}100%{box-shadow:0 0 0 0 rgba(0,229,160,0)}}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{height:60px;background:rgba(11,15,22,.85);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 22px;gap:14px;position:sticky;top:0;z-index:50}
.topbar h1{font-size:15.5px;font-weight:600}
.topbar .crumbs{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--text-mute)}
.topbar .crumbs::before{content:"› "}
.spacer{flex:1}
.badge-status{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-family:'JetBrains Mono',monospace;background:rgba(0,229,160,.08);color:var(--accent);border:1px solid rgba(0,229,160,.2);padding:4px 9px;border-radius:20px}
.content{padding:24px;flex:1}
.grid{display:grid;gap:16px}
.grid-4{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.grid-2{grid-template-columns:repeat(auto-fit,minmax(360px,1fr))}
.grid-3{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;position:relative;overflow:hidden;animation:fadeUp .4s cubic-bezier(.2,.9,.3,1) both}
.card:hover{border-color:var(--border-2)}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.card .label{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--text-mute);font-family:'JetBrains Mono',monospace;font-weight:500;display:flex;align-items:center;gap:7px;margin-bottom:12px}
.card .value{font-size:30px;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:-.5px;line-height:1}
.card .sub{font-size:11.5px;color:var(--text-mute);margin-top:8px;font-family:'JetBrains Mono',monospace}
.card.accent{border-color:rgba(0,229,160,.25)}
.card.accent::after{content:'';position:absolute;inset:0;background:radial-gradient(600px 80px at 80% -10%,rgba(0,229,160,.13),transparent 70%);pointer-events:none}
.value.green{color:var(--accent)}.value.blue{color:var(--blue)}.value.yellow{color:var(--yellow)}.value.red{color:var(--red)}.value.purple{color:var(--purple)}
.table-wrap{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{text-align:left;padding:12px 16px;font-size:10.5px;text-transform:uppercase;letter-spacing:1px;color:var(--text-mute);font-family:'JetBrains Mono',monospace;font-weight:600;border-bottom:1px solid var(--border);background:var(--bg-2)}
tbody td{padding:12px 16px;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--bg-2)}
.pill{display:inline-block;font-size:10.5px;padding:3px 9px;border-radius:20px;font-family:'JetBrains Mono',monospace;font-weight:600;letter-spacing:.3px;border:1px solid}
.pill.green{color:var(--accent);border-color:rgba(0,229,160,.3);background:rgba(0,229,160,.08)}
.pill.red{color:var(--red);border-color:rgba(255,84,112,.3);background:rgba(255,84,112,.08)}
.pill.yellow{color:var(--yellow);border-color:rgba(240,180,41,.3);background:rgba(240,180,41,.08)}
.pill.blue{color:var(--blue);border-color:rgba(88,166,255,.3);background:rgba(88,166,255,.08)}
.pill.gray{color:var(--text-dim);border-color:var(--border-2);background:var(--bg-2)}
.pill.purple{color:var(--purple);border-color:rgba(168,85,247,.3);background:rgba(168,85,247,.08)}
.btn{background:var(--panel-2);border:1px solid var(--border-2);color:var(--text);font-family:inherit;font-size:12.5px;font-weight:500;padding:7px 13px;border-radius:7px;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:6px;user-select:none}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.primary{background:var(--accent);color:#06211a;border-color:var(--accent);font-weight:600}
.btn.primary:hover{background:var(--accent-2)}
.btn.danger{color:var(--red);border-color:rgba(255,84,112,.35)}
.btn.danger:hover{background:rgba(255,84,112,.08)}
.btn.ghost{background:transparent}
.btn.sm{padding:5px 10px;font-size:11.5px}
.btn:disabled{opacity:.4;cursor:not-allowed}
.form-row{margin-bottom:14px}
.form-row label{display:block;font-size:11px;color:var(--text-mute);text-transform:uppercase;letter-spacing:.8px;font-family:'JetBrains Mono',monospace;margin-bottom:6px}
input[type=text],input[type=password],input[type=number],textarea,select{width:100%;background:var(--bg-2);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:10px 12px;font-size:13px;font-family:'JetBrains Mono',monospace;outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--accent)}
.login-shell{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(900px 500px at 50% -10%,rgba(0,229,160,.1),transparent 60%),radial-gradient(700px 500px at 100% 100%,rgba(168,85,247,.08),transparent 60%),var(--bg)}
.login-card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:32px;box-shadow:var(--shadow);animation:fadeUp .5s cubic-bezier(.2,.9,.3,1)}
.terminal{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent);margin-bottom:20px;overflow:hidden;white-space:nowrap}
.terminal-cursor{display:inline-block;width:7px;height:14px;background:var(--accent);vertical-align:middle;animation:blink 1s steps(2) infinite;margin-left:2px}
@keyframes blink{50%{opacity:0}}
.toasts{position:fixed;right:22px;bottom:22px;display:flex;flex-direction:column;gap:10px;z-index:999}
.toast{background:var(--panel);border:1px solid var(--border-2);border-left:3px solid var(--accent);border-radius:8px;padding:12px 16px;min-width:240px;box-shadow:var(--shadow);font-size:12.5px;animation:slideIn .25s ease}
.toast.err{border-left-color:var(--red)}
@keyframes slideIn{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:translateX(0)}}
.hidden{display:none !important}
.row-between{display:flex;justify-content:space-between;align-items:center;gap:12px}
.mb-16{margin-bottom:16px}.mb-24{margin-bottom:24px}.mt-16{margin-top:16px}
.chart-card canvas{max-height:260px}
.kv{display:grid;grid-template-columns:1fr auto;gap:8px;font-size:12.5px;padding:8px 0;border-bottom:1px dashed var(--border)}
.kv:last-child{border-bottom:none}
.kv .k{color:var(--text-mute);font-family:'JetBrains Mono',monospace}
.kv .v{font-family:'JetBrains Mono',monospace;color:var(--text);text-align:right;max-width:65%;overflow-wrap:anywhere;word-break:break-word;line-height:1.4}
pre.logbox{background:#050810;border:1px solid var(--border);border-radius:8px;padding:14px;max-height:520px;overflow:auto;font-size:12px;line-height:1.55;color:#c9d1d9;font-family:'JetBrains Mono',monospace}
pre.logbox .ln{white-space:pre-wrap;word-break:break-all}
pre.logbox .ln.err{color:#ff8899}
pre.logbox .ln.warn{color:#f0b429}
pre.logbox .ln.info{color:#58a6ff}
.code-editor{background:#050810;border:1px solid var(--border);border-radius:8px;color:#c9d1d9;font-family:'JetBrains Mono',monospace;font-size:12.5px;line-height:1.65;padding:14px;min-height:420px;width:100%;resize:vertical;outline:none;tab-size:4}
.code-editor:focus{border-color:var(--accent)}
.file-list{background:var(--panel-2);border:1px solid var(--border);border-radius:8px;max-height:520px;overflow:auto}
.file-item{display:flex;align-items:center;gap:10px;padding:8px 12px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:12.5px;border-bottom:1px solid var(--border);transition:background .1s}
.file-item:hover{background:var(--panel)}
.file-item.active{background:rgba(0,229,160,.08);color:var(--accent)}
.file-item .sz{margin-left:auto;color:var(--text-mute);font-size:11px}
.breadcrumb{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-mute);margin-bottom:12px}
.breadcrumb span{cursor:pointer}
.breadcrumb span:hover{color:var(--accent)}
.spinner{width:14px;height:14px;border:2px solid var(--border-2);border-top-color:var(--accent);border-radius:50%;display:inline-block;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
"""

LOGIN_JS = r"""
const $=s=>document.querySelector(s);
$('#login-form').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const user=$('#u').value.trim(), pass=$('#p').value;
  const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user,pass})});
  const j=await r.json().catch(()=>({}));
  if(j.ok) location.href='/';
  else $('#login-err').textContent=j.error||'Login failed';
});
const term=document.querySelector('.terminal-text');
const words=['> authenticating...','> verifying credentials...','> awaiting input_'];
let wi=0,ci=0,dir=1;
function tick(){
  const w=words[wi];
  term.textContent=w.slice(0,ci);
  if(dir===1){ci++;if(ci>w.length){dir=-1;setTimeout(tick,1200);return;}}
  else{ci--;if(ci<0){dir=1;wi=(wi+1)%words.length;ci=0;}}
  setTimeout(tick,dir===1?55:25);
}
tick();
"""

APP_JS = r"""
const $  = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const api = async (path, opts={}) => {
  const r = await fetch(path, {
    headers:{'Content-Type':'application/json'},
    credentials:'same-origin',
    ...opts,
  });
  if (r.status === 401) { location.href='/login'; return {ok:false}; }
  return r.json();
};
const toast = (msg, err=false) => {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), 3500);
};
const fmtNum   = n => (n ?? 0).toLocaleString();
const fmtBytes = n => {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB']; let i=0; n=+n;
  while (n >= 1024 && i < u.length-1){ n/=1024; i++; }
  return n.toFixed(1)+' '+u[i];
};
const fmtDate = s => { if (!s) return '—'; try { return new Date(s).toLocaleString(); } catch { return s; } };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function rollup(el, target, dur=800) {
  const start = +el.dataset.v || 0;
  const end = +target || 0;
  const t0 = performance.now();
  function step(t) {
    const p = Math.min(1, (t - t0) / dur);
    const e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (end - start) * e).toLocaleString();
    if (p < 1) requestAnimationFrame(step); else el.dataset.v = end;
  }
  requestAnimationFrame(step);
}

// ─── ROUTER ───
const views = {
  dashboard:  renderDashboard,
  users:      renderUsers,
  bots:       renderBots,
  botview:    renderBotView,
  payments:   renderPayments,
  coupons:    renderCoupons,
  tickets:    renderTickets,
  scanlog:    renderScanLog,
  audit:      renderAudit,
  settings:   renderSettings,
  system:     renderSystem,
};
let currentCharts = [];
function cleanup(){ currentCharts.forEach(c=>{try{c.destroy()}catch{}}); currentCharts=[]; }
let _logStream = null;
function stopLogStream(){
  if(_logStream){ try{_logStream.close()}catch{} _logStream=null; }
}
function setActive(name){
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === name));
  $('#view-title').textContent = name === 'botview' ? 'Bot' :
    name.charAt(0).toUpperCase() + name.slice(1);
  $('#crumb').textContent = name;
}
async function route(){
  stopLogStream();
  const hash = (location.hash || '#dashboard').slice(1);
  const [head, arg] = hash.split('/', 2);
  const fn = views[head] || views.dashboard;
  setActive(head);
  cleanup();
  $('#view').innerHTML = '<div style="opacity:.5;padding:40px;text-align:center">Loading…</div>';
  try { await fn(arg); } catch (e) {
    console.error(e);
    $('#view').innerHTML = '<div class="card">Error: '+esc(e.message)+'</div>';
  }
}
window.addEventListener('hashchange', route);

// ═══ DASHBOARD ═══
async function renderDashboard(){
  const [{data:s}, {data:act}] = await Promise.all([api('/api/stats'), api('/api/activity')]);
  const tiles = [
    {label:'Total Users',  value:s.total_users, cls:'green',  icon:'👥', sub:`+${s.today_signups} today`},
    {label:'Total Bots',   value:s.total_bots,  cls:'blue',   icon:'🤖', sub:`${s.running_bots} running`},
    {label:'Paid Users',   value:s.paid_users,  cls:'purple', icon:'💎', sub:`${s.verified} verified`},
    {label:'Revenue',      value:s.revenue,     cls:'yellow', icon:'💰', sub:`${s.approved_pay} approved`},
    {label:'Pending Pays', value:s.pending_pay, cls:'red',    icon:'⏳', sub:'awaiting review'},
    {label:'Banned',       value:s.banned,      cls:'red',    icon:'🚫', sub:'blocked users'},
    {label:'RAM Used',     value:(s.system.mem_used||0),  cls:'blue',   icon:'🧠', sub:`${(s.system.mem_pct||0).toFixed(1)}% of total`, isBytes:true},
    {label:'Disk Used',    value:(s.system.disk_used||0), cls:'yellow', icon:'💾', sub:`${(s.system.disk_pct||0).toFixed(1)}% of total`, isBytes:true},
  ];
  const actHtml = act.length ? act.map(a => `
    <div class="kv">
      <span class="k">${esc((a.ts||'').slice(11,19))} · ${esc(a.kind)} · uid ${esc(a.uid)}</span>
      <span class="v">${esc(a.text)}</span>
    </div>`).join('') : '<div style="color:var(--text-mute);padding:20px 0;text-align:center">No activity yet</div>';

  $('#view').innerHTML = `
    <div class="grid grid-4 mb-24">
      ${tiles.map(t => `
        <div class="card ${t.cls==='green'?'accent':''}">
          <div class="label"><span>${t.icon}</span>${esc(t.label)}</div>
          <div class="value ${t.cls}" data-num="${t.value}" ${t.isBytes?'data-bytes="1"':''}>0</div>
          <div class="sub">${esc(t.sub)}</div>
        </div>`).join('')}
    </div>
    <div class="grid grid-2 mb-24">
      <div class="card chart-card">
        <div class="row-between mb-16">
          <div class="label" style="margin:0">📈 Signups (14 days)</div>
          <span class="pill green">${s.total_users} total</span>
        </div>
        <canvas id="chart-signups"></canvas>
      </div>
      <div class="card chart-card">
        <div class="row-between mb-16">
          <div class="label" style="margin:0">💵 Revenue (14 days)</div>
          <span class="pill yellow">${fmtNum(s.revenue)}৳ total</span>
        </div>
        <canvas id="chart-revenue"></canvas>
      </div>
    </div>
    <div class="grid grid-2 mb-24">
      <div class="card chart-card">
        <div class="label">💎 Plan Distribution</div>
        <canvas id="chart-plans"></canvas>
      </div>
      <div class="card">
        <div class="label">⚡ Live Activity Feed</div>
        <div style="max-height:260px;overflow:auto">${actHtml}</div>
      </div>
    </div>
    <div class="card chart-card">
      <div class="label">🖥️ System Health</div>
      <div class="grid grid-4">
        ${[
          {l:'CPU',     v:(s.system.cpu_pct||0).toFixed(1)+'%', s:`${s.system.cpu_count||'?'} cores`},
          {l:'RAM',     v:(s.system.mem_pct||0).toFixed(1)+'%', s:`${fmtBytes(s.system.mem_used)} / ${fmtBytes(s.system.mem_total)}`},
          {l:'Disk',    v:(s.system.disk_pct||0).toFixed(1)+'%',s:`${fmtBytes(s.system.disk_used)} / ${fmtBytes(s.system.disk_total)}`},
          {l:'Threads', v:s.system.threads||0, s:`pid ${s.system.pid}`},
        ].map(x => `
          <div style="padding:10px 0">
            <div style="font-size:11px;color:var(--text-mute);text-transform:uppercase;letter-spacing:1px;font-family:'JetBrains Mono',monospace">${x.l}</div>
            <div style="font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;margin:6px 0">${esc(x.v)}</div>
            <div style="font-size:11px;color:var(--text-mute);font-family:'JetBrains Mono',monospace">${esc(x.s)}</div>
          </div>`).join('')}
      </div>
    </div>`;

  $$('.value[data-num]').forEach(el => {
    if (el.dataset.bytes){
      const end = +el.dataset.num, t0 = performance.now();
      function step(t){
        const p = Math.min(1, (t-t0)/800);
        el.textContent = fmtBytes(end*(1-Math.pow(1-p,3)));
        if (p<1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    } else rollup(el, el.dataset.num);
  });

  Chart.defaults.color = '#8b949e';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;
  Chart.defaults.borderColor = '#1c2333';

  currentCharts.push(new Chart($('#chart-signups'), {
    type:'line',
    data:{ labels:s.signup_series.map(x=>x.day.slice(5)),
      datasets:[{data:s.signup_series.map(x=>x.count), borderColor:'#00e5a0',
        backgroundColor:(ctx)=>{const g=ctx.chart.ctx.createLinearGradient(0,0,0,240);g.addColorStop(0,'rgba(0,229,160,.35)');g.addColorStop(1,'rgba(0,229,160,0)');return g;},
        fill:true, tension:.35, borderWidth:2, pointRadius:0, pointHoverRadius:5}]},
    options:{responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{x:{grid:{display:false}}, y:{beginAtZero:true, ticks:{precision:0}}},
      animation:{duration:900, easing:'easeOutCubic'}}
  }));
  currentCharts.push(new Chart($('#chart-revenue'), {
    type:'line',
    data:{ labels:s.revenue_series.map(x=>x.day.slice(5)),
      datasets:[{data:s.revenue_series.map(x=>x.amount), borderColor:'#f0b429',
        backgroundColor:(ctx)=>{const g=ctx.chart.ctx.createLinearGradient(0,0,0,240);g.addColorStop(0,'rgba(240,180,41,.35)');g.addColorStop(1,'rgba(240,180,41,0)');return g;},
        fill:true, tension:.35, borderWidth:2, pointRadius:0, pointHoverRadius:5}]},
    options:{responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{x:{grid:{display:false}}, y:{beginAtZero:true}},
      animation:{duration:900, easing:'easeOutCubic'}}
  }));
  const planKeys = Object.keys(s.plan_dist);
  const planColors = {free:'#5c6570', starter:'#58a6ff', basic:'#a855f7', pro:'#00e5a0', enterprise:'#f0b429', lifetime:'#ff5470'};
  currentCharts.push(new Chart($('#chart-plans'), {
    type:'doughnut',
    data:{ labels:planKeys, datasets:[{data:planKeys.map(k=>s.plan_dist[k]),
      backgroundColor:planKeys.map(k=>planColors[k]||'#444'), borderWidth:0, spacing:3}]},
    options:{responsive:true, maintainAspectRatio:false, cutout:'68%',
      plugins:{legend:{position:'right', labels:{padding:14, boxWidth:10}}},
      animation:{animateRotate:true, duration:900}}
  }));
}

// ═══ USERS ═══
async function renderUsers(){
  const {data:users} = await api('/api/users?limit=300');
  $('#view').innerHTML = `
    <div class="card mb-16">
      <div class="row-between">
        <input id="u-search" type="text" placeholder="Search by ID, name or @username..." style="max-width:360px">
        <span class="pill gray">${users.length} users</span>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>User</th><th>Plan</th><th>Bots</th><th>Wallet</th>
          <th>Joined</th><th>Status</th><th style="text-align:right">Actions</th>
        </tr></thead>
        <tbody id="u-body">
          ${users.map(u => `
            <tr data-uid="${esc(u.uid)}">
              <td>
                <div style="font-weight:600">${esc(u.name || '—')}</div>
                <div style="font-size:11px;color:var(--text-mute)" class="mono">
                  <code>${esc(u.uid)}</code> · @${esc(u.username||'—')}
                </div>
              </td>
              <td><span class="pill ${u.plan==='free'?'gray':'green'}">${esc(u.plan)}</span></td>
              <td class="mono">${u.bot_count}</td>
              <td class="mono">${fmtNum(u.wallet)}৳</td>
              <td class="mono" style="font-size:11px;color:var(--text-mute)">${fmtDate(u.joined)}</td>
              <td>${u.banned ? '<span class="pill red">banned</span>' :
                (u.verified ? '<span class="pill green">verified</span>' : '<span class="pill gray">new</span>')}</td>
              <td style="text-align:right;white-space:nowrap">
                <button class="btn sm" data-plan="${esc(u.uid)}">Plan</button>
                ${u.banned ? `<button class="btn sm" data-unban="${esc(u.uid)}">Unban</button>`
                          : `<button class="btn sm danger" data-ban="${esc(u.uid)}">Ban</button>`}
              </td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;

  $('#u-search').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    $$('#u-body tr').forEach(tr => {
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
  document.body.addEventListener('click', async (e) => {
    const t = e.target;
    if (t.dataset?.ban)   await banUser(t.dataset.ban, true);
    if (t.dataset?.unban) await banUser(t.dataset.unban, false);
    if (t.dataset?.plan)  await grantPlanPrompt(t.dataset.plan);
  }, { once: true });
}

async function banUser(uid, doBan){
  const body = doBan ? {reason: prompt('Ban reason:', 'violation') || 'banned'} : {};
  const r = await api(`/api/users/${uid}/${doBan?'ban':'unban'}`, {method:'POST', body:JSON.stringify(body)});
  if (r.ok){ toast(doBan ? 'User banned' : 'User unbanned'); route(); }
  else toast(r.error || 'Failed', true);
}
async function grantPlanPrompt(uid){
  const plan = prompt('Plan (free/starter/basic/pro/enterprise/lifetime):', 'pro');
  if (!plan) return;
  const days = parseInt(prompt('Days (0 for unlimited):', '30') || '0', 10);
  const r = await api(`/api/users/${uid}/plan`, {method:'POST', body:JSON.stringify({plan, days})});
  if (r.ok){ toast('Plan updated'); route(); } else toast(r.error || 'Failed', true);
}

// ═══ BOTS ═══
async function renderBots(){
  const {data:bots} = await api('/api/bots');
  $('#view').innerHTML = `
    <div class="grid grid-2">
      ${bots.map(b => `
        <div class="card">
          <div class="row-between mb-16">
            <div>
              <div style="font-weight:600;font-size:14px">${esc(b.name)}</div>
              <div style="font-size:11px;color:var(--text-mute)" class="mono">
                <code>${esc(b.bid)}</code> · owner <code>${esc(b.owner)}</code>
              </div>
            </div>
            ${b.running ? '<span class="pill green">running</span>' : '<span class="pill gray">stopped</span>'}
          </div>
          <div class="kv"><span class="k">Status</span><span class="v">${esc(b.status)}</span></div>
          <div class="kv"><span class="k">Approval</span><span class="v">${esc(b.approval || '—')}</span></div>
          <div class="kv"><span class="k">PID</span><span class="v">${b.pid || '—'}</span></div>
          <div class="kv"><span class="k">Created</span><span class="v">${fmtDate(b.created)}</span></div>
          ${b.last_error ? `<div class="kv"><span class="k">Last error</span><span class="v" style="color:var(--red);font-size:11px">${esc(b.last_error)}</span></div>` : ''}
          <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
            ${b.running
              ? `<button class="btn sm danger" data-botstop="${esc(b.bid)}">⏹ Stop</button>`
              : `<button class="btn sm primary" data-botstart="${esc(b.bid)}">▶ Start</button>`}
            <button class="btn sm" data-botrestart="${esc(b.bid)}">↻ Restart</button>
            <button class="btn sm" data-botview="${esc(b.bid)}">📂 Files & Logs</button>
          </div>
        </div>`).join('') || '<div class="card">No bots found</div>'}
    </div>`;

  document.body.addEventListener('click', async (e) => {
    const t = e.target;
    const start = t.dataset?.botstart, stop = t.dataset?.botstop, rest = t.dataset?.botrestart, view = t.dataset?.botview;
    if (view){ location.hash = 'botview/' + view; return; }
    const bid = start || stop || rest;
    if (!bid) return;
    t.disabled = true;
    const action = start ? 'start' : stop ? 'stop' : 'restart';
    const r = await api(`/api/bots/${bid}/${action}`, {method:'POST'});
    if (r.ok){ toast(`Bot ${action} OK`); route(); }
    else toast(r.error || `Failed to ${action}`, true);
    t.disabled = false;
  }, { once: true });
}

// ═══ BOT VIEW (files + logs) ═══
async function renderBotView(bid){
  if (!bid){ location.hash = 'bots'; return; }
  const {data:bots} = await api('/api/bots');
  const b = bots.find(x => x.bid === bid);
  if (!b){ $('#view').innerHTML = '<div class="card">Bot not found</div>'; return; }

  $('#view').innerHTML = `
    <div class="card mb-16">
      <div class="row-between">
        <div>
          <div style="font-size:17px;font-weight:700">${esc(b.name)}</div>
          <div style="font-size:11.5px;color:var(--text-mute);font-family:'JetBrains Mono',monospace;margin-top:4px">
            <code>${esc(b.bid)}</code> · owner <code>${esc(b.owner)}</code>
            ${b.running ? `· PID <code>${b.pid}</code>` : ''}
            ${b.cpu != null ? `· CPU ${b.cpu.toFixed(1)}%` : ''}
            ${b.mem ? `· RAM ${fmtBytes(b.mem)}` : ''}
          </div>
        </div>
        <div style="display:flex;gap:8px">
          ${b.running
            ? `<button class="btn danger" data-ctrl="stop">⏹ Stop</button>`
            : `<button class="btn primary" data-ctrl="start">▶ Start</button>`}
          <button class="btn" data-ctrl="restart">↻ Restart</button>
          <button class="btn ghost" onclick="location.hash='bots'">← Back</button>
        </div>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="row-between mb-16">
          <div class="label" style="margin:0">📂 Sandbox Files</div>
          <span class="pill gray" id="file-count">…</span>
        </div>
        <div class="breadcrumb" id="file-crumb"><span data-crumb="">root</span></div>
        <div class="file-list" id="file-list">
          <div style="padding:16px;text-align:center;opacity:.5">Loading…</div>
        </div>
        <div id="editor-wrap" class="hidden mt-16">
          <div class="row-between mb-16">
            <div class="label" id="editor-title" style="margin:0">Editor</div>
            <div style="display:flex;gap:6px">
              <button class="btn sm" id="ed-save">💾 Save</button>
              <button class="btn sm danger" id="ed-delete">🗑 Delete</button>
              <button class="btn sm ghost" id="ed-close">✕ Close</button>
            </div>
          </div>
          <textarea class="code-editor" id="ed-body" spellcheck="false"></textarea>
          <div style="font-size:11px;color:var(--text-mute);margin-top:8px;font-family:'JetBrains Mono',monospace" id="ed-status"></div>
        </div>
      </div>

      <div class="card">
        <div class="row-between mb-16">
          <div class="label" style="margin:0">📡 Live Logs</div>
          <div style="display:flex;gap:6px;align-items:center">
            <span class="pill green" id="log-status">connected</span>
            <button class="btn sm" id="log-clear">🗑 Clear</button>
          </div>
        </div>
        <pre class="logbox" id="log-body"></pre>
      </div>
    </div>`;

  // control buttons
  document.querySelectorAll('[data-ctrl]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const action = btn.dataset.ctrl;
      btn.disabled = true;
      const r = await api(`/api/bots/${bid}/${action}`, {method:'POST'});
      if (r.ok) toast(`Bot ${action} OK`); else toast(r.error || 'Failed', true);
      setTimeout(() => route(), 400);
    });
  });

  // file browser state
  let cwd = '';
  let openFile = null;

  async function loadDir(path='') {
    cwd = path;
    const r = await api(`/api/bots/${bid}/files?path=${encodeURIComponent(path)}`);
    const list = $('#file-list');
    if (!r.ok){ list.innerHTML = '<div style="padding:16px;color:var(--red)">'+esc(r.error)+'</div>'; return; }
    $('#file-count').textContent = r.entries.length + ' items';
    // breadcrumb
    const parts = (path || '').split('/').filter(Boolean);
    let acc = '';
    const crumbs = ['<span data-crumb="">root</span>'];
    parts.forEach(p => {
      acc = acc ? acc + '/' + p : p;
      crumbs.push('<span data-crumb="'+esc(acc)+'">'+esc(p)+'</span>');
    });
    $('#file-crumb').innerHTML = crumbs.join(' / ');
    document.querySelectorAll('[data-crumb]').forEach(el => {
      el.addEventListener('click', () => loadDir(el.dataset.crumb));
    });
    if (!r.entries.length){
      list.innerHTML = '<div style="padding:16px;text-align:center;opacity:.5">Empty directory</div>';
      return;
    }
    list.innerHTML = r.entries.map(en => `
      <div class="file-item" data-name="${esc(en.name)}" data-type="${en.type}">
        <span>${en.type === 'dir' ? '📁' : '📄'}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(en.name)}</span>
        <span class="sz">${en.type === 'dir' ? '' : fmtBytes(en.size)}</span>
      </div>`).join('');
    document.querySelectorAll('.file-item').forEach(el => {
      el.addEventListener('click', () => {
        const name = el.dataset.name;
        const type = el.dataset.type;
        const next = path ? path + '/' + name : name;
        if (type === 'dir'){
          loadDir(next);
        } else {
          openEditor(next, el);
        }
      });
    });
  }

  async function openEditor(path, el) {
    const r = await api(`/api/bots/${bid}/file?path=${encodeURIComponent(path)}`);
    if (!r.ok){ toast(r.error || 'Cannot open', true); return; }
    openFile = path;
    $('#editor-wrap').classList.remove('hidden');
    $('#editor-title').textContent = path;
    $('#ed-body').value = r.content;
    $('#ed-status').textContent = `${r.size} bytes · ${(r.content.match(/\n/g)||[]).length+1} lines`;
    document.querySelectorAll('.file-item').forEach(x => x.classList.remove('active'));
    if (el) el.classList.add('active');
  }

  $('#ed-save').addEventListener('click', async () => {
    if (!openFile) return;
    $('#ed-save').disabled = true;
    const r = await api(`/api/bots/${bid}/file`, {
      method:'POST',
      body: JSON.stringify({path: openFile, content: $('#ed-body').value}),
    });
    $('#ed-save').disabled = false;
    if (r.ok){ toast('Saved'); $('#ed-status').textContent = `${r.size} bytes · saved`; }
    else toast(r.error || 'Save failed', true);
  });
  $('#ed-delete').addEventListener('click', async () => {
    if (!openFile) return;
    if (!confirm('Delete ' + openFile + '?')) return;
    const r = await api(`/api/bots/${bid}/file?path=${encodeURIComponent(openFile)}`, {method:'DELETE'});
    if (r.ok){ toast('Deleted'); $('#editor-wrap').classList.add('hidden'); openFile = null; loadDir(cwd); }
    else toast(r.error || 'Delete failed', true);
  });
  $('#ed-close').addEventListener('click', () => {
    $('#editor-wrap').classList.add('hidden');
    openFile = null;
  });

  // ── LOG STREAM ──
  const logBody = $('#log-body');
  const logStatus = $('#log-status');
  function addLine(line) {
    const div = document.createElement('div');
    div.className = 'ln';
    if (/error|exception|traceback|failed/i.test(line)) div.classList.add('err');
    else if (/warn/i.test(line)) div.classList.add('warn');
    else if (/info|starting|listening/i.test(line)) div.classList.add('info');
    div.textContent = line;
    logBody.appendChild(div);
    // cap at 500 lines
    while (logBody.childElementCount > 500) logBody.removeChild(logBody.firstChild);
    logBody.scrollTop = logBody.scrollHeight;
  }
  logBody.innerHTML = '';
  _logStream = new EventSource(`/api/bots/${bid}/logs/stream`);
  _logStream.onmessage = (e) => { try { addLine(JSON.parse(e.data)); } catch { addLine(e.data); } };
  _logStream.onerror = () => { logStatus.textContent = 'reconnecting…'; logStatus.className = 'pill yellow'; };
  _logStream.onopen  = () => { logStatus.textContent = 'connected'; logStatus.className = 'pill green'; };

  $('#log-clear').addEventListener('click', async () => {
    if (!confirm('Clear log file?')) return;
    await api(`/api/bots/${bid}/logs/clear`, {method:'POST'});
    logBody.innerHTML = '';
    toast('Log cleared');
  });

  loadDir('');
}

// ═══ PAYMENTS ═══
async function renderPayments(){
  const {data:pays} = await api('/api/payments');
  $('#view').innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>ID</th><th>User</th><th>Method</th><th>Plan</th>
          <th>Amount</th><th>Time</th><th>Status</th><th style="text-align:right">Actions</th>
        </tr></thead>
        <tbody>
          ${pays.map(p => `
            <tr>
              <td class="mono" style="font-size:11px"><code>${esc(p.id)}</code></td>
              <td class="mono"><code>${esc(p.uid)}</code></td>
              <td>${esc(p.method||'—')}</td>
              <td>${esc(p.plan||'—')}</td>
              <td class="mono">${fmtNum(p.amount)}৳</td>
              <td class="mono" style="font-size:11px;color:var(--text-mute)">${fmtDate(p.ts)}</td>
              <td><span class="pill ${p.status==='approved'?'green':p.status==='rejected'?'red':'yellow'}">${esc(p.status)}</span></td>
              <td style="text-align:right">
                ${p.status==='pending' ? `
                  <button class="btn sm primary" data-app="${esc(p.id)}">Approve</button>
                  <button class="btn sm danger" data-rej="${esc(p.id)}">Reject</button>` : '—'}
              </td>
            </tr>`).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--text-mute);padding:30px">No payments yet</td></tr>'}
        </tbody>
      </table>
    </div>`;
  document.body.addEventListener('click', async (e) => {
    const t = e.target;
    const pid = t.dataset?.app || t.dataset?.rej;
    if (!pid) return;
    const action = t.dataset.app ? 'approve' : 'reject';
    const r = await api(`/api/payments/${pid}/${action}`, {method:'POST'});
    if (r.ok){ toast(`Payment ${action}d`); route(); } else toast(r.error || 'Failed', true);
  }, { once: true });
}

// ═══ COUPONS ═══
async function renderCoupons(){
  const {data:pairs} = await api('/api/coupons');
  $('#view').innerHTML = `
    <div class="card mb-16">
      <div class="label">Create Coupon</div>
      <div class="grid grid-4">
        <input id="c-code" type="text" placeholder="CODE (e.g. WELCOME20)">
        <input id="c-pct"  type="number" placeholder="Percent %" value="20">
        <input id="c-uses" type="number" placeholder="Uses" value="10">
        <button class="btn primary" id="c-add">Create</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Code</th><th>Percent</th><th>Uses left</th><th>Created</th><th style="text-align:right"></th></tr></thead>
        <tbody>
          ${pairs.map(([code, c]) => `
            <tr>
              <td><code style="color:var(--accent)">${esc(code)}</code></td>
              <td class="mono">${c.percent || 0}%</td>
              <td class="mono">${c.uses_left ?? 0}</td>
              <td class="mono" style="font-size:11px;color:var(--text-mute)">${fmtDate(c.created)}</td>
              <td style="text-align:right"><button class="btn sm danger" data-cdel="${esc(code)}">Delete</button></td>
            </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-mute)">No coupons</td></tr>'}
        </tbody>
      </table>
    </div>`;
  $('#c-add').addEventListener('click', async () => {
    const code = $('#c-code').value.trim();
    const percent = +$('#c-pct').value;
    const uses_left = +$('#c-uses').value;
    if (!code) return toast('Code required', true);
    const r = await api('/api/coupons', {method:'POST', body:JSON.stringify({code, percent, uses_left})});
    if (r.ok){ toast('Coupon created'); route(); } else toast(r.error || 'Failed', true);
  });
  document.body.addEventListener('click', async (e) => {
    const code = e.target.dataset?.cdel;
    if (!code) return;
    const r = await api('/api/coupons/' + encodeURIComponent(code), {method:'DELETE'});
    if (r.ok){ toast('Deleted'); route(); }
  }, { once: true });
}

// ═══ TICKETS ═══
async function renderTickets(){
  const {data:ts} = await api('/api/tickets');
  $('#view').innerHTML = `
    <div class="grid grid-2">
      ${ts.map(t => `
        <div class="card">
          <div class="row-between mb-16">
            <div>
              <div style="font-weight:600">#${esc(t.id)} · ${esc(t.subject)}</div>
              <div style="font-size:11px;color:var(--text-mute)" class="mono">uid <code>${esc(t.uid)}</code> · ${fmtDate(t.opened_at)}</div>
            </div>
            <span class="pill ${t.status==='open'?'green':'gray'}">${esc(t.status)}</span>
          </div>
          ${(t.messages || []).slice(-3).map(m => `
            <div style="font-size:12.5px;margin:6px 0;padding:8px 12px;background:var(--bg-2);border-radius:8px;border-left:2px solid var(--border-2)">
              <b style="color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:11px">${esc(m.from)}</b>
              <div style="margin-top:4px">${esc(m.text)}</div>
            </div>`).join('')}
        </div>`).join('') || '<div class="card">No tickets</div>'}
    </div>`;
}

// ═══ SCAN LOG ═══
async function renderScanLog(){
  const {data:rows} = await api('/api/scan-log');
  $('#view').innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>User</th><th>File</th><th>Verdict</th><th>Risk</th></tr></thead>
        <tbody>
          ${rows.map(s => `
            <tr>
              <td class="mono" style="font-size:11px;color:var(--text-mute)">${fmtDate(s.ts)}</td>
              <td class="mono"><code>${esc(s.uid)}</code></td>
              <td>${esc(s.filename || '—')}</td>
              <td><span class="pill ${s.verdict==='DANGEROUS'?'red':s.verdict==='SUSPICIOUS'?'yellow':'green'}">${esc(s.verdict||'?')}</span></td>
              <td class="mono">${s.risk_score||0}</td>
            </tr>`).join('') || '<tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-mute)">No scans yet</td></tr>'}
        </tbody>
      </table>
    </div>`;
}

// ═══ AUDIT ═══
async function renderAudit(){
  const [{data:list}, {data:file}] = await Promise.all([api('/api/audit'), api('/api/audit/file')]);
  $('#view').innerHTML = `
    <div class="grid grid-2">
      <div class="card">
        <div class="label">Structured Audit (${list.length})</div>
        <div style="max-height:540px;overflow:auto">
          ${list.map(a => `
            <div class="kv">
              <span class="k">${esc((a.ts||'').slice(0,19))} · uid ${esc(a.uid)}</span>
              <span class="v">${esc(a.action)}</span>
            </div>
            <div style="font-size:11px;color:var(--text-mute);padding:0 0 8px 0" class="mono">${esc(a.detail||'')}</div>
          `).join('') || '<div style="color:var(--text-mute);padding:20px;text-align:center">No audit entries</div>'}
        </div>
      </div>
      <div class="card">
        <div class="label">audit.log (raw)</div>
        <pre class="logbox">${esc(file || '(empty)')}</pre>
      </div>
    </div>`;
}

// ═══ SETTINGS ═══
async function renderSettings(){
  const {data:s} = await api('/api/settings');
  const keys = Object.keys(s).sort();
  $('#view').innerHTML = `
    <div class="card mb-16">
      <div class="label">Runtime Settings (live — bot picks up on next read)</div>
      <div style="color:var(--text-mute);font-size:12px;margin-bottom:14px">
        Sensitive keys (containing <code>token</code>, <code>secret</code>, <code>pass</code>) are masked.
      </div>
      <div id="set-rows">
        ${keys.map(k => {
          const v = s[k];
          const sensitive = /token|secret|pass/i.test(k);
          const value = sensitive && v ? '••••••' + String(v).slice(-4) : String(v ?? '');
          const isNum = typeof v === 'number';
          const isBool = typeof v === 'boolean';
          let input;
          if (isBool) {
            input = `<select data-k="${esc(k)}"><option value="true"${v?' selected':''}>true</option><option value="false"${!v?' selected':''}>false</option></select>`;
          } else if (isNum) {
            input = `<input type="number" data-k="${esc(k)}" value="${esc(v)}">`;
          } else {
            input = `<input type="text" data-k="${esc(k)}" value="${esc(value)}" ${sensitive?'placeholder="masked"':''}>`;
          }
          return `<div class="form-row"><label>${esc(k)}</label>${input}</div>`;
        }).join('') || '<div style="color:var(--text-mute)">No settings defined yet</div>'}
      </div>
      <button class="btn primary mt-16" id="set-save">💾 Save Settings</button>
    </div>`;
  $('#set-save').addEventListener('click', async () => {
    const patch = {};
    $$('#set-rows [data-k]').forEach(el => {
      const k = el.dataset.k;
      let v = el.value;
      if (el.tagName === 'SELECT') v = v === 'true';
      else if (/^-?\d+(\.\d+)?$/.test(v) && typeof (s[k]) === 'number') v = parseFloat(v);
      if (/token|secret|pass/i.test(k) && /^••••••/.test(v)) return;
      patch[k] = v;
    });
    const r = await api('/api/settings', {method:'POST', body:JSON.stringify(patch)});
    if (r.ok) toast('Settings saved'); else toast('Save failed', true);
  });
}

// ═══ SYSTEM ═══
async function renderSystem(){
  const {data:s} = await api('/api/system');
  const rows = [
    ['Python',    s.python],
    ['Platform',  s.platform],
    ['Hostname',  s.hostname],
    ['PID',       s.pid],
    ['Threads',   s.threads],
    ['CPU cores', s.cpu_count],
    ['CPU %',     (s.cpu_pct||0).toFixed(2)+'%'],
    ['Panel RSS', fmtBytes(s.rss)],
    ['Load avg',  (s.load||[0,0,0]).map(x=>x.toFixed(2)).join(' / ')],
    ['Memory',    `${fmtBytes(s.mem_used)} / ${fmtBytes(s.mem_total)} (${(s.mem_pct||0).toFixed(1)}%)`],
    ['Disk',      `${fmtBytes(s.disk_used)} / ${fmtBytes(s.disk_total)} (${(s.disk_pct||0).toFixed(1)}%)`],
  ];
  $('#view').innerHTML = `
    <div class="grid grid-2">
      <div class="card">
        <div class="label">🖥️ Runtime</div>
        ${rows.map(([k,v]) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}
      </div>
      <div class="card">
        <div class="label">🔋 Resource Bars</div>
        ${[['CPU %',s.cpu_pct||0,'#00e5a0'],['Memory %',s.mem_pct||0,'#58a6ff'],['Disk %',s.disk_pct||0,'#f0b429']].map(([label, pct, color]) => `
          <div style="margin:14px 0">
            <div class="row-between" style="margin-bottom:6px">
              <span class="mono" style="font-size:12px">${label}</span>
              <span class="mono" style="font-size:12px;color:${color}">${pct.toFixed(1)}%</span>
            </div>
            <div style="height:8px;background:var(--bg-2);border-radius:10px;overflow:hidden">
              <div style="height:100%;width:${Math.min(100,pct)}%;background:${color};border-radius:10px;transition:width .8s ease"></div>
            </div>
          </div>`).join('')}
      </div>
    </div>`;
}

// ═══ BOOT ═══
// ✅ NEW: Wire up sidebar nav clicks
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => {
    const v = el.dataset.view;
    if (v) location.hash = v;
  });
});

// Logout button
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-logout]')) {
    fetch('/api/logout', {method:'POST'}).then(() => location.href = '/login');
  }
});

// Tab support in code editor
document.body.addEventListener('keydown', (e) => {
  if (e.key === 'Tab' && document.activeElement?.classList?.contains('code-editor')) {
    e.preventDefault();
    const el = document.activeElement;
    const start = el.selectionStart, end = el.selectionEnd;
    el.value = el.value.substring(0, start) + '    ' + el.value.substring(end);
    el.selectionStart = el.selectionEnd = start + 4;
  }
});

route();
"""

ICONS = {
  "dashboard": '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
  "users":     '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="7" r="4"/><path d="M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M21 21v-2a4 4 0 0 0-3-3.87"/></svg>',
  "bots":      '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 4v4"/><circle cx="9" cy="14" r="1"/><circle cx="15" cy="14" r="1"/></svg>',
  "payments":  '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M2 10h20"/></svg>',
  "coupons":   '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 8a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4z"/></svg>',
  "tickets":   '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
  "scanlog":   '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/></svg>',
  "audit":     '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/></svg>',
  "settings":  '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  "system":    '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
}

def _nav_top():
    items = [("dashboard","Dashboard"),("users","Users"),("bots","Bots"),
             ("payments","Payments"),("coupons","Coupons"),("tickets","Tickets"),
             ("scanlog","Scan Log")]
    return "".join(f'<div class="nav-item" data-view="{k}">{ICONS[k]}<span>{l}</span></div>'
                   for k, l in items)

def _nav_bottom():
    items = [("audit","Audit Log"),("settings","Settings"),("system","System")]
    return "".join(f'<div class="nav-item" data-view="{k}">{ICONS[k]}<span>{l}</span></div>'
                   for k, l in items)


HTML_LOGIN = r"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · MM Hosting Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>__CSS__</style>
</head><body>
<div class="login-shell">
  <div class="login-card">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:22px">
      <div class="brand-mark">M</div>
      <div>
        <div class="brand-title">MM Hosting</div>
        <div class="brand-sub">admin_dashboard v1.0</div>
      </div>
    </div>
    <div class="terminal"><span class="terminal-text"></span><span class="terminal-cursor"></span></div>
    <form id="login-form">
      <div class="form-row"><label>Username</label>
        <input id="u" name="user" type="text" autocomplete="username" autofocus required></div>
      <div class="form-row"><label>Password</label>
        <input id="p" name="pass" type="password" autocomplete="current-password" required></div>
      <div id="login-err" style="color:var(--red);font-size:12px;margin-bottom:10px;min-height:16px"></div>
      <button class="btn primary" type="submit" style="width:100%;justify-content:center;padding:10px">Sign in →</button>
    </form>
    <div style="margin-top:18px;font-size:11px;color:var(--text-mute);text-align:center;font-family:'JetBrains Mono',monospace">
      PBKDF2 · session cookie
    </div>
  </div>
</div>
<script>__LOGIN_JS__</script>
</body></html>"""

HTML_SHELL = r"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MM Hosting · Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>__CSS__</style>
</head><body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">M</div>
      <div>
        <div class="brand-title">MM Hosting</div>
        <div class="brand-sub">admin_dashboard v1.0</div>
      </div>
    </div>
    <nav class="nav">
      <div class="nav-group-title">Operations</div>
      __NAV_TOP__
      <div class="nav-group-title">Data</div>
      __NAV_BOTTOM__
    </nav>
    <div class="sidebar-footer">
      <div><span class="pulse-dot"></span>bot online</div>
      <div style="margin-top:4px" id="foot-time"></div>
    </div>
  </aside>
  <main class="main">
    <div class="topbar">
      <h1 id="view-title">Dashboard</h1>
      <span class="crumbs" id="crumb">dashboard</span>
      <div class="spacer"></div>
      <button class="btn ghost" data-logout>Logout</button>
      <span class="badge-status"><span class="pulse-dot"></span>live</span>
    </div>
    <div class="content" id="view">Loading…</div>
  </main>
</div>
<div class="toasts" id="toasts"></div>
<script>__APP_JS__</script>
</body></html>"""


@app.route("/")
@login_required
def index():
    return (HTML_SHELL
            .replace("__CSS__", CSS)
            .replace("__NAV_TOP__", _nav_top())
            .replace("__NAV_BOTTOM__", _nav_bottom())
            .replace("__APP_JS__", APP_JS))


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_auth()
    print("=" * 64)
    print("  MM Hosting — Admin Dashboard")
    print(f"  Listening on  http://0.0.0.0:{DASH_PORT}")
    print(f"  DB File       {DB_FILE}")
    print(f"  Sandbox Root  {SANDBOX_DIR}")
    print(f"  Bot Logs Dir  {BOTLOG_DIR}")
    print(f"  psutil        {'OK' if _PSUTIL else 'MISSING — install: pip install psutil'}")
    print("=" * 64)
    app.run(host="0.0.0.0", port=DASH_PORT, debug=False,
            use_reloader=False, threaded=True)