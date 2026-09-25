#!/usr/bin/env python3
"""
MM Hosting — Portable launcher
Works on Wispbyte / Railway / Render / VPS / Replit / Local PC.
"""

import os, sys, time, signal, threading, subprocess
from pathlib import Path

# ✅ PORTABLE: BASE = folder where this file lives
BASE = Path(__file__).resolve().parent
os.chdir(BASE)

DASH_FILE = "admin.py"
BOT_FILE  = "bot.py"

# ✅ PORTABLE: try PORT env, else fallback per platform
# Railway/Render/Heroku inject PORT automatically
# Wispbyte panel allocates it too
# Local PC → use 8080 default
WISPBYTE_PORT = (
    os.environ.get("PORT")
    or os.environ.get("DASH_PORT")
    or "8080"
)

os.environ.setdefault("BOT_TOKEN", "8988407775:AAGXSnJo8g0sQJvZh1xCcbOIrzqtAJGdldc")
os.environ.setdefault("OWNER_ID", "6683255978")
os.environ.setdefault("DASH_USER", "admin")
os.environ.setdefault("DASH_PASS", "MM@Hosting2024!")

LOG_DIR = BASE / "storage" / "data"
LOG_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 55, flush=True)
print(f"  MM Hosting Suite", flush=True)
print(f"  BASE         = {BASE}", flush=True)
print(f"  PORT env     = {os.environ.get('PORT', '<unset>')}", flush=True)
print(f"  Using port   = {WISPBYTE_PORT}", flush=True)
print(f"  Runner PID   = {os.getpid()}", flush=True)
print(f"  Parent PID   = {os.getppid()}", flush=True)
print(f"  Dashboard    = {DASH_FILE}", flush=True)
print(f"  Bot          = {BOT_FILE}", flush=True)
print("=" * 55, flush=True)

for f in (DASH_FILE, BOT_FILE):
    if not (BASE / f).exists():
        print(f"[FATAL] {f} not found in {BASE}", flush=True)
        sys.exit(1)


def _safe_kill_pattern(pat: str) -> int:
    """Kill processes matching `pat`, but NEVER kill ourselves or parent."""
    me = os.getpid()
    ppid = os.getppid()
    killed = 0
    try:
        out = subprocess.run(
            ["pgrep", "-f", pat],
            capture_output=True, text=True, timeout=5,
        ).stdout or ""
    except Exception:
        return 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
        except ValueError:
            continue
        if pid in (me, ppid):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            killed += 1
        except Exception:
            pass
    return killed


print("[boot] safe cleanup — only stale bot.py / admin.py", flush=True)
try:
    n1 = _safe_kill_pattern("bot.py")
    n2 = _safe_kill_pattern("admin.py")
    print(f"[boot] killed {n1} stale bot.py, {n2} stale admin.py", flush=True)
except Exception as e:
    print(f"[boot] cleanup warning: {e}", flush=True)
time.sleep(1)


def _pump(stream, log_path, prefix):
    try:
        fh = open(log_path, "ab", buffering=0)
    except Exception as e:
        print(f"[{prefix}] cannot open log: {e}", flush=True)
        fh = None
    try:
        for raw in iter(stream.readline, b""):
            if not raw:
                break
            if fh:
                try: fh.write(raw)
                except Exception: pass
            try:
                sys.stdout.write(f"[{prefix}] {raw.decode('utf-8','replace')}")
                sys.stdout.flush()
            except Exception:
                pass
    except Exception as e:
        print(f"[{prefix}] pump error: {e}", flush=True)
    finally:
        if fh:
            try: fh.close()
            except Exception: pass


def start_process(name, script, extra_env, log_file):
    env = os.environ.copy()
    env.update(extra_env)
    proc = subprocess.Popen(
        [sys.executable, "-u", script],
        cwd=str(BASE),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        bufsize=0,
    )
    threading.Thread(
        target=_pump,
        args=(proc.stdout, log_file, name),
        daemon=True,
    ).start()
    print(f"[boot] {name} pid={proc.pid}", flush=True)
    return proc


def main():
    print(f"[boot] dashboard port → {WISPBYTE_PORT}", flush=True)
    dash = start_process(
        "dash", DASH_FILE,
        {"DASH_PORT": WISPBYTE_PORT},
        LOG_DIR / "dashboard_stdout.log",
    )
    time.sleep(4)

    # bot.py keepalive → private port 9999 (or OS-assigned)
    bot = start_process(
        "bot", BOT_FILE,
        {"PORT": "9999"},
        LOG_DIR / "bot_stdout.log",
    )

    def _shutdown(sig, frame):
        print("\n[watchdog] shutting down...", flush=True)
        for p in (bot, dash):
            try: p.terminate()
            except Exception: pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while True:
        time.sleep(10)
        if bot.poll() is not None:
            print(f"[watchdog] bot died rc={bot.returncode} — full restart", flush=True)
            try: dash.terminate()
            except Exception: pass
            time.sleep(2)
            os.execv(sys.executable, [sys.executable, "-u", __file__])
        if dash.poll() is not None:
            print(f"[watchdog] dash died rc={dash.returncode} — restarting", flush=True)
            dash = start_process(
                "dash", DASH_FILE,
                {"DASH_PORT": WISPBYTE_PORT},
                LOG_DIR / "dashboard_stdout.log",
            )


if __name__ == "__main__":
    main()