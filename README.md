# Simran Hosting — Admin Dashboard

Standalone web dashboard for the Telegram bot. **Zero changes to `bot.py`.**

## Features
- 📊 Live stats with animated charts (Chart.js)
- 👥 User manager — ban / unban / grant plans / edit wallet
- 🤖 Bot monitor — running PIDs, errors, approval status
- 💳 Payment approval queue
- 🎟️ Coupon manager
- 📩 Ticket inbox
- 🛡️ Security scan log
- 📜 Audit log + raw `audit.log` tail
- ⚙️ Runtime settings editor
- 🖥️ System health (CPU / RAM / Disk / Load)
- 🔐 PBKDF2 login + Flask session cookie

## Installation

```bash
pip install flask psutil