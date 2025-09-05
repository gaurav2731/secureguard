import os
import sqlite3
import logging
import threading
import time
import random
from datetime import datetime, timezone
from flask import Flask, render_template_string, redirect, url_for
import smtplib
from email.mime.text import MIMEText

# --------------------
# Config
# --------------------
DB_FILE = "secureguard.db"
LOG_FILE = "logs/secureguard.log"

EMAIL_FROM = "rsrsrsg369@gmail.com"
EMAIL_TO = "gaurav78969@gmail.com"
EMAIL_PASS = "xdpi pvxy ftqu suyt"   # Gmail app password

# --------------------
# Logging
# --------------------
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger("secureguard")

# --------------------
# DB Setup
# --------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # base table
    c.execute("CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY, ip TEXT)")
    # ensure ts column exists
    try:
        c.execute("SELECT ts FROM blocked_ips LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE blocked_ips ADD COLUMN ts TEXT")
    # ensure status column exists
    try:
        c.execute("SELECT status FROM blocked_ips LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE blocked_ips ADD COLUMN status TEXT")
    conn.commit()
    conn.close()

init_db()

# --------------------
# Email Alerts
# --------------------
def send_email_alert(subject, body):
    try:
        msg = MIMEText(body)
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASS)
            server.send_message(msg)
        logger.info("Email alert sent.")
    except Exception as e:
        logger.error(f"Email failed: {e}")

# --------------------
# Flask App
# --------------------
app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>SecureGuard Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    body { font-family: Arial, sans-serif; background: #0d1b2a; color: #fff; text-align: center; }
    h1 { color: #4cc9f0; }
    .btn { display: inline-block; margin: 10px; padding: 10px 20px;
           background: #1b263b; color: #fff; text-decoration: none; border-radius: 8px; }
    .btn:hover { background: #415a77; }
    table { margin: 0 auto; border-collapse: collapse; width: 80%; }
    th, td { border: 1px solid #4cc9f0; padding: 8px; }
    .stats { margin: 20px auto; width: 50%; text-align: left; background:#1b263b; padding:15px; border-radius:8px; }
    .blocked { color: #ff4d6d; font-weight: bold; }
    .mitigated { color: #ffd60a; font-weight: bold; }
    .through { color: #06d6a0; font-weight: bold; }
  </style>
</head>
<body>
  <h1>🚨 SecureGuard Dashboard 🚨</h1>
  <a href="{{ url_for('simulate') }}" class="btn">Simulate Attack (Force Mitigate)</a>
  <a href="{{ url_for('block_demo') }}" class="btn">Force Block</a>

  <div class="stats">
    <h2>📊 System Status</h2>
    <p><b>Total Entries:</b> {{ total }}</p>
    <p><b>Total Mitigated:</b> {{ total_mitigated }}</p>
    <p><b>Total Blocked:</b> {{ total_blocked }}</p>
    <p><b>Total Through:</b> {{ total_through }}</p>
    <p><b>Running Status:</b> ✅ Active</p>
  </div>

  <h2>Logs (Latest 10)</h2>
  <table>
    <tr><th>IP</th><th>Timestamp</th><th>Status</th></tr>
    {% for row in blocked %}
    <tr>
      <td>{{ row[0] }}</td>
      <td>{{ row[1] }}</td>
      <td class="{% if row[2]=='BLOCKED' %}blocked{% elif row[2]=='MITIGATED' %}mitigated{% else %}through{% endif %}">
        {{ row[2] }}
      </td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

@app.route("/")
def index():
    conn = sqlite3.connect(DB_FILE)
    blocked = conn.execute("SELECT ip, ts, status FROM blocked_ips ORDER BY id DESC LIMIT 10").fetchall()
    total = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    total_mitigated = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE status='MITIGATED'").fetchone()[0]
    total_blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE status='BLOCKED'").fetchone()[0]
    total_through = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE status='THROUGH'").fetchone()[0]
    conn.close()

    return render_template_string(
        TEMPLATE,
        blocked=blocked,
        total=total,
        total_mitigated=total_mitigated,
        total_blocked=total_blocked,
        total_through=total_through
    )

@app.route("/simulate")
def simulate():
    ip = f"192.168.1.{int(time.time()) % 255}"
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO blocked_ips (ip, ts, status) VALUES (?, ?, ?)", (ip, ts, "MITIGATED"))
    conn.commit()
    conn.close()
    logger.warning(f"Mitigated simulated attack from {ip}")
    send_email_alert("🚨 SecureGuard Alert", f"Mitigated simulated attack from {ip} at {ts}")
    return redirect(url_for("index"))

@app.route("/block_demo")
def block_demo():
    ip = f"203.0.113.{int(time.time()) % 255}"
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO blocked_ips (ip, ts, status) VALUES (?, ?, ?)", (ip, ts, "BLOCKED"))
    conn.commit()
    conn.close()
    logger.error(f"Blocked IP {ip}")
    send_email_alert("🚨 SecureGuard Alert", f"Blocked malicious IP {ip} at {ts}")
    return redirect(url_for("index"))

# --------------------
# Auto log generator (random firewall decisions)
# --------------------
def auto_generate_logs():
    while True:
        ip = f"10.0.0.{int(time.time()) % 255}"
        ts = datetime.now(timezone.utc).isoformat()
        status = random.choices(
            ["THROUGH", "MITIGATED", "BLOCKED"],
            weights=[0.5, 0.3, 0.2]
        )[0]
        conn = sqlite3.connect(DB_FILE)
        conn.execute("INSERT INTO blocked_ips (ip, ts, status) VALUES (?, ?, ?)", (ip, ts, status))
        conn.commit()
        conn.close()
        logger.info(f"Traffic event: {ip} => {status}")
        time.sleep(2)

threading.Thread(target=auto_generate_logs, daemon=True).start()

# --------------------
# Run
# --------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
