import os
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template_string, request, redirect, url_for
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# -------- Flask App --------
app = Flask(__name__)

# -------- Logging (rotating + console) --------
os.makedirs("logs", exist_ok=True)
log_handler = RotatingFileHandler("logs/secureguard.log", maxBytes=2_000_000, backupCount=5)
log_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logger = logging.getLogger("SecureGuard")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)
logger.addHandler(console_handler)

# -------- DB Setup --------
DB_FILE = "secureguard.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        message TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        timestamp TEXT)""")
        conn.commit()

init_db()

# -------- Email Alerts --------
EMAIL_USER = os.getenv("SECUREGUARD_EMAIL", "yourgmail@gmail.com")
EMAIL_PASS = os.getenv("SECUREGUARD_PASS", "yourpassword")
EMAIL_TO = os.getenv("SECUREGUARD_TO", "yourgmail@gmail.com")

def send_email_alert(subject, body):
    try:
        msg = MIMEText(body)
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, EMAIL_TO, msg.as_string())

        logger.info(f"📧 Email sent: {subject}")
    except Exception as e:
        logger.error(f"Email failed: {e}")

# -------- DB Helpers --------
def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO events (timestamp, message) VALUES (?, ?)", (timestamp, message))
        conn.commit()
    logger.info(message)
    send_email_alert("SecureGuard Alert", message)

def block_ip(ip):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO blocked_ips (ip, timestamp) VALUES (?, ?)", (ip, timestamp))
        conn.commit()
    log_event(f"🚫 Blocked IP: {ip}")

def unblock_ip(ip):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()
    log_event(f"✅ Unblocked IP: {ip}")

# -------- Routes --------
@app.route("/")
def index():
    with sqlite3.connect(DB_FILE) as conn:
        events = conn.execute("SELECT timestamp, message FROM events ORDER BY id DESC LIMIT 15").fetchall()
        blocked_ips = conn.execute("SELECT ip, timestamp FROM blocked_ips ORDER BY id DESC").fetchall()

    return render_template_string(DASHBOARD_HTML, events=events, blocked_ips=blocked_ips)

@app.route("/block", methods=["POST"])
def block_route():
    ip = request.form.get("ip")
    if ip:
        block_ip(ip)
    return redirect(url_for("index"))

@app.route("/unblock", methods=["POST"])
def unblock_route():
    ip = request.form.get("ip")
    if ip:
        unblock_ip(ip)
    return redirect(url_for("index"))

@app.route("/shutdown", methods=["POST"])
def shutdown():
    log_event("⚠️ Emergency Shutdown Triggered!")
    return redirect(url_for("index"))

@app.route("/simulate", methods=["POST"])
def simulate_attack():
    for i in range(10):
        log_event(f"🚨 Simulated Brute Force Attempt #{i+1} from 192.168.1.{i+10}")
    log_event("🧠 AI-Detected: DDoS Attack Simulation")
    return redirect(url_for("index"))

# -------- HTML Template --------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard Dashboard</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { font-family: Arial, sans-serif; background:#111; color:#eee; text-align:center; }
        h1 { color:#4CAF50; }
        .container { width: 80%; margin: auto; }
        .section { background:#222; padding:20px; margin:10px; border-radius:10px; }
        button { padding:10px 15px; margin:5px; border:none; border-radius:5px; cursor:pointer; }
        .block { background:#f44336; color:white; }
        .unblock { background:#2196F3; color:white; }
        .shutdown { background:#ff9800; color:white; }
        .simulate { background:#9c27b0; color:white; }
        table { width:100%; border-collapse:collapse; margin-top:10px; }
        th, td { padding:8px; border-bottom:1px solid #444; }
    </style>
</head>
<body>
    <h1>🛡 SecureGuard Dashboard</h1>
    <div class="container">
        <div class="section">
            <h2>Actions</h2>
            <form method="post" action="/block">
                <input type="text" name="ip" placeholder="Enter IP to block">
                <button class="block" type="submit">Block IP</button>
            </form>
            <form method="post" action="/unblock">
                <input type="text" name="ip" placeholder="Enter IP to unblock">
                <button class="unblock" type="submit">Unblock IP</button>
            </form>
            <form method="post" action="/shutdown">
                <button class="shutdown" type="submit">Emergency Shutdown</button>
            </form>
            <form method="post" action="/simulate">
                <button class="simulate" type="submit">Simulate Attack</button>
            </form>
        </div>

        <div class="section">
            <h2>Events Log (Auto-refresh 2s)</h2>
            <table>
                <tr><th>Time</th><th>Message</th></tr>
                {% for ts, msg in events %}
                <tr><td>{{ ts }}</td><td>{{ msg }}</td></tr>
                {% endfor %}
            </table>
        </div>

        <div class="section">
            <h2>Blocked IPs</h2>
            <table>
                <tr><th>IP</th><th>Blocked At</th></tr>
                {% for ip, ts in blocked_ips %}
                <tr><td>{{ ip }}</td><td>{{ ts }}</td></tr>
                {% endfor %}
            </table>
        </div>
    </div>
</body>
</html>
"""

# -------- Run --------
if __name__ == "__main__":
    import os
    if os.environ.get('SECUREGUARD_DEV', '0') == '1':
        app.run(host="0.0.0.0", port=5000, debug=True)
