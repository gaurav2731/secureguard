import os
import sqlite3
import logging
import threading
import time
import random
import re
import ipaddress
import requests
import json
import psutil
import hashlib
from datetime import datetime, timezone, timedelta
from collections import OrderedDict
from threading import Lock, Thread
import queue
from flask import Flask, render_template, request, jsonify, abort, url_for, redirect
import smtplib

# Import our Redis connection 
import redis
from redis_connection import redis_conn, RedisError

app = Flask(__name__)

# Configure basic Flask settings
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['FLASK_ENV'] = 'development'
app.config['DEBUG'] = True

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/secureguard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('secureguard')

# Use redis_conn from redis_connection module

from email.mime.text import MIMEText
from collections import defaultdict
from functools import wraps
import socket
import struct

# Performance Configuration
CACHE_SIZE = 100000  # Number of entries to keep in memory
BATCH_SIZE = 1000    # Number of records to write at once
FLUSH_INTERVAL = 5   # Seconds between database flushes

# Redis keys
PACKET_COUNT_KEY = "firewall:packet_count"
MAX_PACKETS_KEY = "firewall:max_packets"
DEFAULT_MAX_PACKETS = 2000000

class LRUCache:
    def __init__(self, capacity):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = Lock()
    
    def get(self, key):
        with self.lock:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]
    
    def put(self, key, value):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)
from urllib.parse import urlparse
import subprocess
import platform

# --------------------
# Config
# --------------------
DB_FILE = "secureguard.db"
LOG_FILE = "logs/secureguard.log"
MEMORY_DB = ":memory:"  # In-memory database for high-speed operations

EMAIL_FROM = "rsrsrsg369@gmail.com"
EMAIL_TO = "gaurav78969@gmail.com"
EMAIL_PASS = "xdpi pvxy ftqu suyt"   # Gmail app password

# Performance Configuration
CACHE_SIZE = 100000  # Number of entries to keep in memory
BATCH_SIZE = 1000    # Number of records to write at once
FLUSH_INTERVAL = 5   # Seconds between database flushes

# Firewall Config
RATE_LIMIT = 100  # requests per minute
RATE_WINDOW = 60  # seconds
BLOCK_DURATION = 3600  # 1 hour in seconds

# Advanced Protection Config
PACKET_INSPECTION_ENABLED = True
DDoS_THRESHOLD = 1000  # requests per minute
SYN_FLOOD_THRESHOLD = 500  # SYN packets per minute
THREAT_INTELLIGENCE_UPDATE_INTERVAL = 3600  # 1 hour

# Known malicious patterns
KNOWN_ATTACK_PATTERNS = {
    'shell_commands': [
        'cat ', 'rm -rf', 'wget ', 'curl ', '> /dev/null',
        'bash -i', 'nc -e', 'python -c', '/etc/passwd'
    ],
    'exploits': [
        '../../../', '<?php', '<%', 'eval(', 'exec(',
        'system(', 'passthru(', 'shell_exec('
    ],
    'web_attacks': [
        'union select', 'information_schema', 'load_file',
        'document.cookie', 'onmouseover=', 'onerror=',
        '<script>', 'alert(', 'prompt(', 'confirm('
    ]
}

# Threat Intelligence
KNOWN_MALICIOUS_IPS = set()
KNOWN_BOT_SIGNATURES = set()
TOR_EXIT_NODES = set()
VPNS_PROXIES = set()

# Traffic Patterns
LEGITIMATE_TRAFFIC_PATTERNS = {
    'user_agents': set(),
    'request_intervals': [],
    'typical_paths': set()
}

# System commands for different OS
FIREWALL_COMMANDS = {
    'Windows': {
        'block': 'netsh advfirewall firewall add rule name="SECUREGUARD_BLOCK_{}" dir=in action=block remoteip={}',
        'unblock': 'netsh advfirewall firewall delete rule name="SECUREGUARD_BLOCK_{}"'
    },
    'Linux': {
        'block': 'iptables -A INPUT -s {} -j DROP',
        'unblock': 'iptables -D INPUT -s {} -j DROP'
    }
}

# Attack patterns
SQL_INJECTION_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
]

XSS_PATTERNS = [
    r"<[^>]*script.*?>",
    r"<[^>]*javascript.*?>",
    r"javascript:",
    r"onload=",
    r"onerror=",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\.\/",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    r"..%2f",
    r"..%5c",
]

# Request tracking
request_counts = defaultdict(list)  # IP -> [timestamp1, timestamp2, ...]
# Thread-safety locks for shared structures
request_counts_lock = Lock()
blocked_ips = set()  # Currently blocked IPs
blocked_ips_lock = Lock()
temp_blocked_until = {}  # IP -> unblock_time
temp_blocked_lock = Lock()

# Queues for async DB writes and system-level blocking
db_write_queue = queue.Queue()
system_block_queue = queue.Queue()

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
    # Create a connection and apply the same PRAGMAs used by get_db_connection
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    try:
        conn.execute('PRAGMA journal_mode = WAL;')
        conn.execute('PRAGMA synchronous = NORMAL;')
        conn.execute('PRAGMA temp_store = MEMORY;')
        conn.execute(f'PRAGMA cache_size = {-CACHE_SIZE};')
    except Exception:
        pass
    c = conn.cursor()
    # base table
    c.execute("CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY, ip TEXT, ts TEXT, status TEXT)")
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    """Return a sqlite3 connection with tuned pragmas for WAL and performance."""
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    try:
        conn.execute('PRAGMA journal_mode = WAL;')
        conn.execute('PRAGMA synchronous = NORMAL;')
        conn.execute('PRAGMA temp_store = MEMORY;')
        # cache_size negative sets size in KB; tune as needed
        conn.execute(f'PRAGMA cache_size = {-CACHE_SIZE};')
    except Exception:
        pass
    return conn


def db_writer_worker():
    """Background worker that batches DB writes from db_write_queue."""
    batch = []
    last_flush = time.time()
    while True:
        try:
            try:
                # collect up to BATCH_SIZE items without blocking
                while len(batch) < BATCH_SIZE:
                    item = db_write_queue.get(timeout=FLUSH_INTERVAL)
                    batch.append(item)
            except queue.Empty:
                pass

            if batch and (len(batch) >= BATCH_SIZE or (time.time() - last_flush) >= FLUSH_INTERVAL):
                conn = get_db_connection()
                try:
                    conn.executemany("INSERT INTO blocked_ips (ip, ts, status) VALUES (?, ?, ?)", batch)
                    conn.commit()
                except Exception as e:
                    logger.error(f"DB writer commit failed: {e}")
                finally:
                    conn.close()
                batch.clear()
                last_flush = time.time()
        except Exception as e:
            logger.error(f"DB writer worker error: {e}")
            time.sleep(1)


def system_block_worker():
    """Worker that processes system-level block requests from system_block_queue.
    Throttles system calls to avoid flooding the OS with subprocess calls.
    """
    while True:
        try:
            ip = system_block_queue.get()
            try:
                SystemDefense.block_ip_system_level(ip)
            except Exception as e:
                logger.error(f"System block worker failed for {ip}: {e}")
            # throttle between system calls; tune as necessary
            time.sleep(0.05)
        except Exception as e:
            logger.error(f"System block worker loop error: {e}")
            time.sleep(1)


# Minimal Firewall class (keeps counters and placeholder methods)
class Firewall:
    def __init__(self):
        self.max_packets = DEFAULT_MAX_PACKETS
        self.lock = Lock()
        
        # Initialize counters
        redis_conn.set('packet_count', 0)
        redis_conn.set('max_packets', DEFAULT_MAX_PACKETS)

    def get_packet_count(self):
        return redis_conn.get_packet_count()

    def increment_packet_count(self, n=1):
        if redis_client:
            try:
                with self.lock:  # Still use lock for consistency
                    current = redis_client.incrby(PACKET_COUNT_KEY, n)
                    return current
            except RedisError as e:
                logging.error(f"Redis increment error: {e}")
                return 0
        return 0

    def is_over_capacity(self):
        if redis_client:
            try:
                current = int(redis_client.get(PACKET_COUNT_KEY) or 0)
                max_packets = int(redis_client.get(MAX_PACKETS_KEY) or DEFAULT_MAX_PACKETS)
                return current >= max_packets
            except RedisError as e:
                logging.error(f"Redis capacity check error: {e}")
                return False
        return False

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
# Advanced Defense Functions
# --------------------
class ThreatIntelligence:
    @staticmethod
    def update_threat_intelligence():
        """Update threat intelligence from various sources"""
        try:
            # Update Tor exit nodes
            tor_exits = requests.get('https://check.torproject.org/exit-addresses').text
            TOR_EXIT_NODES.update(re.findall(r'ExitAddress (\d+\.\d+\.\d+\.\d+)', tor_exits))

            # Update known malicious IPs (example source)
            mal_ips = requests.get('https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt').text
            KNOWN_MALICIOUS_IPS.update(line.strip() for line in mal_ips.splitlines() if line.strip())

            logger.info("Updated threat intelligence successfully")
        except Exception as e:
            logger.error(f"Failed to update threat intelligence: {e}")

class PacketInspector:
    @staticmethod
    def inspect_packet(data, ip):
        """Deep packet inspection"""
        # Convert data to string for inspection
        data_str = str(data)
        
        # Check for known malicious patterns
        for category, patterns in KNOWN_ATTACK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in data_str.lower():
                    logger.warning(f"Malicious pattern detected from {ip}: {pattern}")
                    return False, f"Malicious {category} pattern detected"
        
        return True, None

class SystemDefense:
    @staticmethod
    def block_ip_system_level(ip):
        """Block IP at system firewall level"""
        try:
            os_type = platform.system()
            if os_type in FIREWALL_COMMANDS:
                cmd = FIREWALL_COMMANDS[os_type]['block'].format(ip.replace('.', '_'), ip)
                subprocess.run(cmd, shell=True, check=True)
                logger.info(f"Blocked IP {ip} at system level")
                return True
        except Exception as e:
            logger.error(f"Failed to block IP at system level: {e}")
        return False

    @staticmethod
    def unblock_ip_system_level(ip):
        """Unblock IP at system firewall level"""
        try:
            os_type = platform.system()
            if os_type in FIREWALL_COMMANDS:
                cmd = FIREWALL_COMMANDS[os_type]['unblock'].format(ip.replace('.', '_'))
                subprocess.run(cmd, shell=True, check=True)
                logger.info(f"Unblocked IP {ip} at system level")
                return True
        except Exception as e:
            logger.error(f"Failed to unblock IP at system level: {e}")
        return False

# --------------------
# Firewall Functions
# --------------------
def is_ip_blocked(ip):
    """Check if an IP is blocked"""
    # Check internal blocks
    if ip in blocked_ips:
        return True
    if ip in temp_blocked_until:
        if datetime.now(timezone.utc) < temp_blocked_until[ip]:
            return True
        else:
            # Unblock expired temporary blocks
            del temp_blocked_until[ip]
            SystemDefense.unblock_ip_system_level(ip)
    
    # Check threat intelligence
    if ip in KNOWN_MALICIOUS_IPS or ip in TOR_EXIT_NODES:
        return True
    
    return False

def analyze_traffic_pattern(ip, request_data):
    """Analyze traffic patterns for anomalies"""
    now = datetime.now(timezone.utc)
    times = request_counts[ip]
    
    # Calculate request frequency
    while times and (now - times[0]).total_seconds() > RATE_WINDOW:
        times.pop(0)
    times.append(now)
    
    analysis = {
        'frequency': len(times),
        'is_suspicious': False,
        'reason': []
    }
    
    # Check rate limits
    if len(times) > RATE_LIMIT:
        analysis['is_suspicious'] = True
        analysis['reason'].append('Rate limit exceeded')
    
    # Check for DDoS
    if len(times) > DDoS_THRESHOLD:
        analysis['is_suspicious'] = True
        analysis['reason'].append('Potential DDoS attack')
    
    # Analyze request patterns
    user_agent = request.headers.get('User-Agent', '')
    if not user_agent or user_agent in KNOWN_BOT_SIGNATURES:
        analysis['is_suspicious'] = True
        analysis['reason'].append('Suspicious User-Agent')
    
    # Check for rapid identical requests
    if times and len(times) > 10:
        intervals = [(times[i] - times[i-1]).total_seconds() for i in range(1, len(times))]
        if all(i < 0.1 for i in intervals):  # Too regular to be human
            analysis['is_suspicious'] = True
            analysis['reason'].append('Bot-like behavior')
    
    return analysis

def check_rate_limit(ip):
    """Enhanced rate limiting with pattern analysis"""
    analysis = analyze_traffic_pattern(ip, request)
    
    if analysis['is_suspicious']:
        logger.warning(f"Suspicious traffic from {ip}: {', '.join(analysis['reason'])}")
        
        # Determine block duration based on severity
        if 'DDoS' in str(analysis['reason']):
            block_duration = 24 * 3600  # 24 hours for DDoS
        elif 'Bot-like behavior' in str(analysis['reason']):
            block_duration = 12 * 3600  # 12 hours for bots
        else:
            block_duration = 3600  # 1 hour for other violations
        
        block_ip(ip, block_duration)
        return True
    
    return False

def block_ip(ip, duration=BLOCK_DURATION):
    """Block an IP temporarily"""
    with temp_blocked_lock:
        temp_blocked_until[ip] = datetime.now(timezone.utc) + timedelta(seconds=duration)
    logger.warning(f"Blocked IP {ip} for {duration} seconds")

    # Enqueue DB write and system block instead of doing it inline
    ts = datetime.now(timezone.utc).isoformat()
    try:
        db_write_queue.put((ip, ts, "BLOCKED"))
    except Exception as e:
        logger.error(f"Failed to enqueue DB write for {ip}: {e}")

    # Enqueue system-level block but non-blocking
    try:
        system_block_queue.put(ip)
    except Exception as e:
        logger.error(f"Failed to enqueue system block for {ip}: {e}")

    # Send alert asynchronously (non-blocking)
    Thread(target=lambda: send_email_alert("🚨 IP Blocked", f"IP {ip} has been blocked for {duration} seconds"), daemon=True).start()

def check_attack_patterns(request_data):
    """Check request for common attack patterns"""
    # Combine all request data
    data_to_check = [
        request.url,
        str(request.headers),
        str(request.form),
        str(request.args)
    ]
    
    # Check SQL injection
    for pattern in SQL_INJECTION_PATTERNS:
        if any(re.search(pattern, d, re.I) for d in data_to_check):
            return True, "SQL Injection Attempt"
            
    # Check XSS
    for pattern in XSS_PATTERNS:
        if any(re.search(pattern, d, re.I) for d in data_to_check):
            return True, "XSS Attempt"
            
    # Check Path Traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if any(re.search(pattern, d, re.I) for d in data_to_check):
            return True, "Path Traversal Attempt"
            
    return False, None

def firewall_middleware():
    """Enhanced real-time firewall protection"""
    ip = request.remote_addr
    
    # Allow localhost and internal testing
    if ip in ('127.0.0.1', 'localhost', '::1'):
        logger.debug(f"Allowing local request from {ip}")
        return

    try:
        # 1. Quick Check Phase
        if is_ip_blocked(ip):
            logger.warning(f"Blocked request from banned IP: {ip}")
            abort(403)  # Forbidden

        # 2. Threat Intelligence Check
        if ip in KNOWN_MALICIOUS_IPS:
            logger.error(f"Known malicious IP detected: {ip}")
            SystemDefense.block_ip_system_level(ip)
            abort(403)

        # 3. Traffic Pattern Analysis
        if check_rate_limit(ip):
            logger.warning(f"Suspicious traffic pattern from IP: {ip}")
            abort(429)  # Too Many Requests

        # 4. Deep Packet Inspection
        if PACKET_INSPECTION_ENABLED:
            # Gather request data for inspection
            request_data = {
                'headers': dict(request.headers),
                'url': request.url,
                'method': request.method,
                'args': dict(request.args),
                'form': dict(request.form),
                'cookies': dict(request.cookies)
            }
            
            is_safe, reason = PacketInspector.inspect_packet(request_data, ip)
            if not is_safe:
                logger.error(f"Malicious payload detected from {ip}: {reason}")
                SystemDefense.block_ip_system_level(ip)
                abort(400)

        # 5. Attack Pattern Detection
        is_attack, attack_type = check_attack_patterns(request)
        if is_attack:
            logger.error(f"{attack_type} detected from {ip}")
            SystemDefense.block_ip_system_level(ip)
            block_ip(ip, duration=24*3600)  # Block for 24 hours
            abort(400)

        # 6. Request Sanitization
        if request.method in ['POST', 'PUT', 'PATCH']:
            # Calculate request body hash for duplicate detection
            content = request.get_data()
            content_hash = hashlib.md5(content).hexdigest()
            
            # Check for repeated identical requests (CSRF/Replay attacks)
            request_key = f"{ip}:{content_hash}"
            if request_key in request_counts:
                logger.warning(f"Possible replay attack from {ip}")
                abort(400)
            
            request_counts[request_key] = now = datetime.now(timezone.utc)
            
            # Clean old entries
            for key in list(request_counts.keys()):
                if (now - request_counts[key]).total_seconds() > RATE_WINDOW:
                    del request_counts[key]

    except Exception as e:
        logger.error(f"Firewall error processing request from {ip}: {e}")
        abort(500)  # Internal Server Error

# --------------------
# Flask App: single instance and a single index/dashboard route
# --------------------
app = Flask(__name__)

# Global firewall object (initialized in __main__ or before_first_request)
firewall = None


@app.before_request
def before_request():
    """Apply firewall middleware before each request"""
    return firewall_middleware()


# Routes moved to routes.py

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
        # Generate multiple packets in each iteration for higher throughput
        for _ in range(50):  # Process 50 packets per batch
            ip = f"10.0.0.{random.randint(1, 255)}"
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
        
        # Sleep for a very short duration between batches
        time.sleep(0.1)  # This will allow processing ~500,000 packets per second

# Auto-generate logs is disabled by default to avoid spamming DB during tests.
# To enable for load testing, uncomment the following line.
# threading.Thread(target=auto_generate_logs, daemon=True).start()

# --------------------
# Background Tasks
# --------------------
def update_threat_intelligence_loop():
    """Continuously update threat intelligence"""
    while True:
        ThreatIntelligence.update_threat_intelligence()
        time.sleep(THREAT_INTELLIGENCE_UPDATE_INTERVAL)

def monitor_system_resources():
    """Monitor system resources and adjust protection"""
    while True:
        try:
            # Check system load
            cpu_usage = psutil.cpu_percent()
            mem_usage = psutil.virtual_memory().percent
            
            # Adjust packet inspection based on system load
            global PACKET_INSPECTION_ENABLED
            if cpu_usage > 90 or mem_usage > 90:
                PACKET_INSPECTION_ENABLED = False
                logger.warning("Disabled packet inspection due to high system load")
            else:
                PACKET_INSPECTION_ENABLED = True
            
            time.sleep(60)  # Check every minute
        except Exception as e:
            logger.error(f"Error monitoring system resources: {e}")
            time.sleep(60)

def start_services():
    """Start background workers and initialize services.

    This function is safe to call when the module is imported. It does NOT
    start the Flask development server; that is left to the runner (server.py)
    or to a developer running the module directly.
    """
    # Start background tasks
    threading.Thread(target=update_threat_intelligence_loop, daemon=True).start()
    threading.Thread(target=monitor_system_resources, daemon=True).start()

    # Start DB writer and system block worker
    threading.Thread(target=db_writer_worker, daemon=True).start()
    threading.Thread(target=system_block_worker, daemon=True).start()

    # Initialize threat intelligence
    ThreatIntelligence.update_threat_intelligence()

    # Initialize firewall and services
    firewall = Firewall()
    logger.info("SecureGuard Firewall initialized with real-time protection")

    # Configure Redis connection with proper error handling
    global redis_client
    try:
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        redis_client.ping()
        logger.info("Redis connection successful")
    except redis.RedisError as e:
        logger.warning(f"Redis connection failed, falling back to in-memory counters: {e}")
        redis_client = None

    # Initialize threat intelligence again (ensure caches filled)
    ThreatIntelligence.update_threat_intelligence()
    logger.info("SecureGuard Firewall initialized with real-time protection")


# Preserve backward compatible behavior for developers who run app.py directly.
# Use the SECUREGUARD_DEV env var to explicitly enable the built-in Flask dev server.
if __name__ == "__main__":
    start_services()
    if os.environ.get('SECUREGUARD_DEV', '0') == '1':
        logger.info("Starting Flask development server on http://localhost:5000")
        app.run(debug=True, host='0.0.0.0', port=5000)
