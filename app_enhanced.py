"""
SecureGuard Enhanced Firewall Application
Ultra-Advanced with ML Detection, Clustering, Load Balancing, and Real-time Threat Intelligence
"""
import os
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
import threading
import time
import random
import re
import ipaddress
import requests
import json
import psutil
import hashlib
import numpy as np
from datetime import datetime, timezone, timedelta
from collections import OrderedDict, defaultdict, deque
from threading import Lock, Thread
import queue
import uuid
import socket
from flask import Flask, render_template, request, jsonify, abort, url_for, redirect
import smtplib
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor
import warnings
warnings.filterwarnings('ignore')

# Enhanced imports for advanced features
CORS_ENABLED = False

# Import configuration first
from config_enhanced import (  # type: ignore
    FIREWALL_CONFIG, SERVER_CONFIG, REDIS_CONFIG, PERFORMANCE_CONFIG,
    ML_CONFIG, SECURITY_CONFIG, MONITORING_CONFIG, CLUSTER_CONFIG,
    THREAT_INTELLIGENCE_CONFIG, PROTECTED_WEBSITES
)

# Import enhanced ML detector
try:
    from ml_detector import MLDetector
    ml_detector = MLDetector()
    ML_ENABLED = ML_CONFIG.get('enabled', False)
except ImportError:
    ml_detector = None
    ML_ENABLED = False

# Import enhanced Redis connection
from redis_connection import redis_conn  # type: ignore

# Import cluster manager
from cluster_manager import ClusterManager, LoadBalancer  # type: ignore

# Clustering and Load Balancing Configuration
CLUSTER_MODE = CLUSTER_CONFIG.get('enabled', False)
NODE_ID = CLUSTER_CONFIG.get('node_id', str(uuid.uuid4())[:8])
CLUSTER_NODES = CLUSTER_CONFIG.get('cluster_nodes', ['localhost:5000'])
HEARTBEAT_INTERVAL = CLUSTER_CONFIG.get('heartbeat_interval', 30)
NODE_TIMEOUT = CLUSTER_CONFIG.get('node_timeout', 120)

# Load Balancing Configuration
LOAD_BALANCER_ENABLED = True
LOAD_BALANCER_ALGORITHM = CLUSTER_CONFIG.get('load_balancer_algorithm', 'round_robin')
HEALTH_CHECK_INTERVAL = CLUSTER_CONFIG.get('health_check_interval', 10)

# Enhanced Async Processing
ASYNC_PROCESSING_ENABLED = True
MAX_WORKERS = PERFORMANCE_CONFIG.get('server_threads', 16)
REQUEST_TIMEOUT = 30

# Global instances
cluster_manager = None
load_balancer = None
thread_pool = None

# Initialize Flask app with enhanced configuration
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size

# Initialize template filters immediately after app creation
from filters import init_filters
init_filters(app)

# Also register datetime filter directly
from datetime import datetime
@app.template_filter('datetime')
def format_datetime(value, format="%Y-%m-%d %H:%M:%S"):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value)
    if isinstance(value, datetime):
        return value.strftime(format)
    return value

# Enhanced logging configuration
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/secureguard.log'),
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            'logs/secureguard.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
    ]
)
logger = logging.getLogger('secureguard')

# Performance and Security Configuration
CACHE_SIZE = PERFORMANCE_CONFIG.get('cache_size', 500000)
BATCH_SIZE = PERFORMANCE_CONFIG.get('batch_size', 1000)
FLUSH_INTERVAL = PERFORMANCE_CONFIG.get('flush_interval', 5)

# Enhanced Firewall Configuration
RATE_LIMIT = FIREWALL_CONFIG.get('rate_limit', 1000)
RATE_WINDOW = 60
BLOCK_DURATION = 3600
MAX_PACKETS_PER_MINUTE = FIREWALL_CONFIG.get('max_packets_per_minute', 5000000)

# Advanced Security Configuration
PACKET_INSPECTION_ENABLED = SECURITY_CONFIG.get('packet_inspection_enabled', True)
DDOS_THRESHOLD = SECURITY_CONFIG.get('ddos_threshold', 1000)
SYN_FLOOD_THRESHOLD = SECURITY_CONFIG.get('syn_flood_threshold', 500)
THREAT_INTELLIGENCE_UPDATE_INTERVAL = SECURITY_CONFIG.get('threat_intelligence_update', 1800)

# Enhanced Attack Patterns Database
ENHANCED_ATTACK_PATTERNS = {
    'sql_injection': [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"union.*select.*from", r"information_schema",
        r"concat.*0x", r"load_file", r"into.*dumpfile",
        r"script.*language.*plpgsql", r"declare.*varchar"
    ],
    'xss': [
        r"<script[^>]*>.*?</script>", r"javascript:",
        r"vbscript:", r"onload.*=", r"onerror.*=",
        r"<iframe[^>]*>", r"<object[^>]*>", r"<embed[^>]*>",
        r"document\.cookie", r"document\.write", r"eval\("
    ],
    'command_injection': [
        r";\s*(ls|cat|rm|wget|curl)", r"\|\s*(ls|cat|rm)",
        r"`.*`", r"\$\(.*\)", r"system\(", r"exec\(",
        r"passthru\(", r"shell_exec\(", r"popen\("
    ],
    'path_traversal': [
        r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%252e%252e%252f",
        r"..%2f", r"..%5c", r"%c0%ae%c0%ae", r"%uff0e%uff0e"
    ],
    'file_inclusion': [
        r"php://", r"data://", r"expect://", r"php://input",
        r"php://filter", r"zip://", r"phar://"
    ],
    'ssrf': [
        r"127\.0\.0\.1", r"localhost", r"169\.254\.",
        r"10\.0\.0", r"192\.168\.", r"172\.16\.",
        r"0\.0\.0\.0", r"metadata\.google\.internal"
    ],
    'xxe': [
        r"<!entity", r"system\s+.*file://", r"<!doctype",
        r"entity.*system", r"external.*entity"
    ],
    'deserialization': [
        r"O:\d+:", r"phar://", r"php_unserialize",
        r"unserialize\(", r"yaml_parse", r"json_decode"
    ]
}

# Threat Intelligence Databases
THREAT_DATABASES = {
    'malicious_ips': set(),
    'bot_signatures': set(),
    'tor_exit_nodes': set(),
    'vpn_proxies': set(),
    'malware_hashes': set(),
    'suspicious_domains': set()
}

# Enhanced Traffic Analysis
TRAFFIC_PATTERNS = {
    'legitimate_user_agents': set(),
    'request_intervals': deque(maxlen=10000),
    'typical_paths': set(),
    'normal_response_sizes': deque(maxlen=1000),
    'legitimate_referers': set()
}

# System Commands for Multi-Platform Firewall Management
ENHANCED_FIREWALL_COMMANDS = {
    'Windows': {
        'block': 'netsh advfirewall firewall add rule name="SECUREGUARD_BLOCK_{}" dir=in action=block remoteip={} protocol=TCP',
        'unblock': 'netsh advfirewall firewall delete rule name="SECUREGUARD_BLOCK_{}"',
        'block_udp': 'netsh advfirewall firewall add rule name="SECUREGUARD_BLOCK_UDP_{}" dir=in action=block remoteip={} protocol=UDP',
        'block_port': 'netsh advfirewall firewall add rule name="SECUREGUARD_BLOCK_PORT_{}_{}" dir=in action=block remoteip={} protocol=TCP localport={}'
    },
    'Linux': {
        'block': 'iptables -I INPUT -s {} -j DROP',
        'unblock': 'iptables -D INPUT -s {} -j DROP',
        'block_udp': 'iptables -I INPUT -s {} -p udp -j DROP',
        'block_port': 'iptables -I INPUT -s {} -p tcp --dport {} -j DROP'
    },
    'macOS': {
        'block': 'pfctl -t secureguard_blocked -T add {}',
        'unblock': 'pfctl -t secureguard_blocked -T delete {}',
        'block_udp': 'echo "block drop in proto udp from {} to any" >> /etc/pf.conf',
        'block_port': 'echo "block drop in proto tcp from {} to any port {}" >> /etc/pf.conf'
    }
}

# Enhanced Request Tracking with ML Features
request_counts = defaultdict(lambda: deque(maxlen=1000))  # IP -> timestamps
behavior_cache = defaultdict(lambda: {
    'requests': deque(maxlen=100),
    'threat_score': 0.0,
    'last_seen': 0,
    'user_agent': '',
    'request_patterns': deque(maxlen=50),
    'response_times': deque(maxlen=50),
    'geolocation': None,
    'behavior_profile': {}
})

# Thread-safety locks
locks = {
    'request_counts': Lock(),
    'behavior_cache': Lock(),
    'blocked_ips': Lock(),
    'threat_intelligence': Lock()
}

# Enhanced Blocking System
blocked_ips = {
    'permanent': set(),
    'temporary': {},  # IP -> unblock_time
    'geo_blocked': set(),
    'behavior_blocked': {}  # IP -> block_reason
}

# Queues for Async Processing
processing_queues = {
    'db_writes': queue.Queue(),
    'system_blocks': queue.Queue(),
    'threat_updates': queue.Queue(),
    'ml_training': queue.Queue(),
    'alerts': queue.Queue()
}

# Database Configuration
DB_CONFIG = {
    'file': 'secureguard.db',
    'timeout': 30,
    'cache_size': CACHE_SIZE,
    'journal_mode': 'WAL',
    'synchronous': 'NORMAL',
    'temp_store': 'MEMORY'
}

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'from_addr': os.environ.get('SECUREGUARD_EMAIL_FROM', 'alerts@secureguard.com'),
    'to_addr': os.environ.get('SECUREGUARD_EMAIL_TO', 'admin@secureguard.com'),
    'password': os.environ.get('SECUREGUARD_EMAIL_PASS', ''),
    'tls': True
}

# Initialize Database
def init_enhanced_db():
    """Initialize enhanced database with optimized settings"""
    conn = sqlite3.connect(
        DB_CONFIG['file'],
        timeout=DB_CONFIG['timeout'],
        check_same_thread=False
    )

    try:
        # Performance optimizations
        conn.execute(f'PRAGMA journal_mode = {DB_CONFIG["journal_mode"]};')
        conn.execute(f'PRAGMA synchronous = {DB_CONFIG["synchronous"]};')
        conn.execute(f'PRAGMA temp_store = {DB_CONFIG["temp_store"]};')
        conn.execute(f'PRAGMA cache_size = {-DB_CONFIG["cache_size"]};')
        conn.execute('PRAGMA mmap_size = 268435456;')  # 256MB
        conn.execute('PRAGMA page_size = 4096;')

        cursor = conn.cursor()

        # Enhanced tables
        tables = {
            'blocked_ips': '''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    block_type TEXT DEFAULT 'temporary',
                    duration INTEGER DEFAULT 3600,
                    reason TEXT,
                    threat_score REAL DEFAULT 0.0,
                    user_agent TEXT,
                    country TEXT,
                    asn TEXT,
                    UNIQUE(ip, timestamp)
                )
            ''',
            'traffic_logs': '''
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    method TEXT,
                    url TEXT,
                    status_code INTEGER,
                    response_size INTEGER,
                    user_agent TEXT,
                    processing_time REAL,
                    threat_score REAL DEFAULT 0.0
                )
            ''',
            'threat_intelligence': '''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source TEXT,
                    timestamp REAL NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    UNIQUE(indicator, type)
                )
            ''',
            'ml_training_data': '''
                CREATE TABLE IF NOT EXISTS ml_training_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    features TEXT NOT NULL,
                    label INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    source TEXT
                )
            ''',
            'system_metrics': '''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    cpu_usage REAL,
                    memory_usage REAL,
                    network_rx REAL,
                    network_tx REAL,
                    active_connections INTEGER,
                    queue_size INTEGER
                )
            '''
        }

        for table_name, create_sql in tables.items():
            cursor.execute(create_sql)

        # Create indexes for performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);',
            'CREATE INDEX IF NOT EXISTS idx_blocked_ips_timestamp ON blocked_ips(timestamp);',
            'CREATE INDEX IF NOT EXISTS idx_traffic_logs_ip ON traffic_logs(ip);',
            'CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);',
            'CREATE INDEX IF NOT EXISTS idx_threat_intelligence_type ON threat_intelligence(type);',
            'CREATE INDEX IF NOT EXISTS idx_ml_training_timestamp ON ml_training_data(timestamp);'
        ]

        for index_sql in indexes:
            cursor.execute(index_sql)

        conn.commit()
        logger.info("Enhanced database initialized successfully")

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()

# Initialize database
init_enhanced_db()

def get_enhanced_db_connection():
    """Get enhanced database connection with optimizations"""
    conn = sqlite3.connect(
        DB_CONFIG['file'],
        timeout=DB_CONFIG['timeout'],
        check_same_thread=False
    )

    try:
        conn.execute(f'PRAGMA journal_mode = {DB_CONFIG["journal_mode"]};')
        conn.execute(f'PRAGMA synchronous = {DB_CONFIG["synchronous"]};')
        conn.execute(f'PRAGMA temp_store = {DB_CONFIG["temp_store"]};')
        conn.execute(f'PRAGMA cache_size = {-DB_CONFIG["cache_size"]};')
        conn.row_factory = sqlite3.Row
    except Exception:
        pass

    return conn

# Enhanced Background Workers
def enhanced_db_writer_worker():
    """Enhanced database writer with batching and error recovery"""
    batch = []
    last_flush = time.time()

    while True:
        try:
            # Collect items with timeout
            while len(batch) < BATCH_SIZE:
                try:
                    item = processing_queues['db_writes'].get(timeout=FLUSH_INTERVAL)
                    batch.append(item)
                except queue.Empty:
                    break

            # Flush batch if full or time elapsed
            if batch and (len(batch) >= BATCH_SIZE or (time.time() - last_flush) >= FLUSH_INTERVAL):
                conn = get_enhanced_db_connection()
                try:
                    conn.executemany('''
                        INSERT OR REPLACE INTO blocked_ips
                        (ip, timestamp, block_type, duration, reason, threat_score, user_agent)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', batch)
                    conn.commit()
                    logger.debug(f"Inserted {len(batch)} records to database")
                except Exception as e:
                    logger.error(f"Database batch insert failed: {e}")
                    # Retry individual inserts
                    for item in batch:
                        try:
                            conn.execute('''
                                INSERT OR REPLACE INTO blocked_ips
                                (ip, timestamp, block_type, duration, reason, threat_score, user_agent)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', item)
                            conn.commit()
                        except Exception as e2:
                            logger.error(f"Individual insert failed: {e2}")
                finally:
                    conn.close()

                batch.clear()
                last_flush = time.time()

        except Exception as e:
            logger.error(f"Database writer worker error: {e}")
            time.sleep(1)

def enhanced_system_block_worker():
    """Enhanced system-level blocking with multi-platform support"""
    while True:
        try:
            block_request = processing_queues['system_blocks'].get()
            ip, block_type, duration = block_request

            success = SystemDefense.block_ip_system_level(ip, block_type, duration)
            if success:
                logger.info(f"Successfully blocked {ip} at system level")
            else:
                logger.error(f"Failed to block {ip} at system level")

            time.sleep(0.05)  # Rate limiting

        except Exception as e:
            logger.error(f"System block worker error: {e}")
            time.sleep(1)

def enhanced_threat_intelligence_worker():
    """Enhanced threat intelligence updater"""
    while True:
        try:
            ThreatIntelligence.update_all_sources()
            time.sleep(THREAT_INTELLIGENCE_UPDATE_INTERVAL)
        except Exception as e:
            logger.error(f"Threat intelligence update error: {e}")
            time.sleep(60)

def enhanced_ml_training_worker():
    """ML model retraining worker"""
    while True:
        try:
            if ML_ENABLED and ml_detector:
                # Check if retraining is needed
                if ml_detector.should_retrain():
                    logger.info("Retraining ML model...")
                    ml_detector.retrain_model()
                    logger.info("ML model retrained successfully")

            time.sleep(ML_CONFIG.get('retraining_interval', 3600))

        except Exception as e:
            logger.error(f"ML training worker error: {e}")
            time.sleep(60)

def enhanced_monitoring_worker():
    """System monitoring and metrics collection"""
    while True:
        try:
            metrics = collect_system_metrics()
            store_system_metrics(metrics)

            # Adjust performance based on system load
            adjust_performance_settings(metrics)

            time.sleep(60)

        except Exception as e:
            logger.error(f"Monitoring worker error: {e}")
            time.sleep(60)

# Enhanced Email Alerting
def send_enhanced_email_alert(subject, body, alert_type='info', metadata=None):
    """Enhanced email alerting with categorization"""
    try:
        if not EMAIL_CONFIG['password']:
            logger.warning("Email password not configured, skipping alert")
            return

        msg = MIMEText(f"{body}\n\nMetadata: {json.dumps(metadata or {}, indent=2)}")
        msg['From'] = EMAIL_CONFIG['from_addr']
        msg['To'] = EMAIL_CONFIG['to_addr']
        msg['Subject'] = f"[{alert_type.upper()}] {subject}"

        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            if EMAIL_CONFIG['tls']:
                server.starttls()
            server.login(EMAIL_CONFIG['from_addr'], EMAIL_CONFIG['password'])
            server.send_message(msg)

        logger.info(f"Enhanced email alert sent: {alert_type}")

    except Exception as e:
        logger.error(f"Enhanced email alert failed: {e}")

# Enhanced Threat Intelligence
class ThreatIntelligence:
    @staticmethod
    def update_all_sources():
        """Update all threat intelligence sources"""
        sources = [
            ('tor_exit_nodes', THREAT_INTELLIGENCE_CONFIG['sources']['tor_exit_nodes_url']),
            ('malicious_ips', THREAT_INTELLIGENCE_CONFIG['sources']['malicious_ips_url']),
        ]

        for threat_type, url in sources:
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    indicators = ThreatIntelligence.parse_indicators(response.text, threat_type)
                    ThreatIntelligence.update_database(indicators, threat_type, url)
                    logger.info(f"Updated {threat_type}: {len(indicators)} indicators")
            except Exception as e:
                logger.error(f"Failed to update {threat_type}: {e}")

    @staticmethod
    def parse_indicators(data, threat_type):
        """Parse indicators from various formats"""
        indicators = set()

        if threat_type == 'tor_exit_nodes':
            # Parse Tor exit node format (simple IP list)
            for line in data.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    indicators.add(line)

        elif threat_type == 'malicious_ips':
            # Parse various malicious IP list formats
            for line in data.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract IP addresses
                    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                    if ip_match:
                        indicators.add(ip_match.group())

        return indicators

    @staticmethod
    def update_database(indicators, threat_type, source):
        """Update threat intelligence database"""
        conn = get_enhanced_db_connection()
        try:
            timestamp = time.time()
            for indicator in indicators:
                conn.execute('''
                    INSERT OR REPLACE INTO threat_intelligence
                    (indicator, type, source, timestamp, confidence)
                    VALUES (?, ?, ?, ?, ?)
                ''', (indicator, threat_type, source, timestamp, 0.8))

            conn.commit()

            # Update in-memory cache
            with locks['threat_intelligence']:
                if threat_type == 'malicious_ips':
                    THREAT_DATABASES['malicious_ips'].update(indicators)
                elif threat_type == 'tor_exit_nodes':
                    THREAT_DATABASES['tor_exit_nodes'].update(indicators)

        except Exception as e:
            logger.error(f"Database update failed: {e}")
        finally:
            conn.close()

# Enhanced Packet Inspection
class EnhancedPacketInspector:
    @staticmethod
    def inspect_packet(packet_data, ip):
        """Comprehensive packet inspection with ML"""
        threats_found = []
        threat_score = 0.0

        # ML-based analysis
        if ML_ENABLED and ml_detector:
            ml_result = ml_detector.analyze_packet(packet_data)
            if ml_result['is_threat']:
                threats_found.append(f"ML Detection: {ml_result['threat_score']:.3f}")
                threat_score += ml_result['threat_score']

        # Pattern-based analysis
        pattern_results = EnhancedPacketInspector.check_attack_patterns(packet_data)
        threats_found.extend(pattern_results['threats'])
        threat_score += pattern_results['score']

        # Behavioral analysis
        behavioral_results = EnhancedPacketInspector.analyze_behavior(ip, packet_data)
        threats_found.extend(behavioral_results['threats'])
        threat_score += behavioral_results['score']

        # Threat intelligence check
        ti_results = EnhancedPacketInspector.check_threat_intelligence(ip, packet_data)
        threats_found.extend(ti_results['threats'])
        threat_score += ti_results['score']

        is_safe = threat_score < SECURITY_CONFIG.get('threat_threshold', 0.7)

        return {
            'is_safe': is_safe,
            'threat_score': threat_score,
            'threats_found': threats_found,
            'inspection_details': {
                'ml_analysis': ml_result if 'ml_result' in locals() else None,
                'pattern_analysis': pattern_results,
                'behavioral_analysis': behavioral_results,
                'threat_intelligence': ti_results
            }
        }

    @staticmethod
    def check_attack_patterns(packet_data):
        """Enhanced pattern matching"""
        threats = []
        score = 0.0

        data_to_check = [
            packet_data.get('url', ''),
            str(packet_data.get('headers', {})),
            str(packet_data.get('data', '')),
            str(packet_data.get('cookies', {}))
        ]

        combined_data = ' '.join(data_to_check).lower()

        for attack_type, patterns in ENHANCED_ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined_data, re.I):
                    threats.append(f"{attack_type.upper()}: {pattern}")
                    score += 0.2  # Weight for pattern matches
                    break  # Only count once per attack type

        return {'threats': threats, 'score': min(score, 1.0)}

    @staticmethod
    def analyze_behavior(ip, packet_data):
        """Behavioral analysis"""
        threats = []
        score = 0.0

        with locks['behavior_cache']:
            behavior = behavior_cache[ip]
            now = time.time()

            # Update behavior data
            behavior['requests'].append(now)
            behavior['last_seen'] = now

            # Clean old requests (keep last hour)
            cutoff = now - 3600
            behavior['requests'] = deque([t for t in behavior['requests'] if t > cutoff], maxlen=100)

            # Analyze patterns
            if len(behavior['requests']) > 10:
                intervals = np.diff(behavior['requests'])
                mean_interval = np.mean(intervals)
                std_interval = np.std(intervals)

                # Bot-like behavior: very regular intervals
                if std_interval < mean_interval * 0.1:
                    threats.append("Bot-like regular intervals")
                    score += 0.3

                # High frequency attacks
                recent_requests = sum(1 for t in behavior['requests'] if now - t < 60)
                if recent_requests > 100:
                    threats.append("High frequency requests")
                    score += 0.4

            # Threat score accumulation
            behavior['threat_score'] = min(1.0, behavior['threat_score'] * 0.95 + score * 0.05)

        return {'threats': threats, 'score': score}

    @staticmethod
    def check_threat_intelligence(ip, packet_data):
        """Check against threat intelligence"""
        threats = []
        score = 0.0

        with locks['threat_intelligence']:
            # Check IP against known malicious IPs
            if ip in THREAT_DATABASES['malicious_ips']:
                threats.append("Known malicious IP")
                score += 0.8

            if ip in THREAT_DATABASES['tor_exit_nodes']:
                threats.append("Tor exit node")
                score += 0.6

            # Check user agent against bot signatures
            user_agent = packet_data.get('headers', {}).get('User-Agent', '')
            if user_agent in THREAT_DATABASES['bot_signatures']:
                threats.append("Known bot signature")
                score += 0.5

        return {'threats': threats, 'score': score}

# Enhanced System Defense
class SystemDefense:
    @staticmethod
    def block_ip_system_level(ip, block_type='tcp', duration=None):
        """Enhanced multi-platform system-level blocking"""
        try:
            import platform
            os_type = platform.system()

            if os_type in ENHANCED_FIREWALL_COMMANDS:
                commands = ENHANCED_FIREWALL_COMMANDS[os_type]

                if block_type == 'tcp':
                    cmd = commands['block'].format(ip.replace('.', '_'), ip)
                elif block_type == 'udp':
                    cmd = commands['block_udp'].format(ip.replace('.', '_'), ip)
                else:
                    cmd = commands['block'].format(ip.replace('.', '_'), ip)

                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    logger.info(f"Successfully blocked {ip} at system level ({os_type})")
                    return True
                else:
                    logger.error(f"System block failed: {result.stderr}")
                    return False
            else:
                logger.warning(f"Unsupported OS for system blocking: {os_type}")
                return False

        except Exception as e:
            logger.error(f"System-level blocking failed for {ip}: {e}")
            return False

    @staticmethod
    def unblock_ip_system_level(ip):
        """Unblock IP at system level"""
        try:
            import platform
            os_type = platform.system()

            if os_type in ENHANCED_FIREWALL_COMMANDS:
                cmd = ENHANCED_FIREWALL_COMMANDS[os_type]['unblock'].format(ip.replace('.', '_'))
                import subprocess
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    logger.info(f"Successfully unblocked {ip} at system level")
                    return True
                else:
                    logger.error(f"System unblock failed: {result.stderr}")
                    return False

        except Exception as e:
            logger.error(f"System-level unblocking failed for {ip}: {e}")
            return False

# Enhanced Firewall Functions
def is_ip_blocked_enhanced(ip):
    """Enhanced IP blocking check"""
    # Check permanent blocks
    if ip in blocked_ips['permanent']:
        return True, "Permanent block"

    # Check temporary blocks
    if ip in blocked_ips['temporary']:
        unblock_time = blocked_ips['temporary'][ip]
        if datetime.now(timezone.utc) < unblock_time:
            return True, f"Temporary block until {unblock_time}"
        else:
            # Expired block, remove it
            del blocked_ips['temporary'][ip]
            SystemDefense.unblock_ip_system_level(ip)

    # Check geo-blocks
    if ip in blocked_ips['geo_blocked']:
        return True, "Geo-blocked"

    # Check behavior blocks
    if ip in blocked_ips['behavior_blocked']:
        return True, blocked_ips['behavior_blocked'][ip]

    return False, None

def analyze_traffic_pattern_enhanced(ip, request_data):
    """Enhanced traffic pattern analysis"""
    now = datetime.now(timezone.utc)
    timestamps = request_counts[ip]

    # Clean old timestamps
    cutoff = now - timedelta(seconds=RATE_WINDOW)
    while timestamps and timestamps[0] < cutoff:
        timestamps.popleft()

    timestamps.append(now)

    analysis = {
        'request_count': len(timestamps),
        'time_window': RATE_WINDOW,
        'rate_per_minute': len(timestamps),
        'is_suspicious': False,
        'threat_level': 'low',
        'reasons': []
    }

    # Rate limiting check
    if len(timestamps) > RATE_LIMIT:
        analysis['is_suspicious'] = True
        analysis['threat_level'] = 'medium'
        analysis['reasons'].append('Rate limit exceeded')

    # DDoS detection
    if len(timestamps) > DDOS_THRESHOLD:
        analysis['is_suspicious'] = True
        analysis['threat_level'] = 'high'
        analysis['reasons'].append('DDoS pattern detected')

    # SYN flood detection
    if len(timestamps) > SYN_FLOOD_THRESHOLD:
        analysis['is_suspicious'] = True
        analysis['threat_level'] = 'high'
        analysis['reasons'].append('SYN flood detected')

    # User agent analysis
    user_agent = request_data.headers.get('User-Agent', '')
    if not user_agent or len(user_agent) < 10:
        analysis['is_suspicious'] = True
        analysis['reasons'].append('Suspicious User-Agent')

    # Bot detection
    if user_agent.lower() in THREAT_DATABASES['bot_signatures']:
        analysis['is_suspicious'] = True
        analysis['threat_level'] = 'high'
        analysis['reasons'].append('Known bot signature')

    return analysis

def block_ip_enhanced(ip, duration=BLOCK_DURATION, reason="Suspicious activity", threat_score=0.0):
    """Enhanced IP blocking with detailed logging"""
    block_time = datetime.now(timezone.utc)
    unblock_time = block_time + timedelta(seconds=duration)

    with locks['blocked_ips']:
        if duration == 0:  # Permanent block
            blocked_ips['permanent'].add(ip)
            block_type = 'permanent'
        else:
            blocked_ips['temporary'][ip] = unblock_time
            block_type = 'temporary'

    # Log to database
    db_record = (ip, block_time.timestamp(), block_type, duration, reason, threat_score,
                request.headers.get('User-Agent', ''))
    processing_queues['db_writes'].put(db_record)

    # System-level block
    processing_queues['system_blocks'].put((ip, 'tcp', duration))

    # Send alert
    alert_data = {
        'ip': ip,
        'block_type': block_type,
        'duration': duration,
        'reason': reason,
        'threat_score': threat_score,
        'timestamp': block_time.isoformat()
    }
    processing_queues['alerts'].put(('IP Blocked', f"IP {ip} blocked: {reason}", 'warning', alert_data))

    logger.warning(f"Enhanced block: {ip} for {duration}s - {reason}")

def check_attack_patterns_enhanced(request_data):
    """Enhanced attack pattern detection"""
    threats_found = []
    severity_score = 0.0

    # Combine all request data
    data_parts = [
        request.url,
        str(dict(request.headers)),
        str(dict(request.form)),
        str(dict(request.args)),
        str(dict(request.cookies))
    ]
    combined_data = ' '.join(data_parts)

    # Check all attack patterns
    for attack_type, patterns in ENHANCED_ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined_data, re.I | re.MULTILINE):
                threats_found.append(f"{attack_type.replace('_', ' ').title()}: {pattern}")
                severity_score += 0.15  # Weight each pattern match
                break  # Only count once per attack type

    # Check for encoding attempts
    encoding_indicators = [r'%[0-9a-f]{2}', r'\\x[0-9a-f]{2}', r'\\u[0-9a-f]{4}']
    for indicator in encoding_indicators:
        if re.search(indicator, combined_data):
            threats_found.append(f"Encoding attempt: {indicator}")
            severity_score += 0.1

    return threats_found, severity_score

# Enhanced Firewall Middleware
def enhanced_firewall_middleware():
    """Ultra-advanced firewall middleware"""
    # Exempt health check endpoints from firewall checks
    if request.path in ['/health', '/api/health']:
        return

    ip = request.remote_addr
    start_time = time.time()

    # Allow localhost
    if ip in ('127.0.0.1', 'localhost', '::1'):
        return

    try:
        # 1. Basic IP Block Check
        is_blocked, block_reason = is_ip_blocked_enhanced(ip)
        if is_blocked:
            logger.warning(f"Request blocked - {block_reason}: {ip}")
            abort(403)

        # 2. Traffic Pattern Analysis
        traffic_analysis = analyze_traffic_pattern_enhanced(ip, request)
        if traffic_analysis['is_suspicious']:
            block_duration = 3600 if traffic_analysis['threat_level'] == 'high' else 1800
            block_ip_enhanced(ip, block_duration,
                            f"Traffic pattern: {', '.join(traffic_analysis['reasons'])}")
            abort(429)

        # 3. Threat Intelligence Check
        with locks['threat_intelligence']:
            if ip in THREAT_DATABASES['malicious_ips']:
                block_ip_enhanced(ip, 86400, "Known malicious IP", 0.9)
                abort(403)
            if ip in THREAT_DATABASES['tor_exit_nodes']:
                block_ip_enhanced(ip, 3600, "Tor exit node", 0.7)
                abort(403)

        # 4. Deep Packet Inspection
        if PACKET_INSPECTION_ENABLED:
            packet_data = {
                'ip': ip,
                'method': request.method,
                'url': request.url,
                'headers': dict(request.headers),
                'data': request.get_data(as_text=True, cache=False),
                'cookies': dict(request.cookies),
                'timestamp': start_time
            }

            inspection_result = EnhancedPacketInspector.inspect_packet(packet_data, ip)

            if not inspection_result['is_safe']:
                threat_score = inspection_result['threat_score']
                threats = inspection_result['threats_found']

                # Determine block duration based on threat score
                if threat_score > 0.8:
                    duration = 86400  # 24 hours
                    reason = f"High threat: {', '.join(threats[:3])}"
                elif threat_score > 0.6:
                    duration = 3600   # 1 hour
                    reason = f"Medium threat: {', '.join(threats[:3])}"
                else:
                    duration = 1800   # 30 minutes
                    reason = f"Low threat: {', '.join(threats[:3])}"

                block_ip_enhanced(ip, duration, reason, threat_score)
                abort(400)

        # 5. Attack Pattern Detection
        threats, severity = check_attack_patterns_enhanced(request)
        if threats:
            duration = 7200 if severity > 0.5 else 3600
            block_ip_enhanced(ip, duration, f"Attack pattern: {threats[0]}", severity)
            abort(400)

        # 6. Log legitimate traffic
        processing_time = time.time() - start_time
        log_data = (ip, start_time, request.method, request.url, 200,
                   len(request.get_data(cache=False)), request.headers.get('User-Agent', ''),
                   processing_time, 0.0)
        processing_queues['db_writes'].put(log_data)

    except Exception as e:
        logger.error(f"Firewall middleware error for {ip}: {e}")
        abort(500)

# Flask Routes
@app.before_request
def before_request():
    """Apply enhanced firewall middleware"""
    enhanced_firewall_middleware()

# Proxy functionality for protected websites
def get_backend_for_request():
    """Determine which backend to use based on request"""
    host = request.headers.get('Host', '').split(':')[0]

    # Check if request matches any configured backend
    for backend_name, backend_config in PROTECTED_WEBSITES.items():
        if backend_config.get('enabled', True):
            if backend_config.get('domain') == host or host == 'localhost':
                return backend_config

    # Default to 'default' backend
    return PROTECTED_WEBSITES.get('default', {})

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def proxy_request(path):
    """Proxy requests to protected backend websites"""
    try:
        # Get backend configuration
        backend = get_backend_for_request()
        if not backend:
            return jsonify({'error': 'No backend configured'}), 500

        # Build backend URL
        backend_ip = backend.get('ip', '127.0.0.1')
        backend_port = backend.get('port', 8080)
        use_ssl = backend.get('use_ssl', False)

        # Construct full URL
        scheme = 'https' if use_ssl else 'http'
        backend_url = f"{scheme}://{backend_ip}:{backend_port}"

        # Add path if provided
        if path:
            backend_url += f"/{path}"

        # Add query parameters
        if request.query_string:
            backend_url += f"?{request.query_string.decode('utf-8')}"

        # Prepare headers to forward (exclude host and some internal headers)
        headers_to_forward = {}
        for name, value in request.headers.items():
            if name.lower() not in ['host', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host']:
                headers_to_forward[name] = value

        # Add forwarded headers
        headers_to_forward['X-Forwarded-For'] = request.remote_addr
        headers_to_forward['X-Forwarded-Proto'] = request.scheme
        headers_to_forward['X-Forwarded-Host'] = request.headers.get('Host', '')

        # Prepare request data
        request_data = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            if request.content_type and 'application/json' in request.content_type:
                request_data = request.get_json()
            else:
                request_data = request.get_data()

        # Make request to backend
        response = requests.request(
            method=request.method,
            url=backend_url,
            headers=headers_to_forward,
            data=request_data,
            json=request_data if isinstance(request_data, dict) else None,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,  # Handle redirects manually
            verify=False  # For development; should be True in production
        )

        # Log the proxied request
        logger.info(f"Proxied {request.method} {request.url} -> {backend_url} (Status: {response.status_code})")

        # Prepare response headers (exclude some backend-specific headers)
        response_headers = {}
        for name, value in response.headers.items():
            if name.lower() not in ['server', 'date', 'content-length', 'transfer-encoding']:
                response_headers[name] = value

        # Return response
        return response.content, response.status_code, response_headers

    except requests.exceptions.Timeout:
        logger.error(f"Backend timeout for {request.url}")
        return jsonify({'error': 'Backend timeout'}), 504
    except requests.exceptions.ConnectionError:
        logger.error(f"Backend connection error for {request.url}")
        return jsonify({'error': 'Backend unavailable'}), 502
    except Exception as e:
        logger.error(f"Proxy error for {request.url}: {e}")
        return jsonify({'error': 'Proxy error'}), 500

@app.route('/')
def dashboard():
    """Enhanced main dashboard with real-time metrics"""
    try:
        # Get real-time statistics
        stats = get_realtime_stats()

        return render_template('dashboard.html',
            packet_count=stats['packet_count'],
            max_packets=MAX_PACKETS_PER_MINUTE,
            blocked_count=stats['blocked_count'],
            recent_blocks=stats['recent_blocks'][:10],
            protection_status=get_protection_status(),
            system_metrics=get_system_metrics(),
            threat_intelligence_stats=get_threat_stats(),
            ml_status=get_ml_status(),
            active_page='dashboard'
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html', error=str(e), active_page='dashboard')

@app.route('/control')
def control_panel():
    """Firewall control panel for managing rules and blocking"""
    try:
        # Get current firewall rules and settings
        conn = get_enhanced_db_connection()
        cursor = conn.cursor()

        # Get blocked IPs
        cursor.execute('SELECT ip, timestamp, reason, threat_score FROM blocked_ips ORDER BY timestamp DESC LIMIT 100')
        blocked_ips = cursor.fetchall()

        # Get whitelist/blacklist
        whitelist = FIREWALL_CONFIG.get('whitelist', [])
        blacklist = FIREWALL_CONFIG.get('blacklist', [])

        conn.close()

        return render_template('control_panel.html',
            blocked_ips=blocked_ips,
            whitelist=whitelist,
            blacklist=blacklist,
            firewall_config=FIREWALL_CONFIG,
            active_page='control'
        )
    except Exception as e:
        logger.error(f"Control panel error: {e}")
        return render_template('control_panel.html', error=str(e), active_page='control')

@app.route('/analytics')
def analytics():
    """Analytics and monitoring dashboard"""
    try:
        # Get detailed analytics data
        conn = get_enhanced_db_connection()
        cursor = conn.cursor()

        # Traffic patterns over time
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:00:00', datetime(timestamp, 'unixepoch')) as hour,
                   COUNT(*) as requests,
                   SUM(CASE WHEN threat_score > 0.5 THEN 1 ELSE 0 END) as threats
            FROM traffic_logs
            WHERE timestamp > strftime('%s', 'now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        ''')
        traffic_data = [dict(row) for row in cursor.fetchall()]

        # Top attacking IPs
        cursor.execute('''
            SELECT ip, COUNT(*) as attack_count, AVG(threat_score) as avg_threat
            FROM blocked_ips
            GROUP BY ip
            ORDER BY attack_count DESC
            LIMIT 20
        ''')
        top_attackers = [dict(row) for row in cursor.fetchall()]

        # Attack types distribution
        cursor.execute('''
            SELECT reason, COUNT(*) as count
            FROM blocked_ips
            WHERE reason IS NOT NULL
            GROUP BY reason
            ORDER BY count DESC
        ''')
        attack_types = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return render_template('analytics.html',
            traffic_data=traffic_data,
            top_attackers=top_attackers,
            attack_types=attack_types,
            active_page='analytics'
        )
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return render_template('analytics.html', error=str(e), active_page='analytics')

@app.route('/files')
def file_manager():
    """File manager for browsing and editing project files"""
    try:
        import os
        project_root = os.getcwd()

        # Get directory structure
        def get_directory_structure(path, max_depth=3, current_depth=0):
            if current_depth > max_depth:
                return None

            structure = {'name': os.path.basename(path), 'path': path, 'type': 'directory', 'children': []}

            try:
                items = os.listdir(path)
                for item in sorted(items):
                    if item.startswith('.') or item in ['__pycache__', 'node_modules', '.git']:
                        continue

                    item_path = os.path.join(path, item)
                    if os.path.isdir(item_path):
                        child = get_directory_structure(item_path, max_depth, current_depth + 1)
                        if child:
                            structure['children'].append(child)
                    else:
                        # Check if it's a code file
                        ext = os.path.splitext(item)[1].lower()
                        if ext in ['.py', '.js', '.html', '.css', '.json', '.md', '.txt', '.sh', '.yml', '.yaml']:
                            structure['children'].append({
                                'name': item,
                                'path': item_path,
                                'type': 'file',
                                'extension': ext
                            })
            except PermissionError:
                pass

            return structure

        file_structure = get_directory_structure(project_root)

        return render_template('file_manager.html',
            file_structure=file_structure,
            active_page='files'
        )
    except Exception as e:
        logger.error(f"File manager error: {e}")
        return render_template('file_manager.html', error=str(e), active_page='files')

@app.route('/threats')
def threat_intelligence():
    """Threat intelligence hub"""
    try:
        conn = get_enhanced_db_connection()
        cursor = conn.cursor()

        # Get threat intelligence stats
        cursor.execute('SELECT type, COUNT(*) as count FROM threat_intelligence GROUP BY type')
        threat_stats = cursor.fetchall()

        # Get recent threats
        cursor.execute('''
            SELECT indicator, type, source, timestamp, confidence
            FROM threat_intelligence
            ORDER BY timestamp DESC
            LIMIT 50
        ''')
        recent_threats = cursor.fetchall()

        # Get threat sources
        cursor.execute('SELECT source, COUNT(*) as count FROM threat_intelligence GROUP BY source')
        threat_sources = cursor.fetchall()

        conn.close()

        return render_template('threat_intel.html',
            threat_stats=threat_stats,
            recent_threats=recent_threats,
            threat_sources=threat_sources,
            active_page='threats'
        )
    except Exception as e:
        logger.error(f"Threat intelligence error: {e}")
        return render_template('threat_intel.html', error=str(e), active_page='threats')

@app.route('/system')
def system_monitor():
    """System status and performance monitor"""
    try:
        import psutil
        import platform

        # System information
        system_info = {
            'os': platform.system(),
            'os_version': platform.version(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage('/').total
        }

        # Real-time metrics
        metrics = get_system_metrics()

        # Process information
        current_process = psutil.Process()
        process_info = {
            'pid': current_process.pid,
            'cpu_percent': current_process.cpu_percent(),
            'memory_percent': current_process.memory_percent(),
            'threads': current_process.num_threads(),
            'open_files': len(current_process.open_files())
        }

        # Network interfaces
        net_interfaces = []
        for name, stats in psutil.net_if_addrs().items():
            if stats:
                net_interfaces.append({
                    'name': name,
                    'address': stats[0].address,
                    'netmask': stats[0].netmask if len(stats) > 0 and hasattr(stats[0], 'netmask') else None
                })

        return render_template('system_monitor.html',
            system_info=system_info,
            metrics=metrics,
            process_info=process_info,
            net_interfaces=net_interfaces,
            active_page='system'
        )
    except Exception as e:
        logger.error(f"System monitor error: {e}")
        return render_template('system_monitor.html', error=str(e), active_page='system')

@app.route('/config')
def config_manager():
    """Configuration manager for editing config files"""
    try:
        import os
        import json

        config_files = []

        # Find config files
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.endswith(('.json', '.py', '.yml', '.yaml', '.conf', '.ini')) and 'config' in file.lower():
                    filepath = os.path.join(root, file)
                    try:
                        stat = os.stat(filepath)
                        config_files.append({
                            'name': file,
                            'path': filepath,
                            'size': stat.st_size,
                            'modified': stat.st_mtime,
                            'type': file.split('.')[-1]
                        })
                    except:
                        pass

        # Sort by modification time
        config_files.sort(key=lambda x: x['modified'], reverse=True)

        return render_template('config_manager.html',
            config_files=config_files,
            active_page='config'
        )
    except Exception as e:
        logger.error(f"Config manager error: {e}")
        return render_template('config_manager.html', error=str(e), active_page='config')

@app.route('/api-test')
def api_tester():
    """API testing suite"""
    try:
        # Get available API endpoints
        api_endpoints = [
            {'method': 'GET', 'path': '/api/stats', 'description': 'Get real-time statistics'},
            {'method': 'GET', 'path': '/api/threats', 'description': 'Get threat data'},
            {'method': 'POST', 'path': '/api/block/<ip>', 'description': 'Block an IP address'},
            {'method': 'POST', 'path': '/api/unblock/<ip>', 'description': 'Unblock an IP address'},
            {'method': 'GET', 'path': '/health', 'description': 'Health check'},
            {'method': 'GET', 'path': '/cluster/status', 'description': 'Cluster status'},
            {'method': 'GET', 'path': '/load_balancer/status', 'description': 'Load balancer status'}
        ]

        return render_template('api_tester.html',
            api_endpoints=api_endpoints,
            active_page='api-test'
        )
    except Exception as e:
        logger.error(f"API tester error: {e}")
        return render_template('api_tester.html', error=str(e), active_page='api-test')

@app.route('/api/stats')
def api_stats():
    """Enhanced API statistics"""
    try:
        stats = get_realtime_stats()
        return jsonify({
            'packet_count': stats['packet_count'],
            'blocked_count': stats['blocked_count'],
            'threat_score_avg': stats.get('threat_score_avg', 0.0),
            'active_connections': stats.get('active_connections', 0),
            'system_load': get_system_metrics(),
            'ml_status': get_ml_status(),
            'threat_intelligence': get_threat_stats()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/block/<ip>', methods=['POST'])
def api_block_ip(ip):
    """API endpoint to manually block an IP"""
    try:
        data = request.get_json() or {}
        duration = data.get('duration', 3600)
        reason = data.get('reason', 'Manual block')

        block_ip_enhanced(ip, duration, reason)
        return jsonify({'status': 'success', 'message': f'IP {ip} blocked for {duration} seconds'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock_ip(ip):
    """API endpoint to unblock an IP"""
    try:
        with locks['blocked_ips']:
            if ip in blocked_ips['temporary']:
                del blocked_ips['temporary'][ip]
            if ip in blocked_ips['permanent']:
                blocked_ips['permanent'].remove(ip)

        SystemDefense.unblock_ip_system_level(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '2.0',
        'services': {
            'database': 'connected',
            'firewall': 'active',
            'threat_intelligence': 'enabled',
            'ml_detector': 'disabled' if not ML_ENABLED else 'enabled'
        }
    })

@app.route('/api/health')
def api_health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'version': '2.0',
        'services': {
            'database': 'connected',
            'firewall': 'active',
            'threat_intelligence': 'enabled',
            'ml_detector': 'disabled' if not ML_ENABLED else 'enabled'
        }
    })

@app.route('/api/threats')
def api_threats():
    """Get current threat statistics"""
    try:
        conn = get_enhanced_db_connection()
        cursor = conn.cursor()

        # Get recent threats
        cursor.execute('''
            SELECT ip, reason, threat_score, timestamp
            FROM blocked_ips
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 100
        ''', (time.time() - 86400,))  # Last 24 hours

        threats = []
        for row in cursor.fetchall():
            threats.append({
                'ip': row['ip'],
                'reason': row['reason'],
                'threat_score': row['threat_score'],
                'timestamp': row['timestamp']
            })

        conn.close()
        return jsonify({'threats': threats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Utility Functions
def get_realtime_stats():
    """Get real-time firewall statistics"""
    try:
        conn = get_enhanced_db_connection()
        cursor = conn.cursor()

        # Packet count (simulated)
        packet_count = redis_conn.get_packet_count()

        # Blocked count
        cursor.execute('SELECT COUNT(*) as count FROM blocked_ips WHERE timestamp > ?',
                      (time.time() - 86400,))
        blocked_count = cursor.fetchone()['count']

        # Recent blocks with count per IP
        cursor.execute('''
            SELECT ip, COUNT(*) as count, MAX(timestamp) as last_seen, GROUP_CONCAT(reason, '; ') as reasons
            FROM blocked_ips
            GROUP BY ip
            ORDER BY last_seen DESC
            LIMIT 10
        ''')
        recent_blocks = []
        for row in cursor.fetchall():
            recent_blocks.append((row['ip'], row['count'], row['last_seen']))

        conn.close()

        return {
            'packet_count': packet_count,
            'blocked_count': blocked_count,
            'recent_blocks': recent_blocks
        }
    except Exception as e:
        logger.error(f"Error getting realtime stats: {e}")
        return {'packet_count': 0, 'blocked_count': 0, 'recent_blocks': []}

def get_system_metrics():
    """Get current system metrics"""
    try:
        return {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_connections': len(psutil.net_connections())
        }
    except:
        return {'cpu_usage': 0, 'memory_usage': 0, 'disk_usage': 0, 'network_connections': 0}

def get_threat_stats():
    """Get threat intelligence statistics"""
    try:
        conn = get_enhanced_db_connection()
        cursor = conn.cursor()

        stats = {}
        for threat_type in ['malicious_ips', 'tor_exit_nodes', 'bot_signatures']:
            cursor.execute('SELECT COUNT(*) as count FROM threat_intelligence WHERE type = ?',
                          (threat_type,))
            stats[threat_type] = cursor.fetchone()['count']

        conn.close()
        return stats
    except:
        return {}

def get_ml_status():
    """Get ML detector status"""
    if not ML_ENABLED or not ml_detector:
        return {'enabled': False}

    try:
        return {
            'enabled': True,
            'model_loaded': ml_detector.model is not None,
            'features_count': len(ml_detector.feature_extractors) if hasattr(ml_detector, 'feature_extractors') else 0,
            'last_training': getattr(ml_detector, 'model_metadata', {}).get('training_date', 'Unknown')
        }
    except:
        return {'enabled': True, 'status': 'error'}

def get_protection_status():
    """Get overall protection status"""
    try:
        metrics = get_system_metrics()
        threat_stats = get_threat_stats()

        # Calculate protection score
        protection_score = 100

        # Reduce score based on system load
        if metrics['cpu_usage'] > 80:
            protection_score -= 20
        elif metrics['cpu_usage'] > 60:
            protection_score -= 10

        if metrics['memory_usage'] > 80:
            protection_score -= 20
        elif metrics['memory_usage'] > 60:
            protection_score -= 10

        # Boost score based on threat intelligence
        if threat_stats.get('malicious_ips', 0) > 1000:
            protection_score += 10

        return {
            'status': 'excellent' if protection_score > 90 else 'good' if protection_score > 70 else 'fair',
            'score': max(0, min(100, protection_score)),
            'active_protections': [
                'Real-time ML Detection' if ML_ENABLED else None,
                'Advanced Pattern Matching',
                'Threat Intelligence',
                'Behavioral Analysis',
                'System-level Blocking'
            ]
        }
    except:
        return {'status': 'unknown', 'score': 0, 'active_protections': []}

def collect_system_metrics():
    """Collect detailed system metrics"""
    try:
        return {
            'timestamp': time.time(),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'network_rx': psutil.net_io_counters().bytes_recv,
            'network_tx': psutil.net_io_counters().bytes_sent,
            'active_connections': len(psutil.net_connections()),
            'queue_size': sum(q.qsize() for q in processing_queues.values())
        }
    except:
        return {}

def store_system_metrics(metrics):
    """Store system metrics in database"""
    if not metrics:
        return

    try:
        conn = get_enhanced_db_connection()
        conn.execute('''
            INSERT INTO system_metrics
            (timestamp, cpu_usage, memory_usage, network_rx, network_tx, active_connections, queue_size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics['timestamp'],
            metrics['cpu_usage'],
            metrics['memory_usage'],
            metrics['network_rx'],
            metrics['network_tx'],
            metrics['active_connections'],
            metrics['queue_size']
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to store system metrics: {e}")

def adjust_performance_settings(metrics):
    """Dynamically adjust performance settings based on system load"""
    global PACKET_INSPECTION_ENABLED, MAX_WORKERS

    try:
        cpu_usage = metrics['cpu_usage']
        memory_usage = metrics['memory_usage']

        # Adjust packet inspection
        if cpu_usage > 90 or memory_usage > 90:
            if PACKET_INSPECTION_ENABLED:
                PACKET_INSPECTION_ENABLED = False
                logger.warning("Disabled packet inspection due to high system load")
        elif cpu_usage < 70 and memory_usage < 70:
            if not PACKET_INSPECTION_ENABLED:
                PACKET_INSPECTION_ENABLED = True
                logger.info("Re-enabled packet inspection - system load normalized")

        # Adjust worker threads
        if cpu_usage > 80:
            new_workers = max(4, MAX_WORKERS - 2)
            if new_workers != MAX_WORKERS:
                MAX_WORKERS = new_workers
                logger.warning(f"Reduced worker threads to {MAX_WORKERS} due to high CPU usage")
        elif cpu_usage < 50:
            new_workers = min(32, MAX_WORKERS + 1)
            if new_workers != MAX_WORKERS:
                MAX_WORKERS = new_workers
                logger.info(f"Increased worker threads to {MAX_WORKERS}")

    except Exception as e:
        logger.error(f"Error adjusting performance settings: {e}")

# Enhanced Alert Worker
def enhanced_alert_worker():
    """Process alerts from the queue"""
    while True:
        try:
            alert_data = processing_queues['alerts'].get()
            subject, body, alert_type, metadata = alert_data

            # Send email alert
            send_enhanced_email_alert(subject, body, alert_type, metadata)

            # Log alert
            logger.info(f"Alert sent: {subject}")

        except Exception as e:
            logger.error(f"Alert worker error: {e}")
            time.sleep(1)

# Enhanced Services Initialization
def start_enhanced_services():
    """Start all enhanced background services"""
    global cluster_manager, load_balancer, thread_pool

    logger.info("Starting SecureGuard Enhanced Services...")

    # Start background workers
    workers = [
        ('Database Writer', enhanced_db_writer_worker),
        ('System Block Worker', enhanced_system_block_worker),
        ('Threat Intelligence', enhanced_threat_intelligence_worker),
        ('ML Training', enhanced_ml_training_worker),
        ('Monitoring', enhanced_monitoring_worker),
        ('Alert Processor', enhanced_alert_worker)
    ]

    for worker_name, worker_func in workers:
        thread = Thread(target=worker_func, daemon=True, name=worker_name)
        thread.start()
        logger.info(f"Started {worker_name}")

    # Initialize clustering if enabled
    if CLUSTER_MODE:
        cluster_manager = ClusterManager()
        cluster_manager.add_node(NODE_ID, f"localhost:{os.environ.get('PORT', '5000')}")
        for node_addr in CLUSTER_NODES:
            if node_addr != f"localhost:{os.environ.get('PORT', '5000')}":
                node_id = f"node_{hash(node_addr) % 1000}"
                cluster_manager.add_node(node_id, node_addr)
        cluster_manager.start_heartbeat()
        logger.info("Cluster mode enabled")

    # Initialize load balancer if enabled
    if LOAD_BALANCER_ENABLED:
        load_balancer = LoadBalancer(LOAD_BALANCER_ALGORITHM)
        for node_addr in CLUSTER_NODES:
            load_balancer.add_backend(node_addr)
        load_balancer.start_health_checks()
        logger.info("Load balancer enabled")

    # Initialize async processing
    if ASYNC_PROCESSING_ENABLED:
        thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        logger.info(f"Async processing enabled with {MAX_WORKERS} workers")

    # Initialize threat intelligence
    try:
        ThreatIntelligence.update_all_sources()
    except Exception as e:
        logger.warning(f"Initial threat intelligence update failed: {e}")

    logger.info("SecureGuard Enhanced Services initialized successfully")

# Main Application Entry Point
if __name__ == "__main__":
    start_enhanced_services()

    # Use configuration settings instead of environment variables
    port = SERVER_CONFIG.get('listen_port', 5000)
    host = SERVER_CONFIG.get('listen_host', '127.0.0.1')

    logger.info(f"Starting SecureGuard Enhanced on {host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
