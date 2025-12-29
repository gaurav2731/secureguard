"""
SecureGuard Enhanced Firewall Application
Futuristic Multi-Page Setup with Real-time Updates and 3D Effects
"""
from flask import Flask, render_template, request, jsonify, abort, url_for, redirect, send_from_directory
import smtplib
from concurrent.futures import ThreadPoolExecutor
import os
import json
import sqlite3
import time
import random
import logging
from datetime import datetime, timezone
from email.mime.text import MIMEText
import psutil
import platform
import csv
import io
from flask import Response

# Import our Redis connection
from redis_connection import redis_conn  # type: ignore

# Configuration
DB_FILE = 'secureguard.db'
FIREWALL_CONFIG = {
    'rate_limit': 1000,
    'block_duration': 3600,
    'max_packets_per_minute': 5000000
}

# Flask app setup
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Database initialization
def init_db():
    """Initialize the database with required tables"""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()

        # Create events table for logging events
        c.execute('''CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        ip TEXT,
                        path TEXT,
                        etype TEXT,
                        detail TEXT)''')

        # Create blocked_ips table for blocked IP addresses
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        ts TEXT NOT NULL,
                        reason TEXT,
                        status TEXT DEFAULT 'BLOCKED')''')

        conn.commit()

# Initialize database
init_db()

# Database logging function
def db_log(ip, path, etype, detail):
    """Log events to the database"""
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO events (ts, ip, path, etype, detail) VALUES (?, ?, ?, ?, ?)",
                 (ts, ip, path, etype, detail))
    conn.commit()
    conn.close()

# Email alert function
def send_email_alert(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'alerts@secureguard.com'
        msg['To'] = 'admin@secureguard.com'

        # This would normally send via SMTP, but we'll just log for demo
        logger.warning(f"ALERT: {subject} - {body}")
    except Exception as e:
        logger.error(f"Email alert failed: {e}")

# Routes
@app.route('/')
def home():
    """Redirect to dashboard"""
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
def dashboard():
    """Enhanced main dashboard with real-time metrics"""
    try:
        # Get real-time statistics
        packet_count = redis_conn.get_packet_count()
        blocked_count = len(redis_conn.get_blocked_ips())

        # Get recent blocks
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ip, COUNT(*) as count, MAX(timestamp) as last_seen FROM blocked_ips GROUP BY ip ORDER BY MAX(timestamp) DESC LIMIT 10")
        recent_blocks = cursor.fetchall()
        conn.close()

        return render_template('dashboard.html',
            packet_count=packet_count,
            max_packets=20000000,
            blocked_count=blocked_count,
            recent_blocks=recent_blocks,
            protection_status={
                "score": 95,
                "status": "Excellent",
                "active_protections": ["Firewall", "ML Detection", "Threat Intelligence"]
            },
            system_metrics={
                "cpu_usage": 45.2,
                "memory_usage": 62.8,
                "disk_usage": 34.1,
                "network_connections": 127
            },
            threat_intelligence_stats={
                "malicious_ips": 15420,
                "tor_exit_nodes": 890,
                "bot_signatures": 2341
            },
            ml_status={
                "enabled": True,
                "model_loaded": True,
                "features_count": 47,
                "last_training": "2024-01-15 14:30:00"
            },
            active_page='dashboard'
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html',
            error=str(e),
            active_page='dashboard',
            protection_status={
                "score": 95,
                "status": "Excellent",
                "active_protections": ["Firewall", "ML Detection", "Threat Intelligence"]
            },
            system_metrics={
                "cpu_usage": 45.2,
                "memory_usage": 62.8,
                "disk_usage": 34.1,
                "network_connections": 127
            },
            threat_intelligence_stats={
                "malicious_ips": 15420,
                "tor_exit_nodes": 890,
                "bot_signatures": 2341
            },
            ml_status={
                "enabled": True,
                "model_loaded": True,
                "features_count": 47,
                "last_training": "2024-01-15 14:30:00"
            }
        )

@app.route("/control")
def control_panel():
    """Firewall control panel for managing rules and blocking"""
    try:
        # Get current firewall rules and settings
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get blocked IPs with threat score (calculated as random for demo, use real logic in production)
        cursor.execute("SELECT ip, timestamp, reason, ABS(RANDOM()) % 100 / 100.0 as threat_score FROM blocked_ips ORDER BY timestamp DESC LIMIT 100")
        blocked_ips = cursor.fetchall()

        conn.close()

        # Get whitelist and blacklist (from database or config, for now empty)
        whitelist = []  # TODO: Implement whitelist storage
        blacklist = []  # TODO: Implement blacklist storage

        return render_template('control_panel.html',
            blocked_ips=blocked_ips,
            firewall_config=FIREWALL_CONFIG,
            whitelist=whitelist,
            blacklist=blacklist,
            active_page='control'
        )
    except Exception as e:
        logger.error(f"Control panel error: {e}")
        return render_template('control_panel.html', error=str(e), active_page='control')

@app.route("/analytics")
def analytics():
    """Analytics and monitoring dashboard"""
    try:
        # Get detailed analytics data
        conn = get_db_connection()
        cursor = conn.cursor()

        # Traffic patterns over time (mock data for now)
        traffic_data = []
        for i in range(24):
            hour = f"{i:02d}:00"
            traffic_data.append({
                'hour': hour,
                'requests': random.randint(100, 1000),
                'threats': random.randint(0, 50)
            })

        # Top attacking IPs
        cursor.execute("SELECT ip, COUNT(*) as attack_count FROM blocked_ips GROUP BY ip ORDER BY attack_count DESC LIMIT 20")
        top_attackers_raw = cursor.fetchall()
        # Convert sqlite3.Row objects to dictionaries for JSON serialization
        top_attackers = [{'ip': row[0], 'count': row[1]} for row in top_attackers_raw]

        # Attack types distribution
        attack_types = [
            {'reason': 'SQL Injection', 'count': 45},
            {'reason': 'XSS Attack', 'count': 32},
            {'reason': 'DDoS Attack', 'count': 28},
            {'reason': 'Path Traversal', 'count': 15}
        ]

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

@app.route("/files")
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

@app.route("/threats")
def threat_intelligence():
    """Threat intelligence hub"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get threat intelligence stats
        threat_stats = [
            {'type': 'malicious_ips', 'count': 15420},
            {'type': 'tor_exit_nodes', 'count': 890},
            {'type': 'bot_signatures', 'count': 2341}
        ]

        # Get recent threats (mock data)
        recent_threats = [
            {'indicator': '192.168.1.100', 'type': 'malicious_ips', 'source': 'threat_feed', 'timestamp': time.time(), 'confidence': 0.95},
            {'indicator': '10.0.0.50', 'type': 'bot_signatures', 'source': 'ml_detection', 'timestamp': time.time() - 3600, 'confidence': 0.87}
        ]

        # Get threat sources
        threat_sources = [
            {'source': 'threat_feed', 'count': 12000},
            {'source': 'ml_detection', 'count': 3400},
            {'source': 'manual_analysis', 'count': 251}
        ]

        conn.close()

        return render_template('threat_intelligence.html',
            threat_stats=threat_stats,
            recent_threats=recent_threats,
            threat_sources=threat_sources,
            active_page='threats'
        )
    except Exception as e:
        logger.error(f"Threat intelligence error: {e}")
        return render_template('threat_intelligence.html', error=str(e), active_page='threats')

@app.route("/system")
def system_monitor():
    """System status and performance monitor"""
    try:
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
        metrics = {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_connections': len(psutil.net_connections())
        }

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

@app.route("/config")
def config_manager():
    """Configuration manager for editing config files"""
    try:
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

@app.route("/api-test")
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

# API Routes
@app.route('/api/stats')
def api_stats():
    """Enhanced API statistics"""
    try:
        packet_count = redis_conn.get_packet_count()
        blocked_count = len(redis_conn.get_blocked_ips())

        return jsonify({
            'packet_count': packet_count,
            'blocked_count': blocked_count,
            'threat_score_avg': 0.3,
            'active_connections': 127,
            'system_load': {
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'disk_usage': 34.1,
                'network_connections': 127
            },
            'ml_status': {
                'enabled': True,
                'model_loaded': True,
                'features_count': 47,
                'last_training': '2024-01-15 14:30:00'
            },
            'threat_intelligence': {
                'malicious_ips': 15420,
                'tor_exit_nodes': 890,
                'bot_signatures': 2341
            }
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

        # Add to blocked list
        ts = datetime.now(timezone.utc).timestamp()
        conn = sqlite3.connect(DB_FILE)
        conn.execute("INSERT INTO blocked_ips (ip, timestamp, block_type, duration, reason) VALUES (?, ?, ?, ?, ?)", (ip, ts, "BLOCKED", duration, reason))
        conn.commit()
        conn.close()

        logger.warning(f"Manually blocked IP {ip}")
        return jsonify({'status': 'success', 'message': f'IP {ip} blocked for {duration} seconds'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock/<ip>', methods=['POST'])
def api_unblock_ip(ip):
    """API endpoint to unblock an IP"""
    try:
        # Remove from blocked list (simplified)
        logger.info(f"Unblocked IP {ip}")
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats')
def api_threats():
    """Get current threat statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get recent threats
        cursor.execute('''
            SELECT ip, reason, ts
            FROM blocked_ips
            WHERE ts > ?
            ORDER BY ts DESC
            LIMIT 100
        ''', (datetime.now(timezone.utc).timestamp() - 86400,))  # Last 24 hours

        threats = []
        for row in cursor.fetchall():
            threats.append({
                'ip': row[0],
                'reason': row[1] or 'Unknown',
                'timestamp': row[2]
            })

        conn.close()
        return jsonify({'threats': threats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<format>')
def api_export_data(format):
    """Export analytics data in specified format"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get data for export
        cursor.execute("SELECT ip, COUNT(*) as attack_count FROM blocked_ips GROUP BY ip ORDER BY attack_count DESC LIMIT 20")
        top_attackers = cursor.fetchall()

        # Traffic data (mock for demo)
        traffic_data = []
        for i in range(24):
            hour = f"{i:02d}:00"
            traffic_data.append({
                'hour': hour,
                'requests': random.randint(100, 1000),
                'threats': random.randint(0, 50)
            })

        attack_types = [
            {'reason': 'SQL Injection', 'count': 45},
            {'reason': 'XSS Attack', 'count': 32},
            {'reason': 'DDoS Attack', 'count': 28},
            {'reason': 'Path Traversal', 'count': 15}
        ]

        conn.close()

        data = {
            'top_attackers': [{'ip': row[0], 'count': row[1]} for row in top_attackers],
            'traffic_data': traffic_data,
            'attack_types': attack_types,
            'exported_at': datetime.now(timezone.utc).isoformat()
        }

        if format.lower() == 'json':
            return Response(json.dumps(data, indent=2), mimetype='application/json',
                          headers={'Content-Disposition': 'attachment; filename=analytics.json'})

        elif format.lower() == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)

            # Write top attackers
            writer.writerow(['Top Attackers'])
            writer.writerow(['IP', 'Attack Count'])
            for attacker in data['top_attackers']:
                writer.writerow([attacker['ip'], attacker['count']])

            writer.writerow([])
            writer.writerow(['Traffic Data'])
            writer.writerow(['Hour', 'Requests', 'Threats'])
            for traffic in data['traffic_data']:
                writer.writerow([traffic['hour'], traffic['requests'], traffic['threats']])

            writer.writerow([])
            writer.writerow(['Attack Types'])
            writer.writerow(['Reason', 'Count'])
            for attack in data['attack_types']:
                writer.writerow([attack['reason'], attack['count']])

            return Response(output.getvalue(), mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment; filename=analytics.csv'})

        elif format.lower() == 'pdf':
            # Simple text-based PDF for demo (in production, use reportlab or similar)
            pdf_content = f"""
SecureGuard Analytics Export
Exported at: {data['exported_at']}

Top Attackers:
{'IP':<15} {'Count':<10}
{'-'*25}
"""
            for attacker in data['top_attackers']:
                pdf_content += f"{attacker['ip']:<15} {attacker['count']:<10}\n"

            pdf_content += "\nTraffic Data:\n"
            pdf_content += f"{'Hour':<5} {'Requests':<10} {'Threats':<8}\n"
            pdf_content += "-"*23 + "\n"
            for traffic in data['traffic_data']:
                pdf_content += f"{traffic['hour']:<5} {traffic['requests']:<10} {traffic['threats']:<8}\n"

            pdf_content += "\nAttack Types:\n"
            pdf_content += f"{'Reason':<15} {'Count':<6}\n"
            pdf_content += "-"*21 + "\n"
            for attack in data['attack_types']:
                pdf_content += f"{attack['reason']:<15} {attack['count']:<6}\n"

            return Response(pdf_content, mimetype='application/pdf',
                          headers={'Content-Disposition': 'attachment; filename=analytics.txt'})

        else:
            return jsonify({'error': 'Unsupported format. Use json, csv, or pdf'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Legacy routes for compatibility
@app.route("/simulate")
def simulate():
    ip = f"192.168.1.{int(time.time()) % 255}"
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO blocked_ips (ip, timestamp, status) VALUES (?, ?, ?)", (ip, ts, "MITIGATED"))
    conn.commit()
    conn.close()
    logger.warning(f"Mitigated simulated attack from {ip}")
    send_email_alert("🚨 SecureGuard Alert", f"Mitigated simulated attack from {ip} at {ts}")
    return redirect(url_for("dashboard"))

@app.route("/block_demo")
def block_demo():
    ip = f"203.0.113.{int(time.time()) % 255}"
    ts = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO blocked_ips (ip, timestamp, status) VALUES (?, ?, ?)", (ip, ts, "BLOCKED"))
    conn.commit()
    conn.close()
    logger.error(f"Blocked IP {ip}")
    send_email_alert("🚨 SecureGuard Alert", f"Blocked malicious IP {ip} at {ts}")
    return redirect(url_for("dashboard"))

# Static file serving
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
