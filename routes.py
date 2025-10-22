"""
SecureGuard route handlers
"""
from flask import render_template, jsonify, request, redirect, url_for
from app import app, redis_conn

@app.route('/')
def home():
    return "Hello, SecureGuard!"

    """Dashboard route"""
    try:
        packet_count = redis_conn.get_packet_count()
        blocked_ips = redis_conn.get_blocked_ips()
        
        return render_template('dashboard.html',
            packet_count=packet_count,
            max_packets=2000000,  # 2M packet capacity
            blocked_count=len(blocked_ips),
            recent_blocks=[],  # TODO: Implement recent blocks
            protection_status={
                "Firewall": "Active",
                "Redis": "Active" if redis_conn.client else "Fallback",
                "System": "Protected"
            }
        )
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html',
            error=str(e),
            packet_count=0,
            max_packets=2000000,
            blocked_count=0,
            recent_blocks=[],
            protection_status={"Status": "Error"}
        )

@app.route('/stats')
def stats():
    """Stats API endpoint"""
    try:
        packet_count = redis_conn.get_packet_count()
        blocked_ips = redis_conn.get_blocked_ips()
        
        return jsonify({
            'status': 'ok',
            'packet_count': packet_count,
            'blocked_count': len(blocked_ips),
            'redis_status': 'connected' if redis_conn.client else 'fallback'
        })
    except Exception as e:
        app.logger.error(f"Stats error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500