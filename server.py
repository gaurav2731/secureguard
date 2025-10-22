"""
SecureGuard Server Runner
"""
import os
import sys
import socket
from waitress import serve
from app import app, start_services
# Initialize filters and routes (wsgi.py does this for WSGI deployments)
try:
    from filters import init_filters
    init_filters(app)
except Exception:
    # If filters are missing or fail, continue; app will still start
    pass

# Import routes to ensure endpoints are registered
try:
    import routes  # registers routes on the app
except Exception:
    pass

# Set up minimal config to get the server running
app.config.update(
    SECRET_KEY=os.urandom(24),
    SESSION_COOKIE_SECURE=True,
    PREFERRED_URL_SCHEME='http'
)

if __name__ == "__main__":
    # Initialize background services (threads, redis, threat intel)
    try:
        start_services()
    except Exception:
        # If service init fails, continue to start the server so operators can debug
        pass
    # Start with safe defaults. Bind address is configurable via env var
    # - SECUREGUARD_HOST: host/IP to bind (default 0.0.0.0 to listen on all interfaces)
    # - SECUREGUARD_PORT or PORT: port to bind (default 5000)
    host = os.environ.get('SECUREGUARD_HOST', os.environ.get('HOST', '0.0.0.0'))
    port = int(os.environ.get('SECUREGUARD_PORT', os.environ.get('PORT', 5000)))

    def _get_lan_ips():
        """Return a list of non-loopback IPv4 addresses for this host."""
        ips = set()
        try:
            for res in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM):
                ip = res[4][0]
                if not ip.startswith('127.'):
                    ips.add(ip)
        except Exception:
            pass
        # Fallback: try connecting to a public IP to discover the outgoing interface
        if not ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ips.add(s.getsockname()[0])
                s.close()
            except Exception:
                pass
        return sorted(ips)

    # Friendly startup messages: when binding to 0.0.0.0 we should show reachable URLs
    if host == '0.0.0.0':
        lan_ips = _get_lan_ips()
        print(f"Starting SecureGuard server bound to all interfaces on port {port}")
        print(f"You can connect locally at: http://127.0.0.1:{port}/")
        for ip in lan_ips:
            print(f"You can connect from your LAN at: http://{ip}:{port}/")
        if not lan_ips:
            print("(Could not determine LAN IP; try using your machine's IP or localhost.)")
    else:
        print(f"Starting SecureGuard server at http://{host}:{port}")
    # Waitress serve will listen on the provided host/port. Binding to 0.0.0.0 allows
    # access from other hosts on the same network (e.g., 192.168.x.x).
    serve(app, host=host, port=port, threads=8)