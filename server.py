"""
SecureGuard Server Runner
"""
import os
import sys
from waitress import serve
from app import app
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
    # Start with safe defaults
    host = '127.0.0.1'
    port = 5000
    
    print(f"Starting SecureGuard server at http://{host}:{port}")
    serve(app, host=host, port=port, threads=8)