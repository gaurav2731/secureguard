"""
SecureGuard WSGI Application Entry Point
"""
from app import app  # This imports the Flask app with filters already registered
from filters import init_filters  # Import filters
init_filters(app)  # Initialize filters before routes
import routes  # This imports and registers the routes

# This module is intended to be used by WSGI servers (uWSGI, Gunicorn, Waitress).
# Do NOT start the Flask development server here; use `server.py` for local production
# use with Waitress, or run `app.py` with SECUREGUARD_DEV=1 explicitly for dev.