"""
SecureGuard WSGI Application Entry Point
"""
from app import app  # This imports the Flask app with filters already registered
from filters import init_filters  # Import filters
init_filters(app)  # Initialize filters before routes
import routes  # This imports and registers the routes

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)