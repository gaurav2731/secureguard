"""
SecureGuard production server runner
"""
import os
import logging
from waitress import serve
from app import app, logger

if __name__ == "__main__":
    # Server configuration
    HOST = '127.0.0.1'  # Localhost for security
    PORT = 5000
    THREADS = 8
    
    logger.info(f"Starting SecureGuard server at http://{HOST}:{PORT}")
    
    try:
        serve(
            app,
            host=HOST,
            port=PORT,
            threads=THREADS,
            url_scheme='http',
            channel_timeout=30,
            cleanup_interval=30,
            connection_limit=2048
        )
    except Exception as e:
        logger.error(f"Server failed to start: {e}")
        raise