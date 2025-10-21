"""
SecureGuard Server - Production Runner
"""
import os
import sys
from waitress import serve
from app import app
from redis_init import redis_manager
import logging

if __name__ == "__main__":
    # Configure server
    host = '127.0.0.1'  # Use localhost for security
    port = 5000
    threads = 8

    # Check Redis status
    if redis_manager.client and not redis_manager.fallback_mode:
        print("Redis connection active")
    else:
        print("Warning: Running without Redis - using in-memory counters")

    # Start server
    print(f"Starting SecureGuard server at http://{host}:{port}")
    serve(app,
          host=host,
          port=port,
          threads=threads,
          channel_timeout=30,
          cleanup_interval=30)
