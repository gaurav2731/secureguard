"""
SecureGuard Launcher Script
Handles proper initialization and startup of all components
"""
import os
import sys
import logging
from waitress import serve
from app import app, redis_client

def init_logging():
    """Initialize logging configuration"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/secureguard.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_redis():
    """Check Redis connection and availability"""
    if not redis_client:
        logging.warning("Redis is not configured - running in limited mode")
        return False
    
    try:
        redis_client.ping()
        logging.info("Redis connection verified")
        return True
    except Exception as e:
        logging.error(f"Redis error: {e}")
        return False

def main():
    """Main entry point for the application"""
    init_logging()
    logger = logging.getLogger('secureguard')
    
    # Check Redis (but continue even if it fails)
    check_redis()
    
    # Start the server
    try:
        host = '127.0.0.1'  # localhost
        port = 5000
        threads = 8  # Adjust based on your CPU cores
        
        logger.info(f"Starting SecureGuard server at http://{host}:{port}")
        serve(app, 
              host=host, 
              port=port, 
              threads=threads,
              connection_limit=2048,
              channel_timeout=30,
              cleanup_interval=30)
    except Exception as e:
        logger.error(f"Server failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()