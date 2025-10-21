"""
Redis initialization and connection management
"""
import os
import redis
from redis.exceptions import RedisError
import logging

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='logs/secureguard.log'
)

logger = logging.getLogger(__name__)

class RedisManager:
    def __init__(self, host='localhost', port=6379, db=0):
        self.host = host
        self.port = port
        self.db = db
        self.client = None
        self.fallback_mode = False
        self.connect()
        
    def connect(self):
        """Establish Redis connection with fallback"""
        try:
            self.client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=True,
                socket_timeout=5
            )
            self.client.ping()
            self.fallback_mode = False
            logger.info("Redis connection established")
        except RedisError as e:
            self.client = None
            self.fallback_mode = True
            logger.warning(f"Redis connection failed: {e}. Using in-memory counters.")
            
    def get(self, key, default=None):
        """Get value with fallback"""
        if self.client and not self.fallback_mode:
            try:
                return self.client.get(key) or default
            except RedisError as e:
                logger.error(f"Redis get error: {e}")
        return default
        
    def set(self, key, value):
        """Set value with fallback"""
        if self.client and not self.fallback_mode:
            try:
                return self.client.set(key, value)
            except RedisError as e:
                logger.error(f"Redis set error: {e}")
        return False

# Create global Redis manager instance
redis_manager = RedisManager()