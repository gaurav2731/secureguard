"""
Redis interface for SecureGuard
Handles all Redis operations and provides a clean interface
"""
import redis
from redis.exceptions import RedisError
import logging

logger = logging.getLogger('secureguard.redis')

class RedisInterface:
    def __init__(self):
        self._client = None
        self._connect()
    
    def _connect(self):
        """Establish Redis connection"""
        try:
            self._client = redis.Redis(
                host='localhost',
                port=6379,
                decode_responses=True,
                socket_timeout=5
            )
            self._client.ping()
            logger.info("Redis connection successful")
        except RedisError as e:
            logger.warning(f"Redis connection failed: {e}")
            self._client = None
    
    @property
    def client(self):
        """Get Redis client, potentially reconnecting if needed"""
        if not self._client:
            self._connect()
        return self._client
    
    def increment(self, key, amount=1):
        """Safely increment a key"""
        try:
            if self._client:
                return self._client.incrby(key, amount)
        except RedisError as e:
            logger.error(f"Redis increment error: {e}")
        return None
    
    def get(self, key):
        """Safely get a value"""
        try:
            if self._client:
                return self._client.get(key)
        except RedisError as e:
            logger.error(f"Redis get error: {e}")
        return None
    
    def set(self, key, value):
        """Safely set a value"""
        try:
            if self._client:
                return self._client.set(key, value)
        except RedisError as e:
            logger.error(f"Redis set error: {e}")
        return None

# Global Redis interface instance
redis_interface = RedisInterface()