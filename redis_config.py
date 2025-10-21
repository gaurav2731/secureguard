# Redis connection configuration
import redis
from redis.exceptions import RedisError
import logging

def init_redis():
    """Initialize Redis connection with proper error handling"""
    try:
        client = redis.Redis(
            host='localhost',
            port=6379,
            decode_responses=True,
            socket_timeout=5
        )
        # Test connection
        client.ping()
        logging.info("Redis connection successful")
        return client
    except RedisError as e:
        logging.warning(f"Redis connection failed: {e}")
        return None