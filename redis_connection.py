"""
Redis connection manager for SecureGuard
"""
import redis
from redis.exceptions import RedisError
import logging

logger = logging.getLogger(__name__)

class RedisConnection:
    def __init__(self):
        """Initialize Redis connection with fallback support"""
        self.client = None
        self.fallback_data = {
            'packet_count': 0,
            'blocked_ips': set(),
            'stats': {}
        }
        self.connect()
    
    def connect(self):
        """Establish Redis connection"""
        try:
            self.client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True,
                socket_timeout=5
            )
            # Test connection
            self.client.ping()
            logger.info("Redis connection established")
        except RedisError as e:
            self.client = None
            logger.warning(f"Redis connection failed: {e}. Using in-memory fallback.")
    
    def get_packet_count(self):
        """Get current packet count"""
        if self.client:
            try:
                count = self.client.get('packet_count')
                return int(count) if count else 0
            except RedisError:
                pass
        return self.fallback_data['packet_count']
    
    def increment_packet_count(self):
        """Increment packet counter"""
        if self.client:
            try:
                return self.client.incr('packet_count')
            except RedisError:
                pass
        self.fallback_data['packet_count'] += 1
        return self.fallback_data['packet_count']
    
    def get_blocked_ips(self):
        """Get set of blocked IPs"""
        if self.client:
            try:
                return self.client.smembers('blocked_ips')
            except RedisError:
                pass
        return self.fallback_data['blocked_ips']
    
    def add_blocked_ip(self, ip):
        """Add IP to blocked set"""
        if self.client:
            try:
                return self.client.sadd('blocked_ips', ip)
            except RedisError:
                pass
        self.fallback_data['blocked_ips'].add(ip)
        return True

    def set(self, key, value):
        """Set a key-value pair in Redis"""
        if self.client:
            try:
                return self.client.set(key, value)
            except RedisError:
                pass
        self.fallback_data[key] = value
        return True

# Create global instance
redis_conn = RedisConnection()