"""
Redis connection manager for SecureGuard
"""
import redis
from redis.exceptions import RedisError
import logging
import json
from config_enhanced import REDIS_CONFIG

logger = logging.getLogger(__name__)

# Try to import RedisCluster, but handle gracefully if not available
try:
    from rediscluster import RedisCluster  # type: ignore
    REDIS_CLUSTER_AVAILABLE = True
except ImportError:
    REDIS_CLUSTER_AVAILABLE = False
    logger.warning("RedisCluster not available, using standard Redis only")

class RedisConnection:
    def __init__(self):
        """Initialize Redis connection with clustering and fallback support"""
        self.client = None
        self.cluster_client = None
        self.fallback_data = {
            'packet_count': 0,
            'blocked_ips': set(),
            'stats': {},
            'cache': {},
            'threat_scores': {},
            'behavior_cache': {}
        }
        self.connect()
    
    def connect(self):
        """Establish Redis connection with cluster support"""
        try:
            if REDIS_CONFIG.get('cluster_mode', False) and REDIS_CLUSTER_AVAILABLE:
                # Redis Cluster mode
                startup_nodes = REDIS_CONFIG.get('cluster_nodes', [])
                if startup_nodes:
                    self.cluster_client = RedisCluster(
                        startup_nodes=startup_nodes,
                        decode_responses=True,
                        socket_timeout=REDIS_CONFIG.get('socket_timeout', 5),
                        socket_connect_timeout=REDIS_CONFIG.get('socket_connect_timeout', 5),
                        socket_keepalive=REDIS_CONFIG.get('socket_keepalive', True),
                        socket_keepalive_options=REDIS_CONFIG.get('socket_keepalive_options', {}),
                        health_check_interval=REDIS_CONFIG.get('health_check_interval', 30)
                    )
                    self.cluster_client.ping()
                    logger.info("Redis Cluster connection established")
                    return
            elif REDIS_CONFIG.get('cluster_mode', False) and not REDIS_CLUSTER_AVAILABLE:
                logger.warning("Redis Cluster mode requested but RedisCluster not available, falling back to standard Redis")
            
            # Standard Redis mode
            self.client = redis.Redis(
                host=REDIS_CONFIG.get('host', 'localhost'),
                port=REDIS_CONFIG.get('port', 6379),
                password=REDIS_CONFIG.get('password'),
                db=REDIS_CONFIG.get('db', 0),
                decode_responses=True,
                socket_timeout=REDIS_CONFIG.get('socket_timeout', 5),
                socket_connect_timeout=REDIS_CONFIG.get('socket_connect_timeout', 5),
                socket_keepalive=REDIS_CONFIG.get('socket_keepalive', True),
                socket_keepalive_options=REDIS_CONFIG.get('socket_keepalive_options', {}),
                health_check_interval=REDIS_CONFIG.get('health_check_interval', 30)
            )
            # Test connection
            self.client.ping()
            logger.info("Redis connection established")
        except (RedisError, Exception) as e:
            self.client = None
            self.cluster_client = None
            logger.warning(f"Redis connection failed: {e}. Using in-memory fallback.")
    
    def _get_client(self):
        """Get the appropriate Redis client"""
        if self.cluster_client:
            return self.cluster_client
        return self.client
    
    def get_packet_count(self):
        """Get current packet count"""
        client = self._get_client()
        if client:
            try:
                count = client.get('packet_count')
                return int(count) if count else 0
            except RedisError:
                pass
        return self.fallback_data['packet_count']
    
    def increment_packet_count(self, amount=1):
        """Increment packet counter"""
        client = self._get_client()
        if client:
            try:
                return client.incrby('packet_count', amount)
            except RedisError:
                pass
        self.fallback_data['packet_count'] += amount
        return self.fallback_data['packet_count']
    
    def get_blocked_ips(self):
        """Get set of blocked IPs"""
        client = self._get_client()
        if client:
            try:
                return client.smembers('blocked_ips')
            except RedisError:
                pass
        return self.fallback_data['blocked_ips']
    
    def add_blocked_ip(self, ip, expiry=None):
        """Add IP to blocked set with optional expiry"""
        client = self._get_client()
        if client:
            try:
                if expiry:
                    return client.sadd('blocked_ips', ip) and client.expire(f'blocked_ip:{ip}', expiry)
                else:
                    return client.sadd('blocked_ips', ip)
            except RedisError:
                pass
        self.fallback_data['blocked_ips'].add(ip)
        return True
    
    def remove_blocked_ip(self, ip):
        """Remove IP from blocked set"""
        client = self._get_client()
        if client:
            try:
                return client.srem('blocked_ips', ip)
            except RedisError:
                pass
        self.fallback_data['blocked_ips'].discard(ip)
        return True
    
    def get(self, key):
        """Get a key-value pair"""
        client = self._get_client()
        if client:
            try:
                return client.get(key)
            except RedisError:
                pass
        return self.fallback_data.get(key)
    
    def set(self, key, value, expiry=None):
        """Set a key-value pair with optional expiry"""
        client = self._get_client()
        if client:
            try:
                if expiry:
                    return client.setex(key, expiry, value)
                else:
                    return client.set(key, value)
            except RedisError:
                pass
        self.fallback_data[key] = value
        return True
    
    def delete(self, key):
        """Delete a key"""
        client = self._get_client()
        if client:
            try:
                return client.delete(key)
            except RedisError:
                pass
        if key in self.fallback_data:
            del self.fallback_data[key]
        return True
    
    def exists(self, key):
        """Check if key exists"""
        client = self._get_client()
        if client:
            try:
                return client.exists(key)
            except RedisError:
                pass
        return key in self.fallback_data
    
    def get_cache(self, key):
        """Get from cache with fallback"""
        client = self._get_client()
        if client:
            try:
                return client.get(f'cache:{key}')
            except RedisError:
                pass
        return self.fallback_data['cache'].get(key)
    
    def set_cache(self, key, value, expiry=3600):
        """Set cache with expiry"""
        client = self._get_client()
        if client:
            try:
                return client.setex(f'cache:{key}', expiry, value)
            except RedisError:
                pass
        self.fallback_data['cache'][key] = value
        return True
    
    def get_threat_score(self, ip):
        """Get threat score for IP"""
        client = self._get_client()
        if client:
            try:
                score = client.get(f'threat:{ip}')
                return float(score) if score else 0.0
            except RedisError:
                pass
        return self.fallback_data['threat_scores'].get(ip, 0.0)
    
    def set_threat_score(self, ip, score, expiry=3600):
        """Set threat score for IP"""
        client = self._get_client()
        if client:
            try:
                return client.setex(f'threat:{ip}', expiry, str(score))
            except RedisError:
                pass
        self.fallback_data['threat_scores'][ip] = score
        return True
    
    def get_behavior_data(self, ip):
        """Get behavioral data for IP"""
        client = self._get_client()
        if client:
            try:
                data = client.get(f'behavior:{ip}')
                return json.loads(data) if data else {}
            except (RedisError, json.JSONDecodeError):
                pass
        return self.fallback_data['behavior_cache'].get(ip, {})
    
    def set_behavior_data(self, ip, data, expiry=3600):
        """Set behavioral data for IP"""
        client = self._get_client()
        if client:
            try:
                return client.setex(f'behavior:{ip}', expiry, str(data))
            except RedisError:
                pass
        self.fallback_data['behavior_cache'][ip] = data
        return True
    
    def publish_event(self, channel, message):
        """Publish event to Redis pub/sub"""
        client = self._get_client()
        if client:
            try:
                return client.publish(channel, message)
            except RedisError:
                pass
        return 0
    
    def subscribe(self, channels):
        """Subscribe to Redis pub/sub channels"""
        client = self._get_client()
        if client:
            try:
                pubsub = client.pubsub()
                pubsub.subscribe(channels)
                return pubsub
            except RedisError:
                pass
        return None
    
    def pipeline(self):
        """Get a Redis pipeline for batch operations"""
        client = self._get_client()
        if client:
            try:
                return client.pipeline()
            except RedisError:
                pass
        return None
    
    def is_connected(self):
        """Check if Redis is connected"""
        return self.client is not None or self.cluster_client is not None
    
    def get_stats(self):
        """Get Redis statistics"""
        client = self._get_client()
        if client:
            try:
                info = client.info()
                return {
                    'connected_clients': info.get('connected_clients', 0),
                    'used_memory': info.get('used_memory_human', '0B'),
                    'total_commands_processed': info.get('total_commands_processed', 0),
                    'keyspace_hits': info.get('keyspace_hits', 0),
                    'keyspace_misses': info.get('keyspace_misses', 0)
                }
            except RedisError:
                pass
        return {'status': 'fallback_mode'}

# Create global instance
redis_conn = RedisConnection()
