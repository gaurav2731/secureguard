"""
SecureGuard Enhanced Configuration
Complete configuration for the ultra-advanced firewall system
"""

# Website Configuration
PROTECTED_WEBSITES = {
    'default': {
        'ip': '127.0.0.1',      # Backend website IP
        'port': 8080,           # Backend website port
        'ssl_port': 8443,       # Backend SSL port
        'use_ssl': False,       # Whether to use SSL for backend
        'domain': 'localhost',  # Domain for this backend
        'enabled': True         # Enable/disable this backend
    },
    # Add more websites as needed:
    # 'website2': {
    #     'ip': '192.168.1.100',
    #     'port': 80,
    #     'ssl_port': 443,
    #     'use_ssl': True,
    #     'domain': 'example.com',
    #     'enabled': True
    # }
}

# Legacy support
PROTECTED_WEBSITE = PROTECTED_WEBSITES['default']

# Firewall Settings
FIREWALL_CONFIG = {
    'max_packets_per_minute': 5000000,  # 5M packets per minute (upgraded)
    'block_threshold': 100,             # Block after 100 suspicious requests
    'rate_limit': 1000,                 # Requests per minute per IP
    'whitelist': [],                    # Whitelisted IPs
    'blacklist': []                     # Permanently blocked IPs
}

# Server Configuration
SERVER_CONFIG = {
    'listen_host': '127.0.0.1',  # Firewall listen address
    'listen_port': 5000,         # Firewall listen port
    'proxy_mode': True           # Enable proxy mode for website protection
}

# Redis Configuration (Optional)
REDIS_CONFIG = {
    'host': 'localhost',
    'port': 6379,
    'password': None,
    'db': 0,
    'cluster_mode': False,    # Enable Redis Cluster
    'cluster_nodes': ['localhost:6379', 'localhost:6380']  # Cluster nodes
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'cache_size': 500000,        # 500K entries LRU cache (upgraded)
    'batch_size': 1000,          # Records per database batch
    'flush_interval': 5,         # Seconds between DB writes
    'server_threads': 16,        # Concurrent threads (upgraded)
    'connection_limit': 4096,    # Simultaneous connections (upgraded)
    'timeouts': {
        'channel_timeout': 30,   # Channel timeout in seconds
        'cleanup_interval': 30   # Cleanup interval in seconds
    }
}

# ML Configuration
ML_CONFIG = {
    'enabled': False,  # Temporarily disabled due to import issues
    'model_path': 'models/enhanced_ml_model.pkl',
    'retraining_interval': 3600,  # Retrain every hour
    'feature_count': 50,          # Number of features (upgraded)
    'accuracy_target': 0.98,      # Target accuracy (upgraded)
    'anomaly_threshold': 0.05,    # Isolation Forest contamination
    'ensemble_models': ['rf', 'gb', 'nn']  # Models to use
}

# Security Configuration
SECURITY_CONFIG = {
    'packet_inspection_enabled': True,
    'threat_threshold': 0.7,      # Threat score threshold
    'ddos_threshold': 1000,       # DDoS detection threshold
    'syn_flood_threshold': 500,   # SYN flood threshold
    'threat_intelligence_update': 1800,  # Update interval
    'geo_blocking_enabled': True,
    'behavioral_analysis_enabled': True,
    'zero_day_detection_enabled': True
}

# Monitoring Configuration
MONITORING_CONFIG = {
    'enabled': True,
    'metrics_interval': 60,       # Collect metrics every 60 seconds
    'alerting_enabled': True,
    'log_level': 'INFO',
    'performance_monitoring': True,
    'threat_dashboard_enabled': True
}

# Cluster Configuration
CLUSTER_CONFIG = {
    'enabled': False,             # Enable clustering
    'node_id': 'node_001',
    'cluster_nodes': ['localhost:5000'],
    'heartbeat_interval': 30,     # Heartbeat interval
    'node_timeout': 120,          # Node timeout
    'load_balancer_algorithm': 'round_robin',  # round_robin, least_connections, ip_hash
    'health_check_interval': 10   # Health check interval
}

# Threat Intelligence Configuration
THREAT_INTELLIGENCE_CONFIG = {
    'enabled': True,
    'update_interval': 1800,      # Update every 30 minutes
    'sources': {
        'tor_exit_nodes_url': 'https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst',
        'malicious_ips_url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'bot_signatures_url': 'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list'
    },
    'confidence_threshold': 0.8,  # Minimum confidence for blocking
    'cache_ttl': 3600            # Cache TTL in seconds
}
