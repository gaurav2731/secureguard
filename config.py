"""
SecureGuard Configuration
"""

# Website Configuration
PROTECTED_WEBSITE = {
    'ip': '175.176.186.102',  # Replace with your website's IP
    'port': 80,       # Default HTTP port
    'ssl_port': 443   # Default HTTPS port
}

# Firewall Settings
FIREWALL_CONFIG = {
    'max_packets_per_minute': 2000000,  # 2M packets per minute
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
    'db': 0
}