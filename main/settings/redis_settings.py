"""Redis settings for the application"""

# Redis connection settings
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # Set this in production
REDIS_SSL = False     # Enable in production

# Redis cache settings
REDIS_CACHE_PREFIX = 'stack_cache:'
REDIS_CACHE_DEFAULT_TIMEOUT = 3600  # 1 hour

# Redis connection pool settings
REDIS_POOL_MAX_CONNECTIONS = 100
REDIS_POOL_TIMEOUT = 20
REDIS_POOL_RETRY_ON_TIMEOUT = True

# Cache key prefixes for different features
CACHE_KEYS = {
    'ip_analysis': 'ip_analysis:',
    'domain_analysis': 'domain_analysis:',
    'hash_analysis': 'hash_analysis:',
    'url_analysis': 'url_analysis:',
}

# Cache timeouts for different features (in seconds)
CACHE_TIMEOUTS = {
    'ip_analysis': 3600,        # 1 hour
    'domain_analysis': 7200,    # 2 hours
    'hash_analysis': 86400,     # 24 hours
    'url_analysis': 3600,       # 1 hour
}

# Redis Sentinel settings (for high availability)
REDIS_SENTINEL_ENABLED = False
REDIS_SENTINEL_MASTER = 'mymaster'
REDIS_SENTINEL_NODES = [
    ('localhost', 26379),
    ('localhost', 26380),
    ('localhost', 26381),
]

# Redis key patterns for monitoring
REDIS_MONITOR_PATTERNS = [
    'ip_analysis:*',
    'domain_analysis:*',
    'hash_analysis:*',
    'url_analysis:*',
]
