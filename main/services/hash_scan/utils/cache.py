import logging
from typing import Dict, Optional, Any
import redis
import json
from datetime import timedelta
import os

logger = logging.getLogger(__name__)

class Cache:
    """Redis-based cache for hash analysis results."""
    
    def __init__(self):
        self.redis = None
        self.default_ttl = timedelta(hours=24)  # Cache results for 24 hours by default
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost')
        self._connect()

    def _connect(self):
        """Connect to Redis server."""
        try:
            if not self.redis:
                self.redis = redis.from_url(self.redis_url)
                self.redis.ping()  # Test connection
                logger.info("Successfully connected to Redis")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self.redis = None

    def close(self):
        """Close Redis connection."""
        if self.redis:
            self.redis.close()
            self.redis = None

    def get(self, key: str) -> Optional[Dict]:
        """
        Get cached value for a key.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        try:
            if not self.redis:
                self._connect()
                if not self.redis:
                    return None

            value = self.redis.get(key)
            if value:
                return json.loads(value)
        except Exception as e:
            logger.error(f"Error getting cache key {key}: {str(e)}")
        return None

    def set(self, key: str, value: Any, ttl: Optional[timedelta] = None) -> bool:
        """
        Set cache value with optional TTL.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Optional time-to-live
            
        Returns:
            bool indicating success
        """
        try:
            if not self.redis:
                self._connect()
                if not self.redis:
                    return False

            ttl = ttl or self.default_ttl
            return self.redis.setex(
                key,
                int(ttl.total_seconds()),
                json.dumps(value)
            )
        except Exception as e:
            logger.error(f"Error setting cache key {key}: {str(e)}")
            return False

    def delete(self, key: str) -> bool:
        """
        Delete a cache key.
        
        Args:
            key: Cache key to delete
            
        Returns:
            bool indicating if key was deleted
        """
        try:
            if not self.redis:
                self._connect()
                if not self.redis:
                    return False

            return bool(self.redis.delete(key))
        except Exception as e:
            logger.error(f"Error deleting cache key {key}: {str(e)}")
            return False

    def get_cache_key(self, file_hash: str, platform: str) -> str:
        """Generate a cache key for a hash analysis request."""
        return f"hash_analysis:{platform}:{file_hash}"


# Create global cache instance
cache = Cache()
