import redis
import json
from typing import Any, Optional
from django.conf import settings
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

class RedisCache:
    """Redis cache manager for IP analysis results"""
    
    def __init__(self):
        # Create connection pool
        pool = redis.ConnectionPool(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
            socket_timeout=settings.REDIS_POOL_TIMEOUT,
            socket_connect_timeout=settings.REDIS_POOL_TIMEOUT,
            retry_on_timeout=settings.REDIS_POOL_RETRY_ON_TIMEOUT,
            max_connections=settings.REDIS_POOL_MAX_CONNECTIONS
        )
        
        # Create Redis client with connection pool
        self.redis_client = redis.Redis(
            connection_pool=pool,
            decode_responses=True
        )
        
    def get(self, key: str) -> Optional[dict]:
        """Get cached data for a key"""
        try:
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Redis get error: {str(e)}", exc_info=True)
            return None
            
    def set(self, key: str, value: Any, timeout: int = 3600) -> bool:
        """Set cached data with expiration"""
        try:
            return self.redis_client.setex(
                name=key,
                time=timeout,
                value=json.dumps(value)
            )
        except Exception as e:
            logger.error(f"Redis set error: {str(e)}", exc_info=True)
            return False
            
    def delete(self, key: str) -> bool:
        """Delete cached data"""
        try:
            return bool(self.redis_client.delete(key))
        except Exception as e:
            logger.error(f"Redis delete error: {str(e)}", exc_info=True)
            return False
            
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            return bool(self.redis_client.exists(key))
        except Exception as e:
            logger.error(f"Redis exists error: {str(e)}", exc_info=True)
            return False
            
    def set_many(self, mapping: dict, timeout: int = 3600) -> bool:
        """Set multiple key-value pairs with expiration"""
        try:
            pipeline = self.redis_client.pipeline()
            for key, value in mapping.items():
                pipeline.setex(
                    name=key,
                    time=timeout,
                    value=json.dumps(value)
                )
            pipeline.execute()
            return True
        except Exception as e:
            logger.error(f"Redis set_many error: {str(e)}", exc_info=True)
            return False
            
    def get_many(self, keys: list) -> dict:
        """Get multiple cached values"""
        try:
            pipeline = self.redis_client.pipeline()
            for key in keys:
                pipeline.get(key)
            values = pipeline.execute()
            return {
                key: json.loads(value) if value else None
                for key, value in zip(keys, values)
            }
        except Exception as e:
            logger.error(f"Redis get_many error: {str(e)}", exc_info=True)
            return {}
            
    def clear(self, pattern: str = None) -> bool:
        """Clear all keys matching pattern"""
        try:
            if pattern:
                keys = self.redis_client.keys(pattern)
                if keys:
                    return bool(self.redis_client.delete(*keys))
            return True
        except Exception as e:
            logger.error(f"Redis clear error: {str(e)}", exc_info=True)
            return False
            
    def health_check(self) -> bool:
        """Check if Redis is responsive"""
        try:
            return self.redis_client.ping()
        except Exception as e:
            logger.error(f"Redis health check error: {str(e)}", exc_info=True)
            return False
