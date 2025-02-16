"""
Rate limiting utility for domain scan APIs
"""
import time
from typing import Dict, Tuple
from django.core.cache import cache
from django.conf import settings
import asyncio

class RateLimiter:
    """Rate limiter for API requests"""
    
    # Default rate limits per platform (requests per minute)
    DEFAULT_RATE_LIMITS = {
        'alienvault': 60,    # 1 request per second
        'virustotal': 240,   # 4 requests per minute
        'pulsedive': 30,     # 1 request per 2 seconds
        'metadefender': 120, # 2 requests per second
        'securitytrails': 60 # 1 request per second
    }
    
    @classmethod
    def can_make_request(cls, platform: str, user_id: int) -> Tuple[bool, float]:
        """
        Check if a request can be made for the given platform
        
        Args:
            platform: Platform name
            user_id: User ID making the request
            
        Returns:
            Tuple of (can_request, wait_time)
        """
        rate_limit = cls.DEFAULT_RATE_LIMITS.get(platform, 60)  # Default to 60 rpm
        cache_key = f"rate_limit:{platform}:{user_id}"
        
        # Get the last request timestamps from cache
        timestamps = cache.get(cache_key, [])
        current_time = time.time()
        
        # Remove timestamps older than 1 minute
        timestamps = [ts for ts in timestamps if current_time - ts < 60]
        
        # Check if we're within rate limit
        if len(timestamps) >= rate_limit:
            # Calculate wait time until next available slot
            wait_time = 60 - (current_time - timestamps[0])
            return False, max(0, wait_time)
        
        # Add current timestamp and update cache
        timestamps.append(current_time)
        cache.set(cache_key, timestamps, timeout=60)
        
        return True, 0
    
    @classmethod
    def get_platform_limits(cls) -> Dict[str, int]:
        """Get rate limits for all platforms"""
        return cls.DEFAULT_RATE_LIMITS.copy()
    
    @classmethod
    async def wait_if_needed(cls, platform: str, user_id: int):
        """
        Wait if rate limit is exceeded
        
        Args:
            platform: Platform name
            user_id: User ID making the request
        """
        can_request, wait_time = cls.can_make_request(platform, user_id)
        if not can_request:
            await asyncio.sleep(wait_time)
