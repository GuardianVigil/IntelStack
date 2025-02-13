import logging
from typing import Dict, Optional
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
import os

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter for API requests."""
    
    def __init__(self):
        # Default rate limits per platform (requests per minute)
        self.rate_limits = {
            'virustotal': 4,      # 240 requests/hour
            'hybrid_analysis': 2,  # 120 requests/hour
            'threatfox': 4,       # 240 requests/hour
            'malwarebazaar': 4,   # 240 requests/hour
            'filescan': 10,       # 600 requests/hour
            'metadefender': 10    # 600 requests/hour
        }
        
        # Track request timestamps per platform
        self.request_history: Dict[str, list] = defaultdict(list)
        
        # Time window for rate limiting (1 minute)
        self.window = timedelta(minutes=1)

    def _clean_history(self, platform: str):
        """Remove old requests from history."""
        now = datetime.utcnow()
        self.request_history[platform] = [
            timestamp for timestamp in self.request_history[platform]
            if now - timestamp < self.window
        ]

    async def acquire(self, platform: str) -> bool:
        """
        Try to acquire a rate limit token.
        
        Args:
            platform: Platform name
            
        Returns:
            bool indicating if request is allowed
        """
        now = datetime.utcnow()
        self._clean_history(platform)
        
        # Get rate limit for platform
        rate_limit = self.rate_limits.get(platform, 4)  # Default to 4 requests/minute
        
        # Check if we're under the rate limit
        if len(self.request_history[platform]) < rate_limit:
            self.request_history[platform].append(now)
            return True
            
        # We're at the rate limit, calculate wait time
        oldest_request = self.request_history[platform][0]
        wait_time = (oldest_request + self.window) - now
        
        if wait_time.total_seconds() > 0:
            logger.warning(f"Rate limit reached for {platform}, waiting {wait_time.total_seconds():.2f} seconds")
            await asyncio.sleep(wait_time.total_seconds())
            
        # Remove oldest request and add new one
        self.request_history[platform].pop(0)
        self.request_history[platform].append(now)
        return True

    def update_rate_limit(self, platform: str, requests_per_minute: int):
        """Update rate limit for a platform."""
        self.rate_limits[platform] = requests_per_minute

# Create global rate limiter instance
rate_limiter = RateLimiter()
