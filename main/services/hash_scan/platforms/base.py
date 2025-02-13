from abc import ABC, abstractmethod
import aiohttp
import logging
from typing import Dict, Optional
from ..utils.cache import cache
from ..utils.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

class BasePlatform(ABC):
    """Base class for all hash analysis platforms."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    @abstractmethod
    async def analyze_hash(self, file_hash: str) -> Dict:
        """Analyze a file hash and return the results."""
        pass

    async def _make_request(self, method: str, url: str, headers: Optional[Dict] = None, 
                          params: Optional[Dict] = None, json: Optional[Dict] = None) -> Dict:
        """Make an HTTP request to the platform API with caching and rate limiting."""
        platform = self.__class__.__name__.replace('Client', '').lower()
        cache_key = cache.get_cache_key(file_hash=url, platform=platform)

        # Try to get from cache first
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.info(f"Cache hit for {platform} request: {url}")
            return cached_result

        # Apply rate limiting
        await rate_limiter.acquire(platform)

        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            async with self.session.request(method, url, headers=headers, 
                                         params=params, json=json) as response:
                response.raise_for_status()
                result = await response.json()

                # Cache successful response
                if "error" not in result:
                    cache.set(cache_key, result)
                
                return result

        except aiohttp.ClientError as e:
            logger.error(f"Request failed for {platform}: {str(e)}")
            raise
