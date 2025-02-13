from abc import ABC, abstractmethod
import aiohttp
import logging
import json as jsonlib
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
        
        # Log request details
        logger.debug(f"{platform} request - URL: {url}")
        logger.debug(f"{platform} request - Headers: {headers}")
        logger.debug(f"{platform} request - JSON payload: {json}")
        
        # Apply rate limiting
        await rate_limiter.acquire(platform)

        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            async with self.session.request(method, url, headers=headers, 
                                         params=params, json=json) as response:
                # Log response status
                logger.debug(f"{platform} response status: {response.status}")
                
                # Get response text first
                text = await response.text()
                logger.debug(f"{platform} raw response text: {text}")
                
                try:
                    result = jsonlib.loads(text) if text else {}
                except jsonlib.JSONDecodeError as e:
                    logger.error(f"{platform} JSON decode error: {str(e)}")
                    logger.error(f"{platform} Response text: {text}")
                    raise
                
                # Check response status
                if response.status != 200:
                    logger.error(f"{platform} request failed with status {response.status}")
                    logger.error(f"{platform} error response: {result}")
                    return {"error": f"Request failed with status {response.status}"}
                
                return result

        except aiohttp.ClientError as e:
            logger.error(f"Request failed for {platform}: {str(e)}")
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error for {platform}: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}"}
