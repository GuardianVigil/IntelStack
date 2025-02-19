"""
Base scanner implementation for URL scanning platforms
"""
from typing import Dict, Any, Optional
import aiohttp
import asyncio

class BaseScanner:
    """Base scanner class for all URL scanning platforms"""

    def __init__(self, session: aiohttp.ClientSession, api_key: str):
        self.session = session
        self.api_key = api_key

    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        try:
            async with self.session.request(method, url, **kwargs) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            return {"error": str(e)}

    async def scan(self, url: str) -> Dict[str, Any]:
        """Implement in child class"""
        raise NotImplementedError

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Implement in child class"""
        raise NotImplementedError