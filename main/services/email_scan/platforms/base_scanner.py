"""
Base scanner interface for Email analysis platforms
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import aiohttp
import logging
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Base class for all Email scanning platforms"""

    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        """
        Initialize the scanner
        
        Args:
            session: aiohttp client session for making requests
            api_key: Optional API key for the platform
        """
        self.session = session
        self.api_key = api_key
        self.platform_name = self.__class__.__name__.lower().replace('scanner', '')
        self.rate_limit_delay = 1  # Default delay between requests
        self.last_request_time = datetime.now()

    @abstractmethod
    async def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan email data using the platform
        
        Args:
            email_data: Dictionary containing email data including:
                - headers: Raw email headers
                - ips: List of IPs found in headers
                - urls: List of URLs found in body
                - attachments: List of attachment hashes
                - from_address: Sender email address
                - to_address: Recipient email address
            
        Returns:
            Dictionary containing scan results
        """
        pass

    @abstractmethod
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL using the platform
        
        Args:
            url: URL to scan
            
        Returns:
            Dictionary containing scan results
        """
        pass

    @abstractmethod
    async def scan_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Scan a file hash using the platform
        
        Args:
            file_hash: Hash of the file to scan (MD5, SHA-1, or SHA-256)
            
        Returns:
            Dictionary containing scan results
        """
        pass

    @abstractmethod
    def calculate_threat_score(self, data: Dict[str, Any]) -> Optional[float]:
        """
        Calculate threat score from platform data
        
        Args:
            data: Platform response data
            
        Returns:
            Threat score between 0-100 or None if score cannot be calculated
        """
        pass

    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make an HTTP request with rate limiting and error handling
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to make request to
            **kwargs: Additional arguments to pass to request
            
        Returns:
            Response data as dictionary
        """
        await self._respect_rate_limit()
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                self.last_request_time = datetime.now()
                
                if response.status == 429:  # Too Many Requests
                    retry_after = int(response.headers.get('Retry-After', self.rate_limit_delay))
                    logger.warning(f"{self.platform_name}: Rate limit hit, waiting {retry_after} seconds")
                    await asyncio.sleep(retry_after)
                    return await self._make_request(method, url, **kwargs)
                
                response.raise_for_status()
                return await response.json()
                
        except aiohttp.ClientError as e:
            logger.error(f"{self.platform_name}: Request error: {str(e)}")
            raise

    async def _respect_rate_limit(self):
        """Ensure we respect the rate limit"""
        elapsed = (datetime.now() - self.last_request_time).total_seconds()
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
