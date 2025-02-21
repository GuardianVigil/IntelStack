"""
Base scanner interface for Email analysis platforms
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
import aiohttp
import logging
import asyncio
from datetime import datetime
from django.core.cache import cache
from django.conf import settings
from main.models import APIKey
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Base class for all Email scanning platforms"""

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        """Initialize scanner with API key and session"""
        self._api_key = api_key
        self.session = session
        self.name = self.__class__.__name__
        self.platform_name = self.__class__.__name__
        self.base_url = None
        self.cache_timeout = getattr(settings, 'API_KEY_CACHE_TIMEOUT', 3600)  # 1 hour
        self.rate_limit_delay = 1  # Default delay between requests
        self.last_request_time = datetime.now()

    @property
    async def api_key(self) -> str:
        """Get API key"""
        return self._api_key

    @sync_to_async
    def _get_api_key(self) -> str:
        """Get API key from database"""
        try:
            api_key = APIKey.objects.filter(
                platform=self.platform_name,
                is_active=True
            ).first()
            
            if not api_key:
                raise ValueError(f"No active API key found for {self.platform_name}")
                
            return api_key.key
            
        except Exception as e:
            logger.error(f"Error getting API key for {self.platform_name}: {str(e)}")
            raise

    async def _make_request(self, method: str, url: str, headers: Dict = None, data: Dict = None, params: Dict = None) -> Dict:
        """Make an HTTP request with rate limiting and error handling"""
        try:
            # Get API key
            api_key = await self.api_key
            if not api_key:
                raise ValueError(f"No API key available for {self.name}")
                
            # Add API key to headers
            headers = headers or {}
            if 'api-key' not in headers and 'API-Key' not in headers:
                headers['api-key'] = api_key
                
            # Rate limiting
            now = datetime.now()
            if (now - self.last_request_time).total_seconds() < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay)
            self.last_request_time = now
            
            # Make request
            async with self.session.request(method, url, headers=headers, json=data, params=params) as response:
                if response.status == 429:  # Too Many Requests
                    retry_after = int(response.headers.get('Retry-After', self.rate_limit_delay))
                    await asyncio.sleep(retry_after)
                    return await self._make_request(method, url, headers, data, params)
                    
                response.raise_for_status()
                return await response.json()
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error in {self.name}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error in {self.name} request: {str(e)}")
            raise

    async def _wait_for_scan_result(self, result_url: str, headers: dict, max_attempts: int = 10, delay: int = 15) -> Dict[str, Any]:
        """Wait for scan result with retries"""
        for attempt in range(max_attempts):
            try:
                async with self.session.get(result_url, headers=headers) as response:
                    if response.status == 404:  # Not ready
                        await asyncio.sleep(delay)
                        continue
                    elif response.status == 200:
                        return await response.json()
                    else:
                        response.raise_for_status()
            except Exception as e:
                if attempt == max_attempts - 1:
                    raise
                logger.warning(f"Attempt {attempt + 1}/{max_attempts} failed: {str(e)}")
                await asyncio.sleep(delay)
        
        raise TimeoutError("Max attempts reached waiting for scan result")

    async def _submit_url_scan(self, url: str, submit_url: str, headers: dict = None, data: dict = None) -> Dict[str, Any]:
        """Submit URL for scanning"""
        if headers is None:
            headers = {}
        if 'API-Key' not in headers:
            headers['API-Key'] = await self.api_key
            
        try:
            async with self.session.post(submit_url, headers=headers, json=data) as response:
                if response.status == 200:
                    return await response.json()
                response.raise_for_status()
        except Exception as e:
            logger.error(f"Error submitting URL scan: {str(e)}")
            raise

    def calculate_threat_score(self, data: Dict[str, Any]) -> int:
        """Calculate normalized threat score from scanner results"""
        try:
            # Default implementation - override in subclasses
            if isinstance(data, dict):
                # Check for common threat indicators
                malicious = data.get('malicious', 0)
                threat_score = data.get('threat_score', 0)
                threat_level = data.get('threat_level', '').lower()
                
                if malicious:
                    return 100
                elif threat_score:
                    return min(100, threat_score)
                elif threat_level in ['high', 'critical']:
                    return 80
                elif threat_level == 'medium':
                    return 50
                elif threat_level == 'low':
                    return 20
                
            return 0
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return 0

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

    async def _respect_rate_limit(self):
        """Ensure we respect the rate limit"""
        elapsed = (datetime.now() - self.last_request_time).total_seconds()
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
