"""
Base scanner interface for IP analysis platforms
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import aiohttp
import logging
import asyncio

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Base class for all IP scanning platforms"""

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
        self.last_request_time = 0

    @abstractmethod
    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """
        Scan an IP address using the platform
        
        Args:
            ip_address: IP address to scan
            
        Returns:
            Dictionary containing scan results
        """
        pass

    @abstractmethod
    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """
        Calculate threat score from platform data
        
        Args:
            data: Platform response data
            
        Returns:
            Threat score between 0-100 or None if score cannot be calculated
        """
        pass

    @abstractmethod
    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract WHOIS information from platform data
        
        Args:
            data: Platform response data
            
        Returns:
            Dictionary containing WHOIS information
        """
        pass

    @abstractmethod
    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract network information from platform data
        
        Args:
            data: Platform response data
            
        Returns:
            Dictionary containing network information
        """
        pass

    async def _make_request(
        self, 
        method: str, 
        url: str, 
        headers: Optional[Dict[str, str]] = None, 
        params: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request with error handling
        """
        try:
            # Add default headers if not present
            if headers is None:
                headers = {}
            if 'User-Agent' not in headers:
                headers['User-Agent'] = 'ThreatIntel-Scanner/1.0'

            # Log request details (safely)
            safe_url = url.replace(self.api_key, '<hidden>') if self.api_key else url
            logger.debug(f"{self.platform_name} request: {method} {safe_url}")

            # Respect rate limits
            now = asyncio.get_event_loop().time()
            if now - self.last_request_time < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - (now - self.last_request_time))
            
            async with self.session.request(
                method, 
                url, 
                headers=headers,
                params=params,
                json=json_data
            ) as response:
                self.last_request_time = asyncio.get_event_loop().time()
                
                # Always try to get response text for better error logging
                try:
                    response_text = await response.text()
                    response_data = await response.json() if response_text else {}
                except Exception as e:
                    logger.error(f"{self.platform_name} response parsing error: {str(e)}, text: {response_text[:200]}")
                    response_data = {}

                if response.status == 429:  # Rate limit hit
                    retry_after = response.headers.get('Retry-After', str(self.rate_limit_delay))
                    logger.warning(f"{self.platform_name} rate limit hit")
                    return {"error": f"{self.platform_name} rate limit exceeded. Try again later.", "status": 429}
                
                if response.status == 401 or response.status == 403:  # Auth error
                    logger.error(f"{self.platform_name} API authentication error. Status: {response.status}, Response: {response_text[:200]}")
                    return {"error": "API authentication error. Check API key.", "details": response_data}
                
                if response.status == 404:  # Not found
                    logger.warning(f"{self.platform_name} resource not found: {safe_url}")
                    return {"error": "Resource not found", "details": response_data}
                
                if response.status >= 400:
                    logger.error(f"{self.platform_name} API error: {response.status}, Response: {response_text[:200]}")
                    return {"error": f"API error: {response.status}", "details": response_data}
                
                return response_data
                
        except aiohttp.ClientError as e:
            error_msg = f"{self.platform_name} request error: {str(e)}"
            logger.error(error_msg)
            return {"error": f"Request failed: {str(e)}"}
            
        except Exception as e:
            error_msg = f"{self.platform_name} unexpected error: {str(e)}"
            logger.error(error_msg)
            return {"error": f"Unexpected error: {str(e)}"}
