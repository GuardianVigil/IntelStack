"""
Base scanner implementation for URL scanning platforms
"""
from typing import Dict, Any, Optional, Union
import aiohttp
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

class BaseScanner:
    """Base scanner class for all URL scanning platforms"""

    def __init__(self, session: aiohttp.ClientSession, api_key: str):
        self.session = session
        self.api_key = api_key

    def _clean_dict(self, data: Any) -> Any:
        """Clean dictionary to ensure all keys are strings and values are JSON serializable"""
        try:
            if data is None:
                return ""
            elif isinstance(data, (str, int, float, bool)):
                return data
            elif isinstance(data, dict):
                cleaned = {}
                for k, v in data.items():
                    # Skip None keys
                    if k is None:
                        continue
                    try:
                        # Convert key to string and clean value
                        str_key = str(k)
                        cleaned_value = self._clean_dict(v)
                        if cleaned_value is not None:  # Only add non-None values
                            cleaned[str_key] = cleaned_value
                    except Exception as e:
                        logger.error(f"Error cleaning dictionary key-value pair: {e}")
                        continue
                return cleaned
            elif isinstance(data, (list, tuple, set)):
                cleaned = []
                for item in data:
                    try:
                        cleaned_item = self._clean_dict(item)
                        if cleaned_item is not None:  # Only add non-None items
                            cleaned.append(cleaned_item)
                    except Exception as e:
                        logger.error(f"Error cleaning list item: {e}")
                        continue
                return cleaned
            else:
                try:
                    return str(data)
                except Exception as e:
                    logger.error(f"Error converting value to string: {e}")
                    return ""
        except Exception as e:
            logger.error(f"Error in _clean_dict: {e}")
            return {}

    def _clean_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Clean headers to ensure all keys and values are strings"""
        if not headers:
            return {}
        
        cleaned_headers = {}
        try:
            for key, value in headers.items():
                if key is not None and value is not None:
                    cleaned_headers[str(key)] = str(value)
        except Exception as e:
            logger.error(f"Error cleaning headers: {e}")
        return cleaned_headers

    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling and proper JSON serialization"""
        try:
            # Clean request data before sending
            if 'json' in kwargs:
                kwargs['json'] = self._clean_dict(kwargs['json'])
            if 'data' in kwargs and isinstance(kwargs['data'], dict):
                kwargs['data'] = self._clean_dict(kwargs['data'])
            if 'form' in kwargs and isinstance(kwargs['form'], dict):
                kwargs['data'] = self._clean_dict(kwargs['form'])  # aiohttp uses 'data' for form data
                del kwargs['form']  # Remove 'form' as we've moved it to 'data'

            # Handle headers
            if 'headers' in kwargs:
                kwargs['headers'] = self._clean_headers(kwargs['headers'])
            else:
                # Only set default Content-Type if no headers are provided
                kwargs['headers'] = self._clean_headers({'Content-Type': 'application/json'})

            async with self.session.request(method, url, **kwargs) as response:
                # Log request details for debugging
                logger.debug(f"Request to {url}: method={method}, headers={kwargs.get('headers')}")
                
                try:
                    if response.status == 404:
                        raise aiohttp.ClientError(f"HTTP error {response.status}: Not Found")
                    elif response.status == 410:
                        raise aiohttp.ClientError(f"HTTP error {response.status}: Gone")
                    
                    response.raise_for_status()
                    
                    # Parse and clean response data
                    if response.content_type == 'application/json':
                        data = await response.json()
                        return self._clean_dict(data)
                    else:
                        # Handle non-JSON responses
                        text = await response.text()
                        return {"content": text}
                        
                except aiohttp.ContentTypeError:
                    # Handle invalid JSON responses
                    text = await response.text()
                    logger.error(f"Invalid JSON response: {text}")
                    return {"error": "Invalid JSON response", "content": text}
                    
        except aiohttp.ClientError as e:
            # Log HTTP errors with response details if available
            error_msg = str(e)
            if hasattr(e, 'status'):
                error_msg = f"HTTP error {e.status}: {error_msg}"
            logger.error(f"HTTP error in _make_request: {error_msg}, url='{url}'")
            raise
            
        except Exception as e:
            logger.error(f"Error in _make_request: {str(e)}")
            raise

    async def scan(self, url: str) -> Dict[str, Any]:
        """Implement in child class"""
        raise NotImplementedError

    def calculate_score(self, data: Dict[str, Any]) -> float:
        """Implement in child class"""
        raise NotImplementedError