"""
Pulsedive API integration
"""
import logging
import aiohttp
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class PulsediveAPI:
    """Client for Pulsedive API"""
    
    def __init__(self, api_key: str):
        """
        Initialize Pulsedive client
        
        Args:
            api_key: Pulsedive API key
        """
        self.api_key = api_key
        self.base_url = "https://pulsedive.com/api/v1"

    async def scan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Scan domain using Pulsedive
        
        Args:
            domain: Domain to scan
            
        Returns:
            Scan results or None if error
        """
        try:
            async with aiohttp.ClientSession() as session:
                # First, submit the domain for scanning
                params = {
                    'indicator': domain,
                    'key': self.api_key,
                    'pretty': '1'
                }
                
                # Get domain info
                info_url = f"{self.base_url}/info.php"
                async with session.get(info_url, params=params) as response:
                    if response.status == 200:
                        info_data = await response.json()
                    else:
                        error_data = await response.text()
                        logger.error(f"Pulsedive API error: {error_data}")
                        return None
                
                # Get domain links
                links_url = f"{self.base_url}/info.php"
                params['get'] = 'links'
                async with session.get(links_url, params=params) as response:
                    if response.status == 200:
                        links_data = await response.json()
                    else:
                        links_data = {}
                
                # Combine and process results
                return self._process_response(info_data, links_data)
                
        except Exception as e:
            logger.error(f"Error scanning domain {domain} with Pulsedive: {str(e)}")
            return None

    def _process_response(self, info_data: Dict[str, Any], links_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process Pulsedive API response
        
        Args:
            info_data: Domain info response
            links_data: Domain links response
            
        Returns:
            Processed data
        """
        try:
            return {
                'info': {
                    'risk': info_data.get('risk', 'unknown'),
                    'risk_recommended': info_data.get('risk_recommended'),
                    'manualrisk': info_data.get('manualrisk'),
                    'threats': info_data.get('threats', []),
                    'feeds': info_data.get('feeds', []),
                    'stamp_added': info_data.get('stamp_added'),
                    'stamp_updated': info_data.get('stamp_updated'),
                    'stamp_seen': info_data.get('stamp_seen'),
                    'recent': info_data.get('recent', [])
                },
                'links': {
                    'dns': links_data.get('dns', []),
                    'redirects': links_data.get('redirects', []),
                    'threats': links_data.get('threats', []),
                    'feeds': links_data.get('feeds', [])
                }
            }
        except Exception as e:
            logger.error(f"Error processing Pulsedive response: {str(e)}")
            return {}
