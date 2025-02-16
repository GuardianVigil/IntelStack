"""
MetaDefender API integration
"""
import logging
import aiohttp
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class MetaDefenderAPI:
    """Client for MetaDefender API"""
    
    def __init__(self, api_key: str):
        """
        Initialize MetaDefender client
        
        Args:
            api_key: MetaDefender API key
        """
        self.api_key = api_key
        self.base_url = "https://api.metadefender.com/v4"
        self.headers = {
            "apikey": api_key,
            "Accept": "application/json"
        }

    async def scan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Scan domain using MetaDefender
        
        Args:
            domain: Domain to scan
            
        Returns:
            Scan results or None if error
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Get domain lookup
                url = f"{self.base_url}/domain/{domain}"
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        lookup_data = await response.json()
                    else:
                        error_data = await response.text()
                        logger.error(f"MetaDefender API error: {error_data}")
                        return None

                # Get domain reputation
                rep_url = f"{self.base_url}/domain/reputation/{domain}"
                async with session.get(rep_url, headers=self.headers) as response:
                    if response.status == 200:
                        reputation_data = await response.json()
                    else:
                        reputation_data = {}

                return self._process_response(lookup_data, reputation_data)

        except Exception as e:
            logger.error(f"Error scanning domain {domain} with MetaDefender: {str(e)}")
            return None

    def _process_response(self, lookup_data: Dict[str, Any], reputation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process MetaDefender API response
        
        Args:
            lookup_data: Domain lookup response
            reputation_data: Domain reputation response
            
        Returns:
            Processed data
        """
        try:
            return {
                'lookup_results': {
                    'detected_by': lookup_data.get('detected_by', 0),
                    'scan_results': lookup_data.get('scan_results', []),
                    'address': lookup_data.get('address'),
                    'geo_info': lookup_data.get('geo_info', {}),
                    'last_seen': lookup_data.get('last_seen')
                },
                'reputation': {
                    'reputation_score': reputation_data.get('reputation_score', 0),
                    'threat_level': reputation_data.get('threat_level', 'unknown'),
                    'detection_sources': reputation_data.get('detection_sources', []),
                    'first_seen': reputation_data.get('first_seen'),
                    'last_seen': reputation_data.get('last_seen')
                }
            }
        except Exception as e:
            logger.error(f"Error processing MetaDefender response: {str(e)}")
            return {}
