"""
VirusTotal API integration
"""
import logging
import aiohttp
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class VirusTotalAPI:
    """Client for VirusTotal API"""
    
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal client
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

    async def scan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Scan domain using VirusTotal
        
        Args:
            domain: Domain to scan
            
        Returns:
            Scan results or None if error
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Get domain report
                url = f"{self.base_url}/domains/{domain}"
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._process_response(data)
                    else:
                        error_data = await response.text()
                        logger.error(f"VirusTotal API error: {error_data}")
                        return None
        except Exception as e:
            logger.error(f"Error scanning domain {domain} with VirusTotal: {str(e)}")
            return None

    def _process_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process VirusTotal API response
        
        Args:
            response: Raw API response
            
        Returns:
            Processed data
        """
        try:
            attributes = response.get('data', {}).get('attributes', {})
            
            return {
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'reputation': attributes.get('reputation', 0),
                'total_votes': attributes.get('total_votes', {}),
                'last_analysis_results': attributes.get('last_analysis_results', {}),
                'categories': attributes.get('categories', {}),
                'creation_date': attributes.get('creation_date'),
                'last_update_date': attributes.get('last_update_date'),
                'last_dns_records': attributes.get('last_dns_records', []),
                'tags': attributes.get('tags', []),
                'popularity_ranks': attributes.get('popularity_ranks', {})
            }
        except Exception as e:
            logger.error(f"Error processing VirusTotal response: {str(e)}")
            return {}
