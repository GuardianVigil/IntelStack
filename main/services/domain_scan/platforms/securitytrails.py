"""
SecurityTrails API integration
"""
import logging
import aiohttp
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SecurityTrailsAPI:
    """Client for SecurityTrails API"""
    
    def __init__(self, api_key: str):
        """
        Initialize SecurityTrails client
        
        Args:
            api_key: SecurityTrails API key
        """
        self.api_key = api_key
        self.base_url = "https://api.securitytrails.com/v1"
        self.headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }

    async def scan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Scan domain using SecurityTrails
        
        Args:
            domain: Domain to scan
            
        Returns:
            Scan results or None if error
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Get domain info
                url = f"{self.base_url}/domain/{domain}"
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        domain_data = await response.json()
                    else:
                        error_data = await response.text()
                        logger.error(f"SecurityTrails API error: {error_data}")
                        return None

                # Get associated domains
                associated_url = f"{self.base_url}/domain/{domain}/associated"
                async with session.get(associated_url, headers=self.headers) as response:
                    if response.status == 200:
                        associated_data = await response.json()
                    else:
                        associated_data = {}

                # Get SSL certificates
                ssl_url = f"{self.base_url}/domain/{domain}/ssl"
                async with session.get(ssl_url, headers=self.headers) as response:
                    if response.status == 200:
                        ssl_data = await response.json()
                    else:
                        ssl_data = {}

                return self._process_response(domain_data, associated_data, ssl_data)

        except Exception as e:
            logger.error(f"Error scanning domain {domain} with SecurityTrails: {str(e)}")
            return None

    def _process_response(self, domain_data: Dict[str, Any], associated_data: Dict[str, Any], ssl_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process SecurityTrails API response
        
        Args:
            domain_data: Domain info response
            associated_data: Associated domains response
            ssl_data: SSL certificates response
            
        Returns:
            Processed data
        """
        try:
            return {
                'domain_info': {
                    'alexa_rank': domain_data.get('alexa_rank'),
                    'first_seen': domain_data.get('first_seen'),
                    'current_dns': domain_data.get('current_dns', {}),
                    'hostname': domain_data.get('hostname'),
                    'apex_domain': domain_data.get('apex_domain')
                },
                'associated_domains': {
                    'subdomains': associated_data.get('subdomains', []),
                    'root_domain': associated_data.get('root_domain')
                },
                'ssl_certificates': {
                    'certificates': ssl_data.get('certificates', []),
                    'total_records': ssl_data.get('total_records', 0)
                }
            }
        except Exception as e:
            logger.error(f"Error processing SecurityTrails response: {str(e)}")
            return {}
