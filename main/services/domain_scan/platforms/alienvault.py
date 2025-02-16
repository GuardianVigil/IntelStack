"""
AlienVault OTX API integration
"""
import logging
from typing import Dict, Any, Optional
from OTXv2 import OTXv2, IndicatorTypes

logger = logging.getLogger(__name__)

class AlienVaultAPI:
    """Client for AlienVault OTX API"""
    
    def __init__(self, api_key: str):
        """
        Initialize AlienVault client
        
        Args:
            api_key: AlienVault API key
        """
        self.client = OTXv2(api_key)

    async def scan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Scan domain using AlienVault OTX
        
        Args:
            domain: Domain to scan
            
        Returns:
            Scan results or None if error
        """
        try:
            # Get full domain details
            results = self.client.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
            
            # Extract relevant data
            return {
                'general': results.get('general', {}),
                'reputation': results.get('reputation', {}),
                'geo': results.get('geo', {}),
                'malware': results.get('malware', {}),
                'url_list': results.get('url_list', {}),
                'passive_dns': results.get('passive_dns', {}),
            }
        except Exception as e:
            logger.error(f"Error scanning domain {domain} with AlienVault: {str(e)}")
            return None

    def _extract_threat_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract threat data from AlienVault results
        
        Args:
            results: Raw AlienVault results
            
        Returns:
            Extracted threat data
        """
        threat_data = {
            'pulses': len(results.get('pulse_info', {}).get('pulses', [])),
            'references': results.get('pulse_info', {}).get('references', []),
            'industries': results.get('pulse_info', {}).get('industries', []),
            'malware_families': results.get('pulse_info', {}).get('malware_families', []),
            'adversaries': results.get('pulse_info', {}).get('adversaries', [])
        }
        
        return threat_data
