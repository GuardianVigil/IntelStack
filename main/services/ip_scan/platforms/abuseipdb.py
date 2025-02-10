"""
AbuseIPDB scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class AbuseIPDBScanner(BaseScanner):
    """Scanner for AbuseIPDB platform"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query AbuseIPDB API for IP information"""
        url = f"{self.base_url}/check"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90",
            "verbose": "true"
        }
        
        return await self._make_request("GET", url, headers=headers, params=params)

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from AbuseIPDB data"""
        if not isinstance(data.get('data', {}), dict):
            return None
            
        abuse_confidence_score = data.get('data', {}).get('abuseConfidenceScore')
        return float(abuse_confidence_score) if abuse_confidence_score is not None else None

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from AbuseIPDB data"""
        whois_data = {
            "source": "abuseipdb",
            "registrar": None,
            "organization": None,
            "network": None
        }
        
        if not isinstance(data.get('data', {}), dict):
            return whois_data
            
        data = data.get('data', {})
        whois_data.update({
            "organization": data.get('isp'),
            "network": data.get('network')
        })
        
        return whois_data

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from AbuseIPDB data"""
        network_info = {
            "source": "abuseipdb",
            "isp": None,
            "usage_type": None,
            "network": {
                "country": None,
                "region": None,
                "city": None,
                "coordinates": {
                    "latitude": None,
                    "longitude": None
                }
            }
        }
        
        if not isinstance(data.get('data', {}), dict):
            return network_info
            
        data = data.get('data', {})
        network_info.update({
            "isp": data.get('isp'),
            "usage_type": data.get('usageType'),
            "network": {
                "country": data.get('countryCode'),
                "region": data.get('regionName'),
                "city": data.get('city'),
                "coordinates": {
                    "latitude": data.get('latitude'),
                    "longitude": data.get('longitude')
                }
            }
        })
        
        return network_info
