"""
SecurityTrails scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class SecurityTrailsScanner(BaseScanner):
    """Scanner for SecurityTrails platform"""
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://api.securitytrails.com/v1"
        self.platform_name = 'securitytrails'
        self.rate_limit_delay = 1.5

    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query SecurityTrails API for IP information"""
        headers = {
            "APIKEY": self.api_key,
            "Accept": "application/json"
        }

        # Get IP nearby details
        url = f"{self.base_url}/ips/nearby/{ip_address}"
        ip_data = await self._make_request("GET", url, headers=headers)
        if "error" in ip_data:
            return ip_data

        # Get associated domains if IP data was successful
        if not isinstance(ip_data, dict) or "error" in ip_data:
            return ip_data

        return ip_data

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from SecurityTrails data"""
        if not isinstance(data, dict) or "error" in data:
            return None

        score = 0
        neighbors = data.get('neighbors', [])
        
        if not neighbors:
            return None

        # Score based on number of neighboring IPs
        num_neighbors = len(neighbors)
        if num_neighbors > 0:
            score += min(30, num_neighbors * 2)  # Up to 30 points for neighbors

        # Score based on hostnames
        total_hostnames = sum(len(n.get('hostnames', [])) for n in neighbors)
        if total_hostnames > 0:
            score += min(40, total_hostnames)  # Up to 40 points for hostnames

        return min(score, 100)  # Cap at 100

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from SecurityTrails data"""
        if not isinstance(data, dict) or "error" in data:
            return {}

        neighbors = data.get('neighbors', [])
        if not neighbors:
            return {}

        # Get the first neighbor which usually contains the target IP's info
        target = neighbors[0] if neighbors else {}
        
        return {
            "asn": str(target.get('asn', '')),
            "organization": target.get('organization', ''),
            "hostname": target.get('hostname', ''),
            "country": target.get('country', ''),
            "city": target.get('city', '')
        }

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from SecurityTrails data"""
        if not isinstance(data, dict) or "error" in data:
            return {}

        neighbors = data.get('neighbors', [])
        if not neighbors:
            return {}

        # Get the first neighbor which usually contains the target IP's info
        target = neighbors[0] if neighbors else {}
        
        return {
            "registrar": target.get('organization', ''),
            "registered_country": target.get('country', ''),
            "registration_date": '',  # SecurityTrails doesn't provide this
            "expiration_date": '',    # SecurityTrails doesn't provide this
            "last_updated": ''        # SecurityTrails doesn't provide this
        }
