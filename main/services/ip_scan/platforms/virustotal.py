"""
VirusTotal scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class VirusTotalScanner(BaseScanner):
    """Scanner for VirusTotal platform"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query VirusTotal API for IP information"""
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        return await self._make_request("GET", url, headers=headers)

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from VirusTotal data"""
        if not isinstance(data, dict) or 'data' not in data:
            return None
            
        attributes = data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        total_scans = sum(last_analysis_stats.values() or [0])
        if total_scans == 0:
            return None
        
        malicious = last_analysis_stats.get('malicious', 0)
        suspicious = last_analysis_stats.get('suspicious', 0)
        
        score = ((malicious * 1.0) + (suspicious * 0.5)) / total_scans * 100
        return min(100, score)

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from VirusTotal data"""
        whois_data = {
            "source": "virustotal",
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "last_updated": None,
            "registrant": {},
            "admin": {},
            "technical": {}
        }
        
        if not isinstance(data, dict) or 'data' not in data:
            return whois_data
            
        attributes = data.get('data', {}).get('attributes', {})
        whois = attributes.get('whois', '')
        
        # Parse WHOIS text - basic implementation
        if whois:
            lines = whois.split('\n')
            for line in lines:
                line = line.strip().lower()
                if 'registrar:' in line:
                    whois_data['registrar'] = line.split('registrar:', 1)[1].strip()
                elif 'creation date:' in line:
                    whois_data['creation_date'] = line.split('creation date:', 1)[1].strip()
                elif 'registry expiry date:' in line:
                    whois_data['expiration_date'] = line.split('registry expiry date:', 1)[1].strip()
                elif 'updated date:' in line:
                    whois_data['last_updated'] = line.split('updated date:', 1)[1].strip()
        
        return whois_data

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from VirusTotal data"""
        network_info = {
            "source": "virustotal",
            "asn": None,
            "network": {
                "network": None,
                "country": None
            }
        }
        
        if not isinstance(data, dict) or 'data' not in data:
            return network_info
            
        attributes = data.get('data', {}).get('attributes', {})
        
        # Basic network information
        network_info.update({
            "asn": attributes.get('asn'),
            "network": {
                "network": attributes.get('network'),
                "country": attributes.get('country')
            }
        })
        
        return network_info
