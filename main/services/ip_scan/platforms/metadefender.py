"""
MetaDefender scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class MetaDefenderScanner(BaseScanner):
    """Scanner for MetaDefender platform"""
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://api.metadefender.com/v4"
        
    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query MetaDefender API for IP information"""
        url = f"{self.base_url}/ip/{ip_address}"
        headers = {
            "apikey": self.api_key,
            "Accept": "application/json"
        }
        
        # Get IP lookup data
        lookup_data = await self._make_request("GET", url, headers=headers)
        return lookup_data
        
    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from MetaDefender data"""
        if not isinstance(data, dict):
            return None
            
        if "lookup_results" not in data:
            return None
            
        results = data["lookup_results"]
        
        # Get direct reputation score if available
        score = results.get("reputation_score")
        if score is not None:
            return float(score)
            
        # Calculate score based on detections
        score = 0
        sources = results.get("sources", [])
        
        if sources:
            score += len(sources) * 20  # 20 points per detection source
            
        detected_by = results.get("detected_by", 0)
        if detected_by:
            score += detected_by * 15  # 15 points per detection
            
        confidence = results.get("confidence_level", 0)
        score += confidence

        return min(score, 100)  # Cap at 100

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from MetaDefender data"""
        if not isinstance(data, dict) or "lookup_results" not in data:
            return {}

        results = data["lookup_results"]
        network_info = {
            "asn": results.get("asn", ""),
            "hostname": results.get("hostname", ""),
            "country": results.get("geo", {}).get("country", {}).get("code", ""),
            "city": results.get("geo", {}).get("city", ""),
            "organization": results.get("asn_organization", "")
        }
        return network_info

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from MetaDefender data"""
        if not isinstance(data, dict) or "lookup_results" not in data:
            return {}

        results = data["lookup_results"]
        whois_info = {
            "registrar": results.get("registrar", ""),
            "registered_country": results.get("registered_country", ""),
            "registration_date": results.get("registration_date", ""),
            "expiration_date": results.get("expiration_date", ""),
            "last_updated": results.get("last_updated", "")
        }
        return whois_info
