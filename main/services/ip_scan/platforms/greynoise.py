"""
GreyNoise scanner implementation
"""
import logging
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class GreyNoiseScanner(BaseScanner):
    """Scanner for GreyNoise platform"""
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://api.greynoise.io/v3"
        self.rate_limit_delay = 2  # Increase rate limit delay to 2 seconds
        self._rate_limited = False
        
    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query GreyNoise API for IP information"""
        if self._rate_limited:
            return {"error": "GreyNoise rate limit exceeded. Try again later."}

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # Get community data (main endpoint)
        url = f"{self.base_url}/community/{ip_address}"
        try:
            data = await self._make_request("GET", url, headers=headers)
            
            # Check for rate limit response
            if isinstance(data, dict):
                if data.get("status") == 429 or "rate limit" in data.get("error", "").lower():
                    self._rate_limited = True
                    logger.warning("GreyNoise rate limit hit, disabling further requests")
                    return {"error": "GreyNoise rate limit exceeded. Try again later."}
                return data
                
            return {"error": "Failed to retrieve data"}
            
        except Exception as e:
            if "rate limit" in str(e).lower():
                self._rate_limited = True
                logger.warning("GreyNoise rate limit hit, disabling further requests")
                return {"error": "GreyNoise rate limit exceeded. Try again later."}
            return {"error": f"Error querying GreyNoise: {str(e)}"}

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from GreyNoise data"""
        if not isinstance(data, dict) or "error" in data:
            return None
            
        # Calculate score based on classification
        classification = data.get("classification", "unknown").lower()
        if classification == "malicious":
            return 100
        elif classification == "suspicious":
            return 70
        elif classification == "benign":
            return 0
        return 50  # unknown classification
        
    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from GreyNoise data"""
        if not isinstance(data, dict) or "error" in data:
            return {}
            
        whois_info = {}
        if "metadata" in data:
            metadata = data["metadata"]
            whois_info.update({
                "organization": metadata.get("organization"),
                "asn": metadata.get("asn"),
                "country": metadata.get("country"),
                "city": metadata.get("city"),
                "region": metadata.get("region")
            })
        return {k: v for k, v in whois_info.items() if v is not None}
        
    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from GreyNoise data"""
        if not isinstance(data, dict) or "error" in data:
            return {}
            
        network_info = {}
        if "metadata" in data:
            metadata = data["metadata"]
            network_info.update({
                "ip": data.get("ip"),
                "network": metadata.get("network"),
                "asn": metadata.get("asn"),
                "classification": data.get("classification")
            })
        return {k: v for k, v in network_info.items() if v is not None}
