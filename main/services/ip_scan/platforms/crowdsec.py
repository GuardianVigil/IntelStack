"""
CrowdSec scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner
import logging
import aiohttp

class CrowdSecScanner(BaseScanner):
    """Scanner for CrowdSec API"""
    
    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        super().__init__(session, api_key)
        self.base_url = "https://cti.api.crowdsec.net/v2"  # Changed to CTI API URL
        self.platform_name = 'crowdsec'
        self.rate_limit_delay = 2  # Increased rate limit delay
        self.logger = logging.getLogger(__name__)

    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query CrowdSec API for IP information"""
        url = f"{self.base_url}/smoke/{ip_address}"
        headers = {
            "x-api-key": self.api_key,  # Using x-api-key header
            "Accept": "application/json",
            "User-Agent": "ThreatIntel-Scanner/1.0"
        }
        
        # Log the request details (safely)
        key_preview = self.api_key[:4] + '***' if self.api_key else None
        self.logger.info(f"CrowdSec request - URL: {url}, Key Preview: {key_preview}")
        
        try:
            response = await self._make_request("GET", url, headers=headers)
            self.logger.info(f"CrowdSec raw response: {response}")
            
            if isinstance(response, dict):
                if "message" in response and ("forbidden" in response["message"].lower() or "unauthorized" in response["message"].lower()):
                    self.logger.error(f"CrowdSec authentication error: {response}")
                    return {"error": "API authentication error. Check API key format - should be a CTI API key"}
                return response
            self.logger.error(f"CrowdSec invalid response format: {response}")
            return {"error": "Invalid response format"}
        except Exception as e:
            self.logger.error(f"CrowdSec request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}"}
        
    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from CrowdSec data"""
        try:
            if "error" in data:
                return None
                
            # Extract relevant fields
            behaviors = data.get("behaviors", [])
            scores = data.get("scores", {})
            
            # Base score on behaviors and overall scores
            threat_score = 0
            
            # Add behavior-based scoring
            if behaviors:
                threat_score += len(behaviors) * 20  # Each behavior adds 20 points
                
            # Add overall score if available
            if scores:
                threat_score += float(scores.get("overall", 0))
                
            # Normalize to 0-100 range
            return min(max(threat_score, 0), 100)
        except Exception as e:
            self.logger.error(f"Error calculating CrowdSec score: {str(e)}")
            return None

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from CrowdSec data"""
        try:
            if "error" in data:
                return {}
                
            return {
                "as_name": data.get("as_name", ""),
                "as_num": data.get("as_num", ""),
                "country": data.get("country", ""),
                "reverse_dns": data.get("reverse_dns", ""),
                "network": data.get("network", "")
            }
        except Exception as e:
            self.logger.error(f"Error extracting CrowdSec WHOIS data: {str(e)}")
            return {}

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from CrowdSec data"""
        try:
            if "error" in data:
                return {}
                
            return {
                "ip": data.get("ip", ""),
                "range": data.get("range", ""),
                "as_name": data.get("as_name", ""),
                "as_num": data.get("as_num", ""),
                "location": {
                    "country": data.get("country", ""),
                    "city": data.get("city", "")
                },
                "behaviors": data.get("behaviors", []),
                "scores": data.get("scores", {}),
                "last_seen": data.get("last_seen", ""),
                "first_seen": data.get("first_seen", "")
            }
        except Exception as e:
            self.logger.error(f"Error extracting CrowdSec network info: {str(e)}")
            return {}
