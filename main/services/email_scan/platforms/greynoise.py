"""
GreyNoise scanner for email analysis
"""
from typing import Dict, Any, Optional
import logging
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class GreyNoiseScanner(BaseScanner):
    """Scanner for GreyNoise API"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://api.greynoise.io/v3"
        self.headers = {
            "key": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit_delay = 1

    async def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan email data using GreyNoise"""
        results = {
            "ip_analysis": {},
            "classification": None
        }

        # GreyNoise only analyzes IPs
        for ip in email_data.get("ips", []):
            ip_result = await self._check_ip(ip)
            results["ip_analysis"][ip] = ip_result

        return results

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """GreyNoise doesn't support URL scanning"""
        return {
            "platform": "greynoise",
            "url": url,
            "analysis": "URL scanning not supported by GreyNoise"
        }

    async def scan_hash(self, file_hash: str) -> Dict[str, Any]:
        """GreyNoise doesn't support file hash scanning"""
        return {
            "platform": "greynoise",
            "hash": file_hash,
            "analysis": "File hash scanning not supported by GreyNoise"
        }

    async def _check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP address against GreyNoise"""
        try:
            # First try RIOT endpoint
            riot_endpoint = f"{self.base_url}/riot/ip/{ip}"
            riot_data = await self._make_request("GET", riot_endpoint, headers=self.headers)
            
            # Then get community data
            community_endpoint = f"{self.base_url}/community/{ip}"
            community_data = await self._make_request("GET", community_endpoint, headers=self.headers)
            
            return self._parse_ip_response(riot_data, community_data)
            
        except Exception as e:
            logger.error(f"Error checking IP {ip} with GreyNoise: {str(e)}")
            return {"error": str(e)}

    def _parse_ip_response(self, riot_data: Dict[str, Any], community_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GreyNoise IP check response"""
        try:
            # Combine RIOT and community data
            is_malicious = (
                riot_data.get("riot", False) or
                community_data.get("classification") in ["malicious", "suspicious"]
            )
            
            return {
                "platform": "greynoise",
                "is_malicious": is_malicious,
                "classification": community_data.get("classification"),
                "actor": riot_data.get("name"),
                "last_seen": community_data.get("last_seen"),
                "riot": {
                    "is_riot": riot_data.get("riot", False),
                    "category": riot_data.get("category"),
                    "trust_level": riot_data.get("trust_level"),
                    "description": riot_data.get("description")
                },
                "community": {
                    "noise": community_data.get("noise", False),
                    "riot": community_data.get("riot", False),
                    "classification": community_data.get("classification"),
                    "name": community_data.get("name"),
                    "tags": community_data.get("tags", [])
                },
                "metadata": {
                    "organization": community_data.get("metadata", {}).get("organization"),
                    "country": community_data.get("metadata", {}).get("country"),
                    "city": community_data.get("metadata", {}).get("city")
                }
            }
        except Exception as e:
            logger.error(f"Error parsing GreyNoise response: {str(e)}")
            return {"error": str(e)}

    def calculate_threat_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from GreyNoise data"""
        try:
            if "error" in data:
                return None

            score = 0
            
            # Score based on classification
            classification = data.get("classification", "").lower()
            if classification == "malicious":
                score += 100
            elif classification == "suspicious":
                score += 70
            elif classification == "benign":
                score += 0
            else:
                score += 50

            # Adjust based on RIOT data
            if data.get("riot", {}).get("is_riot"):
                trust_level = data.get("riot", {}).get("trust_level", 1)
                score = min(100, score + (10 * trust_level))

            # Adjust based on community tags
            malicious_tags = ["malware", "scanner", "attack", "exploit"]
            tags = data.get("community", {}).get("tags", [])
            if any(tag in malicious_tags for tag in tags):
                score = min(100, score + 20)

            return float(score)

        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return None
