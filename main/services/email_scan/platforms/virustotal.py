"""
VirusTotal scanner for email analysis
"""
from typing import Dict, Any, Optional
import logging
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class VirusTotalScanner(BaseScanner):
    """Scanner for VirusTotal API"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }
        self.rate_limit_delay = 15  # VirusTotal has a 4 requests/minute limit for free API

    async def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan email data using VirusTotal"""
        results = {
            "sender_analysis": await self._analyze_email_address(email_data["from_address"]),
            "urls": [],
            "attachments": []
        }

        # Analyze URLs
        for url in email_data.get("urls", []):
            url_result = await self.scan_url(url)
            results["urls"].append(url_result)

        # Analyze attachment hashes
        for file_hash in email_data.get("attachments", []):
            hash_result = await self.scan_hash(file_hash)
            results["attachments"].append(hash_result)

        return results

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan a URL using VirusTotal"""
        try:
            # First try to get existing analysis
            url_id = self._encode_url(url)
            endpoint = f"{self.base_url}/urls/{url_id}"
            response = await self._make_request("GET", endpoint, headers=self.headers)
            
            return self._parse_url_response(response)
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            return {"error": str(e)}

    async def scan_hash(self, file_hash: str) -> Dict[str, Any]:
        """Scan a file hash using VirusTotal"""
        try:
            endpoint = f"{self.base_url}/files/{file_hash}"
            response = await self._make_request("GET", endpoint, headers=self.headers)
            
            return self._parse_file_response(response)
        except Exception as e:
            logger.error(f"Error scanning hash {file_hash}: {str(e)}")
            return {"error": str(e)}

    async def _analyze_email_address(self, email: str) -> Dict[str, Any]:
        """Analyze an email address using VirusTotal"""
        # This is a placeholder as VirusTotal doesn't directly analyze email addresses
        return {
            "platform": "virustotal",
            "email": email,
            "analysis": "Email address analysis not available through VirusTotal"
        }

    def calculate_threat_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from VirusTotal data"""
        try:
            if "error" in data:
                return None

            total_score = 0
            components = 0

            # Calculate score from URL analysis
            for url_data in data.get("urls", []):
                if "malicious" in url_data:
                    total_score += url_data["malicious"] * 100
                    components += 1

            # Calculate score from attachment analysis
            for attachment_data in data.get("attachments", []):
                if "malicious" in attachment_data:
                    total_score += attachment_data["malicious"] * 100
                    components += 1

            return total_score / components if components > 0 else None

        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return None

    def _parse_url_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal URL scan response"""
        try:
            attributes = response.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "platform": "virustotal",
                "scan_date": attributes.get("last_analysis_date"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("harmless", 0),
                "reputation": attributes.get("reputation", 0),
                "total_votes": {
                    "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                }
            }
        except Exception as e:
            logger.error(f"Error parsing URL response: {str(e)}")
            return {"error": str(e)}

    def _parse_file_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal file scan response"""
        try:
            attributes = response.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "platform": "virustotal",
                "scan_date": attributes.get("last_analysis_date"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "clean": stats.get("undetected", 0),
                "type_description": attributes.get("type_description"),
                "size": attributes.get("size"),
                "md5": attributes.get("md5"),
                "sha1": attributes.get("sha1"),
                "sha256": attributes.get("sha256")
            }
        except Exception as e:
            logger.error(f"Error parsing file response: {str(e)}")
            return {"error": str(e)}

    @staticmethod
    def _encode_url(url: str) -> str:
        """Encode URL for VirusTotal API"""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
