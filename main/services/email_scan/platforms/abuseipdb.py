"""
AbuseIPDB scanner for email analysis
"""
from typing import Dict, Any, Optional
import logging
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class AbuseIPDBScanner(BaseScanner):
    """Scanner for AbuseIPDB API"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        self.rate_limit_delay = 1  # AbuseIPDB has different rate limits based on subscription

    async def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan email data using AbuseIPDB"""
        results = {
            "ip_analysis": {},
            "confidence_score": None
        }

        # AbuseIPDB only analyzes IPs
        for ip in email_data.get("ips", []):
            ip_result = await self._check_ip(ip)
            results["ip_analysis"][ip] = ip_result

        return results

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """AbuseIPDB doesn't support URL scanning"""
        return {
            "platform": "abuseipdb",
            "url": url,
            "analysis": "URL scanning not supported by AbuseIPDB"
        }

    async def scan_hash(self, file_hash: str) -> Dict[str, Any]:
        """AbuseIPDB doesn't support file hash scanning"""
        return {
            "platform": "abuseipdb",
            "hash": file_hash,
            "analysis": "File hash scanning not supported by AbuseIPDB"
        }

    async def _check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP address against AbuseIPDB"""
        try:
            endpoint = f"{self.base_url}/check"
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            }
            
            response = await self._make_request("GET", endpoint, headers=self.headers, params=params)
            return self._parse_ip_response(response)
            
        except Exception as e:
            logger.error(f"Error checking IP {ip} with AbuseIPDB: {str(e)}")
            return {"error": str(e)}

    def _parse_ip_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB IP check response"""
        try:
            data = response.get("data", {})
            
            return {
                "platform": "abuseipdb",
                "is_malicious": data.get("abuseConfidenceScore", 0) > 50,
                "confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "last_reported_at": data.get("lastReportedAt"),
                "country": data.get("countryCode"),
                "domain": data.get("domain"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "reports": [
                    {
                        "category": report.get("categories", []),
                        "date": report.get("reportedAt"),
                        "comment": report.get("comment")
                    }
                    for report in data.get("reports", [])
                ]
            }
        except Exception as e:
            logger.error(f"Error parsing AbuseIPDB response: {str(e)}")
            return {"error": str(e)}

    def calculate_threat_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from AbuseIPDB data"""
        try:
            if "error" in data:
                return None

            # AbuseIPDB provides confidence score from 0-100
            confidence_score = data.get("confidence_score")
            if confidence_score is not None:
                return float(confidence_score)

            return None

        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return None
