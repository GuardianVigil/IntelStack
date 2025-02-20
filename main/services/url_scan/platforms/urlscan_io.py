"""
URLScan.io scanner implementation
"""
from typing import Dict, Any, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)

from .base_scanner import BaseScanner

class URLScanScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://urlscan.io/api/v1"

    def _structure_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Structure the raw API response into a table-friendly format"""
        try:
            if not isinstance(data, dict):
                return {"error": "Invalid response from URLScan.io"}

            page = data.get("page", {})
            lists = data.get("lists", {})
            
            return {
                "page_info": {
                    "url": str(page.get("url", "N/A")),
                    "domain": str(page.get("domain", "N/A")),
                    "ip": str(page.get("ip", "N/A")),
                    "country": str(page.get("country", "N/A")),
                    "server": str(page.get("server", "N/A")),
                    "city": str(page.get("city", "N/A")),
                    "asnname": str(page.get("asnname", "N/A"))
                },
                "security_info": {
                    "threat_score": float(data.get("score", 0)),
                    "malicious": bool(data.get("malicious", False)),
                    "encrypted": bool(page.get("tlsIssued", False)),
                    "certificate_issuer": str(page.get("tlsIssuer", "N/A")),
                    "certificate_valid_from": str(page.get("tlsValidFrom", "N/A")),
                    "certificate_valid_to": str(page.get("tlsValidTo", "N/A"))
                },
                "technologies": lists.get("technologies", []),
                "screenshot_url": str(data.get("screenshot", "")),
                "score": self.calculate_score(data)
            }
        except Exception as e:
            logger.error(f"Error in _structure_results: {str(e)}")
            return {"error": f"Failed to structure results: {str(e)}"}

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            # URLScan.io requires the API key in the 'api-key' header
            headers = {
                "api-key": self.api_key,
                "Content-Type": "application/json"
            }
            data = {
                "url": url,
                "visibility": "public"  # Make scan results publicly accessible
            }
            
            # Submit the URL for scanning
            submit_response = await self._make_request("POST", 
                f"{self.base_url}/scan/", headers=headers, json=data)
            
            if "uuid" not in submit_response:
                return {"error": "Failed to initiate scan"}

            # Get the scan UUID
            uuid = submit_response["uuid"]
            logger.info(f"URLScan.io scan submitted with UUID: {uuid}")

            # Wait 15 seconds before first poll
            await asyncio.sleep(15)
            
            # Poll for results every 15 seconds
            max_attempts = 12  # Total timeout: 15s initial + (12 * 15s) = 195s
            for attempt in range(max_attempts):
                try:
                    result = await self._make_request("GET", 
                        f"{self.base_url}/result/{uuid}/",
                        headers=headers)
                    
                    # If we get a result, process it
                    if isinstance(result, dict) and "task" in result:
                        # Add screenshot URL to the result
                        result["screenshot"] = f"https://urlscan.io/screenshots/{uuid}.png"
                        return self._structure_results(result)

                except Exception as e:
                    if "404" in str(e):
                        # 404 means result not ready, continue polling
                        logger.info(f"URLScan.io result not ready (attempt {attempt + 1}/{max_attempts}), waiting 15 seconds...")
                        await asyncio.sleep(15)
                        continue
                    elif "410" in str(e):
                        # 410 means scan was deleted
                        return {"error": "Scan was deleted by URLScan.io"}
                    else:
                        # Other error, log and continue polling
                        logger.warning(f"Error polling URLScan.io (attempt {attempt + 1}/{max_attempts}): {str(e)}")
                        await asyncio.sleep(15)
                        continue
            
            return {"error": "Scan timeout - results not available within 195 seconds"}
            
        except Exception as e:
            logger.error(f"Error in URLScan.io scan: {str(e)}")
            return {"error": str(e)}

    def calculate_score(self, data: Dict[str, Any]) -> float:
        """Calculate threat score from scan data"""
        try:
            if not isinstance(data, dict):
                return 0.0
            
            # Use existing score if available
            if "score" in data:
                return float(data["score"])
            
            # Calculate score based on available data
            score = 0.0
            
            # Check if marked as malicious
            if data.get("malicious", False):
                score += 50
            
            # Check for security features
            page = data.get("page", {})
            if not page.get("tlsIssued", False):
                score += 20  # Penalize for no HTTPS
            
            # Add points for suspicious technologies
            lists = data.get("lists", {})
            suspicious_tech = ["wordpress", "php", "jquery"]  # Example suspicious technologies
            technologies = lists.get("technologies", [])
            score += sum(5 for tech in technologies if tech.lower() in suspicious_tech)
            
            return min(score, 100)  # Cap at 100
            
        except Exception as e:
            logger.error(f"Error calculating score: {str(e)}")
            return 0.0