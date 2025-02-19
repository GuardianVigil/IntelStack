"""
URLScan.io scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class URLScanScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://urlscan.io/api/v1"

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        data = {
            "url": url,
            "visibility": "public"
        }
        
        submit_response = await self._make_request("POST", f"{self.base_url}/scan/",
                                                 headers=headers, json=data)
        
        if "uuid" in submit_response:
            # Poll for results
            scan_id = submit_response["uuid"]
            for _ in range(5):
                result = await self._make_request("GET",
                    f"{self.base_url}/result/{scan_id}/",
                    headers={"API-Key": self.api_key})
                if "data" in result:
                    return result
                await asyncio.sleep(10)
        return submit_response

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from scan data"""
        if not isinstance(data, dict) or "verdicts" not in data:
            return None
        
        verdicts = data["verdicts"]
        score = 0
        
        if verdicts.get("overall", {}).get("malicious"):
            score += 50
        if verdicts.get("overall", {}).get("suspicious"):
            score += 25
            
        return float(min(100, score))