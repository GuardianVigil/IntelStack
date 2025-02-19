"""
Hybrid Analysis scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class HybridAnalysisScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        headers = {
            "api-key": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"url": url, "environment_id": 160}
        submit_response = await self._make_request("POST", f"{self.base_url}/submit/url", 
                                                 headers=headers, data=data)
        
        if "job_id" in submit_response:
            # Poll for results
            job_id = submit_response["job_id"]
            for _ in range(20):
                result = await self._make_request("GET", 
                    f"{self.base_url}/report/{job_id}/summary",
                    headers={"api-key": self.api_key})
                if result.get("state") == "SUCCESS":
                    return result
                await asyncio.sleep(10)
        return submit_response

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from scan data"""
        if not isinstance(data, dict):
            return None
        
        threat_score = data.get("threat_score")
        if threat_score is not None:
            return float(threat_score)
        
        # Alternative scoring based on verdict
        verdict_map = {
            "malicious": 100,
            "suspicious": 50,
            "no specific threat": 0
        }
        verdict = data.get("verdict", "").lower()
        return float(verdict_map.get(verdict, 0))