"""
VirusTotal scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner
import base64

class VirusTotalScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning and get results"""
        # Submit URL
        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-apikey": self.api_key
        }
        
        # Convert URL to base64 for API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # First try to get existing analysis
        analysis = await self._make_request("GET", 
                                          f"{self.base_url}/urls/{url_id}",
                                          headers=headers)
        
        if "error" in analysis:
            # Submit new scan if not found
            submit_url = f"{self.base_url}/urls"
            data = {"url": url}
            submit_response = await self._make_request("POST", 
                                                     submit_url,
                                                     headers=headers,
                                                     data=data)
            
            if "data" in submit_response:
                analysis_id = submit_response["data"]["id"]
                # Poll for results
                for _ in range(10):
                    analysis = await self._make_request("GET",
                        f"{self.base_url}/analyses/{analysis_id}",
                        headers=headers)
                    if analysis.get("data", {}).get("attributes", {}).get("status") == "completed":
                        break
                    await asyncio.sleep(15)
        
        return analysis

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from VirusTotal data"""
        if not isinstance(data, dict) or "data" not in data:
            return None
            
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        
        if not stats:
            return None
        
        total = sum(stats.values())
        if total == 0:
            return 0.0
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        # Calculate score: (malicious * 1.0 + suspicious * 0.5) / total * 100
        score = ((malicious * 1.0) + (suspicious * 0.5)) / total * 100
        return min(100, score)

    def extract_categories(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract categories and tags from results"""
        if not isinstance(data, dict) or "data" not in data:
            return {}
            
        attributes = data.get("data", {}).get("attributes", {})
        return {
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "times_submitted": attributes.get("times_submitted"),
            "reputation": attributes.get("reputation")
        }