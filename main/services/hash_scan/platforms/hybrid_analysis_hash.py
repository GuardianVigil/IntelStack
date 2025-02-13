from typing import Dict, Optional
from .base import BasePlatform

class HybridAnalysisClient(BasePlatform):
    """Client for interacting with Hybrid Analysis API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """
        Analyze a file hash using Hybrid Analysis API.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash to analyze
            
        Returns:
            Dict containing the analysis results
        """
        # First, search for the hash
        search_url = f"{self.base_url}/search/hash"
        headers = {
            "api-key": self.api_key,
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        search_response = await self._make_request(
            "POST", 
            search_url, 
            headers=headers,
            params={"hash": file_hash}
        )

        if "error" in search_response:
            return search_response

        # If we found a match, get the detailed overview
        if search_response and isinstance(search_response, list) and len(search_response) > 0:
            sha256_hash = search_response[0].get("sha256")
            if sha256_hash:
                overview_url = f"{self.base_url}/overview/{sha256_hash}"
                headers = {
                    "api-key": self.api_key,
                    "accept": "application/json"
                }

                overview_response = await self._make_request("GET", overview_url, headers=headers)
                
                if "error" in overview_response:
                    return overview_response

                try:
                    return {
                        "platform": "hybrid_analysis",
                        "found": True,
                        "scan_results": {
                            "verdict": overview_response.get("verdict"),
                            "threat_score": overview_response.get("threat_score"),
                            "sha256": overview_response.get("sha256"),
                            "sha1": overview_response.get("sha1"),
                            "md5": overview_response.get("md5"),
                            "file_type": overview_response.get("type"),
                            "environment_description": overview_response.get("environment_description"),
                            "analysis_start_time": overview_response.get("analysis_start_time"),
                            "total_signatures": len(overview_response.get("signatures", [])),
                            "signatures": overview_response.get("signatures", []),
                            "processes": overview_response.get("processes", []),
                            "tags": overview_response.get("tags", [])
                        }
                    }
                except Exception as e:
                    return {"error": f"Failed to parse Hybrid Analysis response: {str(e)}"}

        return {
            "platform": "hybrid_analysis",
            "found": False,
            "message": "Hash not found in Hybrid Analysis database"
        }
