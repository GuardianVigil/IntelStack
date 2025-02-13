from typing import Dict
from .base import BasePlatform

class VirusTotalClient(BasePlatform):
    """Client for interacting with VirusTotal API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """
        Analyze a file hash using VirusTotal API.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash to analyze
            
        Returns:
            Dict containing the analysis results
        """
        url = f"{self.base_url}/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

        response = await self._make_request("GET", url, headers=headers)
        
        if "error" in response:
            return response

        try:
            data = response.get("data", {})
            attributes = data.get("attributes", {})
            
            return {
                "platform": "virustotal",
                "found": True,
                "scan_results": {
                    "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                    "total_scans": sum(attributes.get("last_analysis_stats", {}).values()),
                    "sha256": attributes.get("sha256"),
                    "sha1": attributes.get("sha1"),
                    "md5": attributes.get("md5"),
                    "file_type": attributes.get("type_description"),
                    "first_seen": attributes.get("first_submission_date"),
                    "last_seen": attributes.get("last_submission_date"),
                    "reputation": attributes.get("reputation"),
                    "names": attributes.get("names", []),
                    "scan_results": attributes.get("last_analysis_results", {})
                }
            }
        except Exception as e:
            return {"error": f"Failed to parse VirusTotal response: {str(e)}"}
