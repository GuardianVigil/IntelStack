from typing import Dict
from .base import BasePlatform

class FileScanClient(BasePlatform):
    """Client for interacting with FileScan API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.filescan.io/api/v1"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """
        Search for a file hash in FileScan database.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash to analyze
            
        Returns:
            Dict containing the analysis results
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }

        # First try to get existing report
        response = await self._make_request(
            "GET",
            f"{self.base_url}/reports/hash/{file_hash}",
            headers=headers
        )

        if "error" in response:
            return response

        try:
            if response.get("status") == "success":
                report = response.get("report", {})
                return {
                    "platform": "filescan",
                    "found": True,
                    "scan_results": {
                        "scan_id": report.get("scan_id"),
                        "sha256": report.get("sha256"),
                        "sha1": report.get("sha1"),
                        "md5": report.get("md5"),
                        "file_type": report.get("file_type"),
                        "file_size": report.get("file_size"),
                        "scan_date": report.get("scan_date"),
                        "score": report.get("score"),
                        "verdict": report.get("verdict"),
                        "signatures": report.get("signatures", []),
                        "yara_matches": report.get("yara_matches", []),
                        "mitre_attacks": report.get("mitre_attacks", []),
                        "network_indicators": report.get("network_indicators", []),
                        "file_metadata": report.get("file_metadata", {})
                    }
                }
            else:
                return {
                    "platform": "filescan",
                    "found": False,
                    "message": "Hash not found in FileScan database"
                }
        except Exception as e:
            return {"error": f"Failed to parse FileScan response: {str(e)}"}