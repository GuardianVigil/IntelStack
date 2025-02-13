from typing import Dict
from .base import BasePlatform

class MetaDefenderClient(BasePlatform):
    """Client for interacting with MetaDefender API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://api.metadefender.com/v4"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """
        Search for a file hash in MetaDefender database.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash to analyze
            
        Returns:
            Dict containing the analysis results
        """
        headers = {
            "apikey": self.api_key,
            "Accept": "application/json"
        }

        response = await self._make_request(
            "GET",
            f"{self.base_url}/hash/{file_hash}",
            headers=headers
        )

        if "error" in response:
            return response

        try:
            if "scan_results" in response:
                scan_results = response.get("scan_results", {})
                file_info = response.get("file_info", {})
                
                return {
                    "platform": "metadefender",
                    "found": True,
                    "scan_results": {
                        "overall_status": scan_results.get("scan_all_result_a"),
                        "total_engines": scan_results.get("total_avs"),
                        "total_detected": scan_results.get("total_detected_avs"),
                        "scan_time": scan_results.get("start_time"),
                        "file_info": {
                            "file_size": file_info.get("file_size"),
                            "file_type": file_info.get("file_type"),
                            "md5": file_info.get("md5"),
                            "sha1": file_info.get("sha1"),
                            "sha256": file_info.get("sha256")
                        },
                        "scan_details": scan_results.get("scan_details", {}),
                        "threat_name": scan_results.get("threat_found", ""),
                        "def_time": scan_results.get("def_time")
                    }
                }
            else:
                return {
                    "platform": "metadefender",
                    "found": False,
                    "message": "Hash not found in MetaDefender database"
                }
        except Exception as e:
            return {"error": f"Failed to parse MetaDefender response: {str(e)}"}