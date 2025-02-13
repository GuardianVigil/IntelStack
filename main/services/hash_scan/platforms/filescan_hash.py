import logging
from typing import Dict
from .base import BasePlatform

logger = logging.getLogger(__name__)

class FileScanClient(BasePlatform):
    """Client for interacting with the FileScan API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.filescan.io/api/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    async def analyze_hash(self, file_hash: str) -> Dict:
        """
        Query FileScan for information about a file hash.
        
        Args:
            file_hash: The hash to look up (SHA-256)
            
        Returns:
            Dict containing the scan results
        """
        try:
            endpoint = f"/search/hash/{file_hash}"
            url = f"{self.base_url}{endpoint}"
            
            logger.debug(f"Making request to FileScan: {url}")
            async with self.session.get(url, headers=self.headers) as response:
                if response.status == 404:
                    logger.info(f"No results found for hash {file_hash} in FileScan")
                    return {
                        "sha256": file_hash,
                        "overall_verdict": "unknown",
                        "fuzzyhash": {"hash": None, "verdict": "unknown"},
                        "mdcloud": {
                            "total_av_engines": 0,
                            "detected_av_engines": 0,
                            "scan_time": None
                        },
                        "filescan_reports": []
                    }
                
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"FileScan API error: {response.status} - {error_text}")
                    return {"error": f"API request failed: {response.status}"}
                
                try:
                    result = await response.json()
                except Exception as e:
                    logger.error(f"Failed to parse FileScan JSON response: {str(e)}")
                    return {"error": "Failed to parse API response"}

            # Log the raw response for debugging
            logger.debug(f"FileScan raw response: {result}")
            
            # Format the response
            formatted_response = {
                "sha256": file_hash,
                "overall_verdict": result.get("verdict", "unknown"),
                "fuzzyhash": result.get("fuzzyhash", {"hash": None, "verdict": "unknown"}),
                "mdcloud": {
                    "total_av_engines": result.get("mdcloud", {}).get("total_av_engines", 0),
                    "detected_av_engines": result.get("mdcloud", {}).get("detected_av_engines", 0),
                    "scan_time": result.get("mdcloud", {}).get("scan_time")
                },
                "filescan_reports": result.get("reports", [])
            }

            return formatted_response

        except Exception as e:
            logger.error(f"Error in FileScan analyze_hash: {str(e)}")
            return {
                "sha256": file_hash,
                "error": str(e),
                "overall_verdict": "error",
                "fuzzyhash": {"hash": None, "verdict": "unknown"},
                "mdcloud": {
                    "total_av_engines": 0,
                    "detected_av_engines": 0,
                    "scan_time": None
                },
                "filescan_reports": []
            }