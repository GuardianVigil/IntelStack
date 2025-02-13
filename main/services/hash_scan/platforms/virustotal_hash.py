import logging
from typing import Dict
from .base import BasePlatform

logger = logging.getLogger(__name__)

class VirusTotalClient(BasePlatform):
    """Client for interacting with VirusTotal API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """Analyze a file hash using VirusTotal."""
        try:
            logger.info(f"VirusTotal: Analyzing hash {file_hash}")
            
            url = f"{self.base_url}/files/{file_hash}"
            headers = {
                'x-apikey': self.api_key,
                'accept': 'application/json'
            }
            
            logger.debug(f"VirusTotal: Making request to {url}")
            async with self.session.get(url, headers=headers) as response:
                response_text = await response.text()
                logger.debug(f"VirusTotal: Raw response: {response_text}")
                
                if response.status != 200:
                    logger.error(f"VirusTotal: Request failed with status {response.status}: {response_text}")
                    if response.status == 404:
                        return {
                            "found": False,
                            "message": "Hash not found in VirusTotal database"
                        }
                    raise Exception(f"Request failed: {response.status}, {response_text}")
                
                result = await response.json()
                logger.info(f"VirusTotal: Got response for hash {file_hash}")
                
                if "data" in result:
                    data = result["data"]
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    return {
                        "found": True,
                        "scan_results": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "total_scans": sum(stats.values()),
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
                else:
                    return {
                        "found": False,
                        "message": "Invalid response format from VirusTotal"
                    }

        except Exception as e:
            logger.error(f"VirusTotal: Error analyzing hash: {str(e)}")
            return {"error": str(e)}
