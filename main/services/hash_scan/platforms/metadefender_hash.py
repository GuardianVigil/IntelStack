import logging
from typing import Dict
from .base import BasePlatform

logger = logging.getLogger(__name__)

class MetaDefenderClient(BasePlatform):
    """Client for interacting with MetaDefender API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://api.metadefender.com/v4"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """Analyze a file hash using MetaDefender."""
        try:
            logger.info(f"MetaDefender: Analyzing hash {file_hash}")
            
            url = f"{self.base_url}/hash/{file_hash}"
            headers = {
                'apikey': self.api_key,
                'Accept': 'application/json'
            }
            
            logger.debug(f"MetaDefender: Making request to {url}")
            async with self.session.get(url, headers=headers) as response:
                response_text = await response.text()
                logger.debug(f"MetaDefender: Raw response: {response_text}")
                
                if response.status != 200:
                    logger.error(f"MetaDefender: Request failed with status {response.status}: {response_text}")
                    if response.status == 404:
                        return {
                            "found": False,
                            "message": "Hash not found in MetaDefender database"
                        }
                    raise Exception(f"Request failed: {response.status}, {response_text}")
                
                result = await response.json()
                logger.info(f"MetaDefender: Got response for hash {file_hash}")
                
                if "scan_results" in result:
                    scan_results = result.get("scan_results", {})
                    file_info = result.get("file_info", {})
                    
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
            logger.error(f"MetaDefender: Error analyzing hash: {str(e)}")
            return {"error": str(e)}