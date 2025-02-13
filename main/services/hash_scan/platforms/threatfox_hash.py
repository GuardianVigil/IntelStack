from typing import Dict
from .base import BasePlatform
import logging

logger = logging.getLogger(__name__)

class ThreatFoxClient(BasePlatform):
    """Client for interacting with ThreatFox API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://threatfox-api.abuse.ch/api/v1"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """Analyze a file hash using ThreatFox."""
        logger.info(f"ThreatFox analyzing hash: {file_hash}")
        
        headers = {
            "Auth-Key": self.api_key,
            "Content-Type": "application/json"
        }

        data = {
            "query": "search_hash",
            "hash": file_hash
        }

        try:
            response = await self._make_request(
                method="POST",
                url=self.base_url,
                headers=headers,
                json=data
            )
            
            logger.info(f"ThreatFox raw response: {response}")
            
            # Check if we got a valid response
            if response.get("query_status") == "ok" and "data" in response:
                matches = response["data"]
                logger.info(f"ThreatFox found {len(matches)} results")
                
                return {
                    "platform": "threatfox",
                    "found": len(matches) > 0,
                    "scan_results": {
                        "total_matches": len(matches),
                        "matches": matches
                    } if matches else None
                }
            
            # Handle no results or error cases
            if "error" in response:
                logger.warning(f"ThreatFox error: {response['error']}")
                return {
                    "platform": "threatfox",
                    "found": False,
                    "scan_results": None
                }
            
            # Handle unknown response format
            logger.error(f"ThreatFox unexpected response format: {response}")
            return {
                "platform": "threatfox",
                "found": False,
                "scan_results": None
            }

        except Exception as e:
            logger.error(f"ThreatFox request failed: {str(e)}")
            return {
                "platform": "threatfox",
                "found": False,
                "scan_results": None
            }
