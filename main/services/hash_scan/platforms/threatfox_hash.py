from typing import Dict
from .base import BasePlatform

class ThreatFoxClient(BasePlatform):
    """Client for interacting with ThreatFox API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://threatfox-api.abuse.ch/api/v1"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """
        Search for a file hash in ThreatFox database.
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash to analyze
            
        Returns:
            Dict containing the analysis results
        """
        headers = {
            "API-KEY": self.api_key,
            "Content-Type": "application/json"
        }

        data = {
            "query": "search_ioc",
            "search_term": file_hash
        }

        response = await self._make_request("POST", self.base_url, headers=headers, json=data)
        
        if "error" in response:
            return response

        try:
            if response.get("query_status") == "ok":
                data = response.get("data", [])
                if data:
                    return {
                        "platform": "threatfox",
                        "found": True,
                        "scan_results": {
                            "total_matches": len(data),
                            "matches": [{
                                "ioc_id": item.get("ioc_id"),
                                "threat_type": item.get("threat_type"),
                                "malware": item.get("malware"),
                                "confidence_level": item.get("confidence_level"),
                                "first_seen": item.get("first_seen"),
                                "last_seen": item.get("last_seen"),
                                "tags": item.get("tags", []),
                                "reference": item.get("reference")
                            } for item in data]
                        }
                    }
                else:
                    return {
                        "platform": "threatfox",
                        "found": False,
                        "message": "Hash not found in ThreatFox database"
                    }
            else:
                return {
                    "error": f"Query failed: {response.get('query_status')}"
                }
        except Exception as e:
            return {"error": f"Failed to parse ThreatFox response: {str(e)}"}
