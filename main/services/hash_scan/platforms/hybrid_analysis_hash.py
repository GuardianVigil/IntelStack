from typing import Dict, Optional
from .base import BasePlatform
import logging

logger = logging.getLogger(__name__)

class HybridAnalysisClient(BasePlatform):
    """Client for interacting with Hybrid Analysis API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """Analyze a file hash using Hybrid Analysis."""
        try:
            # First, search for the hash
            headers = {
                'accept': 'application/json',
                'api-key': self.api_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            search_url = "https://www.hybrid-analysis.com/api/v2/search/hash"
            search_data = f"hash={file_hash}"
            
            async with self.session.post(search_url, headers=headers, data=search_data) as response:
                if response.status != 200:
                    raise Exception(f"Request failed: {response.status}, {await response.text()}")
                search_result = await response.json()

            # If we got a SHA256 from the search, get the overview
            if search_result and isinstance(search_result, list) and len(search_result) > 0:
                sha256 = search_result[0].get('sha256')
                if sha256:
                    overview_url = f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}"
                    headers.pop('Content-Type', None)  # Remove Content-Type for GET request
                    
                    async with self.session.get(overview_url, headers=headers) as response:
                        if response.status != 200:
                            raise Exception(f"Overview request failed: {response.status}")
                        overview_result = await response.json()
                        return overview_result

            return search_result

        except Exception as e:
            logger.error(f"Error in Hybrid Analysis: {str(e)}")
            return {"error": str(e)}
