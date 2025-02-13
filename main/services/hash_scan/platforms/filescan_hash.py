from typing import Dict
from .base import BasePlatform

class FileScanClient(BasePlatform):
    """Client for interacting with FileScan API."""

    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://www.filescan.io/api/v1"

    async def analyze_hash(self, file_hash: str) -> Dict:
        """Analyze a file hash using FileScan."""
        try:
            headers = {
                'accept': 'application/json',
                'X-Api-Key': self.api_key
            }

            # Determine URL based on hash length
            if len(file_hash) == 32:  # MD5
                url = f"https://www.filescan.io/api/reputation/hash?md5={file_hash}"
            elif len(file_hash) == 40:  # SHA1
                url = f"https://www.filescan.io/api/reputation/hash?sha1={file_hash}"
            elif len(file_hash) == 64:  # SHA256
                url = f"https://www.filescan.io/api/reputation/hash?sha256={file_hash}"
            else:
                return {"error": "Invalid hash length. Must be MD5, SHA1, or SHA256."}

            async with self.session.get(url, headers=headers) as response:
                if response.status != 200:
                    raise Exception(f"Request failed: {response.status}, {await response.text()}")
                result = await response.json()
                return result

        except Exception as e:
            logger.error(f"Error in FileScan: {str(e)}")
            return {"error": str(e)}