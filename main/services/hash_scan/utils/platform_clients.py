import aiohttp
from typing import Dict, Optional

class BaseClient:
    """Base class for platform API clients."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def _make_request(self, url: str, method: str = 'GET', headers: Optional[Dict] = None, 
                          params: Optional[Dict] = None, json: Optional[Dict] = None) -> Dict:
        """Make an HTTP request to the API."""
        session = await self._get_session()
        async with session.request(method, url, headers=headers, params=params, json=json) as response:
            response.raise_for_status()
            return await response.json()

class HybridAnalysisClient(BaseClient):
    """Client for Hybrid Analysis API."""
    
    BASE_URL = 'https://www.hybrid-analysis.com/api/v2'

    async def lookup_hash(self, file_hash: str) -> Dict:
        """Look up a file hash in Hybrid Analysis."""
        url = f"{self.BASE_URL}/search/hash"
        headers = {
            'api-key': self.api_key,
            'User-Agent': 'Falcon Sandbox'
        }
        params = {'hash': file_hash}
        return await self._make_request(url, headers=headers, params=params)

class PulsediveClient(BaseClient):
    """Client for Pulsedive API."""
    
    BASE_URL = 'https://pulsedive.com/api/v1'

    async def lookup_hash(self, file_hash: str) -> Dict:
        """Look up a file hash in Pulsedive."""
        url = f"{self.BASE_URL}/info"
        params = {
            'indicator': file_hash,
            'key': self.api_key
        }
        return await self._make_request(url, params=params)

class VirusTotalClient(BaseClient):
    """Client for VirusTotal API."""
    
    BASE_URL = 'https://www.virustotal.com/api/v3'

    async def lookup_hash(self, file_hash: str) -> Dict:
        """Look up a file hash in VirusTotal."""
        url = f"{self.BASE_URL}/files/{file_hash}"
        headers = {'x-apikey': self.api_key}
        return await self._make_request(url, headers=headers)

class GreyNoiseClient(BaseClient):
    """Client for GreyNoise API."""
    
    BASE_URL = 'https://api.greynoise.io/v3'

    async def lookup_hash(self, file_hash: str) -> Dict:
        """Look up a file hash in GreyNoise."""
        url = f"{self.BASE_URL}/hashes/{file_hash}"
        headers = {'key': self.api_key}
        return await self._make_request(url, headers=headers)
