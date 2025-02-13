import aiohttp
import asyncio
from typing import Dict, Optional
from django.conf import settings
import logging
from ....models import APIKey
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

class HybridAnalysisClient:
    """Client for Hybrid Analysis API."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json"
        }

    async def search_hash(self, file_hash: str) -> Dict:
        """Search for a hash in Hybrid Analysis."""
        async with aiohttp.ClientSession() as session:
            try:
                url = f"{self.base_url}/search/hash"
                async with session.post(url, headers=self.headers, data={"hash": file_hash}) as response:
                    response_json = await response.json()
                    if response.status == 200 and isinstance(response_json, list) and len(response_json) > 0:
                        # Return first result since it's most relevant
                        return response_json[0]
                    elif response.status == 200 and isinstance(response_json, list):
                        return {"error": "No results found"}
                    else:
                        logger.error(f"Hybrid Analysis API error: {response_json}")
                        return {"error": f"API error: {response.status}"}
            except Exception as e:
                logger.error(f"Hybrid Analysis request failed: {str(e)}")
                return {"error": str(e)}

class PulsediveClient:
    """Client for Pulsedive API."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://pulsedive.com/api/v1"

    async def search_hash(self, file_hash: str) -> Dict:
        """Search for a hash in Pulsedive."""
        async with aiohttp.ClientSession() as session:
            try:
                params = {
                    "indicator": file_hash,
                    "key": self.api_key,
                    "pretty": "1"
                }
                url = f"{self.base_url}/info/indicator"
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        try:
                            return await response.json()
                        except Exception as e:
                            logger.error(f"Failed to parse Pulsedive JSON response: {str(e)}")
                            return {"error": "Invalid JSON response"}
                    else:
                        error_text = await response.text()
                        logger.error(f"Pulsedive API error: {error_text}")
                        return {"error": f"API error: {response.status}"}
            except Exception as e:
                logger.error(f"Pulsedive request failed: {str(e)}")
                return {"error": str(e)}

class VirusTotalClient:
    """Client for VirusTotal API."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "accept": "application/json"
        }

    async def get_file_report(self, file_hash: str) -> Dict:
        """Get file report from VirusTotal."""
        async with aiohttp.ClientSession() as session:
            try:
                url = f"{self.base_url}/files/{file_hash}"
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        logger.error(f"VirusTotal API error: {error_text}")
                        return {"error": f"API error: {response.status}"}
            except Exception as e:
                logger.error(f"VirusTotal request failed: {str(e)}")
                return {"error": str(e)}

class GreyNoiseClient:
    """Client for GreyNoise API."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3"
        self.headers = {
            "key": api_key,
            "accept": "application/json"
        }

    async def search_hash(self, file_hash: str) -> Dict:
        """Search for a hash in GreyNoise."""
        async with aiohttp.ClientSession() as session:
            try:
                url = f"{self.base_url}/riot/{file_hash}"
                async with session.get(url, headers=self.headers) as response:
                    response_json = await response.json()
                    if response.status == 200:
                        return response_json
                    elif response.status == 404:
                        return {"error": "Hash not found"}
                    else:
                        logger.error(f"GreyNoise API error: {response_json}")
                        return {"error": f"API error: {response.status}"}
            except Exception as e:
                logger.error(f"GreyNoise request failed: {str(e)}")
                return {"error": str(e)}

@sync_to_async
def get_api_key_from_db(platform: str) -> Optional[str]:
    """Get API key from database asynchronously."""
    try:
        api_key_obj = APIKey.objects.filter(platform=platform, is_active=True).first()
        if api_key_obj:
            return api_key_obj.api_key
        return None
    except Exception as e:
        logger.error(f"Error getting API key for platform {platform}: {str(e)}")
        return None

async def get_platform_client(platform: str) -> Optional[object]:
    """Get the appropriate platform client based on platform name."""
    try:
        api_key = await get_api_key_from_db(platform)
        if not api_key:
            logger.error(f"No active API key found for platform: {platform}")
            return None
            
        clients = {
            'hybrid_analysis': lambda: HybridAnalysisClient(api_key),
            'pulsedive': lambda: PulsediveClient(api_key),
            'virustotal': lambda: VirusTotalClient(api_key),
            'greynoise': lambda: GreyNoiseClient(api_key)
        }
        
        client_factory = clients.get(platform)
        if client_factory:
            return client_factory()
        return None
    except Exception as e:
        logger.error(f"Error getting client for platform {platform}: {str(e)}")
        return None
