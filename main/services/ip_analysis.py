"""
IP Analysis Service for threat intelligence platforms
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from .cache_manager import RedisCache
from .thread_manager import ThreadPoolManager
from .encryption import decrypt_api_key
import logging
from asgiref.sync import sync_to_async
from django.conf import settings

logger = logging.getLogger(__name__)

class IPAnalysisService:
    """Service for analyzing IP addresses using multiple threat intelligence platforms"""
    
    def __init__(self):
        self.cache = RedisCache()
        self.thread_pool = ThreadPoolManager()
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
            
    async def _get_api_key(self, platform: str) -> str:
        """Get decrypted API key for platform"""
        try:
            encrypted_key = await sync_to_async(lambda: settings.API_KEYS.get(platform))()
            if not encrypted_key:
                logger.warning(f"No API key found for platform: {platform}")
                return None
            return await sync_to_async(decrypt_api_key)(encrypted_key)
        except Exception as e:
            logger.error(f"Error getting API key for {platform}: {str(e)}", exc_info=True)
            return None
            
    async def _query_platform(self, platform: str, ip_address: str) -> Dict[str, Any]:
        """Query a specific threat intelligence platform"""
        try:
            api_key = await self._get_api_key(platform)
            if not api_key:
                return {'error': f'No API key available for {platform}'}
                
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            headers = {'Authorization': f'Bearer {api_key}'}
            
            async with self.session.get(
                f'https://api.{platform}.com/v1/ip/{ip_address}',
                headers=headers
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    logger.error(f"Error from {platform}: {error_text}")
                    return {'error': f'Platform error: {error_text}'}
                    
        except Exception as e:
            logger.error(f"Error querying {platform}: {str(e)}", exc_info=True)
            return {'error': str(e)}
            
    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using all available threat intelligence platforms"""
        try:
            # Check cache first
            cache_key = f'ip_analysis:{ip_address}'
            cached_result = await sync_to_async(self.cache.get)(cache_key)
            if cached_result:
                logger.info(f"Cache hit for IP: {ip_address}")
                return cached_result
                
            # Initialize session if needed
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            # Query all platforms concurrently
            platforms = ['virustotal', 'alienvault', 'ibmxforce']  # Add more platforms as needed
            tasks = [self._query_platform(platform, ip_address) for platform in platforms]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            processed_results = {}
            threat_score = 0
            confidence = 0
            
            for platform, result in zip(platforms, results):
                if isinstance(result, Exception):
                    logger.error(f"Error from {platform}: {str(result)}", exc_info=True)
                    processed_results[platform] = {'error': str(result)}
                else:
                    processed_results[platform] = result
                    if 'score' in result:
                        threat_score += result['score']
                        confidence += result.get('confidence', 0)
                        
            # Calculate final scores
            num_valid_results = sum(1 for r in results if not isinstance(r, Exception))
            if num_valid_results > 0:
                threat_score /= num_valid_results
                confidence /= num_valid_results
                
            final_result = {
                'ip_address': ip_address,
                'results': processed_results,
                'threat_score': threat_score,
                'confidence': confidence,
                'threat_details': self._calculate_threat_level(threat_score),
                'provider_scores': {
                    platform: result.get('score', 0) 
                    for platform, result in zip(platforms, results)
                    if not isinstance(result, Exception)
                },
                'categories': self._extract_categories(processed_results)
            }
            
            # Cache the result
            await sync_to_async(self.cache.set)(
                cache_key,
                final_result,
                timeout=3600  # 1 hour
            )
            
            return final_result
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip_address}: {str(e)}", exc_info=True)
            raise
            
    def _calculate_threat_level(self, score: float) -> Dict[str, str]:
        """Calculate threat level details based on score"""
        if score >= 8:
            return {'level': 'High', 'class': 'danger'}
        elif score >= 5:
            return {'level': 'Medium', 'class': 'warning'}
        else:
            return {'level': 'Low', 'class': 'success'}
            
    def _extract_categories(self, results: Dict[str, Any]) -> List[str]:
        """Extract unique categories from platform results"""
        categories = set()
        for platform_results in results.values():
            if isinstance(platform_results, dict):
                platform_categories = platform_results.get('categories', [])
                if isinstance(platform_categories, list):
                    categories.update(platform_categories)
        return sorted(list(categories))
