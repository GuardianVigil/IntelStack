"""
IP Analysis Service for threat intelligence platforms
"""

import logging
import aiohttp
import asyncio
from typing import Dict, Any, List
from django.conf import settings
from django.core.cache import cache
from asgiref.sync import sync_to_async
from ..models import APIKey

logger = logging.getLogger(__name__)

class IPAnalysisService:
    """Service for analyzing IP addresses using multiple threat intelligence platforms."""
    
    def __init__(self, user):
        self.session = None
        self.cache = cache
        self.user = user
            
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def _get_api_key(self, platform):
        """Get API key for the specified platform"""
        try:
            api_key = await sync_to_async(lambda: APIKey.objects.filter(
                user=self.user,
                platform=platform,
                is_active=True
            ).first())()
            
            if not api_key:
                logger.warning(f"No API key configured for {platform}")
                return None
                
            decrypted_key = await sync_to_async(api_key.get_decrypted_api_key)()
            return decrypted_key
        except Exception as e:
            logger.error(f"Error getting API key for {platform}: {str(e)}", exc_info=True)
            return None

    async def _query_platform(self, platform: str, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query a specific threat intelligence platform"""
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            headers = {'X-ApiKey': api_key}
            
            if platform == 'virustotal':
                url = f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip_address}'
            elif platform == 'alienvault':
                url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}'
                headers = {'X-OTX-API-KEY': api_key}
            elif platform == 'ibmxforce':
                url = f'https://api.xforce.ibmcloud.com/ipr/{ip_address}'
                headers = {'Authorization': f'Basic {api_key}'}
            else:
                return {'error': f'Unsupported platform: {platform}'}
                
            async with self.session.get(url, headers=headers) as response:
                data = await response.json()
                return self._process_platform_response(platform, data)
                
        except Exception as e:
            logger.error(f"Error querying {platform}: {str(e)}", exc_info=True)
            return {'error': str(e)}

    def _process_platform_response(self, platform: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process the response from a threat intelligence platform"""
        if platform == 'virustotal':
            return {
                'score': data.get('positives', 0) * 10,  # Convert to 0-100 scale
                'categories': [cat for cat, present in data.get('categories', {}).items() if present],
                'results': data
            }
        elif platform == 'alienvault':
            pulse_count = len(data.get('pulse_info', {}).get('pulses', []))
            return {
                'score': min(pulse_count * 20, 100),  # Convert to 0-100 scale
                'categories': [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])],
                'results': data
            }
        elif platform == 'ibmxforce':
            score = data.get('score', 0)
            return {
                'score': score,
                'categories': data.get('cats', []),
                'results': data
            }
        return {'error': 'Unsupported platform'}

    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using multiple threat intelligence platforms"""
        results = {}
        threat_score = 0
        confidence = 0
        provider_scores = {}
        categories = set()
        active_providers = 0

        # Initialize tasks for each provider
        tasks = []
        
        # VirusTotal
        vt_key = await self._get_api_key('virustotal')
        if vt_key:
            tasks.append(self._query_platform('virustotal', ip_address, vt_key))
        
        # AlienVault OTX
        otx_key = await self._get_api_key('alienvault')
        if otx_key:
            tasks.append(self._query_platform('alienvault', ip_address, otx_key))
        
        # IBM X-Force
        xforce_key = await self._get_api_key('ibmxforce')
        if xforce_key:
            tasks.append(self._query_platform('ibmxforce', ip_address, xforce_key))

        # Execute all tasks concurrently
        if tasks:
            provider_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for platform, result in zip(['virustotal', 'alienvault', 'ibmxforce'], provider_results):
                if isinstance(result, Exception):
                    logger.error(f"Provider error: {str(result)}")
                    results[platform] = {'error': str(result)}
                    continue
                    
                if not result:
                    continue
                
                results[platform] = result
                
                if 'score' in result:
                    provider_scores[platform] = result['score']
                    threat_score += result['score']
                    active_providers += 1
                
                if 'categories' in result:
                    categories.update(result['categories'])

        # Calculate final scores
        if active_providers > 0:
            threat_score = threat_score / active_providers
            confidence = min(100, (active_providers / 3) * 100)  # 3 is total number of providers
        
        # Determine threat level and class
        threat_details = self._get_threat_level(threat_score)

        return {
            'results': results,
            'threat_score': threat_score,
            'confidence': confidence,
            'threat_details': threat_details,
            'provider_scores': provider_scores,
            'categories': list(categories)
        }

    def _get_threat_level(self, score: float) -> Dict[str, str]:
        """Determine threat level and corresponding CSS class based on score"""
        if score >= 80:
            return {'level': 'Critical', 'class': 'danger'}
        elif score >= 60:
            return {'level': 'High', 'class': 'warning'}
        elif score >= 40:
            return {'level': 'Medium', 'class': 'info'}
        else:
            return {'level': 'Low', 'class': 'success'}
