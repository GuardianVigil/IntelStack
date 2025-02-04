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
            elif platform == 'abuseipdb':
                url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'
                headers = {'Key': api_key, 'Accept': 'application/json'}
            elif platform == 'crowdsec':
                url = f'https://api.crowdsec.net/v2/signals?ip={ip_address}'
                headers = {'X-Api-Key': api_key}
            elif platform == 'greynoise':
                url = f'https://api.greynoise.io/v3/community/{ip_address}'
                headers = {'key': api_key}
            elif platform == 'securitytrails':
                url = f'https://api.securitytrails.com/v1/ip/{ip_address}'
                headers = {'APIKEY': api_key}
            else:
                return {'error': f'Unsupported platform: {platform}'}
                
            async with self.session.get(url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    return {'error': f'API Error: {error_text}'}
                data = await response.json()
                return self._process_platform_response(platform, data)
                
        except Exception as e:
            logger.error(f"Error querying {platform}: {str(e)}", exc_info=True)
            return {'error': str(e)}

    def _process_platform_response(self, platform: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process the response from a threat intelligence platform"""
        try:
            if platform == 'virustotal':
                return {
                    'score': data.get('positives', 0) * 10,  # Convert to 0-100 scale
                    'categories': [cat for cat, present in data.get('categories', {}).items() if present],
                    'results': data
                }
            elif platform == 'abuseipdb':
                abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                return {
                    'score': abuse_score,  # Already 0-100
                    'categories': ['Abuse' if abuse_score > 50 else 'Clean'],
                    'results': data.get('data', {})
                }
            elif platform == 'crowdsec':
                signals = len(data.get('signals', []))
                return {
                    'score': min(signals * 20, 100),  # Convert to 0-100 scale
                    'categories': ['Malicious' if signals > 0 else 'Clean'],
                    'results': data
                }
            elif platform == 'greynoise':
                is_malicious = data.get('classification') == 'malicious'
                return {
                    'score': 100 if is_malicious else 0,
                    'categories': [data.get('classification', 'unknown')],
                    'results': data
                }
            elif platform == 'securitytrails':
                risk_score = data.get('risk_score', 0)
                return {
                    'score': risk_score,
                    'categories': data.get('tags', []),
                    'results': data
                }
            return {'error': 'Unsupported platform'}
        except Exception as e:
            logger.error(f"Error processing {platform} response: {str(e)}", exc_info=True)
            return {'error': str(e)}

    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using multiple threat intelligence platforms"""
        results = {}
        threat_score = 0
        confidence = 0
        provider_scores = {}
        categories = set()
        active_providers = 0

        # List of all platforms to check
        platforms = ['virustotal', 'abuseipdb', 'crowdsec', 'greynoise', 'securitytrails']
        tasks = []
        
        # Initialize tasks for each provider
        for platform in platforms:
            api_key = await self._get_api_key(platform)
            if api_key:
                tasks.append((platform, self._query_platform(platform, ip_address, api_key)))
        
        # Execute all tasks concurrently
        if tasks:
            for platform, task in tasks:
                try:
                    result = await task
                    if isinstance(result, Exception):
                        logger.error(f"Provider error: {str(result)}")
                        results[platform] = {'error': str(result)}
                        continue
                        
                    if not result:
                        continue
                    
                    results[platform] = result.get('results', {})
                    
                    if 'score' in result:
                        provider_scores[platform] = result['score']
                        threat_score += result['score']
                        active_providers += 1
                    
                    if 'categories' in result:
                        categories.update(result['categories'])
                except Exception as e:
                    logger.error(f"Error processing {platform} result: {str(e)}", exc_info=True)
                    results[platform] = {'error': str(e)}

        # Calculate final scores
        if active_providers > 0:
            threat_score = threat_score / active_providers
            confidence = (active_providers / len(platforms)) * 100
        
        threat_details = self._get_threat_level(threat_score)
        
        return {
            'results': results,
            'threat_score': threat_score,
            'confidence': confidence,
            'provider_scores': provider_scores,
            'categories': list(categories),
            'threat_details': threat_details
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
