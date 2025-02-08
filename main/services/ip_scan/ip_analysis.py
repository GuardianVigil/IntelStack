"""
IP Analysis Service for threat intelligence platforms
"""

import asyncio
import aiohttp
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings
from .platforms_score import calculate_platform_scores, extract_whois_info
from .threat_score import calculate_threat_score, get_threat_details
from ...models import APIKey
from django.db.models import Model
from asgiref.sync import sync_to_async
from django.core.cache.backends.base import BaseCache

logger = logging.getLogger(__name__)

class IPAnalysisService:
    """Service for analyzing IP addresses using multiple threat intelligence platforms."""
    
    def __init__(self, user):
        self.session = None
        self.cache = cache
        self.user = user
        self.api_keys = {}
        self.cache_enabled = True
        
        # Test if cache is available
        try:
            self.cache.get("test")
            logger.info("Cache is available")
        except Exception as e:
            logger.warning(f"Cache is not available, proceeding without caching: {str(e)}")
            self.cache_enabled = False
            
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _get_api_key(self, platform):
        """Get API key for the specified platform"""
        if platform in self.api_keys:
            return self.api_keys[platform]
            
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
            self.api_keys[platform] = decrypted_key
            return decrypted_key
        except Exception as e:
            logger.error(f"Error getting API key for {platform}: {str(e)}", exc_info=True)
            return None

    async def _query_virustotal(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query VirusTotal API"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": api_key}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                logger.error(f"VirusTotal API error: {response.status}")
                return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"VirusTotal request error: {str(e)}")
            return {"error": str(e)}

    async def _query_abuseipdb(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query AbuseIPDB API"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 30
        }
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    return await response.json()
                logger.error(f"AbuseIPDB API error: {response.status}")
                return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"AbuseIPDB request error: {str(e)}")
            return {"error": str(e)}

    async def _query_greynoise(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query GreyNoise API"""
        url = f"https://api.greynoise.io/v3/community/{ip_address}"
        headers = {
            "accept": "application/json",
            "key": api_key
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                logger.error(f"GreyNoise API error: {response.status}")
                return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"GreyNoise request error: {str(e)}")
            return {"error": str(e)}

    async def _query_securitytrails(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query SecurityTrails API"""
        url = f"https://api.securitytrails.com/v1/ip/{ip_address}"
        headers = {
            "apikey": api_key,
            "Accept": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                logger.error(f"SecurityTrails API error: {response.status}")
                return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"SecurityTrails request error: {str(e)}")
            return {"error": str(e)}

    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Analyze IP address using multiple threat intelligence platforms
        """
        # Try to get cached result if caching is enabled
        if self.cache_enabled:
            try:
                cache_key = f"ip_analysis_{ip_address}"
                cached_result = await sync_to_async(self.cache.get)(cache_key)
                if cached_result:
                    logger.info(f"Found cached result for {ip_address}")
                    return cached_result
            except Exception as e:
                logger.warning(f"Error accessing cache: {str(e)}")
                self.cache_enabled = False

        platform_data = {}
        platform_scores = {}
        tasks = []
        
        # Query all platforms concurrently
        platforms = {
            'virustotal': self._query_virustotal,
            'abuseipdb': self._query_abuseipdb,
            'greynoise': self._query_greynoise,
            'securitytrails': self._query_securitytrails
        }
        
        # First check if we have any API keys configured
        available_platforms = []
        for platform in platforms.keys():
            api_key = await self._get_api_key(platform)
            if api_key:
                available_platforms.append(platform)
                tasks.append(platforms[platform](ip_address, api_key))
            else:
                platform_data[platform] = {"error": "No API key configured"}
                platform_scores[platform] = None

        if not available_platforms:
            logger.error("No API keys configured for any platform")
            return {
                'error': 'No API keys configured. Please configure at least one API key in Settings > API Configuration.',
                'ip_address': ip_address,
                'overall_score': None,
                'threat_level': None,
                'recommendation': "Unable to analyze IP. Please configure API keys first.",
                'whois_info': None,
                'platform_scores': platform_scores,
                'platform_data': platform_data
            }

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for platform, result in zip(available_platforms, results):
                if isinstance(result, Exception):
                    logger.error(f"Error querying {platform}: {str(result)}")
                    platform_data[platform] = {"error": str(result)}
                    platform_scores[platform] = None
                else:
                    platform_data[platform] = result
                    try:
                        platform_scores[platform] = calculate_platform_scores(result, platform=platform)
                    except Exception as e:
                        logger.error(f"Error calculating score for {platform}: {str(e)}")
                        platform_scores[platform] = None

        # Calculate overall threat score only if we have at least one valid result
        valid_scores = {k: v for k, v in platform_scores.items() if v is not None}
        if valid_scores:
            overall_score = calculate_threat_score(valid_scores)
            threat_details = get_threat_details(overall_score)
            threat_level = threat_details['threat_level']
            recommendation = threat_details['recommendation']
        else:
            logger.error("No valid scores from any platform")
            overall_score = None
            threat_level = None
            recommendation = "Unable to calculate threat score. All platform queries failed."
        
        # Get WHOIS information from VirusTotal data if available
        whois_info = extract_whois_info(platform_data.get('virustotal', {})) if 'virustotal' in platform_data else None

        result = {
            'ip_address': ip_address,
            'overall_score': overall_score,
            'threat_level': threat_level,
            'recommendation': recommendation,
            'whois_info': whois_info,
            'platform_scores': platform_scores,
            'platform_data': platform_data
        }

        # Cache the result if caching is enabled and we have valid data
        if self.cache_enabled and valid_scores:
            try:
                await sync_to_async(self.cache.set)(f"ip_analysis_{ip_address}", result, timeout=3600)
                logger.info(f"Cached result for {ip_address}")
            except Exception as e:
                logger.warning(f"Error caching result: {str(e)}")
                self.cache_enabled = False

        return result
