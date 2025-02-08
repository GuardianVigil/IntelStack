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
            api_key = await sync_to_async(APIKey.objects.get)(user=self.user, platform=platform, is_active=True)
            decrypted_key = await sync_to_async(api_key.get_decrypted_api_key)()
            self.api_keys[platform] = decrypted_key
            return decrypted_key
        except APIKey.DoesNotExist:
            logger.warning(f"No API key found for {platform}")
            return None
        except Exception as e:
            logger.error(f"Error getting API key for {platform}: {str(e)}")
            return None

    async def _query_virustotal(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query VirusTotal API"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
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
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": str(ip_address),  
            "maxAgeInDays": "90",  
            "verbose": "true"  
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

    async def _query_crowdsec(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query CrowdSec API"""
        url = f"https://cti.api.crowdsec.net/v2/smoke/{ip_address}"  # Fixed API endpoint
        headers = {
            "x-api-key": api_key,  # Fixed header name
            "Accept": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    # Transform CrowdSec response to match our format
                    return {
                        "ip": ip_address,
                        "score": data.get("scores", {}).get("overall", {}).get("score", 0),
                        "decisions": data.get("decisions", []),
                        "behaviors": data.get("behaviors", []),
                        "classifications": data.get("classifications", []),
                        "references": data.get("references", []),
                        "history": data.get("history", {}),
                        "background_noise": data.get("background_noise", False),
                        "message": data.get("message", ""),
                        "last_update": data.get("last_update", "")
                    }
                logger.error(f"CrowdSec API error: {response.status}")
                return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"CrowdSec request error: {str(e)}")
            return {"error": str(e)}

    async def _query_securitytrails(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Query SecurityTrails API"""
        url = f"https://api.securitytrails.com/v1/ips/nearby/{ip_address}"
        headers = {
            "accept": "application/json",
            "APIKEY": api_key
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    # Transform SecurityTrails response to match our format
                    return {
                        "neighbors": data.get("blocks", []),
                        "history": data.get("history", {}),
                        "associated": data.get("associated", {}),
                        "tags": data.get("tags", [])
                    }
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

        tasks = []
        
        # Create tasks for each platform
        for platform in ['virustotal', 'abuseipdb', 'greynoise', 'securitytrails', 'crowdsec']:
            api_key = await self._get_api_key(platform)
            if not api_key:
                logger.warning(f"No API key found for {platform}")
                continue
                
            query_func = getattr(self, f'_query_{platform}')
            tasks.append(query_func(ip_address, api_key))
        
        # Execute all queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        platform_data = {}
        platform_scores = {}
        whois_info = None
        
        for platform, result in zip(['virustotal', 'abuseipdb', 'greynoise', 'securitytrails', 'crowdsec'], results):
            if isinstance(result, Exception):
                logger.error(f"{platform} query failed: {str(result)}")
                continue
                
            if isinstance(result, dict) and not result.get('error'):
                platform_data[platform] = result
                score = calculate_platform_scores(result, platform)
                if score is not None:
                    platform_scores[platform] = score
                    
                # Extract WHOIS info from VirusTotal response
                if platform == 'virustotal':
                    whois_info = extract_whois_info(result)
        
        # Calculate overall threat score
        valid_scores = [score for score in platform_scores.values() if score is not None]
        overall_score = sum(valid_scores) / len(valid_scores) if valid_scores else None
        
        # Determine threat level based on overall score
        threat_level = "Unknown"
        if overall_score is not None:
            if overall_score >= 80:
                threat_level = "Critical"
            elif overall_score >= 60:
                threat_level = "High"
            elif overall_score >= 40:
                threat_level = "Medium"
            elif overall_score >= 20:
                threat_level = "Low"
            else:
                threat_level = "Safe"
        
        result = {
            "ip_address": ip_address,
            "overall_score": overall_score,
            "threat_level": threat_level,
            "platform_scores": platform_scores,
            "platform_data": platform_data,
            "whois_info": whois_info or {}
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
