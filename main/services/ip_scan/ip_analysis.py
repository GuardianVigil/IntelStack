"""
IP Analysis Service for threat intelligence platforms
"""
import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from django.core.cache import cache
from django.conf import settings
from ...models import APIKey
from asgiref.sync import sync_to_async

from .platforms.virustotal import VirusTotalScanner
from .platforms.abuseipdb import AbuseIPDBScanner
from .platforms.greynoise import GreyNoiseScanner
from .platforms.crowdsec import CrowdSecScanner
from .platforms.securitytrails import SecurityTrailsScanner
from .platforms.ipinfo import IPInfoScanner
from .platforms.metadefender import MetaDefenderScanner
from .platforms.pulsedive import PulsediveScanner
from .platforms.alienvault import AlienVaultScanner

from .utils.platform_scoring import calculate_platform_scores
from .utils.data_formatter import DataFormatter

logger = logging.getLogger(__name__)

class IPAnalysisService:
    """Service for analyzing IP addresses using multiple threat intelligence platforms"""
    def __init__(self, session=None):
        self.session = session
        self._own_session = session is None
        self.cache_enabled = getattr(settings, 'THREAT_INTEL_CACHE_ENABLED', True)
        self.cache_timeout = getattr(settings, 'THREAT_INTEL_CACHE_TIMEOUT', 3600)
        self.scanners = {}

    async def __aenter__(self):
        """Async context manager enter"""
        if self._own_session:
            self.session = aiohttp.ClientSession()
        await self.initialize_scanners()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._own_session and self.session:
            await self.session.close()
        self.session = None

    @sync_to_async
    def _get_api_keys(self) -> Dict[str, str]:
        """Get API keys for all platforms"""
        api_keys = {}
        try:
            for key in APIKey.objects.filter(is_active=True):
                try:
                    decrypted_key = key.api_key
                    # Log first 4 chars of key for debugging
                    key_preview = decrypted_key[:4] + '***' if decrypted_key else None
                    logger.info(f"Retrieved key for platform {key.platform}: {'success' if decrypted_key else 'failed'} (preview: {key_preview})")
                    if decrypted_key:
                        api_keys[key.platform.lower()] = decrypted_key
                    else:
                        logger.error(f"Failed to decrypt key for platform: {key.platform}")
                except Exception as e:
                    logger.error(f"Error decrypting key for platform {key.platform}: {str(e)}")
        except Exception as e:
            logger.error(f"Error retrieving API keys: {str(e)}")
        
        # Log the platforms we got keys for
        logger.info(f"Retrieved {len(api_keys)} valid API keys for platforms: {', '.join(api_keys.keys())}")
        return api_keys

    async def initialize_scanners(self):
        """Initialize platform scanners with API keys"""
        api_keys = await self._get_api_keys()
        scanner_classes = {
            'virustotal': VirusTotalScanner,
            'abuseipdb': AbuseIPDBScanner,
            'greynoise': GreyNoiseScanner,
            'crowdsec': CrowdSecScanner,
            'securitytrails': SecurityTrailsScanner,
            'ipinfo': IPInfoScanner,
            'metadefender': MetaDefenderScanner,
            'pulsedive': PulsediveScanner,
            'alienvault': AlienVaultScanner
        }

        for platform, scanner_class in scanner_classes.items():
            api_key = api_keys.get(platform)
            if api_key:
                self.scanners[platform] = scanner_class(self.session, api_key)

    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using all available threat intelligence platforms"""
        if not self.scanners:
            await self.initialize_scanners()

        # Check cache first
        cache_key = f"ip_analysis_{ip_address}"
        if self.cache_enabled:
            cached_result = cache.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for IP {ip_address}")
                return cached_result

        # Collect results from all available scanners
        tasks = []
        for platform, scanner in self.scanners.items():
            tasks.append(self._scan_with_platform(scanner, ip_address, platform))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        platform_data = {}
        platform_scores = {}
        errors = {}

        for platform, data in results:
            if isinstance(data, Exception):
                errors[platform] = str(data)
                continue

            if isinstance(data, dict):
                if "error" in data:
                    errors[platform] = data["error"]
                    continue

                platform_data[platform] = data
                score = calculate_platform_scores(data, platform)
                if score is not None:
                    platform_scores[platform] = score

        # Format the platform data for display
        platform_data = DataFormatter.process_platform_data(platform_data)

        # Prepare final results
        final_results = {
            "summary": {
                "threat_score": self._calculate_overall_score(platform_scores),
                "confidence": self._calculate_confidence(platform_scores),
                "risk_level": self._get_risk_level(platform_scores),
                "platform_scores": platform_scores,
                "errors": errors,
                "last_analysis_date": datetime.now().isoformat()
            },
            "platform_data": platform_data
        }

        # Cache the results
        if self.cache_enabled:
            cache.set(cache_key, final_results, self.cache_timeout)

        return final_results

    async def _scan_with_platform(self, scanner, ip_address: str, platform: str) -> tuple:
        """Execute scan for a single platform with error handling"""
        try:
            result = await scanner.scan(ip_address)
            return platform, result
        except Exception as e:
            logger.error(f"Error scanning with {platform}: {str(e)}")
            return platform, {"error": str(e)}

    def _calculate_overall_score(self, platform_scores: Dict[str, float]) -> float:
        """Calculate overall threat score from platform scores"""
        if not platform_scores:
            return 0

        total_score = sum(platform_scores.values())
        return round(total_score / len(platform_scores), 2)

    def _calculate_confidence(self, platform_scores: Dict[str, float]) -> float:
        """Calculate confidence score based on number of responding platforms"""
        total_platforms = len(self.scanners)
        if total_platforms == 0:
            return 0

        responding_platforms = len(platform_scores)
        return round((responding_platforms / total_platforms) * 100, 2)

    @staticmethod
    def _get_risk_level(platform_scores: Dict[str, float]) -> str:
        """Determine risk level based on platform scores"""
        if not platform_scores:
            return "Unknown"

        avg_score = sum(platform_scores.values()) / len(platform_scores)

        if avg_score >= 80:
            return "Critical"
        elif avg_score >= 60:
            return "High"
        elif avg_score >= 40:
            return "Medium"
        elif avg_score >= 20:
            return "Low"
        return "Info"
