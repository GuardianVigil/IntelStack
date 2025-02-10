"""
IP Analysis Service for threat intelligence platforms
"""
import asyncio
import aiohttp
import logging
import ipaddress
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from django.core.cache import cache
from django.conf import settings
from ...models import APIKey
from asgiref.sync import sync_to_async
from aiohttp import ClientTimeout
from ratelimit import limits, sleep_and_retry

from .platforms.virustotal import VirusTotalScanner
from .platforms.abuseipdb import AbuseIPDBScanner
from .platforms.greynoise import GreyNoiseScanner
from .platforms.crowdsec import CrowdSecScanner
from .platforms.securitytrails import SecurityTrailsScanner
from .platforms.ipinfo import IPInfoScanner
from .platforms.metadefender import MetaDefenderScanner
from .platforms.pulsedive import PulsediveScanner
from .platforms.alienvault import AlienVaultScanner

from .utils.platform_scoring import calculate_platform_scores, calculate_combined_score
from .utils.data_formatter import DataFormatter

logger = logging.getLogger(__name__)

# Default timeouts for API calls
DEFAULT_TIMEOUT = ClientTimeout(total=30, connect=10)
RATE_LIMIT_CALLS = 10
RATE_LIMIT_PERIOD = 60  # 1 minute

class IPAnalysisError(Exception):
    """Base exception for IP Analysis errors"""
    pass

class InvalidIPError(IPAnalysisError):
    """Exception raised for invalid IP addresses"""
    pass

class RateLimitError(IPAnalysisError):
    """Exception raised when rate limit is exceeded"""
    pass

class IPAnalysisService:
    """Service for analyzing IP addresses using multiple threat intelligence platforms"""
    def __init__(self, session=None):
        self.session = session
        self._own_session = session is None
        self.cache_enabled = getattr(settings, 'THREAT_INTEL_CACHE_ENABLED', True)
        self.cache_timeout = getattr(settings, 'THREAT_INTEL_CACHE_TIMEOUT', 3600)
        self.scanners = {}
        self._last_request_time = datetime.now()

    async def __aenter__(self):
        """Async context manager enter"""
        if self._own_session:
            self.session = aiohttp.ClientSession(timeout=DEFAULT_TIMEOUT)
        await self.initialize_scanners()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._own_session and self.session:
            await self.session.close()
        self.session = None

    def validate_ip(self, ip_address: str) -> bool:
        """
        Validate IP address format
        Raises InvalidIPError if IP is invalid
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                raise InvalidIPError("Private IP addresses are not allowed")
            if ip.is_loopback:
                raise InvalidIPError("Loopback addresses are not allowed")
            if ip.is_link_local:
                raise InvalidIPError("Link-local addresses are not allowed")
            return True
        except ValueError:
            raise InvalidIPError(f"Invalid IP address format: {ip_address}")

    @sleep_and_retry
    @limits(calls=RATE_LIMIT_CALLS, period=RATE_LIMIT_PERIOD)
    async def _check_rate_limit(self):
        """Check if we're within rate limits"""
        pass

    @sync_to_async
    def _get_api_keys(self) -> Dict[str, str]:
        """Get API keys for all platforms"""
        api_keys = {}
        try:
            for key in APIKey.objects.filter(is_active=True):
                try:
                    # Use the api_key property instead of get_decrypted_key
                    decrypted_key = key.api_key
                    key_preview = decrypted_key[:4] + '***' if decrypted_key else None
                    logger.info(f"Retrieved key for platform {key.platform}: {'success' if decrypted_key else 'failed'} (preview: {key_preview})")
                    if decrypted_key:
                        api_keys[key.platform.lower()] = decrypted_key
                except Exception as e:
                    logger.error(f"Error decrypting key for platform {key.platform}: {str(e)}")
        except Exception as e:
            logger.error(f"Error retrieving API keys: {str(e)}")
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

    async def _scan_with_platform(self, scanner, ip_address: str) -> Tuple[str, Dict[str, Any]]:
        """Execute scan with a single platform with error handling"""
        platform_name = scanner.__class__.__name__.replace('Scanner', '').lower()
        try:
            result = await scanner.scan(ip_address)
            return platform_name, {"status": "success", "data": result}
        except asyncio.TimeoutError:
            logger.error(f"Timeout while scanning {ip_address} with {platform_name}")
            return platform_name, {"status": "error", "error": "Request timed out"}
        except Exception as e:
            logger.error(f"Error scanning {ip_address} with {platform_name}: {str(e)}")
            return platform_name, {"status": "error", "error": str(e)}

    async def _write_scan_log(self, ip_address: str, scan_data: Dict[str, Any]) -> None:
        """Write detailed scan results to a log file"""
        import json
        from datetime import datetime
        import os

        log_file = os.path.join(os.path.dirname(__file__), 'ipdata.txt')
        
        # Format the data for better readability
        formatted_data = {
            "scan_time": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "summary": scan_data["summary"],
            "platform_details": {}
        }

        # Format each platform's data
        for platform, data in scan_data["platform_data"].items():
            formatted_data["platform_details"][platform] = {
                "raw_data": data,
                "formatted_data": self._format_platform_data(platform, data)
            }

        # Write to file with proper formatting
        try:
            with open(log_file, 'a') as f:
                f.write("\n" + "="*80 + "\n")
                f.write(f"SCAN RESULTS FOR IP: {ip_address}\n")
                f.write(f"TIMESTAMP: {formatted_data['scan_time']}\n")
                f.write("="*80 + "\n\n")
                
                # Write summary
                f.write("SUMMARY:\n")
                f.write("-"*40 + "\n")
                summary = formatted_data["summary"]
                f.write(f"Threat Score: {summary['threat_score']}\n")
                f.write(f"Total Platforms: {summary['total_platforms']}\n")
                f.write(f"Successful Platforms: {summary['successful_platforms']}\n")
                if summary.get('errors'):
                    f.write("\nErrors:\n")
                    for error in summary['errors']:
                        f.write(f"- {error['platform']}: {error['error']}\n")
                f.write("\n")

                # Write detailed platform data
                f.write("DETAILED PLATFORM RESULTS:\n")
                f.write("="*80 + "\n\n")
                
                for platform, details in formatted_data["platform_details"].items():
                    f.write(f"[{platform.upper()}]\n")
                    f.write("-"*40 + "\n")
                    
                    if details.get('formatted_data'):
                        f.write("Formatted Data:\n")
                        for key, value in details['formatted_data'].items():
                            f.write(f"{key}: {value}\n")
                    
                    f.write("\nRaw Data:\n")
                    f.write(json.dumps(details['raw_data'], indent=2))
                    f.write("\n\n")
                
                f.write("="*80 + "\n\n")
        except Exception as e:
            logger.error(f"Error writing scan log: {str(e)}")

    def _format_platform_data(self, platform: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format platform-specific data for better readability"""
        formatted = {}
        
        if platform == 'virustotal':
            if isinstance(data, dict):
                formatted = {
                    "Malicious Votes": data.get("malicious", 0),
                    "Suspicious Votes": data.get("suspicious", 0),
                    "Last Analysis Date": data.get("last_analysis_date", "N/A"),
                    "Country": data.get("country", "N/A"),
                    "AS Owner": data.get("as_owner", "N/A"),
                    "Network": data.get("network", "N/A"),
                    "Categories": data.get("categories", []),
                    "Tags": data.get("tags", [])
                }
        
        elif platform == 'abuseipdb':
            if isinstance(data, dict):
                formatted = {
                    "Abuse Score": data.get("abuseConfidenceScore", 0),
                    "Total Reports": data.get("totalReports", 0),
                    "Last Reported": data.get("lastReportedAt", "N/A"),
                    "Country": data.get("countryCode", "N/A"),
                    "ISP": data.get("isp", "N/A"),
                    "Domain": data.get("domain", "N/A"),
                    "Categories": data.get("categories", []),
                    "Last Report Details": data.get("lastReportDetails", "N/A")
                }
        
        elif platform == 'greynoise':
            if isinstance(data, dict):
                formatted = {
                    "Classification": data.get("classification", "N/A"),
                    "Last Seen": data.get("last_seen", "N/A"),
                    "Intent": data.get("intent", "N/A"),
                    "Noise": data.get("noise", False),
                    "RIOT": data.get("riot", False),
                    "Name": data.get("name", "N/A"),
                    "Tags": data.get("tags", []),
                    "Metadata": data.get("metadata", {})
                }

        elif platform == 'crowdsec':
            if isinstance(data, dict):
                formatted = {
                    "Score": data.get("score", 0),
                    "Background Noise": data.get("background_noise", False),
                    "IP Range": data.get("ip_range", "N/A"),
                    "AS Name": data.get("as_name", "N/A"),
                    "AS Number": data.get("as_number", "N/A"),
                    "Location": data.get("location", {}),
                    "Behaviors": data.get("behaviors", []),
                    "Reverse DNS": data.get("reverse_dns", "N/A")
                }

        elif platform == 'securitytrails':
            if isinstance(data, dict):
                formatted = {
                    "Host Names": data.get("hostnames", []),
                    "Mail Servers": data.get("mail_servers", []),
                    "Sub Domains": data.get("subdomains", []),
                    "Tags": data.get("tags", []),
                    "Alexa Rank": data.get("alexa_rank", "N/A"),
                    "Whois": data.get("whois", {}),
                    "SSL Certificates": data.get("ssl_certificates", [])
                }

        elif platform == 'ipinfo':
            if isinstance(data, dict):
                formatted = {
                    "Hostname": data.get("hostname", "N/A"),
                    "City": data.get("city", "N/A"),
                    "Region": data.get("region", "N/A"),
                    "Country": data.get("country", "N/A"),
                    "Location": data.get("loc", "N/A"),
                    "Organization": data.get("org", "N/A"),
                    "Postal Code": data.get("postal", "N/A"),
                    "Timezone": data.get("timezone", "N/A")
                }

        elif platform == 'metadefender':
            if isinstance(data, dict):
                formatted = {
                    "Threat Level": data.get("threat_level", "N/A"),
                    "Detected By": data.get("detected_by", 0),
                    "Total Engines": data.get("total_engines", 0),
                    "Scan Time": data.get("scan_time", "N/A"),
                    "Malware Family": data.get("malware_family", "N/A"),
                    "File Type": data.get("file_type", "N/A"),
                    "Trust Factor": data.get("trust_factor", 0)
                }

        elif platform == 'pulsedive':
            if isinstance(data, dict):
                formatted = {
                    "Risk Level": data.get("risk", "N/A"),
                    "Threats": data.get("threats", []),
                    "Feed Names": data.get("feed_names", []),
                    "Properties": data.get("properties", {}),
                    "Recent Activities": data.get("recent_activities", []),
                    "Links": data.get("links", [])
                }

        elif platform == 'alienvault':
            if isinstance(data, dict):
                formatted = {
                    "Reputation": data.get("reputation", 0),
                    "Activities": data.get("activities", []),
                    "Risk Score": data.get("risk_score", 0),
                    "First Seen": data.get("first_seen", "N/A"),
                    "Last Seen": data.get("last_seen", "N/A"),
                    "Industries": data.get("industries", []),
                    "Threat Types": data.get("threat_types", [])
                }
        
        return formatted

    async def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address using all available threat intelligence platforms"""
        try:
            # Validate IP address
            self.validate_ip(ip_address)
            
            # Check rate limit
            await self._check_rate_limit()

            if not self.scanners:
                await self.initialize_scanners()

            # Check cache first
            cache_key = f"ip_analysis_{ip_address}"
            if self.cache_enabled:
                cached_result = cache.get(cache_key)
                if cached_result:
                    logger.info(f"Cache hit for IP {ip_address}")
                    return cached_result

            # Execute all platform scans concurrently with timeout
            tasks = [
                self._scan_with_platform(scanner, ip_address)
                for scanner in self.scanners.values()
            ]
            
            platform_results = {}
            scan_errors = []
            platform_scores = {}
            
            # Wait for all scans to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for platform_name, result in results:
                if isinstance(result, Exception):
                    scan_errors.append({
                        "platform": platform_name,
                        "error": str(result)
                    })
                    continue
                    
                if result["status"] == "error":
                    scan_errors.append({
                        "platform": platform_name,
                        "error": result["error"]
                    })
                else:
                    platform_results[platform_name] = result["data"]
                    # Calculate individual platform scores
                    score = calculate_platform_scores(result["data"], platform_name)
                    if score is not None:
                        platform_scores[platform_name] = score

            # Calculate combined threat score
            threat_score_data = calculate_combined_score(platform_scores)
            threat_score = threat_score_data.get('overall_score', 0)

            # Format the final response
            response = {
                "ip_address": ip_address,
                "timestamp": datetime.utcnow().isoformat(),
                "platform_data": platform_results,
                "summary": {
                    "threat_score": threat_score,
                    "platform_scores": platform_scores,
                    "total_platforms": len(self.scanners),
                    "successful_platforms": len(platform_results),
                    "errors": scan_errors if scan_errors else None
                }
            }

            # Write detailed scan results to log file
            await self._write_scan_log(ip_address, response)

            # Cache the result
            if self.cache_enabled and platform_results:
                cache.set(cache_key, response, self.cache_timeout)

            return response

        except InvalidIPError as e:
            logger.warning(f"Invalid IP address attempt: {ip_address}")
            raise
        except RateLimitError:
            logger.warning(f"Rate limit exceeded for IP analysis")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during IP analysis: {str(e)}")
            raise IPAnalysisError(f"Failed to analyze IP: {str(e)}")

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
