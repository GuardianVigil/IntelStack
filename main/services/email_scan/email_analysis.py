"""
Email Analysis Service for threat intelligence platforms
"""
import asyncio
import aiohttp
import logging
import email
from email import policy
import re
from typing import Dict, Any, Optional, List, Tuple
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
# Import other platform scanners here

from .utils.data_formatter import format_email_data
from .utils.scoring import calculate_threat_score, calculate_confidence_score

logger = logging.getLogger(__name__)

# Default timeouts for API calls
DEFAULT_TIMEOUT = ClientTimeout(total=30, connect=10)
RATE_LIMIT_CALLS = 10
RATE_LIMIT_PERIOD = 60  # 1 minute

class EmailAnalysisError(Exception):
    """Base exception for Email Analysis errors"""
    pass

class EmailAnalysisService:
    """Service for analyzing emails using multiple threat intelligence platforms"""
    
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
            # Add other scanner classes here
        }
        
        for platform, scanner_class in scanner_classes.items():
            api_key = api_keys.get(platform)
            if api_key:
                self.scanners[platform] = scanner_class(self.session, api_key)

    def parse_email_headers(self, header_content: str) -> Dict[str, Any]:
        """Parse email headers into structured data"""
        try:
            email_message = email.message_from_string(header_content, policy=policy.default)
            
            # Extract basic information
            basic_info = {
                "from": email_message.get("From", ""),
                "to": email_message.get("To", ""),
                "subject": email_message.get("Subject", ""),
                "date": email_message.get("Date", ""),
                "message_id": email_message.get("Message-ID", ""),
                "return_path": email_message.get("Return-Path", "")
            }
            
            # Extract authentication results
            auth_results = email_message.get("Authentication-Results", "")
            auth_info = {
                "spf": self._parse_spf_result(auth_results),
                "dkim": self._parse_dkim_result(auth_results),
                "dmarc": self._parse_dmarc_result(auth_results)
            }
            
            # Extract IPs from headers
            received_headers = email_message.get_all("Received", [])
            ips = self._extract_ips_from_headers(received_headers)
            
            # Extract URLs from body
            urls = self._extract_urls_from_body(email_message)
            
            # Extract attachment information
            attachments = self._extract_attachment_info(email_message)
            
            return {
                "basic_info": basic_info,
                "authentication": auth_info,
                "ips": ips,
                "urls": urls,
                "attachments": attachments,
                "raw_headers": [{"name": k, "value": v} for k, v in email_message.items()]
            }
            
        except Exception as e:
            logger.error(f"Error parsing email headers: {str(e)}")
            raise EmailAnalysisError(f"Failed to parse email headers: {str(e)}")

    async def analyze_email(self, header_content: str) -> Dict[str, Any]:
        """Analyze email using all available threat intelligence platforms"""
        try:
            # Parse email headers
            parsed_data = self.parse_email_headers(header_content)
            
            # Check cache if enabled
            if self.cache_enabled:
                cache_key = f"email_analysis_{hash(header_content)}"
                cached_result = cache.get(cache_key)
                if cached_result:
                    logger.info("Returning cached email analysis result")
                    return cached_result

            # Analyze with each platform
            platform_results = {}
            tasks = []
            
            for platform, scanner in self.scanners.items():
                tasks.append(self._scan_with_platform(scanner, parsed_data))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for platform_name, result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error from {platform_name}: {str(result)}")
                        platform_results[platform_name] = {"error": str(result)}
                    else:
                        platform_results[platform_name] = result

            # Calculate scores
            threat_score = calculate_threat_score(platform_results)
            confidence_score = calculate_confidence_score(platform_results)
            
            # Format final results
            final_results = format_email_data(parsed_data, platform_results, threat_score, confidence_score)
            
            # Cache results if enabled
            if self.cache_enabled:
                cache.set(cache_key, final_results, self.cache_timeout)
            
            return final_results
            
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            raise EmailAnalysisError(f"Failed to analyze email: {str(e)}")

    async def _scan_with_platform(self, scanner, email_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Execute scan with a single platform with error handling"""
        platform_name = scanner.__class__.__name__.replace('Scanner', '').lower()
        try:
            result = await scanner.scan_email(email_data)
            return platform_name, {"status": "success", "data": result}
        except Exception as e:
            logger.error(f"Error scanning with {platform_name}: {str(e)}")
            return platform_name, {"status": "error", "error": str(e)}

    def _parse_spf_result(self, auth_results: str) -> Dict[str, str]:
        """Parse SPF results from Authentication-Results header"""
        spf_match = re.search(r'spf=(\w+)', auth_results)
        return {
            "result": spf_match.group(1) if spf_match else "unknown",
            "details": auth_results
        }

    def _parse_dkim_result(self, auth_results: str) -> Dict[str, str]:
        """Parse DKIM results from Authentication-Results header"""
        dkim_match = re.search(r'dkim=(\w+)', auth_results)
        return {
            "result": dkim_match.group(1) if dkim_match else "unknown",
            "details": auth_results
        }

    def _parse_dmarc_result(self, auth_results: str) -> Dict[str, str]:
        """Parse DMARC results from Authentication-Results header"""
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
        return {
            "result": dmarc_match.group(1) if dmarc_match else "unknown",
            "details": auth_results
        }

    def _extract_ips_from_headers(self, received_headers: List[str]) -> List[str]:
        """Extract IP addresses from Received headers"""
        ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        ips = []
        
        for header in received_headers:
            matches = re.findall(ip_pattern, header)
            ips.extend(matches)
        
        return list(set(ips))  # Remove duplicates

    def _extract_urls_from_body(self, email_message) -> List[str]:
        """Extract URLs from email body"""
        urls = []
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    content = part.get_payload(decode=True).decode()
                    urls.extend(re.findall(url_pattern, content))
        else:
            content = email_message.get_payload(decode=True).decode()
            urls.extend(re.findall(url_pattern, content))
        
        return list(set(urls))  # Remove duplicates

    def _extract_attachment_info(self, email_message) -> List[Dict[str, str]]:
        """Extract information about email attachments"""
        attachments = []
        
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                    
                filename = part.get_filename()
                if filename:
                    import hashlib
                    content = part.get_payload(decode=True)
                    
                    attachment_info = {
                        "filename": filename,
                        "content_type": part.get_content_type(),
                        "size": len(content),
                        "md5": hashlib.md5(content).hexdigest(),
                        "sha1": hashlib.sha1(content).hexdigest(),
                        "sha256": hashlib.sha256(content).hexdigest()
                    }
                    attachments.append(attachment_info)
        
        return attachments
