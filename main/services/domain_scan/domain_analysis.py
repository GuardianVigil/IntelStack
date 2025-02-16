"""
Domain Analysis Service for scanning domains across multiple threat intelligence platforms
"""
import asyncio
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from django.conf import settings
from django.db.models import QuerySet
from asgiref.sync import sync_to_async
from main.models import APIKey
from .platforms.alienvault import AlienVaultAPI
from .platforms.virustotal import VirusTotalAPI
from .platforms.pulsedive import PulsediveAPI
from .platforms.metadefender import MetaDefenderAPI
from .platforms.securitytrails import SecurityTrailsAPI
from .utils.data_aggregation import aggregate_platform_data
from .utils.data_formatter import DataFormatter
from .utils.threat_score import calculate_threat_score
from .utils.rate_limiter import RateLimiter
from .utils.cache_manager import CacheManager

logger = logging.getLogger(__name__)

# Create sync_to_async functions for cache operations
get_cached_results = sync_to_async(CacheManager.get_cached_results)
cache_results = sync_to_async(CacheManager.cache_results)
get_cached_platform_results = sync_to_async(CacheManager.get_cached_platform_results)
cache_platform_results = sync_to_async(CacheManager.cache_platform_results)

class DomainAnalysisService:
    """Service for analyzing domains using multiple threat intelligence platforms"""
    
    def __init__(self, user):
        """Initialize service with user for API key access"""
        self.user = user
        self.platforms = {}
        self.log_file = Path("/home/Agile/code/Vristo/main/services/domain_scan/data.txt")

    async def _log_platform_data(self, domain: str, platform_name: str, data: Any):
        """Log platform data to file"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "domain": domain,
            "platform": platform_name,
            "data": data
        }
        
        # Use sync_to_async for file operations
        await sync_to_async(self._write_log)(log_entry)

    def _write_log(self, log_entry: Dict):
        """Write log entry to file (sync operation)"""
        try:
            # Ensure parent directories exist
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create formatted header
            platform = log_entry["platform"].upper()
            domain = log_entry["domain"]
            timestamp = log_entry["timestamp"]
            
            # Format the header
            header = f"""
{'=' * 100}
PLATFORM: {platform}
DOMAIN: {domain}
TIMESTAMP: {timestamp}
{'-' * 100}"""
            
            # Append to file
            with self.log_file.open("a") as f:
                f.write(header + "\n")
                if isinstance(log_entry["data"], dict):
                    json.dump(log_entry["data"], f, indent=2, default=str)
                else:
                    f.write(str(log_entry["data"]))
                f.write("\n\n")
        except Exception as e:
            logger.error(f"Error writing to log file: {str(e)}")

    async def initialize(self):
        """Initialize platform API clients with keys from database"""
        try:
            # Get API keys from database using sync_to_async
            api_keys = await sync_to_async(self._get_api_keys)()
            
            # Initialize platform clients with API keys
            if alienvault_key := api_keys.get('alienvault'):
                self.platforms['alienvault'] = AlienVaultAPI(alienvault_key)
            
            if virustotal_key := api_keys.get('virustotal'):
                self.platforms['virustotal'] = VirusTotalAPI(virustotal_key)
            
            if pulsedive_key := api_keys.get('pulsedive'):
                self.platforms['pulsedive'] = PulsediveAPI(pulsedive_key)
            
            if metadefender_key := api_keys.get('metadefender'):
                self.platforms['metadefender'] = MetaDefenderAPI(metadefender_key)
            
            if securitytrails_key := api_keys.get('securitytrails'):
                self.platforms['securitytrails'] = SecurityTrailsAPI(securitytrails_key)
            
            if not self.platforms:
                logger.warning(f"No API keys found for user {self.user.username}")
                
        except Exception as e:
            logger.error(f"Error initializing platform APIs: {str(e)}")
            raise

    def _get_api_keys(self) -> Dict[str, str]:
        """Get API keys from database (runs in sync context)"""
        return {
            key.platform: key.api_key 
            for key in APIKey.objects.filter(user=self.user)
        }

    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a domain using all available threat intelligence platforms
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary containing analysis results from all platforms
        """
        try:
            # Initialize platforms if not already done
            if not self.platforms:
                await self.initialize()
            
            # Check cache first
            if cached_results := await get_cached_results(domain, self.user.id):
                logger.info(f"Using cached results for domain {domain}")
                await self._log_platform_data(domain, "CACHE_HIT", cached_results)
                return cached_results
            
            # Create tasks for parallel platform scanning
            tasks = []
            for platform_name, platform in self.platforms.items():
                tasks.append(self._scan_platform(platform_name, platform, domain))
            
            # Run platform scans in parallel
            platform_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            platform_data = {}
            has_valid_data = False
            
            for platform_name, result in zip(self.platforms.keys(), platform_results):
                if isinstance(result, Exception):
                    error_data = {"error": str(result)}
                    platform_data[platform_name] = error_data
                    await self._log_platform_data(domain, f"{platform_name}_ERROR", error_data)
                else:
                    if result and isinstance(result, dict) and not result.get('error'):
                        has_valid_data = True
                        platform_data[platform_name] = result
                        await self._log_platform_data(domain, f"{platform_name}_RESULT", result)
                        # Cache individual platform results
                        await cache_platform_results(domain, self.user.id, platform_name, result)
                    else:
                        platform_data[platform_name] = {"error": "Invalid or empty response"}
                        await self._log_platform_data(domain, f"{platform_name}_ERROR", {"error": "Invalid or empty response"})
            
            # Check if we have any valid data
            if not has_valid_data:
                error_msg = "No valid data received from any platform"
                logger.error(error_msg)
                await self._log_platform_data(domain, "NO_VALID_DATA", {"error": error_msg})
                return {
                    'domain': domain,
                    'error': error_msg,
                    'platform_data': platform_data
                }
            
            # Log raw platform data
            await self._log_platform_data(domain, "ALL_PLATFORMS_RAW", platform_data)
            
            # Aggregate and format data
            try:
                aggregated_data = aggregate_platform_data(platform_data)
                await self._log_platform_data(domain, "AGGREGATED_DATA", aggregated_data)
                
                threat_score = calculate_threat_score(aggregated_data)
                formatted_data = DataFormatter.format_domain_data(aggregated_data)
                
                final_results = {
                    'domain': domain,
                    'threat_score': threat_score,
                    'summary': aggregated_data.get('summary', {}),
                    'whois': aggregated_data.get('whois', {}),
                    'security_analysis': aggregated_data.get('security_analysis', {}),
                    'platform_data': formatted_data
                }
                
                # Log final results
                await self._log_platform_data(domain, "FINAL_RESULTS", final_results)
                
                # Cache the final results
                await cache_results(domain, self.user.id, final_results)
                
                return final_results
                
            except Exception as e:
                error_msg = f"Error processing platform data: {str(e)}"
                logger.error(error_msg)
                await self._log_platform_data(domain, "PROCESSING_ERROR", {"error": error_msg})
                return {
                    'domain': domain,
                    'error': error_msg,
                    'raw_data': platform_data
                }
            
        except Exception as e:
            error_msg = f"Error analyzing domain {domain}: {str(e)}"
            logger.error(error_msg)
            await self._log_platform_data(domain, "FATAL_ERROR", {"error": error_msg})
            return {
                'domain': domain,
                'error': error_msg
            }

    async def _scan_platform(self, platform_name: str, platform: Any, domain: str) -> Optional[Dict[str, Any]]:
        """
        Scan domain using a specific platform
        
        Args:
            platform_name: Name of the platform
            platform: Platform API client instance
            domain: Domain to scan
            
        Returns:
            Platform scan results or None if error
        """
        try:
            # Check platform cache first
            if cached_results := await get_cached_platform_results(domain, self.user.id, platform_name):
                logger.info(f"Using cached {platform_name} results for domain {domain}")
                return cached_results
            
            # Check rate limit
            can_request, wait_time = RateLimiter.can_make_request(platform_name, self.user.id)
            
            # Wait if needed
            if not can_request:
                logger.info(f"Rate limit hit for {platform_name}, waiting {wait_time} seconds")
                await asyncio.sleep(wait_time)
            
            # Scan domain
            results = await platform.scan_domain(domain)
            
            # Validate results
            if not results or not isinstance(results, dict):
                raise ValueError(f"Invalid response from {platform_name}")
            
            # Cache results
            await cache_platform_results(domain, self.user.id, platform_name, results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning {domain} with {platform_name}: {str(e)}")
            return {"error": str(e)}

    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        # Cleanup if needed
        pass
