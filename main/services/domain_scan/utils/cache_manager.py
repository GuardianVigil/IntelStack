"""
Cache manager for domain scan results
"""
import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from django.core.cache import cache
from django.conf import settings

class CacheManager:
    """Manager for caching domain scan results"""
    
    # Cache timeouts (in seconds)
    CACHE_TIMEOUTS = {
        'domain_results': 3600,  # 1 hour
        'platform_results': 1800  # 30 minutes
    }
    
    @classmethod
    def get_cached_results(cls, domain: str, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get cached results for a domain
        
        Args:
            domain: Domain name
            user_id: User ID
            
        Returns:
            Cached results or None
        """
        cache_key = cls._get_cache_key(domain, user_id)
        cached_data = cache.get(cache_key)
        
        if cached_data:
            # Check if cache is still fresh
            if cls._is_cache_fresh(cached_data):
                return cached_data['data']
            else:
                # Remove stale cache
                cache.delete(cache_key)
        
        return None
    
    @classmethod
    def cache_results(cls, domain: str, user_id: int, results: Dict[str, Any]):
        """
        Cache results for a domain
        
        Args:
            domain: Domain name
            user_id: User ID
            results: Results to cache
        """
        cache_key = cls._get_cache_key(domain, user_id)
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'data': results
        }
        cache.set(
            cache_key, 
            cache_data, 
            timeout=cls.CACHE_TIMEOUTS['domain_results']
        )
    
    @classmethod
    def cache_platform_results(cls, domain: str, user_id: int, platform: str, results: Dict[str, Any]):
        """
        Cache results from a specific platform
        
        Args:
            domain: Domain name
            user_id: User ID
            platform: Platform name
            results: Platform results to cache
        """
        cache_key = cls._get_platform_cache_key(domain, user_id, platform)
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'data': results
        }
        cache.set(
            cache_key, 
            cache_data, 
            timeout=cls.CACHE_TIMEOUTS['platform_results']
        )
    
    @classmethod
    def get_cached_platform_results(cls, domain: str, user_id: int, platform: str) -> Optional[Dict[str, Any]]:
        """
        Get cached results for a specific platform
        
        Args:
            domain: Domain name
            user_id: User ID
            platform: Platform name
            
        Returns:
            Cached platform results or None
        """
        cache_key = cls._get_platform_cache_key(domain, user_id, platform)
        cached_data = cache.get(cache_key)
        
        if cached_data and cls._is_cache_fresh(cached_data):
            return cached_data['data']
        return None
    
    @classmethod
    def clear_cache(cls, domain: str, user_id: int):
        """
        Clear all cached data for a domain
        
        Args:
            domain: Domain name
            user_id: User ID
        """
        # Clear main results
        cache_key = cls._get_cache_key(domain, user_id)
        cache.delete(cache_key)
        
        # Clear platform results
        for platform in ['alienvault', 'virustotal', 'pulsedive', 'metadefender', 'securitytrails']:
            platform_key = cls._get_platform_cache_key(domain, user_id, platform)
            cache.delete(platform_key)
    
    @classmethod
    def _get_cache_key(cls, domain: str, user_id: int) -> str:
        """Generate cache key for domain results"""
        return f"domain_scan:results:{user_id}:{domain}"
    
    @classmethod
    def _get_platform_cache_key(cls, domain: str, user_id: int, platform: str) -> str:
        """Generate cache key for platform results"""
        return f"domain_scan:platform:{user_id}:{domain}:{platform}"
    
    @classmethod
    def _is_cache_fresh(cls, cached_data: Dict[str, Any]) -> bool:
        """Check if cached data is still fresh"""
        try:
            cache_time = datetime.fromisoformat(cached_data['timestamp'])
            max_age = timedelta(seconds=cls.CACHE_TIMEOUTS['domain_results'])
            return datetime.now() - cache_time < max_age
        except (KeyError, ValueError):
            return False
