from typing import Optional, Dict
from .base import BasePlatform
from .virustotal_hash import VirusTotalClient
from .hybrid_analysis_hash import HybridAnalysisClient
from .threatfox_hash import ThreatFoxClient
from .malwarebazaar_hash import MalwareBazaarClient
from .filescan_hash import FileScanClient
from .metadefender_hash import MetaDefenderClient

class PlatformFactory:
    """Factory for creating platform-specific clients."""
    
    _platforms = {
        'virustotal': VirusTotalClient,
        'hybrid_analysis': HybridAnalysisClient,
        'threatfox': ThreatFoxClient,
        'malwarebazaar': MalwareBazaarClient,
        'filescan': FileScanClient,
        'metadefender': MetaDefenderClient
    }

    @classmethod
    async def create_client(cls, platform_name: str, api_key: str) -> Optional[BasePlatform]:
        """
        Create a platform-specific client instance.
        
        Args:
            platform_name: Name of the platform to create client for
            api_key: API key for the platform
            
        Returns:
            Platform client instance or None if platform not supported
        """
        platform_class = cls._platforms.get(platform_name.lower())
        if platform_class:
            return platform_class(api_key)
        return None

    @classmethod
    def get_supported_platforms(cls) -> Dict[str, str]:
        """Get a list of supported platforms and their descriptions."""
        return {
            'virustotal': 'VirusTotal malware analysis service',
            'hybrid_analysis': 'Hybrid Analysis malware analysis platform',
            'threatfox': 'ThreatFox IOC platform',
            'malwarebazaar': 'MalwareBazaar malware repository',
            'filescan': 'FileScan malware analysis service',
            'metadefender': 'MetaDefender multi-scanning platform'
        }
