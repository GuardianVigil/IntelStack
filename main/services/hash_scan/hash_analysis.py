from datetime import datetime
import logging
from typing import Dict, List, Optional

from django.conf import settings

from .utils.data_formatter import DataFormatter
from .utils.platform_clients import (
    HybridAnalysisClient,
    PulsediveClient,
    VirusTotalClient,
    GreyNoiseClient
)

logger = logging.getLogger(__name__)

class HashAnalysisService:
    """Service for analyzing file hashes using various threat intelligence platforms."""

    def __init__(self):
        """Initialize the HashAnalysisService with platform clients."""
        self.data_formatter = DataFormatter()
        self.platform_clients = {
            'hybrid_analysis': HybridAnalysisClient(settings.HYBRID_ANALYSIS_API_KEY),
            'pulsedive': PulsediveClient(settings.PULSEDIVE_API_KEY),
            'virustotal': VirusTotalClient(settings.VIRUSTOTAL_API_KEY),
            'greynoise': GreyNoiseClient(settings.GREYNOISE_API_KEY)
        }

    async def analyze_hash(self, file_hash: str, platforms: Optional[List[str]] = None) -> Dict:
        """
        Analyze a file hash using specified threat intelligence platforms.
        
        Args:
            file_hash: The hash to analyze (MD5, SHA1, or SHA256)
            platforms: Optional list of platforms to use. If None, use all available platforms.
        
        Returns:
            Dict containing analysis results from each platform
        """
        if not file_hash:
            raise ValueError("Hash cannot be empty")

        if platforms is None:
            platforms = list(self.platform_clients.keys())

        platform_data = {}
        errors = []

        for platform in platforms:
            try:
                if platform not in self.platform_clients:
                    continue

                client = self.platform_clients[platform]
                raw_data = await client.lookup_hash(file_hash)
                
                if raw_data:
                    platform_data[platform] = raw_data
                
            except Exception as e:
                logger.error(f"Error getting data from {platform} for hash {file_hash}: {str(e)}")
                errors.append({
                    'platform': platform,
                    'error': str(e)
                })

        # Format the response
        formatted_platform_data = self.data_formatter.process_platform_data(platform_data)
        
        response = {
            "hash": file_hash,
            "timestamp": datetime.utcnow().isoformat(),
            "platform_data": formatted_platform_data,
            "errors": errors
        }

        return response

    @staticmethod
    def get_supported_platforms() -> List[str]:
        """Get list of supported threat intelligence platforms."""
        return [
            'hybrid_analysis',
            'pulsedive',
            'virustotal',
            'greynoise'
        ]
