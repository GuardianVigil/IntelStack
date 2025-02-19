"""
Main URL scanning module
"""
import asyncio
import aiohttp
from typing import Dict, Any, List
import os
from datetime import datetime

from .platforms.hybrid_analysis import HybridAnalysisScanner
from .platforms.urlscan_io import URLScanScanner
from .platforms.virustotal import VirusTotalScanner
from .platforms.screenshot_machine import ScreenshotMachineScanner
from .utils.threat_score import calculate_overall_threat_score, get_threat_level
from .utils.whois_lookup import get_whois_info

class URLScanner:
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL using all available platforms"""
        scanners = [
            HybridAnalysisScanner(self.session, self.api_keys["hybrid_analysis"]),
            URLScanScanner(self.session, self.api_keys["urlscan"]),
            VirusTotalScanner(self.session, self.api_keys["virustotal"]),
            ScreenshotMachineScanner(self.session, self.api_keys["screenshot_machine"])
        ]

        # Run all scans concurrently
        scan_tasks = [scanner.scan(url) for scanner in scanners]
        results = await asyncio.gather(*scan_tasks)

        # Calculate scores (excluding Screenshot Machine which returns None)
        scores = [scanner.calculate_score(result) 
                 for scanner, result in zip(scanners, results)]
        
        # Get WHOIS information
        whois_info = await get_whois_info(url)

        # Calculate overall threat score (excluding None values from Screenshot Machine)
        overall_score = calculate_overall_threat_score([s for s in scores if s is not None])
        threat_level = get_threat_level(overall_score)

        # Extract screenshot path if available
        screenshot_info = results[3] if results[3].get("success") else None
        screenshot_path = screenshot_info.get("screenshot_path") if screenshot_info else None

        return {
            "url": url,
            "scan_date": datetime.utcnow().isoformat(),
            "overall_score": overall_score,
            "threat_level": threat_level,
            "platform_results": {
                "hybrid_analysis": results[0],
                "urlscan": results[1],
                "virustotal": results[2]
            },
            "screenshot": {
                "path": screenshot_path,
                "timestamp": screenshot_info.get("timestamp") if screenshot_info else None
            } if screenshot_path else None,
            "whois_info": whois_info
        }