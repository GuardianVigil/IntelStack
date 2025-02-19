"""
Screenshot Machine scanner implementation
"""
from typing import Dict, Any, Optional
import hashlib
import urllib.parse
from .base_scanner import BaseScanner
import os
from datetime import datetime

class ScreenshotMachineScanner(BaseScanner):
    def __init__(self, session, api_key, secret_phrase=""):
        super().__init__(session, api_key)
        self.secret_phrase = secret_phrase
        self.base_url = "https://api.screenshotmachine.com"
        
    def _generate_api_url(self, url: str, options: Dict[str, Any]) -> str:
        """Generate Screenshot Machine API URL with hash if secret phrase is provided"""
        api_url = f"{self.base_url}/?key={self.api_key}"
        
        if self.secret_phrase:
            api_url = api_url + "&hash=" + hashlib.md5(
                (url + self.secret_phrase).encode('utf-8')
            ).hexdigest()
            
        options["url"] = url
        api_url = api_url + "&" + urllib.parse.urlencode(options)
        return api_url

    async def scan(self, url: str) -> Dict[str, Any]:
        """Capture screenshot of the URL"""
        # Define screenshot options
        options = {
            "dimension": "1366x768",
            "device": "desktop",
            "format": "png",
            "cacheLimit": "0",
            "delay": "2000",
            "zoom": "100"
        }
        
        api_url = self._generate_api_url(url, options)
        
        # Create directory structure for screenshots
        timestamp = datetime.now().strftime("%Y-%m-%d")
        directory = f"storage/screenshots/{timestamp}"
        os.makedirs(directory, exist_ok=True)
        
        # Generate unique filename
        filename = f"{hashlib.md5(url.encode()).hexdigest()}.png"
        filepath = f"{directory}/{filename}"
        
        try:
            # Download screenshot
            async with self.session.get(api_url) as response:
                if response.status == 200:
                    with open(filepath, 'wb') as f:
                        f.write(await response.read())
                    
                    return {
                        "success": True,
                        "screenshot_path": filepath,
                        "url": url,
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Failed to capture screenshot: {response.status}",
                        "url": url
                    }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "url": url
            }

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Screenshot Machine doesn't provide a threat score"""
        return None