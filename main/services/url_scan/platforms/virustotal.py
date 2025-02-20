"""
VirusTotal scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner
import base64
import asyncio
import logging

logger = logging.getLogger(__name__)

class VirusTotalScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    def _structure_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Structure the raw API response into a table-friendly format"""
        try:
            if not isinstance(data, dict):
                return {"error": "Invalid response from VirusTotal"}

            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            # Clean up analysis results
            clean_results = {}
            for engine, result in results.items():
                if engine is not None and isinstance(result, dict):
                    clean_results[str(engine)] = {
                        "category": str(result.get("category", "N/A")),
                        "result": str(result.get("result", "N/A")),
                        "method": str(result.get("method", "N/A"))
                    }
            
            return {
                "basic_info": {
                    "id": str(data.get("id", "N/A")),
                    "type": str(data.get("type", "N/A")),
                    "status": str(attributes.get("status", "N/A")),
                    "reputation": int(attributes.get("reputation", 0)),
                    "times_submitted": int(attributes.get("times_submitted", 0)),
                    "first_submission_date": str(attributes.get("first_submission_date", "N/A")),
                    "last_analysis_date": str(attributes.get("last_analysis_date", "N/A"))
                },
                "analysis_stats": {
                    "harmless": int(stats.get("harmless", 0)),
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "undetected": int(stats.get("undetected", 0)),
                    "timeout": int(stats.get("timeout", 0))
                },
                "analysis_results": clean_results,
                "score": self.calculate_score(data)
            }
        except Exception as e:
            logger.error(f"Error in _structure_results: {str(e)}")
            return {"error": f"Failed to structure results: {str(e)}"}

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            headers = {
                "x-apikey": self.api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # First, get the URL ID
            url_id = await self._get_url_id(url)
            if not url_id:
                return {"error": "Failed to get URL ID"}
            
            # Get analysis results
            result = await self._make_request("GET", 
                f"{self.base_url}/urls/{url_id}",
                headers=headers)
            
            if "data" in result:
                return self._structure_results(result["data"])
            return {"error": "Failed to get analysis results"}
            
        except Exception as e:
            logger.error(f"Error in VirusTotal scan: {str(e)}")
            return {"error": str(e)}

    async def _get_url_id(self, url: str) -> Optional[str]:
        """Get URL identifier from VirusTotal"""
        try:
            headers = {
                "x-apikey": self.api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # Submit URL for analysis
            response = await self._make_request("POST", 
                f"{self.base_url}/urls",
                headers=headers,
                form={"url": url})  # Use form instead of data
            
            if "data" in response:
                # Extract URL ID from response
                url_id = response["data"]["id"]
                # Convert to base64 for API endpoint
                return url_id
            return None
            
        except Exception as e:
            logger.error(f"Error getting URL ID: {str(e)}")
            return None

    def calculate_score(self, data: Dict[str, Any]) -> float:
        """Calculate threat score from scan data"""
        try:
            if not isinstance(data, dict):
                return 0.0
            
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            if not stats:
                return 0.0
            
            # Calculate score based on analysis stats
            total_scans = sum(stats.values())
            if total_scans == 0:
                return 0.0
            
            # Weight different categories
            weights = {
                "malicious": 1.0,
                "suspicious": 0.5,
                "timeout": 0.1,
                "harmless": 0.0,
                "undetected": 0.0
            }
            
            weighted_score = 0.0
            for category, weight in weights.items():
                count = stats.get(category, 0)
                weighted_score += (count / total_scans) * weight * 100
            
            # Add reputation factor
            reputation = attributes.get("reputation", 0)
            reputation_factor = max(0, min(20, abs(reputation)))  # Cap at 20 points
            if reputation < 0:
                weighted_score += reputation_factor
            else:
                weighted_score -= reputation_factor
            
            return min(max(weighted_score, 0), 100)  # Keep between 0 and 100
            
        except Exception as e:
            logger.error(f"Error calculating score: {str(e)}")
            return 0.0

    def extract_categories(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract categories and tags from results"""
        if not isinstance(data, dict) or "data" not in data:
            return {}
            
        attributes = data.get("data", {}).get("attributes", {})
        return {
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "times_submitted": attributes.get("times_submitted"),
            "reputation": attributes.get("reputation")
        }