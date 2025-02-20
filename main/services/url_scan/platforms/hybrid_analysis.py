"""
Hybrid Analysis scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner
import asyncio
import logging

logger = logging.getLogger(__name__)

class HybridAnalysisScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    def _structure_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Structure the raw API response into a table-friendly format"""
        try:
            if not isinstance(data, dict):
                return {"error": "Invalid response from Hybrid Analysis"}

            # Helper function to safely convert to float
            def safe_float(value, default=0.0):
                try:
                    if not value:  # Handle empty string, None, etc.
                        return default
                    return float(value)
                except (ValueError, TypeError):
                    return default

            return {
                "summary": {
                    "threat_score": safe_float(data.get("threat_score", 0)),
                    "verdict": str(data.get("verdict", "N/A")),
                    "threat_level": str(data.get("threat_level", "N/A")),
                    "environment_id": str(data.get("environment_id", "N/A")),
                    "submission_type": str(data.get("submission_type", "N/A"))
                },
                "analysis": {
                    "type": str(data.get("type", "N/A")),
                    "vx_family": str(data.get("vx_family", "N/A")),
                    "process_count": int(data.get("process_count", 0)),
                    "total_network_connections": int(data.get("total_network_connections", 0)),
                    "total_processes": int(data.get("total_processes", 0)),
                    "total_signatures": int(data.get("total_signatures", 0))
                },
                "classification_tags": data.get("classification_tags", []),
                "compromised_hosts": data.get("compromised_hosts", []),
                "hosts": data.get("hosts", []),
                "domains": data.get("domains", []),
                "score": self.calculate_score(data)
            }
        except Exception as e:
            logger.error(f"Error in _structure_results: {str(e)}")
            return {"error": f"Failed to structure results: {str(e)}"}

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            headers = {
                "api-key": self.api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = {"url": url, "environment_id": 160}
            
            submit_response = await self._make_request("POST", f"{self.base_url}/submit/url", 
                                                     headers=headers, data=data)
            
            if "job_id" in submit_response:
                # Poll for results
                job_id = submit_response["job_id"]
                for _ in range(20):
                    result = await self._make_request("GET", 
                        f"{self.base_url}/report/{job_id}/summary",
                        headers={"api-key": self.api_key})
                    
                    if result.get("state") == "SUCCESS":
                        return self._structure_results(result)
                    await asyncio.sleep(10)
                    
                return {"error": "Scan timeout"}
                
            return {"error": "Failed to initiate scan"}
            
        except Exception as e:
            logger.error(f"Error in Hybrid Analysis scan: {str(e)}")
            return {"error": str(e)}

    def calculate_score(self, data: Dict[str, Any]) -> float:
        """Calculate threat score from scan data"""
        try:
            if not isinstance(data, dict):
                return 0.0
            
            # Helper function to safely convert to float
            def safe_float(value, default=0.0):
                try:
                    if not value:  # Handle empty string, None, etc.
                        return default
                    return float(value)
                except (ValueError, TypeError):
                    return default
            
            # Base score on threat_score if available
            threat_score = safe_float(data.get("threat_score", 0))
            if threat_score > 0:
                return threat_score
            
            # Calculate score based on other factors
            score = 0.0
            
            # Check verdict
            verdict = str(data.get("verdict", "")).lower()
            if verdict in ["malicious", "suspicious"]:
                score += 50
            
            # Check threat level
            threat_level = str(data.get("threat_level", "")).lower()
            if threat_level == "high":
                score += 30
            elif threat_level == "medium":
                score += 15
            
            # Add points for suspicious indicators
            score += len(data.get("classification_tags", [])) * 5
            score += len(data.get("compromised_hosts", [])) * 10
            
            return min(score, 100)  # Cap at 100
            
        except Exception as e:
            logger.error(f"Error calculating score: {str(e)}")
            return 0.0