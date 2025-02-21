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

            # Extract domains and hosts
            domains = data.get("domains", [])
            hosts = data.get("hosts", [])
            compromised_hosts = data.get("compromised_hosts", [])

            # Get process and network info
            total_processes = data.get("total_processes", 0)
            total_network_connections = data.get("total_network_connections", 0)
            total_signatures = data.get("total_signatures", 0)

            # Get submission info
            submissions = data.get("submissions", [])
            submission_info = submissions[0] if submissions else {}

            # Get environment info
            environment_id = data.get("environment_id")
            environment_description = data.get("environment_description", "Unknown")

            return {
                "basic_info": {
                    "environment": f"{environment_description} (ID: {environment_id})" if environment_id else "Unknown",
                    "analysis_time": data.get("analysis_start_time", "N/A"),
                    "verdict": data.get("verdict", "Unknown"),
                    "submission_type": "URL Analysis" if data.get("url_analysis") else "File Analysis"
                },
                "network_info": {
                    "total_processes": total_processes,
                    "total_network_connections": total_network_connections,
                    "total_signatures": total_signatures,
                    "domains": domains,
                    "hosts": hosts,
                    "compromised_hosts": compromised_hosts
                },
                "submission_details": {
                    "url": submission_info.get("url", "N/A"),
                    "submitted_at": submission_info.get("created_at", "N/A")
                },
                "threat_info": {
                    "threat_score": self.calculate_score(data),
                    "threat_level": data.get("threat_level", 0),
                    "verdict": data.get("verdict", "Unknown"),
                    "vx_family": data.get("vx_family", "None"),
                    "tags": data.get("tags", []),
                    "classification_tags": data.get("classification_tags", [])
                }
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
        """Calculate threat score from Hybrid Analysis results"""
        try:
            # Get threat level and verdict
            threat_level = data.get("threat_level", 0)
            verdict = data.get("verdict", "").lower()
            
            # Count malicious indicators
            malicious_tags = sum(1 for tag in data.get("tags", []) 
                               if "malicious" in tag.lower())
            classification_tags = len(data.get("classification_tags", []))
            compromised_hosts = len(data.get("compromised_hosts", []))
            
            # Base score from threat level (0-100)
            base_score = threat_level * 20  # Convert 0-5 scale to 0-100
            
            # Add points for malicious indicators
            score = base_score
            score += malicious_tags * 10  # +10 points per malicious tag
            score += classification_tags * 5  # +5 points per classification tag
            score += compromised_hosts * 15  # +15 points per compromised host
            
            # Adjust based on verdict
            if "malicious" in verdict:
                score += 30
            elif "suspicious" in verdict:
                score += 15
                
            # Ensure score is between 0 and 100
            return round(max(0.0, min(100.0, score)), 2)
            
        except Exception as e:
            logger.error(f"Error calculating score: {str(e)}")
            return 0.0