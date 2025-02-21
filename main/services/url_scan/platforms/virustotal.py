"""
VirusTotal scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner
import base64
import asyncio
import logging
import re

logger = logging.getLogger(__name__)

class VirusTotalScanner(BaseScanner):
    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def scan(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            # Step 1: Submit URL for scanning
            headers = {
                "x-apikey": self.api_key,
                "content-type": "application/x-www-form-urlencoded",
                "accept": "application/json"
            }
            
            # Submit URL for analysis
            submit_response = await self._make_request(
                "POST", 
                f"{self.base_url}/urls",
                headers=headers,
                form={"url": url}
            )
            
            if "data" not in submit_response:
                return {"error": "Failed to submit URL for scanning"}
            
            analysis_id = submit_response["data"]["id"]
            logger.info(f"VirusTotal scan submitted with ID: {analysis_id}")
            
            # Step 2: Poll for analysis results
            await asyncio.sleep(15)  # Initial wait
            
            max_attempts = 12  # Total timeout: 15s initial + (12 * 15s) = 195s
            for attempt in range(max_attempts):
                try:
                    analysis_result = await self._make_request(
                        "GET",
                        f"{self.base_url}/analyses/{analysis_id}",
                        headers=headers
                    )
                    
                    if "data" in analysis_result:
                        status = analysis_result["data"]["attributes"]["status"]
                        if status == "completed":
                            # Step 3: Get the final URL report
                            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                            result = await self._make_request(
                                "GET", 
                                f"{self.base_url}/urls/{url_id}",
                                headers=headers
                            )
                            
                            if "data" in result:
                                return self._structure_results(result["data"])
                            return {"error": "Failed to get URL report"}
                            
                    logger.info(f"VirusTotal analysis not ready (attempt {attempt + 1}/{max_attempts}), waiting 15 seconds...")
                    await asyncio.sleep(15)
                    
                except Exception as e:
                    logger.warning(f"Error polling VirusTotal (attempt {attempt + 1}/{max_attempts}): {str(e)}")
                    await asyncio.sleep(15)
                    continue
            
            return {"error": "Scan timeout - results not available within 195 seconds"}
            
        except Exception as e:
            logger.error(f"Error in VirusTotal scan: {str(e)}")
            return {"error": str(e)}

    def _structure_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Structure the raw API response into a table-friendly format"""
        try:
            if not isinstance(data, dict):
                return {"error": "Invalid response from VirusTotal"}

            attributes = data.get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            # Get domain info
            whois_data = attributes.get("whois", "")
            registrar = None
            creation_date = None
            updated_date = None
            
            # Parse WHOIS data if available
            if whois_data:
                # Try to extract registrar and dates from WHOIS
                registrar_match = re.search(r"Registrar:\s*(.+?)(?:\n|$)", whois_data)
                created_match = re.search(r"Creation Date:\s*(.+?)(?:\n|$)", whois_data)
                updated_match = re.search(r"Updated Date:\s*(.+?)(?:\n|$)", whois_data)
                
                registrar = registrar_match.group(1) if registrar_match else None
                creation_date = created_match.group(1) if created_match else None
                updated_date = updated_match.group(1) if updated_match else None

            # Structure domain info
            domain_info = {
                "domain": attributes.get("id", ""),
                "apex_domain": attributes.get("tld", ""),
                "ip_addresses": [record.get("value") for record in attributes.get("last_dns_records", []) if record.get("type") in ["A", "AAAA"]],
                "asn": attributes.get("as_owner", ""),
                "countries": [attributes.get("country", "")] if attributes.get("country") else [],
                "server": attributes.get("last_http_server", ""),
                "last_analysis": attributes.get("last_analysis_date", ""),
                "registrar": registrar or attributes.get("registrar", ""),
                "created_date": creation_date or attributes.get("creation_date", ""),
                "updated_date": updated_date or attributes.get("last_update_date", ""),
                "ssl_info": attributes.get("last_https_certificate", {}),
                "redirects": attributes.get("last_redirects", [])
            }

            # Get all analysis results
            analysis_results = []
            for engine, result in attributes.get("last_analysis_results", {}).items():
                analysis_results.append({
                    "engine_name": engine,
                    "category": result.get("category", "N/A"),
                    "result": result.get("result", "N/A"),
                    "method": result.get("method", "N/A")
                })

            # Calculate total detections
            total_detections = last_analysis_stats.get("malicious", 0)
            total_engines = sum(last_analysis_stats.values())

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
                "domain_info": domain_info,
                "analysis_summary": {
                    "harmless": last_analysis_stats.get("harmless", 0),
                    "malicious": last_analysis_stats.get("malicious", 0),
                    "suspicious": last_analysis_stats.get("suspicious", 0),
                    "undetected": last_analysis_stats.get("undetected", 0),
                    "timeout": last_analysis_stats.get("timeout", 0)
                },
                "analysis_results": analysis_results,
                "categories": attributes.get("categories", {}),
                "tags": attributes.get("tags", []),
                "total_votes": {
                    "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                },
                "reputation": attributes.get("reputation", 0),
                "score": self.calculate_score(data)
            }
        except Exception as e:
            logger.error(f"Error in _structure_results: {str(e)}")
            return {"error": f"Failed to structure results: {str(e)}"}

    def calculate_score(self, data: Dict[str, Any]) -> float:
        """Calculate threat score from VirusTotal results"""
        try:
            attributes = data.get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            
            # Get detection counts
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            total_scans = sum(last_analysis_stats.values())
            
            if total_scans == 0:
                return 0.0
            
            # Base score from detections
            detection_score = ((malicious * 100) + (suspicious * 50)) / total_scans
            
            # Add points for reputation
            reputation = attributes.get("reputation", 0)
            reputation_score = abs(min(reputation, 0)) * 2  # Negative reputation increases score
            
            # Add points for malicious votes
            total_votes = attributes.get("total_votes", {})
            malicious_votes = total_votes.get("malicious", 0)
            total_votes_count = malicious_votes + total_votes.get("harmless", 0)
            if total_votes_count > 0:
                vote_score = (malicious_votes * 100) / total_votes_count
            else:
                vote_score = 0
            
            # Add points for malicious tags
            malicious_tags = sum(1 for tag in attributes.get("tags", [])
                               if any(keyword in tag.lower() 
                                    for keyword in ["malicious", "phishing", "malware", "spam"]))
            tag_score = malicious_tags * 10
            
            # Calculate final score
            final_score = (detection_score * 0.4 +  # 40% weight for detections
                         reputation_score * 0.3 +   # 30% weight for reputation
                         vote_score * 0.2 +         # 20% weight for votes
                         tag_score * 0.1)           # 10% weight for tags
            
            return round(min(100.0, max(0.0, final_score)), 2)
            
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