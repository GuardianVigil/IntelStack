import os
import json
import time
import logging
import requests
from datetime import datetime
from typing import Dict, Any, Optional

# Set up logging
logger = logging.getLogger(__name__)

class SandboxAnalyzer:
    def __init__(self, api_key: str, debug_output_dir: str):
        """Initialize the SandboxAnalyzer with VirusTotal API key and debug output directory."""
        self.api_key = api_key
        self.api_url = "https://www.virustotal.com/api/v3"
        self.debug_output_dir = debug_output_dir
        self.headers = {"x-apikey": self.api_key}
        
        # Ensure debug directory exists
        os.makedirs(self.debug_output_dir, exist_ok=True)
        logger.info(f"SandboxAnalyzer initialized with debug output dir: {debug_output_dir}")

    def _save_debug_output(self, data: Dict[str, Any], prefix: str = "virustotal") -> None:
        """Save debug output to a file."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{prefix}_debug_{timestamp}.txt"
            filepath = os.path.join(self.debug_output_dir, filename)
            
            os.makedirs(self.debug_output_dir, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            
            logger.info(f"Debug output saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save debug output: {str(e)}")

    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload a file to VirusTotal and return the analysis ID."""
        try:
            logger.info(f"Uploading file: {file_path}")
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                response = requests.post(
                    f"{self.api_url}/files",
                    files=files,
                    headers=self.headers
                )
                response.raise_for_status()
                data = response.json()
                self._save_debug_output(data, "upload")
                logger.info(f"File uploaded successfully. Analysis ID: {data['data']['id']}")
                return data["data"]["id"]
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error during upload: {str(e)}")
            self._save_debug_output({"error": str(e), "type": "request_error"}, "upload_error")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during upload: {str(e)}")
            self._save_debug_output({"error": str(e), "type": "unexpected_error"}, "upload_error")
            return None

    def get_analysis_report(self, analysis_id: str, max_attempts: int = 20, wait_time: int = 30) -> Optional[Dict]:
        """Get the analysis report from VirusTotal, waiting for completion.
        
        Args:
            analysis_id: The ID of the analysis to retrieve
            max_attempts: Maximum number of attempts to fetch the report (default: 20)
            wait_time: Time to wait between attempts in seconds (default: 30)
        """
        logger.info(f"Getting analysis report for ID: {analysis_id}")
        for attempt in range(max_attempts):
            try:
                logger.info(f"Attempt {attempt + 1}/{max_attempts} to get analysis report")
                response = requests.get(
                    f"{self.api_url}/analyses/{analysis_id}",
                    headers=self.headers
                )
                response.raise_for_status()
                data = response.json()
                
                self._save_debug_output(data, f"analysis_attempt_{attempt + 1}")
                
                status = data["data"]["attributes"]["status"]
                logger.info(f"Analysis status: {status}")
                
                if status == "completed":
                    logger.info("Analysis completed successfully")
                    return data
                
                if attempt < max_attempts - 1:
                    logger.info(f"Analysis not complete yet. Waiting {wait_time} seconds before next attempt...")
                    time.sleep(wait_time)
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"API request error during analysis: {str(e)}")
                self._save_debug_output({"error": str(e), "type": "request_error"}, f"analysis_error_{attempt + 1}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error during analysis: {str(e)}")
                self._save_debug_output({"error": str(e), "type": "unexpected_error"}, f"analysis_error_{attempt + 1}")
                return None
                
        logger.warning(f"Analysis did not complete after {max_attempts} attempts")
        return None

    def get_behavior_summary(self, file_id: str) -> Optional[Dict]:
        """Get behavior summary for a file."""
        try:
            logger.info(f"Getting behavior summary for file ID: {file_id}")
            response = requests.get(
                f"{self.api_url}/files/{file_id}/behaviour_summary",
                headers=self.headers
            )
            response.raise_for_status()
            data = response.json()
            self._save_debug_output(data, "behavior")
            logger.info("Behavior summary retrieved successfully")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error during behavior summary: {str(e)}")
            self._save_debug_output({"error": str(e), "type": "request_error"}, "behavior_error")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during behavior summary: {str(e)}")
            self._save_debug_output({"error": str(e), "type": "unexpected_error"}, "behavior_error")
            return None

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Main method to analyze a file and return results."""
        logger.info(f"Starting analysis for file: {file_path}")
        results = {
            "success": False,
            "error": None,
            "results": None
        }

        # Upload file
        analysis_id = self.upload_file(file_path)
        if not analysis_id:
            error_msg = "Failed to upload file to VirusTotal"
            logger.error(error_msg)
            results["error"] = error_msg
            return results

        # Get analysis report
        report = self.get_analysis_report(analysis_id)
        if not report:
            error_msg = "Failed to get analysis report from VirusTotal"
            logger.error(error_msg)
            results["error"] = error_msg
            return results

        # Get file ID (SHA256) from the report
        try:
            file_id = report["meta"]["file_info"]["sha256"]
            logger.info(f"File ID (SHA256): {file_id}")
        except (KeyError, TypeError) as e:
            error_msg = f"Failed to get file ID from report: {str(e)}"
            logger.error(error_msg)
            results["error"] = error_msg
            return results

        # Get behavior summary
        behavior = self.get_behavior_summary(file_id)
        if not behavior:
            # Continue even if behavior summary fails, just log the error
            logger.warning("Failed to get behavior summary, continuing with partial results")
            behavior = {"data": {"attributes": {}}}

        # Prepare final results
        try:
            results["success"] = True
            results["results"] = {
                "summary": {
                    "threat_score": self._calculate_threat_score(report),
                    "stats": self._extract_detection_stats(report)
                },
                "file_info": {
                    "type": report["meta"]["file_info"].get("type", "Unknown"),
                    "size": report["meta"]["file_info"].get("size", 0),
                    "hashes": {
                        "sha256": file_id,
                        "sha1": report["meta"]["file_info"].get("sha1", ""),
                        "md5": report["meta"]["file_info"].get("md5", "")
                    }
                },
                "behavior": behavior.get("data", {}).get("attributes", {}),
                "scan_results": report["data"]["attributes"].get("results", {})
            }
            
            # Save the final results for debugging
            self._save_debug_output(results, "final_results")
            logger.info("Analysis completed successfully")
            
            return results
        except Exception as e:
            error_msg = f"Error preparing final results: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["error"] = error_msg
            return results

    def _calculate_threat_score(self, report: Dict) -> int:
        """Calculate a threat score based on detection ratio."""
        try:
            stats = report["data"]["attributes"]["stats"]
            total = stats["malicious"] + stats["undetected"]
            if total == 0:
                return 0
            return int((stats["malicious"] / total) * 100)
        except (KeyError, TypeError, ZeroDivisionError) as e:
            logger.warning(f"Error calculating threat score: {str(e)}")
            return 0

    def _extract_detection_stats(self, report: Dict) -> Dict:
        """Extract detection statistics from the report."""
        try:
            return report["data"]["attributes"]["stats"]
        except (KeyError, TypeError) as e:
            logger.warning(f"Error extracting detection stats: {str(e)}")
            return {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "timeout": 0
            }
