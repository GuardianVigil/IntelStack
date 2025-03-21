import os
import json
import time
import logging
import requests
from typing import Dict, Any, Optional

# Set up logging
logger = logging.getLogger(__name__)

class SandboxAnalyzer:
    def __init__(self, api_key: str):
        """Initialize the SandboxAnalyzer with VirusTotal API key."""
        self.api_key = api_key
        self.api_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        
        logger.info("SandboxAnalyzer initialized")

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
                logger.info(f"File uploaded successfully. Analysis ID: {data['data']['id']}")
                return data["data"]["id"]
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error during upload: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during upload: {str(e)}")
            return None

    def get_analysis_report(self, analysis_id: str, max_attempts: int = 20, wait_time: int = 30) -> Optional[Dict]:
        """Get the analysis report from VirusTotal, waiting for completion."""
        logger.info(f"Getting analysis report for ID: {analysis_id}")
        
        for attempt in range(max_attempts):
            try:
                logger.info(f"Attempt {attempt + 1}/{max_attempts} to get analysis report")
                response = requests.get(
                    f"{self.api_url}/analyses/{analysis_id}",
                    headers=self.headers
                )
                
                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', wait_time))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                    
                response.raise_for_status()
                data = response.json()
                
                # Validate response structure
                if not isinstance(data, dict) or "data" not in data:
                    logger.error("Invalid response format from VirusTotal")
                    time.sleep(wait_time)
                    continue
                
                status = data["data"]["attributes"]["status"]
                logger.info(f"Analysis status: {status}")
                
                if status == "completed":
                    logger.info("Analysis completed successfully")
                    return data
                elif status == "queued" or status == "in-progress":
                    logger.info(f"Analysis {status}, waiting...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Unexpected analysis status: {status}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"API request error during analysis: {str(e)}")
                time.sleep(wait_time)
                continue
            except Exception as e:
                logger.error(f"Unexpected error during analysis: {str(e)}")
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
            logger.info("Behavior summary retrieved successfully")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error during behavior summary: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during behavior summary: {str(e)}")
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
            behavior = {"data": {}}

        # Prepare final results
        try:
            results["success"] = True
            
            # Initialize processed behavior data structure
            processed_behavior = {
                "processes": [],
                "network_http": [],
                "files": [],
                "registry": [],
                "mitre_attack": []
            }
            
            # Extract MITRE ATT&CK techniques
            try:
                if "mitre_attack_techniques" in behavior.get("data", {}):
                    processed_behavior["mitre_attack"] = behavior["data"]["mitre_attack_techniques"]
            except Exception as e:
                logger.error(f"Error extracting MITRE ATT&CK data: {str(e)}")
            
            # Extract file operations
            if "files_written" in behavior.get("data", {}):
                for file_path in behavior["data"]["files_written"]:
                    processed_behavior["files"].append({
                        "path": file_path,
                        "operation": "write"
                    })
            
            if "files_deleted" in behavior.get("data", {}):
                for file_path in behavior["data"]["files_deleted"]:
                    processed_behavior["files"].append({
                        "path": file_path,
                        "operation": "delete"
                    })
            
            # Extract registry operations
            if "registry_keys_opened" in behavior.get("data", {}):
                for reg_key in behavior["data"]["registry_keys_opened"]:
                    processed_behavior["registry"].append({
                        "key": reg_key,
                        "operation": "open",
                        "value": ""
                    })
            
            # Extract network operations
            if "ip_traffic" in behavior.get("data", {}):
                for traffic in behavior["data"]["ip_traffic"]:
                    processed_behavior["network_http"].append({
                        "url": f"{traffic.get('destination_ip')}:{traffic.get('destination_port')}",
                        "method": traffic.get('transport_layer_protocol', 'Unknown'),
                        "host": traffic.get('destination_ip', '')
                    })
            
            # Extract process information
            if "processes_created" in behavior.get("data", {}):
                for i, cmd in enumerate(behavior["data"]["processes_created"]):
                    processed_behavior["processes"].append({
                        "pid": i + 1000,  # Generate a fake PID since we don't have the actual one
                        "name": cmd.split('/')[-1] if '/' in cmd else cmd.split('\\')[-1] if '\\' in cmd else cmd,
                        "command_line": cmd
                    })
            elif "processes_tree" in behavior.get("data", {}):
                for process in behavior["data"]["processes_tree"]:
                    processed_behavior["processes"].append({
                        "pid": process.get("process_id", "Unknown"),
                        "name": process.get("name", "").replace('"', ''),
                        "command_line": process.get("name", "")
                    })
            
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
                "behavior": processed_behavior,
                "scan_results": report["data"]["attributes"].get("results", {})
            }
            
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