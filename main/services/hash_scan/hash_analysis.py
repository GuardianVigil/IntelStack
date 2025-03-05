from typing import Dict, List, Optional
import asyncio
import logging
import json
from datetime import datetime
from django.contrib.auth.models import User
from .platforms.factory import PlatformFactory
from .utils.db import get_api_keys
from .utils.data_formatter_hash import format_platform_data, calculate_confidence_score

logger = logging.getLogger(__name__)

class HashAnalysisService:
    """Service for analyzing file hashes across multiple platforms."""

    def __init__(self, user: User = None):
        self.supported_platforms = PlatformFactory.get_supported_platforms()
        self.user = user

    async def analyze_hash(self, file_hash: str, platforms: Optional[List[str]] = None) -> Dict:
        """Analyze a file hash across multiple platforms."""
        try:
            # Define allowed platforms
            ALLOWED_PLATFORMS = ['virustotal', 'hybrid_analysis', 'malwarebazaar', 'metadefender', 'threatfox', 'filescan']
            
            # Get API keys for allowed platforms only
            api_keys = {k: v for k, v in (await get_api_keys()).items() if k in ALLOWED_PLATFORMS}
            
            results = {
                'hash': file_hash,
                'platforms': {},
                'file_info': {
                    'hash': file_hash,
                    'type': None,
                    'size': None,
                    'magic': None,
                    'mime_type': None,
                    'first_seen': None,
                    'last_seen': None
                },
                'threat_metrics': {
                    'threat_score': 0,
                    'confidence_score': 0,
                    'risk_level': 'Unknown',
                    'detection_rate': 0,
                    'verdict': 'Unknown'
                }
            }

            # Process each platform
            for platform, api_key in api_keys.items():
                if not api_key:
                    continue

                try:
                    platform_result = await self._analyze_platform(platform, api_key, file_hash)
                    
                    if platform_result:
                        # Format the platform data
                        formatted_result = format_platform_data(platform, platform_result)
                        results['platforms'][platform] = formatted_result
                        
                        # Log platform response for debugging
                        logger.debug(f"{platform.upper()} RESPONSE: {json.dumps(platform_result)}")
                        
                        # Extract file info from platform results
                        if platform == 'virustotal' and 'scan_results' in platform_result:
                            vt_results = platform_result['scan_results']
                            results['file_info'].update({
                                'type': vt_results.get('file_type'),
                                'size': vt_results.get('size'),
                                'first_seen': datetime.fromtimestamp(vt_results.get('first_seen', 0)).isoformat() if vt_results.get('first_seen') else None,
                                'last_seen': datetime.fromtimestamp(vt_results.get('last_seen', 0)).isoformat() if vt_results.get('last_seen') else None
                            })
                        elif platform == 'hybrid_analysis' and not results['file_info'].get('type'):
                            results['file_info'].update({
                                'type': platform_result.get('type'),
                                'size': platform_result.get('size'),
                                'first_seen': platform_result.get('submitted_at'),
                                'last_seen': platform_result.get('last_multi_scan')
                            })
                        elif platform == 'malwarebazaar' and 'data' in platform_result:
                            mb_data = platform_result['data'][0] if platform_result['data'] else {}
                            if not results['file_info'].get('type'):
                                results['file_info'].update({
                                    'type': mb_data.get('file_type'),
                                    'size': mb_data.get('file_size'),
                                    'first_seen': mb_data.get('first_seen'),
                                    'last_seen': mb_data.get('last_seen')
                                })
                
                except Exception as e:
                    results['platforms'][platform] = {'error': str(e)}
                    logger.error(f"{platform.upper()} ERROR: {str(e)}")

            # Calculate overall metrics
            self._calculate_overall_metrics(results)
            
            # Calculate confidence score
            results['threat_metrics']['confidence_score'] = calculate_confidence_score(results['platforms'])

            return results

        except Exception as e:
            logger.error(f"Error in analyze_hash: {str(e)}")
            raise

    async def _analyze_platform(self, platform: str, api_key: str, file_hash: str) -> Dict:
        """Analyze hash on a specific platform."""
        try:
            logger.info(f"Creating client for {platform}")
            client = await PlatformFactory.create_client(platform, api_key)
            if client:
                async with client:
                    logger.info(f"Analyzing hash on {platform}")
                    result = await client.analyze_hash(file_hash)
                    return result
            else:
                logger.error(f"Failed to create client for {platform}")
                return {"error": "Failed to create platform client"}

        except Exception as e:
            logger.error(f"Error in _analyze_platform for {platform}: {str(e)}")
            return {"error": str(e)}

    def _is_valid_hash(self, file_hash: str) -> bool:
        """
        Validate hash format (MD5, SHA-1, or SHA-256).
        
        Args:
            file_hash: Hash string to validate
            
        Returns:
            bool indicating if hash format is valid
        """
        hash_lengths = {
            32: 'MD5',
            40: 'SHA-1',
            64: 'SHA-256'
        }
        
        if not isinstance(file_hash, str):
            return False
            
        hash_length = len(file_hash)
        if hash_length not in hash_lengths:
            return False
            
        # Check if hash contains only valid hexadecimal characters
        try:
            int(file_hash, 16)
            return True
        except ValueError:
            return False

    def _calculate_overall_metrics(self, results: Dict) -> None:
        """Calculate overall threat metrics from all platform results."""
        threat_metrics = results['threat_metrics']
        platforms = results.get('platforms', {})
        
        total_detections = 0
        total_engines = 0
        platform_scores = []
        
        # Process VirusTotal results
        if 'virustotal' in platforms:
            vt_data = platforms['virustotal']
            if 'summary' in vt_data:
                total_scans = vt_data['summary'].get('total_scans', 0)
                malicious = vt_data['summary'].get('malicious', 0)
                if total_scans > 0:
                    detection_rate = (malicious / total_scans) * 100
                    platform_scores.append(detection_rate)
                    total_engines += total_scans
                    total_detections += malicious

        # Process Hybrid Analysis results
        if 'hybrid_analysis' in platforms:
            ha_data = platforms['hybrid_analysis']
            if 'summary' in ha_data:
                threat_score = ha_data['summary'].get('threat_score')
                if threat_score is not None:
                    platform_scores.append(threat_score)
                    if threat_score >= 50:
                        total_detections += 1
                    total_engines += 1

        # Process FileScan results
        if 'filescan' in platforms:
            fs_data = platforms['filescan']
            if 'summary' in fs_data:
                total = fs_data['summary'].get('total_engines', 0)
                detected = fs_data['summary'].get('total_detected', 0)
                if total > 0:
                    detection_rate = (detected / total) * 100
                    platform_scores.append(detection_rate)
                    total_engines += total
                    total_detections += detected

        # Calculate final scores
        if platform_scores:
            # Calculate threat score as weighted average of platform scores
            threat_metrics['threat_score'] = int(sum(platform_scores) / len(platform_scores))
            
            # Calculate overall detection rate
            threat_metrics['detection_rate'] = int((total_detections / total_engines * 100) if total_engines > 0 else 0)
            
            # Set risk level and verdict based on threat score
            if threat_metrics['threat_score'] >= 80:
                threat_metrics['risk_level'] = 'Critical'
                threat_metrics['verdict'] = 'Malicious'
            elif threat_metrics['threat_score'] >= 60:
                threat_metrics['risk_level'] = 'High'
                threat_metrics['verdict'] = 'Malicious'
            elif threat_metrics['threat_score'] >= 40:
                threat_metrics['risk_level'] = 'Medium'
                threat_metrics['verdict'] = 'Suspicious'
            elif threat_metrics['threat_score'] > 20:
                threat_metrics['risk_level'] = 'Low'
                threat_metrics['verdict'] = 'Suspicious'
            else:
                threat_metrics['risk_level'] = 'Safe'
                threat_metrics['verdict'] = 'Clean'

    def _calculate_threat_score(self, results: Dict) -> Dict:
        """Calculate overall threat metrics from all platform results."""
        threat_metrics = {
            "threat_score": 0,
            "confidence_score": 0,
            "risk_level": "unknown",
            "detection_rate": 0,
            "verdict": "unknown",
            "detection_stats": {
                "total": 0,
                "detected": 0,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0
            },
            "malware_families": set(),
            "classifications": set(),
            "threat_categories": set(),
            "severity_factors": []
        }

        platform_scores = []
        total_engines = 0

        # Process VirusTotal results
        if "virustotal" in results["platforms"]:
            vt_data = results["platforms"]["virustotal"].get("scan_results", {})
            if vt_data:
                # Process detection stats
                stats = vt_data.get("last_analysis_stats", {})
                threat_metrics["detection_stats"]["malicious"] += stats.get("malicious", 0)
                threat_metrics["detection_stats"]["suspicious"] += stats.get("suspicious", 0)
                threat_metrics["detection_stats"]["undetected"] += stats.get("undetected", 0)
                
                total = sum(stats.values()) if stats else 0
                if total > 0:
                    detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    platform_scores.append((detected / total) * 100)
                    total_engines += total

        # Process Hybrid Analysis results
        if "hybrid_analysis" in results["platforms"]:
            ha_data = results["platforms"]["hybrid_analysis"]
            if ha_data.get("verdict") == "malicious":
                threat_metrics["severity_factors"].append({
                    "type": "platform_verdict",
                    "platform": "hybrid_analysis",
                    "verdict": "malicious"
                })
                platform_scores.append(100)
            elif ha_data.get("verdict") == "suspicious":
                platform_scores.append(50)
            total_engines += 1

        # Process MalwareBazaar results
        if "malwarebazaar" in results["platforms"] and results["platforms"]["malwarebazaar"].get("data"):
            mb_data = results["platforms"]["malwarebazaar"]["data"][0]
            if mb_data.get("signature"):
                threat_metrics["malware_families"].add(mb_data["signature"])
            if mb_data.get("tags"):
                threat_metrics["threat_categories"].update(mb_data["tags"])
            platform_scores.append(100)  # If result exists, it's malicious
            total_engines += 1

        # Process ThreatFox results
        if "threatfox" in results["platforms"]:
            tf_data = results["platforms"]["threatfox"]
            if tf_data.get("found"):
                scan_results = tf_data.get("scan_results", {})
                if scan_results.get("total_matches", 0) > 0:
                    platform_scores.append(100)
                    if "matches" in scan_results:
                        for match in scan_results["matches"]:
                            if match.get("malware"):
                                threat_metrics["malware_families"].add(match["malware"])
                            if match.get("threat_type"):
                                threat_metrics["threat_categories"].add(match["threat_type"])
                total_engines += 1

        # Calculate final scores
        if platform_scores:
            threat_metrics["threat_score"] = int(sum(platform_scores) / len(platform_scores))
            threat_metrics["detection_rate"] = int((len([s for s in platform_scores if s > 50]) / len(platform_scores)) * 100)
            
            # Calculate confidence based on number of engines that analyzed the file
            max_expected_engines = 100  # Reasonable maximum number of engines
            threat_metrics["confidence_score"] = int(min((total_engines / max_expected_engines) * 100, 100))

        # Determine risk level
        if threat_metrics["threat_score"] >= 80:
            threat_metrics["risk_level"] = "Critical"
            threat_metrics["verdict"] = "Malicious"
        elif threat_metrics["threat_score"] >= 60:
            threat_metrics["risk_level"] = "High"
            threat_metrics["verdict"] = "Malicious"
        elif threat_metrics["threat_score"] >= 40:
            threat_metrics["risk_level"] = "Medium"
            threat_metrics["verdict"] = "Suspicious"
        elif threat_metrics["threat_score"] > 20:
            threat_metrics["risk_level"] = "Low"
            threat_metrics["verdict"] = "Suspicious"
        else:
            threat_metrics["risk_level"] = "Safe"
            threat_metrics["verdict"] = "Clean"

        # Convert sets to lists for JSON serialization
        threat_metrics["malware_families"] = list(threat_metrics["malware_families"])
        threat_metrics["classifications"] = list(threat_metrics["classifications"])
        threat_metrics["threat_categories"] = list(threat_metrics["threat_categories"])

        return threat_metrics
