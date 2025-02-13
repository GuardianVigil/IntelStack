from typing import Dict, List, Optional
import asyncio
import logging
from datetime import datetime
from django.contrib.auth.models import User
from .platforms.factory import PlatformFactory
from .utils.db import get_api_keys

logger = logging.getLogger(__name__)

class HashAnalysisService:
    """Service for analyzing file hashes across multiple platforms."""

    def __init__(self, user: User = None):
        self.supported_platforms = PlatformFactory.get_supported_platforms()
        self.user = user

    async def analyze_hash(self, file_hash: str, platforms: Optional[List[str]] = None) -> Dict:
        """
        Analyze a file hash across multiple platforms.
        
        Args:
            file_hash: The hash to analyze
            platforms: Optional list of specific platforms to check. If None, checks all platforms.
            
        Returns:
            Dict containing analysis results from each platform
        """
        try:
            # Get API keys for all platforms
            api_keys = await get_api_keys()
            
            if not api_keys:
                raise ValueError("No API keys available")

            # Initialize results
            results = {
                'hash': file_hash,
                'platforms': {},
                'sigma_score': 0,
                'total_detections': 0
            }

            # Process each platform
            for platform, api_key in api_keys.items():
                if platforms and platform not in platforms:
                    continue
                    
                if not api_key:
                    logger.warning(f"No API key available for {platform}")
                    continue

                try:
                    platform_result = await self._analyze_platform(platform, api_key, file_hash)
                    if platform_result:
                        results['platforms'][platform] = platform_result
                        results['total_detections'] += platform_result.get('detections', 0)
                        results['sigma_score'] += platform_result.get('score', 0)
                except Exception as e:
                    logger.error(f"Error analyzing hash on {platform}: {str(e)}")
                    results['platforms'][platform] = {'error': str(e)}

            # Calculate final sigma score
            platform_count = len([p for p in results['platforms'].values() if 'error' not in p])
            if platform_count > 0:
                results['sigma_score'] = results['sigma_score'] / platform_count

            return results

        except Exception as e:
            logger.error(f"Error in analyze_hash: {str(e)}")
            raise

    async def _analyze_platform(self, platform: str, api_key: str, file_hash: str) -> Dict:
        """Analyze hash on a specific platform and handle errors."""
        try:
            client = await PlatformFactory.create_client(platform, api_key)
            if client:
                async with client:
                    result = await client.analyze_hash(file_hash)
                    return result
        except Exception as e:
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

    def _calculate_threat_score(self, results: Dict) -> Dict:
        """Calculate overall threat metrics from all platform results."""
        threat_metrics = {
            "threat_score": 0,
            "confidence_score": 0,
            "risk_level": "unknown",
            "malware_families": set(),
            "detection_stats": {
                "total": 0,
                "detected": 0,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0
            },
            "classifications": set(),
            "first_seen": None,
            "last_seen": None,
            "threat_categories": set(),
            "severity_factors": []
        }

        # Process VirusTotal results
        if "virustotal" in results["platforms"]:
            vt_data = results["platforms"]["virustotal"]
            if "scan_results" in vt_data:
                # Process detection stats
                stats = vt_data["scan_results"].get("last_analysis_stats", {})
                threat_metrics["detection_stats"]["malicious"] += stats.get("malicious", 0)
                threat_metrics["detection_stats"]["suspicious"] += stats.get("suspicious", 0)
                threat_metrics["detection_stats"]["undetected"] += stats.get("undetected", 0)
                threat_metrics["detection_stats"]["total"] = sum(stats.values())
                threat_metrics["detection_stats"]["detected"] = stats.get("malicious", 0) + stats.get("suspicious", 0)

                # Process sandbox verdicts
                sandbox_score = 0
                sandbox_confidence = 0
                sandbox_count = 0
                
                if "sandbox_verdicts" in vt_data["scan_results"]:
                    for verdict in vt_data["scan_results"]["sandbox_verdicts"].values():
                        sandbox_count += 1
                        if verdict.get("category") == "malicious":
                            sandbox_score += 100
                            if "confidence" in verdict:
                                sandbox_confidence += verdict["confidence"]
                        
                        if "malware_classification" in verdict:
                            threat_metrics["classifications"].update(verdict["malware_classification"])
                            threat_metrics["threat_categories"].update(
                                [c.lower() for c in verdict["malware_classification"]]
                            )
                        
                        if "malware_names" in verdict:
                            threat_metrics["malware_families"].update(verdict["malware_names"])

                # Calculate sandbox impact
                if sandbox_count > 0:
                    sandbox_score = sandbox_score / sandbox_count
                    sandbox_confidence = sandbox_confidence / sandbox_count

                # Process sigma rules if available
                sigma_score = 0
                if "sigma_analysis_results" in vt_data["scan_results"]:
                    sigma_rules = vt_data["scan_results"]["sigma_analysis_results"]
                    rule_weights = {"critical": 100, "high": 75, "medium": 50, "low": 25}
                    
                    for rule in sigma_rules:
                        rule_level = rule.get("rule_level", "").lower()
                        if rule_level in rule_weights:
                            sigma_score += rule_weights[rule_level]
                            threat_metrics["severity_factors"].append({
                                "type": "sigma_rule",
                                "level": rule_level,
                                "description": rule.get("rule_title", "Unknown rule")
                            })

        # Process MalwareBazaar results
        if "malwarebazaar" in results["platforms"]:
            mb_data = results["platforms"]["malwarebazaar"]
            if "data" in mb_data and len(mb_data["data"]) > 0:
                mb_result = mb_data["data"][0]
                
                # Process vendor intelligence
                if "vendor_intel" in mb_result:
                    for vendor, intel in mb_result["vendor_intel"].items():
                        if isinstance(intel, list):
                            for item in intel:
                                if "malware_family" in item and item["malware_family"]:
                                    threat_metrics["malware_families"].add(item["malware_family"])
                                if "verdict" in item:
                                    threat_metrics["threat_categories"].add(item["verdict"].lower())
                        elif isinstance(intel, dict):
                            if "malware_family" in intel and intel["malware_family"]:
                                threat_metrics["malware_families"].add(intel["malware_family"])
                            if "score" in intel:
                                try:
                                    score = float(intel["score"])
                                    threat_metrics["severity_factors"].append({
                                        "type": "vendor_score",
                                        "vendor": vendor,
                                        "score": score
                                    })
                                except (ValueError, TypeError):
                                    pass

        # Calculate weighted threat score (0-100)
        weights = {
            "detection_ratio": 0.4,    # 40% weight for detection ratio
            "sandbox_verdict": 0.3,     # 30% weight for sandbox analysis
            "sigma_rules": 0.2,        # 20% weight for sigma rules
            "vendor_intel": 0.1        # 10% weight for vendor intelligence
        }

        # 1. Detection ratio score
        detection_score = 0
        if threat_metrics["detection_stats"]["total"] > 0:
            detection_ratio = threat_metrics["detection_stats"]["detected"] / threat_metrics["detection_stats"]["total"]
            detection_score = detection_ratio * 100

        # 2. Sandbox verdict score (already calculated)

        # 3. Sigma rules score (normalize to 0-100)
        if sigma_score > 100:
            sigma_score = 100

        # 4. Vendor intelligence score
        vendor_score = 0
        if threat_metrics["severity_factors"]:
            vendor_scores = [f["score"] for f in threat_metrics["severity_factors"] 
                           if f["type"] == "vendor_score"]
            if vendor_scores:
                vendor_score = sum(vendor_scores) / len(vendor_scores)

        # Calculate final weighted threat score
        threat_metrics["threat_score"] = int(
            (detection_score * weights["detection_ratio"]) +
            (sandbox_score * weights["sandbox_verdict"]) +
            (sigma_score * weights["sigma_rules"]) +
            (vendor_score * weights["vendor_intel"])
        )

        # Calculate confidence score (0-100)
        platform_confidence = len([p for p in results["platforms"] if results["platforms"][p]]) / len(self.supported_platforms) * 100
        sandbox_confidence_weight = 0.4
        platform_confidence_weight = 0.6
        
        threat_metrics["confidence_score"] = int(
            (sandbox_confidence * sandbox_confidence_weight) +
            (platform_confidence * platform_confidence_weight)
        )

        # Determine risk level with more granular thresholds
        if threat_metrics["threat_score"] >= 80:
            threat_metrics["risk_level"] = "critical"
        elif threat_metrics["threat_score"] >= 60:
            threat_metrics["risk_level"] = "high"
        elif threat_metrics["threat_score"] >= 40:
            threat_metrics["risk_level"] = "medium"
        elif threat_metrics["threat_score"] > 20:
            threat_metrics["risk_level"] = "low"
        else:
            threat_metrics["risk_level"] = "safe"

        # Add severity explanation
        threat_metrics["severity_explanation"] = self._generate_severity_explanation(
            threat_metrics["threat_score"],
            threat_metrics["confidence_score"],
            threat_metrics["severity_factors"]
        )

        # Convert sets to lists for JSON serialization
        threat_metrics["malware_families"] = list(threat_metrics["malware_families"])
        threat_metrics["classifications"] = list(threat_metrics["classifications"])
        threat_metrics["threat_categories"] = list(threat_metrics["threat_categories"])

        return threat_metrics

    def _generate_severity_explanation(self, threat_score: int, confidence_score: int, severity_factors: list) -> str:
        """Generate a human-readable explanation of the severity assessment."""
        explanation = []

        # Threat score explanation
        if threat_score >= 80:
            explanation.append("This file shows strong indicators of being malicious")
        elif threat_score >= 60:
            explanation.append("This file exhibits significant suspicious behavior")
        elif threat_score >= 40:
            explanation.append("This file shows some concerning characteristics")
        elif threat_score > 20:
            explanation.append("This file has minor suspicious indicators")
        else:
            explanation.append("This file shows no significant signs of malicious behavior")

        # Add confidence context
        if confidence_score >= 80:
            explanation.append("with high confidence based on multiple reliable sources")
        elif confidence_score >= 60:
            explanation.append("with moderate confidence from several sources")
        else:
            explanation.append("but confidence is limited due to insufficient data")

        # Add specific factors
        if severity_factors:
            factor_explanations = []
            for factor in severity_factors:
                if factor["type"] == "sigma_rule":
                    factor_explanations.append(f"Triggered {factor['level']} severity rule: {factor['description']}")
                elif factor["type"] == "vendor_score":
                    factor_explanations.append(f"{factor['vendor']} rated severity at {factor['score']}/100")

            if factor_explanations:
                explanation.append("Key findings include: " + "; ".join(factor_explanations))

        return " ".join(explanation)
