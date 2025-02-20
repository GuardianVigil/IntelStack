"""
Main URL scanning module
"""
import asyncio
import aiohttp
from typing import Dict, Any, List
import os
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

from .platforms.hybrid_analysis import HybridAnalysisScanner
from .platforms.urlscan_io import URLScanScanner
from .platforms.virustotal import VirusTotalScanner
from .platforms.domain_info import get_domain_info

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

    def _clean_response(self, data: Any) -> Any:
        """Clean response data to ensure JSON serializable"""
        if data is None:
            return ""
        elif isinstance(data, (str, int, float, bool)):
            return data
        elif isinstance(data, dict):
            return {
                str(k): self._clean_response(v)
                for k, v in data.items()
                if k is not None
            }
        elif isinstance(data, (list, tuple)):
            return [self._clean_response(x) for x in data if x is not None]
        else:
            try:
                return str(data)
            except:
                return ""

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL using multiple platforms and return aggregated results
        """
        try:
            # Initialize scanners with proper error handling
            scanners = []
            for platform, api_key in self.api_keys.items():
                if platform == "hybrid_analysis":
                    scanners.append(HybridAnalysisScanner(self.session, api_key))
                elif platform == "urlscan":
                    scanners.append(URLScanScanner(self.session, api_key))
                elif platform == "virustotal":
                    scanners.append(VirusTotalScanner(self.session, api_key))
            
            # Collect results from all platforms
            platform_results = {}
            for scanner in scanners:
                platform_name = scanner.__class__.__name__.replace('Scanner', '').lower()
                try:
                    result = await scanner.scan(url)
                    # Clean and validate result
                    if isinstance(result, dict):
                        platform_results[platform_name] = self._clean_response(result)
                    else:
                        platform_results[platform_name] = {"error": "Invalid response format"}
                except Exception as e:
                    logger.error(f"Error in {platform_name} scan: {str(e)}")
                    platform_results[platform_name] = {"error": str(e)}

            # Get domain info with error handling
            try:
                domain_info = get_domain_info(
                    urlscan_result=platform_results.get('urlscan', {}),
                    virustotal_result=platform_results.get('virustotal', {}),
                    hybrid_result=platform_results.get('hybridanalysis', {})
                )
            except Exception as e:
                logger.error(f"Error getting domain info: {str(e)}")
                domain_info = {"error": str(e)}

            # Calculate overall threat score with validation
            total_score = 0
            num_scores = 0
            for result in platform_results.values():
                if isinstance(result, dict) and 'score' in result:
                    try:
                        score = float(result['score'])
                        if 0 <= score <= 100:  # Validate score range
                            total_score += score
                            num_scores += 1
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Invalid score value: {e}")

            overall_score = round(total_score / max(num_scores, 1), 2)  # Avoid division by zero
            threat_level = 'High' if overall_score >= 80 else 'Medium' if overall_score >= 40 else 'Low'

            # Prepare final response with thorough cleaning
            response = {
                'url': str(url),
                'scan_date': datetime.now().isoformat(),
                'threat_level': str(threat_level),
                'overall_score': float(overall_score),
                'domain_info': self._clean_response(domain_info),
                'platform_results': platform_results,
                'categories': [
                    {
                        'name': 'Overall Threat',
                        'risk': str(threat_level),
                        'description': f"Overall threat score: {overall_score}/100"
                    }
                ]
            }

            # Add platform-specific categories
            for platform, result in platform_results.items():
                if isinstance(result, dict) and 'score' in result:
                    try:
                        score = float(result['score'])
                        risk = 'High' if score >= 80 else 'Medium' if score >= 40 else 'Low'
                        response['categories'].append({
                            'name': str(platform).replace('_', ' ').title(),
                            'risk': str(risk),
                            'description': f"Platform score: {score}/100"
                        })
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Error processing platform score: {e}")

            # Validate final response is JSON serializable
            try:
                json.dumps(response)
                return response
            except (TypeError, ValueError) as e:
                logger.error(f"Response serialization error: {e}")
                return {
                    "error": "Failed to serialize response",
                    "message": str(e)
                }

        except Exception as e:
            logger.error(f"Error in URL scan: {str(e)}")
            return {"error": str(e)}