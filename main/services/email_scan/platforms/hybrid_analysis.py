from typing import Dict, Any, Optional
import aiohttp
import logging
import asyncio
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class HybridAnalysisScanner(BaseScanner):
    """Scanner for Hybrid Analysis"""

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(api_key, session)
        self.base_url = 'https://www.hybrid-analysis.com/api/v2'
        self.headers = {
            'User-Agent': 'Vristo Email Scanner',
            'accept': 'application/json',
            'api-key': api_key
        }

    async def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan email data - focusing on attachments and URLs"""
        results = {
            'attachments': {},
            'urls': {}
        }
        
        # Scan attachments
        for attachment in email_data.get('attachments', []):
            if 'hash' in attachment:
                try:
                    result = await self.scan_hash(attachment['hash'])
                    results['attachments'][attachment['hash']] = result
                except Exception as e:
                    logger.warning(f"Error scanning attachment hash {attachment['hash']}: {str(e)}")
                    continue
        
        # Scan URLs
        for url in email_data.get('urls', []):
            try:
                result = await self.scan_url(url)
                results['urls'][url] = result
            except Exception as e:
                logger.warning(f"Error scanning URL {url}: {str(e)}")
                continue
                
        return results

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            headers = {
                'User-Agent': 'Vristo Email Scanner',
                'accept': 'application/json',
                'api-key': self.api_key
            }
            
            # First check if URL was previously scanned
            params = {'url': url}
            async with self.session.get(f'{self.base_url}/search/terms', headers=headers, params=params) as response:
                if response.status == 200:
                    search_results = await response.json()
                    if search_results and len(search_results) > 0:
                        # Use most recent result
                        result = search_results[0]
                        return {
                            'malicious': 1 if result.get('verdict') == 'malicious' else 0,
                            'threat_score': result.get('threat_score', 0),
                            'threat_level': result.get('threat_level', 'unknown'),
                            'last_seen': result.get('analysis_start_time'),
                            'status': 'completed'
                        }
                
            # If no previous results, submit for scanning
            data = {
                'url': url,
                'environment_id': 100,  # Windows 7 32-bit
                'no_share_third_party': True,
                'no_hash_lookup': True
            }
            
            # Submit scan
            submission = await self._submit_url_scan(url, f'{self.base_url}/submit/url', headers, data)
            job_id = submission.get('job_id')
            
            if not job_id:
                return {'error': 'No job ID received'}
            
            # Wait for results with retries
            try:
                result = await self._wait_for_scan_result(
                    f'{self.base_url}/report/{job_id}/summary',
                    headers,
                    max_attempts=10,
                    delay=15
                )
                
                return {
                    'malicious': 1 if result.get('verdict') == 'malicious' else 0,
                    'threat_score': result.get('threat_score', 0),
                    'threat_level': result.get('threat_level', 'unknown'),
                    'analysis_id': job_id,
                    'status': 'completed'
                }
            except TimeoutError:
                return {
                    'job_id': job_id,
                    'status': 'pending',
                    'message': 'Analysis submitted but results not yet available'
                }
                    
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            return {'error': str(e)}

    async def scan_hash(self, file_hash: str) -> Dict[str, Any]:
        """Get analysis results for a file hash"""
        try:
            endpoint = f"{self.base_url}/search/hash"
            params = {'hash': file_hash}
            
            result = await self._make_request(endpoint, params=params)
            
            if not result:
                return {'error': 'No results found'}
                
            # Get the most recent analysis
            latest = result[0] if isinstance(result, list) else result
            
            return {
                'threat_score': latest.get('threat_score', 0),
                'verdict': latest.get('verdict'),
                'malware_family': latest.get('malware_family'),
                'threat_level': latest.get('threat_level', 'unknown'),
                'file_type': latest.get('type'),
                'environment': latest.get('environment_id'),
                'analysis_time': latest.get('analysis_start_time'),
                'report_url': latest.get('report_url')
            }
            
        except Exception as e:
            logger.error(f"Error scanning hash {file_hash}: {str(e)}")
            return {'error': str(e)}

    def calculate_threat_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from Hybrid Analysis data"""
        try:
            # If there's an error, return None
            if 'error' in data:
                return None
                
            # Start with the platform's threat score (0-100)
            base_score = data.get('threat_score', 0)
            
            # Adjust based on verdict
            verdict = data.get('verdict', '').lower()
            if verdict in ['malicious', 'suspicious']:
                base_score = max(base_score, 70)  # At least 70 if marked malicious/suspicious
                
            # Adjust based on threat level
            threat_level = data.get('threat_level', '').lower()
            threat_level_scores = {
                'high': 90,
                'medium': 70,
                'low': 50,
                'none': 0
            }
            level_score = threat_level_scores.get(threat_level, base_score)
            base_score = max(base_score, level_score)
            
            # Increase score if malware family is identified
            if data.get('malware_family'):
                base_score = max(base_score, 80)  # At least 80 if malware family identified
                
            return min(base_score, 100)  # Cap at 100
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return None
