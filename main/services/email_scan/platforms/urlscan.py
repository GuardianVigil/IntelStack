from typing import Dict, Any, Optional
import aiohttp
import logging
import asyncio
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class URLScanScanner(BaseScanner):
    """Scanner for URLScan.io"""

    def __init__(self, api_key: str, session: aiohttp.ClientSession):
        super().__init__(api_key, session)
        self.base_url = 'https://urlscan.io/api/v1'
        self.headers = {
            'Content-Type': 'application/json'
        }

    async def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan email data - primarily focusing on URLs"""
        results = {}
        urls = email_data.get('urls', [])
        
        for url in urls:
            try:
                scan_result = await self.scan_url(url)
                if scan_result:
                    results[url] = scan_result
            except Exception as e:
                logger.warning(f"Error scanning URL {url}: {str(e)}")
                continue
                
        return results

    async def _submit_url_scan(self, url: str, endpoint: str, headers: Dict[str, str], data: Dict[str, str]) -> Dict[str, Any]:
        async with self.session.post(endpoint, headers=headers, json=data) as response:
            if response.status == 200:
                return await response.json()
            else:
                logger.error(f"Error submitting URL to URLScan: {await response.text()}")
                return {'error': 'Failed to submit URL'}

    async def _wait_for_scan_result(self, endpoint: str, headers: Dict[str, str], max_attempts: int = 10, delay: int = 15) -> Dict[str, Any]:
        attempts = 0
        while attempts < max_attempts:
            async with self.session.get(endpoint, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    await asyncio.sleep(delay)
                    attempts += 1
                else:
                    logger.error(f"Error getting URLScan results: {await response.text()}")
                    raise Exception('Failed to get scan results')
        raise TimeoutError('Timed out waiting for scan results')

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            headers = {
                'Content-Type': 'application/json'
            }
            data = {
                'url': url,
                'visibility': 'private'
            }
            
            # Submit scan
            submission = await self._submit_url_scan(url, f'{self.base_url}/scan/', headers, data)
            scan_id = submission.get('uuid')
            
            if not scan_id:
                return {'error': 'No scan ID received'}
            
            # Wait for results with retries
            try:
                scan_result = await self._wait_for_scan_result(
                    f'{self.base_url}/result/{scan_id}',
                    headers,
                    max_attempts=10,
                    delay=15
                )
                
                return {
                    'malicious': scan_result.get('stats', {}).get('malicious', 0),
                    'score': scan_result.get('verdicts', {}).get('overall', {}).get('score', 0),
                    'categories': scan_result.get('verdicts', {}).get('overall', {}).get('categories', []),
                    'brands': scan_result.get('brands', []),
                    'status': 'completed'
                }
            except TimeoutError:
                return {
                    'scan_id': scan_id,
                    'status': 'pending',
                    'message': 'Scan submitted but results not yet available'
                }
                    
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            return {'error': str(e)}

    async def scan_hash(self, file_hash: str) -> Dict[str, Any]:
        """URLScan doesn't support hash scanning"""
        return {'error': 'Hash scanning not supported by URLScan'}

    def calculate_threat_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from URLScan data"""
        try:
            # If there's an error, return None
            if 'error' in data:
                return None
                
            # Base score on URLScan's verdict score (0-100)
            base_score = data.get('score', 0) * 100
            
            # Increase score if marked as malicious
            if data.get('malicious'):
                base_score = max(base_score, 75)  # At least 75 if marked malicious
                
            # Adjust based on categories
            categories = data.get('categories', [])
            malicious_categories = ['malware', 'phishing', 'spam', 'scam']
            if any(cat in malicious_categories for cat in categories):
                base_score = max(base_score, 85)  # At least 85 if malicious categories found
                
            return min(base_score, 100)  # Cap at 100
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return None
