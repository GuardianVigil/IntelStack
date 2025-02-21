import re
import email
from email import policy
import aiohttp
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import dns.resolver
from datetime import datetime, timedelta
import logging

from django.conf import settings
from django.db.models import Q
from asgiref.sync import sync_to_async
from main.models import APIKey

from .platforms.virustotal import VirusTotalScanner
from .platforms.abuseipdb import AbuseIPDBScanner
from .platforms.greynoise import GreyNoiseScanner
from .platforms.urlscan import URLScanScanner
from .platforms.hybrid_analysis import HybridAnalysisScanner
from .utils.scoring import calculate_threat_score, calculate_risk_indicators

logger = logging.getLogger(__name__)

class EmailAnalyzer:
    SCANNER_CLASSES = {
        'virustotal': VirusTotalScanner,
        'abuseipdb': AbuseIPDBScanner,
        'greynoise': GreyNoiseScanner,
        'urlscan': URLScanScanner,
        'hybrid_analysis': HybridAnalysisScanner
    }

    def __init__(self, user=None):
        """Initialize the email analyzer with all required scanners"""
        self.session = aiohttp.ClientSession()
        self.user = user
        self.scanners = {}
        
    async def initialize_scanners(self):
        """Initialize scanners with API keys"""
        try:
            # Get API keys from database
            api_keys = await sync_to_async(APIKey.objects.filter)(is_active=True)
            api_keys = await sync_to_async(list)(api_keys)
            
            # Create scanner instances
            for platform, scanner_class in self.SCANNER_CLASSES.items():
                try:
                    api_key = next((key.key for key in api_keys if key.platform == platform), None)
                    if api_key:
                        self.scanners[platform] = scanner_class(api_key, self.session)
                except Exception as e:
                    logger.warning(f"Failed to initialize {platform} scanner: {str(e)}")
                    continue
        except Exception as e:
            logger.warning(f"Error getting API key for {platform}: {str(e)}")
            return None
        
    async def analyze_email(self, header_content: str, attachments: List[Tuple[str, bytes]] = None) -> Dict[str, Any]:
        """
        Analyze email headers, URLs, and attachments
        
        Args:
            header_content: Raw email content including headers
            attachments: Optional list of (filename, content) tuples
            
        Returns:
            Comprehensive analysis results
        """
        try:
            logger.info("Starting email analysis")
            
            # Parse email from raw content
            email_message = email.message_from_string(header_content, policy=policy.default)
            if not email_message:
                raise ValueError("Failed to parse email content")
                
            logger.info("Successfully parsed email message")
            
            # Start all analysis tasks concurrently
            analysis_tasks = [
                self._analyze_headers(email_message),
                self._analyze_authentication(email_message),
                self._analyze_urls(email_message),
                self._analyze_sender_ip(email_message)
            ]
            
            if attachments:
                analysis_tasks.append(self._analyze_attachments(attachments))
                
            logger.info(f"Starting {len(analysis_tasks)} analysis tasks")
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Process results and handle any errors
            headers_result, auth_result, urls_result, ip_result, *attachment_results = results
            
            # Log any errors
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Task {i} failed: {str(result)}")
            
            analysis_results = {
                'headers': headers_result if not isinstance(headers_result, Exception) else {
                    'error': str(headers_result),
                    'headers': {},
                    'received_chain': []
                },
                'authentication': auth_result if not isinstance(auth_result, Exception) else {
                    'error': str(auth_result),
                    'spf': 'neutral',
                    'dkim': 'neutral',
                    'dmarc': 'neutral'
                },
                'urls': urls_result if not isinstance(urls_result, Exception) else [],
                'sender_ip': ip_result if not isinstance(ip_result, Exception) else {
                    'error': str(ip_result),
                    'ip': '',
                    'analysis': {}
                },
                'attachments': attachment_results[0] if attachments and not isinstance(attachment_results[0], Exception) else []
            }
            
            logger.info("Calculating risk assessment")
            
            # Calculate risk assessment
            risk_assessment = await self._calculate_risk_assessment(analysis_results)
            analysis_results['risk_assessment'] = risk_assessment
            
            # Add timeline
            current_time = datetime.now()
            analysis_results['timeline'] = [
                {'timestamp': current_time.isoformat(), 'event': 'Analysis completed', 'status': 'success'},
                {'timestamp': (current_time - timedelta(seconds=1)).isoformat(), 'event': 'Risk assessment calculated', 'status': 'success'},
                {'timestamp': (current_time - timedelta(seconds=2)).isoformat(), 'event': 'URL analysis completed', 'status': 'success' if not isinstance(urls_result, Exception) else 'error'},
                {'timestamp': (current_time - timedelta(seconds=3)).isoformat(), 'event': 'Authentication analysis completed', 'status': 'success' if not isinstance(auth_result, Exception) else 'error'},
                {'timestamp': (current_time - timedelta(seconds=4)).isoformat(), 'event': 'Header analysis completed', 'status': 'success' if not isinstance(headers_result, Exception) else 'error'}
            ]
            
            logger.info("Analysis completed successfully")
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            current_time = datetime.now()
            return {
                'error': str(e),
                'headers': {
                    'headers': {},
                    'received_chain': []
                },
                'authentication': {
                    'spf': 'neutral',
                    'dkim': 'neutral',
                    'dmarc': 'neutral'
                },
                'urls': [],
                'attachments': [],
                'sender_ip': {
                    'ip': '',
                    'analysis': {}
                },
                'risk_assessment': {
                    'threat_score': 0,
                    'risk_level': 'unknown',
                    'risk_factors': [],
                    'indicators': {
                        'authentication_failed': False,
                        'suspicious_urls': 0,
                        'malicious_attachments': 0,
                        'suspicious_sender': False
                    }
                },
                'timeline': [
                    {'timestamp': current_time.isoformat(), 'event': 'Analysis failed', 'status': 'error', 'error': str(e)}
                ]
            }

    async def _analyze_headers(self, email_message) -> Dict[str, Any]:
        """Analyze email headers"""
        try:
            # Extract basic headers
            headers = {}
            for header in ['from', 'to', 'subject', 'date', 'message-id', 'received']:
                value = email_message.get(header, '')
                if isinstance(value, (list, tuple)):
                    headers[header] = [str(v) for v in value]
                else:
                    headers[header] = str(value)
            
            # Parse received headers
            received_headers = email_message.get_all('received', [])
            received_chain = []
            
            for header in received_headers:
                try:
                    # Extract IP addresses
                    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(header))
                    
                    # Extract timestamp
                    timestamp_match = re.search(r';(.*?)(?:\(.*?\))?\s*$', str(header))
                    timestamp = timestamp_match.group(1).strip() if timestamp_match else None
                    
                    # Extract hostnames
                    from_match = re.search(r'from\s+([^\s]+)', str(header))
                    by_match = re.search(r'by\s+([^\s]+)', str(header))
                    
                    received_chain.append({
                        'raw': str(header),
                        'ips': ips,
                        'timestamp': timestamp,
                        'from_host': from_match.group(1) if from_match else None,
                        'by_host': by_match.group(1) if by_match else None
                    })
                except Exception as e:
                    logger.warning(f"Error parsing received header: {str(e)}")
                    continue
            
            return {
                'headers': headers,
                'received_chain': received_chain
            }
            
        except Exception as e:
            logger.error(f"Error analyzing headers: {str(e)}")
            return {
                'headers': {},
                'received_chain': [],
                'error': str(e)
            }

    async def _analyze_authentication(self, email_message) -> Dict[str, Any]:
        """Analyze email authentication results"""
        try:
            auth_results = {
                'spf': 'neutral',
                'dkim': 'neutral',
                'dmarc': 'neutral'
            }
            
            # Check Authentication-Results header
            auth_header = email_message.get('Authentication-Results', '')
            
            # Parse SPF
            spf_match = re.search(r'spf=(\w+)', auth_header)
            if spf_match:
                auth_results['spf'] = spf_match.group(1).lower()
                
            # Parse DKIM
            dkim_match = re.search(r'dkim=(\w+)', auth_header)
            if dkim_match:
                auth_results['dkim'] = dkim_match.group(1).lower()
                
            # Parse DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', auth_header)
            if dmarc_match:
                auth_results['dmarc'] = dmarc_match.group(1).lower()
                
            # Add raw headers for reference
            auth_results['raw_headers'] = {
                'authentication_results': auth_header,
                'received_spf': email_message.get('Received-SPF', ''),
                'dkim_signature': email_message.get('DKIM-Signature', '')
            }
            
            return auth_results
            
        except Exception as e:
            logger.error(f"Error analyzing authentication: {str(e)}")
            return {
                'spf': 'neutral',
                'dkim': 'neutral',
                'dmarc': 'neutral',
                'error': str(e),
                'raw_headers': {}
            }

    async def _analyze_urls(self, email_message) -> List[Dict[str, Any]]:
        """Analyze URLs found in email"""
        try:
            urls = set()
            
            # Extract URLs from headers
            for header in ['from', 'to', 'subject']:
                value = email_message.get(header, '')
                urls.update(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', value))
            
            # Extract URLs from body
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
                        content = part.get_payload(decode=True)
                        if content:
                            try:
                                text = content.decode()
                                urls.update(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
                            except UnicodeDecodeError:
                                logger.warning("Failed to decode email part")
            else:
                content = email_message.get_payload(decode=True)
                if content:
                    try:
                        text = content.decode()
                        urls.update(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
                    except UnicodeDecodeError:
                        logger.warning("Failed to decode email content")
            
            logger.info(f"Found {len(urls)} unique URLs")
            
            # Analyze each URL
            results = []
            for url in urls:
                try:
                    # Check URL against scanners
                    scanner_results = {}
                    for name, scanner in self.scanners.items():
                        try:
                            if hasattr(scanner, 'scan_url'):
                                result = await self._safe_scan_url(scanner, url)
                                if result:
                                    scanner_results[name] = result
                        except Exception as e:
                            logger.error(f"Error scanning URL with {name}: {str(e)}")
                    
                    results.append({
                        'url': url,
                        'analysis': scanner_results,
                        'malicious': any(result.get('malicious', False) for result in scanner_results.values())
                    })
                except Exception as e:
                    logger.error(f"Error analyzing URL {url}: {str(e)}")
                    results.append({
                        'url': url,
                        'error': str(e),
                        'analysis': {},
                        'malicious': False
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"Error in URL analysis: {str(e)}")
            return []

    async def _safe_scan_url(self, scanner, url: str) -> Dict[str, Any]:
        """Safely execute URL scan with error handling"""
        try:
            return await scanner.scan_url(url)
        except Exception as e:
            logger.error(f"Error scanning URL {url} with {scanner.name}: {str(e)}")
            return {'error': str(e)}

    async def _analyze_attachments(self, attachments: List[Tuple[str, bytes]]) -> List[Dict[str, Any]]:
        """Analyze email attachments"""
        results = []
        for filename, content in attachments:
            attachment_results = {}
            
            # Query each scanner that supports file analysis
            for name, scanner in self.scanners.items():
                if hasattr(scanner, 'scan_file'):
                    try:
                        attachment_results[name] = await scanner.scan_file(filename, content)
                    except Exception as e:
                        logger.warning(f"Error scanning attachment {filename} with {name}: {str(e)}")
                        continue
            
            results.append({
                'filename': filename,
                'analysis': attachment_results,
                'size': len(content)
            })
            
        return results

    async def _analyze_sender_ip(self, email_message) -> Dict[str, Any]:
        """Analyze sender IP"""
        try:
            # Get the first received header
            received = email_message.get_all('received', [])
            if not received:
                return {'error': 'No received headers found'}
            
            # Extract the first IP address found
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(received[0]))
            if not ips:
                return {'error': 'No IP address found in received headers'}
            
            sender_ip = ips[0]
            
            # Check IP against scanners
            analysis_results = {}
            for name, scanner in self.scanners.items():
                try:
                    if hasattr(scanner, 'scan_ip'):
                        result = await scanner.scan_ip(sender_ip)
                        if result:
                            analysis_results[name] = result
                except Exception as e:
                    logger.error(f"Error scanning IP with {name}: {str(e)}")
            
            # Determine reputation
            reputation = 'unknown'
            if analysis_results:
                malicious_count = sum(1 for result in analysis_results.values() 
                                    if result.get('malicious', False))
                if malicious_count > len(analysis_results) / 2:
                    reputation = 'malicious'
                elif malicious_count > 0:
                    reputation = 'suspicious'
                else:
                    reputation = 'clean'
            
            return {
                'ip': sender_ip,
                'reputation': reputation,
                'analysis': analysis_results,
                'geolocation': await self._get_ip_geolocation(sender_ip)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing sender IP: {str(e)}")
            return {
                'error': str(e),
                'ip': '',
                'reputation': 'unknown',
                'analysis': {},
                'geolocation': {}
            }

    async def _get_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation data"""
        try:
            async with self.session.get(f'https://ipapi.co/{ip}/json/') as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'country': data.get('country_name'),
                        'region': data.get('region'),
                        'city': data.get('city'),
                        'latitude': data.get('latitude'),
                        'longitude': data.get('longitude')
                    }
        except Exception as e:
            logger.warning(f"Error getting IP geolocation: {str(e)}")
        
        return {}

    async def _calculate_risk_assessment(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        try:
            # Calculate threat score
            threat_score = await self._calculate_threat_score(analysis)
            
            # Calculate risk indicators
            risk_indicators = await self._calculate_risk_indicators(analysis)
            
            # Determine risk level
            risk_level = self._determine_risk_level(threat_score)
            
            # Compile risk factors
            risk_factors = []
            
            # Authentication failures
            if analysis['authentication'].get('spf') == 'fail':
                risk_factors.append('SPF authentication failed')
            if analysis['authentication'].get('dkim') == 'fail':
                risk_factors.append('DKIM authentication failed')
            if analysis['authentication'].get('dmarc') == 'fail':
                risk_factors.append('DMARC authentication failed')
            
            # Suspicious URLs
            malicious_urls = [url for url in analysis.get('urls', []) if url.get('malicious', False)]
            if malicious_urls:
                risk_factors.append(f'Found {len(malicious_urls)} malicious URLs')
            
            # Suspicious attachments
            malicious_attachments = [att for att in analysis.get('attachments', []) if att.get('malicious', False)]
            if malicious_attachments:
                risk_factors.append(f'Found {len(malicious_attachments)} suspicious attachments')
            
            # Suspicious sender IP
            if analysis.get('sender_ip', {}).get('reputation', 'unknown') == 'malicious':
                risk_factors.append('Sender IP has poor reputation')
            
            return {
                'threat_score': threat_score,
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'indicators': risk_indicators
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk assessment: {str(e)}")
            return {
                'threat_score': 0,
                'risk_level': 'unknown',
                'risk_factors': [],
                'indicators': {
                    'authentication_failed': False,
                    'suspicious_urls': 0,
                    'malicious_attachments': 0,
                    'suspicious_sender': False
                }
            }

    async def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate overall threat score"""
        try:
            score = 0
            
            # Authentication (-20 to +20)
            auth = analysis.get('authentication', {})
            if auth.get('spf') == 'pass':
                score += 10
            elif auth.get('spf') == 'fail':
                score -= 10
                
            if auth.get('dkim') == 'pass':
                score += 5
            elif auth.get('dkim') == 'fail':
                score -= 5
                
            if auth.get('dmarc') == 'pass':
                score += 5
            elif auth.get('dmarc') == 'fail':
                score -= 5
            
            # URLs (up to +50)
            malicious_urls = len([url for url in analysis.get('urls', []) if url.get('malicious', False)])
            score -= min(malicious_urls * 10, 50)
            
            # Attachments (up to +20)
            malicious_attachments = len([att for att in analysis.get('attachments', []) if att.get('malicious', False)])
            score -= min(malicious_attachments * 10, 20)
            
            # Sender IP (up to +10)
            if analysis.get('sender_ip', {}).get('reputation') == 'malicious':
                score -= 10
            
            # Normalize score to 0-100 range where 100 is most malicious
            normalized_score = int(((100 - score) / 2) + 50)
            return max(0, min(100, normalized_score))
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return 0

    async def _calculate_risk_indicators(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk indicators from analysis results"""
        try:
            return {
                'authentication_failed': any(analysis.get('authentication', {}).get(auth) == 'fail' 
                                          for auth in ['spf', 'dkim', 'dmarc']),
                'suspicious_urls': len([url for url in analysis.get('urls', []) 
                                     if url.get('malicious', False)]),
                'malicious_attachments': len([att for att in analysis.get('attachments', [])
                                            if att.get('malicious', False)]),
                'suspicious_sender': analysis.get('sender_ip', {}).get('reputation') == 'malicious'
            }
        except Exception as e:
            logger.error(f"Error calculating risk indicators: {str(e)}")
            return {
                'authentication_failed': False,
                'suspicious_urls': 0,
                'malicious_attachments': 0,
                'suspicious_sender': False
            }

    def _determine_risk_level(self, threat_score: int) -> str:
        """Determine risk level based on threat score"""
        if threat_score >= 80:
            return 'Critical'
        elif threat_score >= 60:
            return 'High'
        elif threat_score >= 40:
            return 'Medium'
        elif threat_score >= 20:
            return 'Low'
        return 'Clean'

    async def close(self):
        """Close the aiohttp session"""
        await self.session.close()
