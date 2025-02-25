import requests
import json
import time
import logging
from datetime import datetime, timedelta
from django.conf import settings
from main.models import APIKey
from functools import wraps
from typing import Dict, List, Any
from django.core.cache import cache

logger = logging.getLogger(__name__)

class ThreatFeedService:
    def __init__(self):
        self.api_keys = self._load_api_keys()
        # Define rate limits for each platform (in seconds)
        self.rate_limits = {
            'otx': 1,
            'threatfox': 1,
            'pulsedive': 1,
            # Add aliases to handle possible variations in platform name extraction
            'alienvault': 1,
        }
        self.last_request = {}
        self.cache_timeout = 300  # 5 minutes cache

    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from database"""
        keys = {}
        platforms = ['alienvault', 'threatfox', 'pulsedive']
        for platform in platforms:
            api_key = APIKey.objects.filter(platform=platform, is_active=True).first()
            if api_key and api_key.api_key:
                keys[platform] = api_key.api_key
        return keys

    def rate_limited(func):
        """Rate limiting decorator"""
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Extract platform name correctly from function name
            func_name = func.__name__
            
            # Map function names to platform keys
            platform_mapping = {
                'fetch_otx_feeds': 'otx',
                'fetch_threatfox_feeds': 'threatfox',
                'fetch_pulsedive_feeds': 'pulsedive',
                'test_otx': 'otx',
                'test_threatfox': 'threatfox',
                'test_pulsedive': 'pulsedive'
            }
            
            # Get platform from mapping or use fallback
            if func_name in platform_mapping:
                platform = platform_mapping[func_name]
            else:
                # Fallback: try to extract from function name
                if func_name.startswith('fetch_') and '_feeds' in func_name:
                    # Extract the middle part between 'fetch_' and '_feeds'
                    platform = func_name[len('fetch_'):-len('_feeds')]
                else:
                    # Last resort: use the last part of the function name
                    platform = func_name.split('_')[-1]
            
            # Ensure the platform exists in rate_limits
            if platform not in self.rate_limits:
                logger.warning(f"No rate limit defined for platform: {platform}, using default")
                # Use a default rate limit
                self.rate_limits[platform] = 1
                
            if platform in self.last_request:
                elapsed = time.time() - self.last_request[platform]
                if elapsed < self.rate_limits[platform]:
                    time.sleep(self.rate_limits[platform] - elapsed)
            self.last_request[platform] = time.time()
            return func(self, *args, **kwargs)
        return wrapper

    def _determine_severity(self, threat_data: Dict[str, Any]) -> str:
        """Determine threat severity based on various factors"""
        # Keywords indicating critical severity
        critical_keywords = ['critical', 'high-risk', 'apt', 'zero-day', 'ransomware', 'backdoor']
        title = threat_data.get('title', '').lower()
        desc = threat_data.get('description', '').lower()
        
        # Check for critical keywords
        if any(keyword in title or keyword in desc for keyword in critical_keywords):
            return 'Critical'
            
        # Check for specific threat types
        threat_type = threat_data.get('type', '').lower()
        if threat_type in ['apt', 'ransomware', 'backdoor']:
            return 'Critical'
        elif threat_type in ['malware', 'botnet']:
            return 'High'
        elif threat_type in ['phishing', 'spam']:
            return 'Medium'
            
        # Consider the number of indicators
        indicators = threat_data.get('indicators', [])
        if len(indicators) > 20:
            return 'High'
        elif len(indicators) > 10:
            return 'Medium'
            
        return 'Low'

    def _determine_threat_type(self, data: Dict[str, Any]) -> str:
        """Determine threat type based on available data"""
        title = data.get('title', '').lower()
        desc = data.get('description', '').lower()
        
        type_indicators = {
            'APT': ['apt', 'advanced persistent threat', 'targeted attack'],
            'Malware': ['malware', 'ransomware', 'trojan', 'virus', 'worm', 'backdoor'],
            'Phishing': ['phish', 'credential', 'social engineering'],
            'Botnet': ['botnet', 'c2', 'command and control'],
            'Exploit': ['exploit', 'vulnerability', 'cve-'],
            'Spam': ['spam', 'unsolicited']
        }
        
        for threat_type, keywords in type_indicators.items():
            if any(keyword in title or keyword in desc for keyword in keywords):
                return threat_type
                
        return 'Unknown'

    @rate_limited
    def fetch_otx_feeds(self) -> List[Dict[str, Any]]:
        """Fetch threat feeds from AlienVault OTX"""
        if 'alienvault' not in self.api_keys:
            logger.error("AlienVault OTX API key not configured")
            return []

        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # Process and normalize OTX data
            threats = []
            for pulse in data.get('results', []):
                threat = {
                    'source': 'OTX',
                    'title': pulse.get('name', ''),
                    'description': pulse.get('description', ''),
                    'indicators': [i['indicator'] for i in pulse.get('indicators', [])],
                    'timestamp': pulse.get('modified', datetime.now().isoformat()),
                    'type': self._determine_threat_type(pulse),
                    'raw_data': pulse
                }
                threat['severity'] = self._determine_severity(threat)
                threats.append(threat)
                
            return threats
            
        except Exception as e:
            logger.error(f"Error fetching OTX feeds: {str(e)}")
            return []

    @rate_limited
    def fetch_threatfox_feeds(self) -> List[Dict[str, Any]]:
        """Fetch threat feeds from ThreatFox"""
        if 'threatfox' not in self.api_keys:
            logger.error("ThreatFox API key not configured")
            return []

        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {
            'query': 'get_iocs',
            'days': 1
        }
        
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()
            data = response.json()
            
            # Process and normalize ThreatFox data
            threats = []
            for ioc in data.get('data', []):
                if not isinstance(ioc, dict):
                    continue
                    
                threat = {
                    'source': 'ThreatFox',
                    'title': f"{ioc.get('malware', '')} - {ioc.get('threat_type', '')}",
                    'description': f"IOC Type: {ioc.get('ioc_type', '')}\nThreat Type: {ioc.get('threat_type', '')}\nMalware: {ioc.get('malware', '')}",
                    'indicators': [ioc.get('ioc', '')],
                    'timestamp': datetime.fromtimestamp(ioc.get('first_seen_utc', time.time())).isoformat(),
                    'type': self._determine_threat_type({'title': ioc.get('malware', '')}),
                    'raw_data': ioc
                }
                threat['severity'] = self._determine_severity(threat)
                threats.append(threat)
                
            return threats
            
        except Exception as e:
            logger.error(f"Error fetching ThreatFox feeds: {str(e)}")
            return []

    @rate_limited
    def fetch_pulsedive_feeds(self) -> List[Dict[str, Any]]:
        """Fetch threat feeds from Pulsedive"""
        if 'pulsedive' not in self.api_keys:
            logger.error("Pulsedive API key not configured")
            return []

        threats = []
        for fid in range(1, 6):
            try:
                url = 'https://pulsedive.com/api/info.php'
                params = {
                    'fid': fid,
                    'pretty': '1',
                    'key': self.api_keys['pulsedive']
                }
                
                response = requests.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                if isinstance(data, dict):
                    items = [data]
                elif isinstance(data, list):
                    items = data
                else:
                    continue
                
                for item in items:
                    threat = {
                        'source': 'Pulsedive',
                        'title': item.get('name', ''),
                        'description': item.get('description', ''),
                        'indicators': [item.get('indicator', '')],
                        'timestamp': item.get('stamp_updated', datetime.now().isoformat()),
                        'type': self._determine_threat_type(item),
                        'raw_data': item
                    }
                    threat['severity'] = self._determine_severity(threat)
                    threats.append(threat)
                    
                time.sleep(1.1)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error fetching Pulsedive feed {fid}: {str(e)}")
                continue
                
        return threats

    def get_all_feeds(self) -> Dict[str, Any]:
        """Fetch all threat feeds with caching"""
        cache_key = 'threat_feeds'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            logger.info("Returning cached threat feeds")
            return cached_data

        try:
            # Get active platform names based on configured API keys
            active_platforms = []
            if 'alienvault' in self.api_keys:
                active_platforms.append('OTX')
            if 'threatfox' in self.api_keys:
                active_platforms.append('ThreatFox')
            if 'pulsedive' in self.api_keys:
                active_platforms.append('Pulsedive')

            all_threats = []
            
            # Only fetch from platforms that have API keys configured
            if not active_platforms:
                logger.warning("No threat feeds available - no API keys configured")
                return {
                    'threats': [],
                    'stats': {
                        'total': 0,
                        'today': 0,
                        'trend': 0,
                        'critical': 0,
                        'high': 0,
                        'malware': 0,
                        'sources': {'otx': False, 'threatfox': False, 'pulsedive': False}
                    },
                    'timestamp': datetime.now().isoformat(),
                    'active_platforms': [],
                    'message': 'No API keys configured. Please configure API keys in settings.'
                }

            # Fetch OTX feeds
            if 'alienvault' in self.api_keys:
                try:
                    logger.info("Fetching OTX feeds")
                    otx_threats = self.fetch_otx_feeds()
                    if isinstance(otx_threats, list):
                        logger.info(f"Successfully fetched {len(otx_threats)} OTX threats")
                        all_threats.extend(otx_threats)
                    else:
                        logger.error(f"OTX feeds returned unexpected type: {type(otx_threats)}")
                except Exception as e:
                    logger.error(f"Error fetching OTX feeds: {str(e)}", exc_info=True)
            
            # Fetch ThreatFox feeds
            if 'threatfox' in self.api_keys:
                try:
                    logger.info("Fetching ThreatFox feeds")
                    threatfox_threats = self.fetch_threatfox_feeds()
                    if isinstance(threatfox_threats, list):
                        logger.info(f"Successfully fetched {len(threatfox_threats)} ThreatFox threats")
                        all_threats.extend(threatfox_threats)
                    else:
                        logger.error(f"ThreatFox feeds returned unexpected type: {type(threatfox_threats)}")
                except Exception as e:
                    logger.error(f"Error fetching ThreatFox feeds: {str(e)}", exc_info=True)
            
            # Fetch Pulsedive feeds
            if 'pulsedive' in self.api_keys:
                try:
                    logger.info("Fetching Pulsedive feeds")
                    pulsedive_threats = self.fetch_pulsedive_feeds()
                    if isinstance(pulsedive_threats, list):
                        logger.info(f"Successfully fetched {len(pulsedive_threats)} Pulsedive threats")
                        all_threats.extend(pulsedive_threats)
                    else:
                        logger.error(f"Pulsedive feeds returned unexpected type: {type(pulsedive_threats)}")
                except Exception as e:
                    logger.error(f"Error fetching Pulsedive feeds: {str(e)}", exc_info=True)

            # Prepare the final result
            result = {
                'threats': all_threats,
                'stats': self._calculate_stats(all_threats),
                'timestamp': datetime.now().isoformat(),
                'active_platforms': active_platforms
            }
            
            # Cache the result
            logger.info(f"Caching {len(all_threats)} threats from {len(active_platforms)} active platforms")
            cache.set(cache_key, result, self.cache_timeout)
            return result

        except Exception as e:
            logger.error(f"Error fetching threat feeds: {str(e)}", exc_info=True)
            return {
                'threats': [],
                'stats': {
                    'total': 0,
                    'today': 0,
                    'trend': 0,
                    'critical': 0,
                    'high': 0,
                    'malware': 0,
                    'sources': {'otx': False, 'threatfox': False, 'pulsedive': False}
                },
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }

    def _calculate_stats(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from threat data"""
        today = datetime.now()
        yesterday = today - timedelta(days=1)
        
        total_count = len(threats)
        today_count = sum(1 for t in threats if datetime.fromisoformat(t['timestamp'].replace('Z', '')).date() == today.date())
        yesterday_count = sum(1 for t in threats if datetime.fromisoformat(t['timestamp'].replace('Z', '')).date() == yesterday.date())
        
        critical_count = sum(1 for t in threats if t['severity'] == 'Critical')
        high_count = sum(1 for t in threats if t['severity'] == 'High')
        malware_count = sum(1 for t in threats if t['type'] == 'Malware')
        
        # Calculate trends
        trend = ((today_count - yesterday_count) / max(yesterday_count, 1)) * 100 if yesterday_count > 0 else 0
        
        return {
            'total': total_count,
            'today': today_count,
            'trend': round(trend, 1),
            'critical': critical_count,
            'high': high_count,
            'malware': malware_count,
            'sources': {
                'otx': any(t['source'] == 'OTX' for t in threats),
                'threatfox': any(t['source'] == 'ThreatFox' for t in threats),
                'pulsedive': any(t['source'] == 'Pulsedive' for t in threats)
            }
        }

    def refresh_feeds(self) -> Dict[str, Any]:
        """Force refresh of threat feeds"""
        cache.delete('threat_feeds')
        return self.get_all_feeds()