import requests
import json
import time
import os
import logging
from datetime import datetime
from django.conf import settings
from main.models import APIKey

logger = logging.getLogger(__name__)

class ThreatFeedService:
    def __init__(self):
        self.api_keys = self._load_api_keys()
        self.rate_limits = {
            'otx': 1,
            'threatfox': 1,
            'pulsedive': 1
        }
        self.last_request = {}

    def _load_api_keys(self):
        """Load API keys from database"""
        keys = {}
        platforms = ['alienvault', 'threatfox', 'pulsedive']
        for platform in platforms:
            api_key = APIKey.objects.filter(platform=platform, is_active=True).first()
            if api_key:
                keys[platform] = api_key.api_key
        return keys

    def fetch_otx_feeds(self):
        """Fetch threat feeds from AlienVault OTX"""
        if 'alienvault' not in self.api_keys:
            return {"error": "AlienVault OTX API key not configured"}

        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"OTX API error: {str(e)}"}

    def fetch_threatfox_feeds(self):
        """Fetch threat feeds from ThreatFox"""
        if 'threatfox' not in self.api_keys:
            return {"error": "ThreatFox API key not configured"}

        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {
            'query': 'get_iocs',
            'days': 1
        }
        
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"ThreatFox API error: {str(e)}"}

    def fetch_pulsedive_feeds(self):
        """Fetch threat feeds from Pulsedive"""
        if 'pulsedive' not in self.api_keys:
            return {"error": "Pulsedive API key not configured"}

        all_threats = []
        for fid in range(1, 6):
            url = 'https://pulsedive.com/api/info.php'
            params = {
                'fid': fid,
                'pretty': '1',
                'key': self.api_keys['pulsedive']
            }
            
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                threats = response.json()
                
                if isinstance(threats, dict):
                    all_threats.append(threats)
                elif isinstance(threats, list):
                    all_threats.extend(threats)
                    
                time.sleep(1.1)  # Rate limiting
                
            except Exception as e:
                print(f"Error fetching FID {fid}: {str(e)}")
                continue
                
        return all_threats

    def get_all_feeds(self):
        """Fetch all threat feeds"""
        try:
            # For development/testing, load from test file
            test_file_path = 'main/services/threat_feed/test/threat_feed.txt'
            if os.path.exists(test_file_path):
                with open(test_file_path, 'r') as f:
                    test_data = f.read()
                    # Parse the test data
                    sections = test_data.split('\n\n')
                    threats = []
                    current_section = None
                    
                    for section in sections:
                        if section.startswith('Testing OTX:'):
                            try:
                                # Extract JSON data
                                json_str = section[section.find('['):].strip()
                                otx_data = json.loads(json_str)
                                threats.extend(otx_data)
                            except json.JSONDecodeError as e:
                                logger.error(f"Error parsing OTX test data: {e}")
                    
                    return {
                        'otx': {'results': threats},
                        'threatfox': {'data': []},
                        'pulsedive': []
                    }

        except Exception as e:
            logger.error(f"Error loading test data: {e}", exc_info=True)
            return {
                'otx': {'results': []},
                'threatfox': {'data': []},
                'pulsedive': []
            }

        # If no test data or in production, fetch from APIs
        return {
            'otx': self.fetch_otx_feeds(),
            'threatfox': self.fetch_threatfox_feeds(),
            'pulsedive': self.fetch_pulsedive_feeds()
        }

    def process_feeds(self, feeds):
        """Process and format the feeds for frontend display"""
        processed_data = []
        
        # Process OTX feeds
        if 'otx' in feeds and isinstance(feeds['otx'], dict):
            results = feeds['otx'].get('results', [])
            if isinstance(results, list):
                for item in results:
                    # Handle test data format
                    if isinstance(item, dict) and 'source' in item and item['source'] == 'OTX':
                        threat = {
                            'id': item.get('id', ''),
                            'source': item['source'],
                            'title': item.get('title', ''),
                            'description': item.get('description', ''),
                            'indicators': item.get('indicators', []),
                            'timestamp': item.get('timestamp', ''),
                            'type': self._determine_threat_type(item.get('title', '').split()),
                            'severity': 'High' if 'critical' in item.get('title', '').lower() else 'Medium'
                        }
                        processed_data.append(threat)
                    else:
                        # Handle regular OTX API response format
                        threat = {
                            'id': item.get('id', ''),
                            'source': 'OTX',
                            'title': item.get('name', ''),
                            'description': item.get('description', ''),
                            'indicators': [i['indicator'] for i in item.get('indicators', [])],
                            'timestamp': item.get('modified', ''),
                            'type': self._determine_threat_type(item.get('tags', [])),
                            'severity': self._calculate_severity(item)
                        }
                        processed_data.append(threat)

        # Process ThreatFox feeds
        if 'threatfox' in feeds and isinstance(feeds['threatfox'], dict):
            for ioc in feeds['threatfox'].get('data', []):
                if not isinstance(ioc, dict):
                    continue
                threat = {
                    'id': str(ioc.get('id', '')),
                    'source': 'ThreatFox',
                    'title': f"{ioc.get('malware', '')} - {ioc.get('threat_type', '')}",
                    'description': f"IOC Type: {ioc.get('ioc_type', '')}\nThreat Type: {ioc.get('threat_type', '')}",
                    'indicators': [ioc.get('ioc', '')],
                    'timestamp': datetime.fromtimestamp(ioc.get('first_seen_utc', 0)).isoformat(),
                    'type': 'Malware',
                    'severity': self._calculate_severity_from_confidence(ioc.get('confidence_level', 0))
                }
                processed_data.append(threat)

        # Process Pulsedive feeds
        if 'pulsedive' in feeds and isinstance(feeds['pulsedive'], list):
            for feed in feeds['pulsedive']:
                if not isinstance(feed, dict):
                    continue
                threat = {
                    'id': str(feed.get('iid', '')),
                    'source': 'Pulsedive',
                    'title': feed.get('name', ''),
                    'description': feed.get('description', ''),
                    'indicators': [feed.get('indicator', '')],
                    'timestamp': feed.get('stamp_updated', ''),
                    'type': self._map_pulsedive_type(feed.get('type', '')),
                    'severity': self._map_pulsedive_risk(feed.get('risk', ''))
                }
                processed_data.append(threat)

        return processed_data

    def _determine_threat_type(self, tags):
        """Determine threat type based on tags"""
        if isinstance(tags, str):
            tags = [tags]
            
        tags = [t.upper() for t in tags]
        
        if any('APT' in t for t in tags):
            return 'APT'
        elif any('PHISH' in t for t in tags):
            return 'Phishing'
        elif any('MALWARE' in t for t in tags):
            return 'Malware'
        elif any('BOTNET' in t for t in tags):
            return 'Botnet'
        return 'Unknown'

    def _calculate_severity(self, pulse):
        """Calculate severity based on pulse data"""
        # Check for critical keywords in tags
        critical_keywords = ['critical', 'high-risk', 'apt', 'zero-day', 'ransomware']
        tags = [tag.lower() for tag in pulse.get('tags', [])]
        
        if any(keyword in tags for keyword in critical_keywords):
            return 'Critical'
            
        # Check number of indicators
        indicator_count = len(pulse.get('indicators', []))
        if indicator_count > 20:
            return 'High'
        elif indicator_count > 10:
            return 'Medium'
            
        return 'Low'

    def _calculate_severity_from_confidence(self, confidence):
        """Calculate severity based on confidence level"""
        if confidence >= 80:
            return 'Critical'
        elif confidence >= 60:
            return 'High'
        elif confidence >= 40:
            return 'Medium'
        return 'Low'

    def _map_pulsedive_type(self, ptype):
        """Map Pulsedive threat types to our categories"""
        type_mapping = {
            'malware': 'Malware',
            'phishing': 'Phishing',
            'apt': 'APT',
            'exploit': 'Malware',
            'botnet': 'Malware',
            'ransomware': 'Malware'
        }
        return type_mapping.get(str(ptype).lower(), 'Malware')

    def _map_pulsedive_risk(self, risk):
        """Map Pulsedive risk levels to our severity levels"""
        risk_mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'none': 'Low'
        }
        return risk_mapping.get(str(risk).lower(), 'Medium')