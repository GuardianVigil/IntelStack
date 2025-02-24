import requests
import json
import time
from datetime import datetime
from django.conf import settings
from main.models import APIKey

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
        return {
            'otx': self.fetch_otx_feeds(),
            'threatfox': self.fetch_threatfox_feeds(),
            'pulsedive': self.fetch_pulsedive_feeds()
        }

    def process_feeds(self, feeds):
        """Process and format the feeds for frontend display"""
        stats = {
            'malware_count': 0,
            'phishing_count': 0,
            'apt_count': 0,
            'vuln_count': 0
        }
        
        processed_feeds = []
        
        # Process OTX feeds
        if 'otx' in feeds and not isinstance(feeds['otx'], dict) or 'error' not in feeds['otx']:
            for pulse in feeds['otx'].get('results', []):
                feed_type = 'malware'
                if 'APT' in pulse.get('tags', []):
                    feed_type = 'apt'
                    stats['apt_count'] += 1
                elif 'Phishing' in pulse.get('tags', []):
                    feed_type = 'phishing'
                    stats['phishing_count'] += 1
                else:
                    stats['malware_count'] += 1
                
                processed_feeds.append({
                    'name': pulse.get('name', ''),
                    'description': pulse.get('description', ''),
                    'category': feed_type,
                    'provider': 'AlienVault OTX',
                    'last_update': pulse.get('modified'),
                    'status': 'active'
                })
        
        # Process ThreatFox feeds
        if 'threatfox' in feeds and not isinstance(feeds['threatfox'], dict) or 'error' not in feeds['threatfox']:
            for ioc in feeds['threatfox'].get('data', []):
                stats['malware_count'] += 1
                processed_feeds.append({
                    'name': ioc.get('malware', ''),
                    'description': ioc.get('threat_type', ''),
                    'category': 'malware',
                    'provider': 'ThreatFox',
                    'last_update': datetime.fromtimestamp(ioc.get('last_seen', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                    'status': 'active'
                })
        
        # Process Pulsedive feeds
        if 'pulsedive' in feeds and isinstance(feeds['pulsedive'], list):
            for feed in feeds['pulsedive']:
                feed_type = feed.get('category', 'malware').lower()
                if feed_type == 'phishing':
                    stats['phishing_count'] += 1
                elif feed_type == 'vulnerability':
                    stats['vuln_count'] += 1
                else:
                    stats['malware_count'] += 1
                
                processed_feeds.append({
                    'name': feed.get('feed', ''),
                    'description': feed.get('description', ''),
                    'category': feed_type,
                    'provider': 'Pulsedive',
                    'last_update': feed.get('stamp_updated', ''),
                    'status': 'active'
                })
        
        return {
            'feeds': processed_feeds,
            'stats': stats
        }