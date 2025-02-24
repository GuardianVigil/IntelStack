import requests
import json
import time
import logging
from datetime import datetime
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatFeedTester:
    def __init__(self):
        self.api_keys = {
            'otx': None,
            'threatfox': None,
            'pulsedive': None
        }
        self.rate_limits = {
            'otx': 1,  # 1 request per second
            'threatfox': 1,  # 1 request per second
            'pulsedive': 1  # 1 request per second
        }
        self.last_request = {}
        self.cache = {}

    def rate_limited(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            platform = func.__name__.split('_')[-1]
            if platform in self.last_request:
                elapsed = time.time() - self.last_request[platform]
                if elapsed < 1/self.rate_limits[platform]:
                    time.sleep((1/self.rate_limits[platform]) - elapsed)
            self.last_request[platform] = time.time()
            return func(self, *args, **kwargs)
        return wrapper

    @rate_limited
    def test_otx(self, retries=3):
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = self._get_headers('otx')
        
        for attempt in range(retries):
            try:
                response = requests.get(url, headers=headers)
                logger.debug(f"OTX Response: {response.status_code} {response.text[:200]}")
                
                if response.status_code == 401:
                    return "OTX Error: Invalid API key"
                    
                response.raise_for_status()
                
                if not response.headers.get('Content-Type', '').startswith('application/json'):
                    raise ValueError("Invalid content type in OTX response")
                    
                data = response.json()
                
                if not isinstance(data, dict) or 'results' not in data:
                    raise ValueError("Invalid OTX API response structure")
                    
                return self._process_otx_data(data)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"OTX Request failed: {str(e)}")
                if attempt == retries - 1:
                    return f"OTX Error: {str(e)}"
                time.sleep(2 ** attempt)
            except ValueError as e:
                logger.error(f"OTX Data validation failed: {str(e)}")
                if attempt == retries - 1:
                    return f"OTX Error: {str(e)}"
                time.sleep(2 ** attempt)

    
                
    @rate_limited
    def test_threatfox(self, retries=3):
        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {
            'query': 'get_iocs',
            'days': 1
        }
        headers = self._get_headers('threatfox')
        
        for attempt in range(retries):
            try:
                response = requests.post(url, json=data, headers=headers)
                logger.debug(f"ThreatFox Response: {response.status_code} {response.text[:200]}")
                
                if response.status_code == 401:
                    return "ThreatFox Error: Invalid API key"
                    
                response.raise_for_status()
                
                if not response.headers.get('Content-Type', '').startswith('application/json'):
                    raise ValueError("Invalid content type in ThreatFox response")
                    
                data = response.json()
                
                if not isinstance(data, dict) or 'data' not in data:
                    raise ValueError("Invalid ThreatFox API response structure")
                    
                return self._process_threatfox_data(data)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"ThreatFox Request failed: {str(e)}")
                if attempt == retries - 1:
                    return f"ThreatFox Error: {str(e)}"
                time.sleep(2 ** attempt)
            except ValueError as e:
                logger.error(f"ThreatFox Data validation failed: {str(e)}")
                if attempt == retries - 1:
                    return f"ThreatFox Error: {str(e)}"
                time.sleep(2 ** attempt)

    @rate_limited
    def test_pulsedive(self, retries=3):
        try:
            api_key = self.api_keys.get('pulsedive')
            if not api_key:
                raise ValueError("Pulsedive API key not found.")

            all_threats = []
            for fid in range(1, 6):  # Fetch data for fid 1 to 5
                for attempt in range(retries):
                    try:
                        url = 'https://pulsedive.com/api/info.php'
                        params = {
                            'fid': fid,
                            'pretty': '1',
                            'key': api_key
                        }
                        response = requests.get(url, params=params)
                        
                        if response.status_code == 429:  # Rate limit exceeded
                            time.sleep(2 ** attempt)  # Exponential backoff
                            continue
                            
                        response.raise_for_status()
                        threats = response.json()
                        
                        if isinstance(threats, dict):
                            all_threats.append(threats)
                        elif isinstance(threats, list):
                            all_threats.extend(threats)
                            
                        time.sleep(1.1)  # Ensure we stay under rate limit
                        break  # Success, move to next FID
                        
                    except requests.exceptions.RequestException as e:
                        if attempt == retries - 1:
                            print(f"Failed to fetch FID {fid} after {retries} attempts: {str(e)}")
                        else:
                            time.sleep(2 ** attempt)  # Exponential backoff

            print("\n=== Pulsedive Results ===")
            print(json.dumps(all_threats, indent=4))
            return all_threats
            
        except Exception as e:
            print(f"ERROR: Pulsedive Data validation failed: {str(e)}")
            return []

    def _process_otx_data(self, data):
        """Process OTX API response data"""
        return [{
            'source': 'OTX',
            'title': pulse.get('name'),
            'description': pulse.get('description'),
            'indicators': [i['indicator'] for i in pulse.get('indicators', [])],
            'timestamp': pulse.get('modified')
        } for pulse in data.get('results', [])]


    def _process_threatfox_data(self, data):
        """Process ThreatFox API response data"""
        return [{
            'source': 'ThreatFox',
            'ioc': ioc.get('ioc'),
            'ioc_type': ioc.get('ioc_type'),
            'threat_type': ioc.get('threat_type'),
            'malware': ioc.get('malware'),
            'first_seen': ioc.get('first_seen_utc')
        } for ioc in data.get('data', [])]

    def set_api_key(self, platform, key):
        """Set API key for a specific platform"""
        if platform not in self.api_keys:
            raise ValueError(f"Invalid platform: {platform}")
        self.api_keys[platform] = key

    def get_api_key(self, platform):
        """Get API key for a specific platform"""
        return self.api_keys.get(platform)

    def remove_api_key(self, platform):
        """Remove API key for a specific platform"""
        if platform in self.api_keys:
            self.api_keys[platform] = None

    def _get_headers(self, platform):
        """Generate headers with API key if available"""
        headers = {'Content-Type': 'application/json'}
        if self.api_keys[platform]:
            if platform == 'otx':
                headers['X-OTX-API-KEY'] = self.api_keys[platform]
            elif platform == 'threatfox':
                headers['Authorization'] = f"Bearer {self.api_keys[platform]}"
        return headers

if __name__ == "__main__":
    tester = ThreatFeedTester()
    
    # Set API keys (if you have them)
    tester.set_api_key('otx', '74a4a5952635789101271500d1a61281e78ab1b7c4f515819a6b6f112c64fc1f')
    tester.set_api_key('threatfox', '66ec3df79abee07b4ae4b1655c823405cde2021871340a83')
    tester.set_api_key('pulsedive', '54589826af335f275e53017ee18944d76891662c8d77c0f11be174aae133e930')

    
    print("Testing OTX:")
    print(json.dumps(tester.test_otx(), indent=2))

    print("\nTesting ThreatFox:")
    print(json.dumps(tester.test_threatfox(), indent=2))

    tester.test_pulsedive()