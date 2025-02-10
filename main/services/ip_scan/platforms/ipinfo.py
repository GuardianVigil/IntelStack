"""
IPInfo scanner implementation
"""
from typing import Dict, Any, Optional, Tuple
from .base_scanner import BaseScanner
import logging
import aiohttp

class IPInfoScanner(BaseScanner):
    """Scanner for IPInfo API"""
    
    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        super().__init__(session, api_key)
        self.base_url = "https://ipinfo.io"
        self.platform_name = 'ipinfo'
        self.logger = logging.getLogger(__name__)
        
    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query IPInfo API for IP information"""
        url = f"{self.base_url}/{ip_address}/json?token={self.api_key}"
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'ThreatIntel-Scanner/1.0'
        }
        
        # Log the request details (safely)
        key_preview = self.api_key[:4] + '***' if self.api_key else None
        self.logger.info(f"IPInfo request - URL: {self.base_url}/{ip_address}/json?token=<hidden>, Key Preview: {key_preview}")
        
        try:
            basic_info = await self._make_request("GET", url, headers=headers)
            self.logger.info(f"IPInfo basic info response: {basic_info}")
            
            if isinstance(basic_info, dict):
                if basic_info.get("error", {}).get("title") == "Unauthorized":
                    self.logger.error(f"IPInfo authentication error: {basic_info}")
                    return {"error": "API authentication error. Check API key."}
                
                # Extract ASN and organization from org field if available
                if "org" in basic_info:
                    asn, org = self._parse_org_field(basic_info["org"])
                    basic_info["asn"] = asn
                    basic_info["organization"] = org
                
                # Parse location coordinates if available
                if "loc" in basic_info:
                    try:
                        lat, lon = basic_info["loc"].split(",")
                        basic_info["latitude"] = float(lat)
                        basic_info["longitude"] = float(lon)
                    except (ValueError, TypeError):
                        self.logger.warning(f"Failed to parse location coordinates: {basic_info['loc']}")
                
                return basic_info
            
            self.logger.error(f"IPInfo invalid response format: {basic_info}")
            return {"error": "Invalid response format"}
        except Exception as e:
            self.logger.error(f"IPInfo request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}"}

    def _parse_org_field(self, org_field: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse ASN and organization from org field"""
        if not org_field:
            return None, None
            
        parts = org_field.split(" ", 1)
        if len(parts) == 2 and parts[0].startswith("AS"):
            return parts[0], parts[1]
        return None, org_field

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from IPInfo data"""
        if not isinstance(data, dict) or "error" in data:
            return None
            
        score = 0
        
        # Score based on organization/ASN
        org = data.get("organization", "").lower()
        if any(keyword in org for keyword in ["hosting", "datacenter", "cloud"]):
            score += 10
            
        # Score based on hostname indicators
        hostname = data.get("hostname", "").lower()
        if any(indicator in hostname for indicator in ["tor", "vpn", "proxy", "exit"]):
            score += 25
            
        # Score based on known hosting ASNs
        asn = data.get("asn", "")
        if asn:
            known_hosting_asns = {"AS13335", "AS14061", "AS16509", "AS15169"}  # Cloudflare, Digital Ocean, AWS, Google
            if asn in known_hosting_asns:
                score += 15
                
        return score if score > 0 else None

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from IPInfo data"""
        whois_data = {
            "source": "ipinfo",
            "organization": None,
            "asn": None,
            "network": None,
            "country": None,
            "city": None,
            "region": None,
            "coordinates": None,
            "hostname": None,
            "timezone": None
        }
        
        if not isinstance(data, dict):
            return whois_data
            
        whois_data.update({
            "organization": data.get("organization"),
            "asn": data.get("asn"),
            "country": data.get("country"),
            "city": data.get("city"),
            "region": data.get("region"),
            "hostname": data.get("hostname"),
            "timezone": data.get("timezone")
        })
        
        # Add coordinates if available
        if "latitude" in data and "longitude" in data:
            whois_data["coordinates"] = {
                "latitude": data["latitude"],
                "longitude": data["longitude"]
            }
            
        return whois_data

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from IPInfo data"""
        network_info = {
            "source": "ipinfo",
            "asn": None,
            "organization": None,
            "privacy": {
                "is_vpn": False,
                "is_proxy": False,
                "is_tor": False,
                "is_hosting": False
            },
            "network": {
                "network": None,
                "country": None,
                "region": None,
                "city": None,
                "coordinates": None
            }
        }
        
        if not isinstance(data, dict):
            return network_info
            
        # Update network information
        network_info.update({
            "asn": data.get("asn"),
            "organization": data.get("organization"),
            "network": {
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "coordinates": None
            }
        })
        
        # Parse coordinates if available
        if "latitude" in data and "longitude" in data:
            network_info["network"]["coordinates"] = {
                "latitude": data["latitude"],
                "longitude": data["longitude"]
            }
        
        # Detect privacy flags from hostname and organization
        hostname = data.get("hostname", "").lower()
        org = data.get("organization", "").lower()
        
        network_info["privacy"].update({
            "is_tor": "tor" in hostname or "tor" in org,
            "is_vpn": "vpn" in hostname or "vpn" in org,
            "is_proxy": "proxy" in hostname or "proxy" in org,
            "is_hosting": any(keyword in org for keyword in ["hosting", "datacenter", "cloud"])
        })
        
        return network_info
