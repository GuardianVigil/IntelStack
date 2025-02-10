"""
AlienVault OTX scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class AlienVaultScanner(BaseScanner):
    """Scanner for AlienVault OTX platform"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://otx.alienvault.com/api/v1"

    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query AlienVault OTX API for IP information"""
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        }
        
        # Get general indicator details
        url = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
        general_data = await self._make_request("GET", url, headers=headers)
        if "error" in general_data:
            return general_data
            
        # Get reputation data
        reputation_url = f"{self.base_url}/indicators/IPv4/{ip_address}/reputation"
        reputation_data = await self._make_request("GET", reputation_url, headers=headers)
        
        # Get geo data
        geo_url = f"{self.base_url}/indicators/IPv4/{ip_address}/geo"
        geo_data = await self._make_request("GET", geo_url, headers=headers)
        
        # Get malware data
        malware_url = f"{self.base_url}/indicators/IPv4/{ip_address}/malware"
        malware_data = await self._make_request("GET", malware_url, headers=headers)
        
        # Get passive DNS data
        pdns_url = f"{self.base_url}/indicators/IPv4/{ip_address}/passive_dns"
        pdns_data = await self._make_request("GET", pdns_url, headers=headers)
        
        return {
            "general": general_data,
            "reputation": reputation_data if "error" not in reputation_data else {},
            "geo": geo_data if "error" not in geo_data else {},
            "malware": malware_data if "error" not in malware_data else {},
            "passive_dns": pdns_data if "error" not in pdns_data else {}
        }

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from AlienVault OTX data"""
        if not isinstance(data, dict):
            return None
            
        score = 0
        factors = []
        
        # Check pulse data
        general = data.get("general", {})
        if "pulse_info" in general:
            pulse_info = general["pulse_info"]
            num_pulses = len(pulse_info.get("pulses", []))
            if num_pulses > 0:
                pulse_score = min(50, num_pulses * 10)  # Max 50 points from pulses
                score += pulse_score
                factors.append(f"Found in {num_pulses} threat pulses")
        
        # Check reputation data - Fixed None handling
        reputation = data.get("reputation", {})
        if reputation:
            reputation_score = reputation.get("reputation")
            if reputation_score is not None:
                score += float(reputation_score) * 10  # Reputation is 0-10, multiply by 10
                factors.append(f"Reputation score: {reputation_score}")
        
        # Check malware data
        malware = data.get("malware", {})
        if malware.get("samples", []):
            num_samples = len(malware["samples"])
            malware_score = min(30, num_samples * 5)  # Max 30 points from malware
            score += malware_score
            factors.append(f"Associated with {num_samples} malware samples")
        
        return min(100, score) if score > 0 else None

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from AlienVault OTX data"""
        whois_data = {
            "source": "alienvault",
            "organization": None,
            "domain_names": []
        }
        
        if not isinstance(data, dict):
            return whois_data
            
        # Extract organization from general data
        general = data.get("general", {})
        if "organization" in general:
            whois_data["organization"] = general["organization"]
            
        # Extract associated domains from passive DNS
        pdns = data.get("passive_dns", {})
        if "passive_dns" in pdns:
            domains = []
            for record in pdns["passive_dns"]:
                if "hostname" in record:
                    domains.append(record["hostname"])
            whois_data["domain_names"] = domains[:10]  # Limit to 10 domains
            
        return whois_data

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from AlienVault OTX data"""
        network_info = {
            "source": "alienvault",
            "organization": None,
            "network": {
                "country": None,
                "city": None,
                "coordinates": {
                    "latitude": None,
                    "longitude": None
                }
            },
            "asn": None
        }
        
        if not isinstance(data, dict):
            return network_info
            
        # Extract geo information
        geo = data.get("geo", {})
        if geo:
            network_info["network"].update({
                "country": geo.get("country_name"),
                "city": geo.get("city"),
                "coordinates": {
                    "latitude": geo.get("latitude"),
                    "longitude": geo.get("longitude")
                }
            })
            
        # Extract organization and ASN
        general = data.get("general", {})
        if general:
            network_info.update({
                "organization": general.get("organization"),
                "asn": general.get("asn")
            })
            
        return network_info
