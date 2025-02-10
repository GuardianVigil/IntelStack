"""
Pulsedive scanner implementation
"""
from typing import Dict, Any, Optional
from .base_scanner import BaseScanner

class PulsediveScanner(BaseScanner):
    """Scanner for Pulsedive platform"""

    def __init__(self, session, api_key):
        super().__init__(session, api_key)
        self.base_url = "https://pulsedive.com/api/info.php"

    async def scan(self, ip_address: str) -> Dict[str, Any]:
        """Query Pulsedive API for IP information"""
        params = {
            "indicator": ip_address,
            "key": self.api_key,
            "pretty": 1,
            "get_meta": 1,  # Get additional metadata
            "get_feeds": 1,  # Get feed information
            "get_properties": 1  # Get property information
        }
        
        return await self._make_request("GET", self.base_url, params=params)

    def calculate_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Calculate threat score from Pulsedive data"""
        if not isinstance(data, dict):
            return None
            
        # Risk level mapping
        risk_scores = {
            "none": 0,
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100
        }
        
        # Base score from risk level
        score = risk_scores.get(data.get("risk", "none").lower(), 0)
        
        # Adjust score based on additional factors
        if "riskfactors" in data:
            for factor in data["riskfactors"]:
                # Add points based on risk factor severity
                factor_risk = factor.get("risk", "").lower()
                score += risk_scores.get(factor_risk, 0) * 0.2  # 20% weight for each risk factor
                
        # Adjust for threats
        if "threats" in data:
            score += len(data["threats"]) * 10  # 10 points per associated threat
            
        # Adjust for feeds
        if "feeds" in data:
            score += len(data["feeds"]) * 5  # 5 points per feed listing
            
        return min(100, score)

    def extract_whois(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract WHOIS information from Pulsedive data"""
        whois_data = {
            "source": "pulsedive",
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "last_updated": None,
            "registrant": {
                "name": None,
                "organization": None,
                "email": None
            }
        }
        
        if not isinstance(data, dict):
            return whois_data
            
        properties = data.get("properties", {})
        whois = properties.get("whois", {})
        
        if whois:
            whois_data.update({
                "registrar": whois.get("registrar"),
                "creation_date": whois.get("creation_date"),
                "expiration_date": whois.get("expiration_date"),
                "last_updated": whois.get("updated_date")
            })
            
            # Extract registrant information if available
            registrant = whois.get("registrant", {})
            if registrant:
                whois_data["registrant"].update({
                    "name": registrant.get("name"),
                    "organization": registrant.get("organization"),
                    "email": registrant.get("email")
                })
                
        return whois_data

    def extract_network_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from Pulsedive data"""
        network_info = {
            "source": "pulsedive",
            "organization": None,
            "network": {
                "country": None,
                "coordinates": {
                    "latitude": None,
                    "longitude": None
                }
            },
            "protocols": [],
            "ports": []
        }
        
        if not isinstance(data, dict):
            return network_info
            
        properties = data.get("properties", {})
        
        # Extract geo information
        geo = properties.get("geo", {})
        if geo:
            network_info["network"].update({
                "country": geo.get("country"),
                "coordinates": {
                    "latitude": geo.get("latitude"),
                    "longitude": geo.get("longitude")
                }
            })
            
        # Extract protocols and ports
        if "protocol" in properties:
            network_info["protocols"] = properties["protocol"]
        if "port" in properties:
            network_info["ports"] = properties["port"]
            
        return network_info
