from typing import Dict, Any, List, Optional
from datetime import datetime

class DomainInfo:
    def __init__(self):
        self.domain: str = ""
        self.apex_domain: str = ""
        self.ip_addresses: List[str] = []
        self.asn_info: List[str] = []
        self.countries: List[str] = []
        self.server: Optional[str] = None
        self.last_analysis: Optional[datetime] = None
        self.registrar: Optional[str] = None
        self.created_date: Optional[datetime] = None
        self.updated_date: Optional[datetime] = None
        self.ssl_info: Dict[str, Any] = {}
        self.redirects: List[Dict[str, Any]] = []

    @classmethod
    def from_scan_results(cls, urlscan_result: Dict[str, Any], 
                         virustotal_result: Dict[str, Any], 
                         hybrid_result: Dict[str, Any]) -> 'DomainInfo':
        """
        Create a DomainInfo instance from the results of multiple scanning platforms
        """
        info = cls()
        
        # Extract information from URLScan.io
        if urlscan_result:
            page_info = urlscan_result.get("page", {})
            lists_info = urlscan_result.get("lists", {})
            
            info.domain = page_info.get("domain", "")
            info.apex_domain = page_info.get("apexDomain", "")
            info.ip_addresses.extend(lists_info.get("ips", []))
            info.asn_info.extend(lists_info.get("asns", []))
            info.countries.extend(lists_info.get("countries", []))
            info.server = page_info.get("server")
            
            # Get SSL/TLS information
            certificates = lists_info.get("certificates", [])
            if certificates:
                info.ssl_info = certificates[0]
            
            # Get redirect information
            if "data" in urlscan_result and "requests" in urlscan_result["data"]:
                for req in urlscan_result["data"]["requests"]:
                    if "redirectResponse" in req:
                        info.redirects.append({
                            "from_url": req["request"]["url"],
                            "to_url": req["redirectResponse"]["headers"].get("Location", ""),
                            "status_code": req["redirectResponse"]["status"]
                        })

        # Extract information from VirusTotal
        if virustotal_result:
            attributes = virustotal_result.get("data", {}).get("attributes", {})
            if "date" in attributes:
                info.last_analysis = datetime.fromtimestamp(attributes["date"])

        # Extract information from Hybrid Analysis
        if hybrid_result:
            # Add any unique IP addresses
            hybrid_ips = hybrid_result.get("hosts", [])
            info.ip_addresses.extend([ip for ip in hybrid_ips if ip not in info.ip_addresses])
            
            # Add domain information
            hybrid_domains = hybrid_result.get("domains", [])
            if hybrid_domains and not info.domain:
                info.domain = hybrid_domains[0]

        # Remove duplicates
        info.ip_addresses = list(set(info.ip_addresses))
        info.asn_info = list(set(info.asn_info))
        info.countries = list(set(info.countries))

        return info

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the domain information to a dictionary format
        """
        return {
            "domain": self.domain,
            "apex_domain": self.apex_domain,
            "ip_addresses": self.ip_addresses,
            "asn_info": self.asn_info,
            "countries": self.countries,
            "server": self.server,
            "last_analysis": self.last_analysis.isoformat() if self.last_analysis else None,
            "registrar": self.registrar,
            "created_date": self.created_date.isoformat() if self.created_date else None,
            "updated_date": self.updated_date.isoformat() if self.updated_date else None,
            "ssl_info": self.ssl_info,
            "redirects": self.redirects
        }

def get_domain_info(urlscan_result: Dict[str, Any], 
                   virustotal_result: Dict[str, Any], 
                   hybrid_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get comprehensive domain information from multiple scanning platforms
    """
    domain_info = DomainInfo.from_scan_results(
        urlscan_result=urlscan_result,
        virustotal_result=virustotal_result,
        hybrid_result=hybrid_result
    )
    return domain_info.to_dict()
