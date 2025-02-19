"""
WHOIS lookup utilities
"""
import whois
from typing import Dict, Any, Optional

async def get_whois_info(url: str) -> Dict[str, Any]:
    """Get WHOIS information for a domain"""
    try:
        w = whois.whois(url)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "status": w.status,
            "name_servers": w.name_servers,
            "registrant": {
                "name": w.name,
                "organization": w.org,
                "email": w.email
            }
        }
    except Exception as e:
        return {"error": str(e)}