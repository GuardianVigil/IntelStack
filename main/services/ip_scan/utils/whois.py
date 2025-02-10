"""
WHOIS data utilities for IP analysis
"""
from typing import Dict, Any, List
from datetime import datetime

def combine_whois_data(whois_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Combine WHOIS data from multiple sources
    
    Args:
        whois_data: List of WHOIS data from different platforms
        
    Returns:
        Combined WHOIS information
    """
    combined = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "last_updated": None,
        "registrant": {
            "name": None,
            "organization": None,
            "email": None
        },
        "admin": {
            "name": None,
            "organization": None,
            "email": None
        },
        "technical": {
            "name": None,
            "organization": None,
            "email": None
        }
    }
    
    # Track which platforms provided which fields
    sources = {}
    
    for data in whois_data:
        if not data:
            continue
            
        platform = data.get("source", "unknown")
        
        # Basic WHOIS fields
        if data.get("registrar"):
            combined["registrar"] = data["registrar"]
            sources["registrar"] = platform
            
        # Dates - convert to ISO format if needed
        for date_field in ["creation_date", "expiration_date", "last_updated"]:
            if date_field in data:
                try:
                    if isinstance(data[date_field], str):
                        # Try to parse and standardize date format
                        date = datetime.fromisoformat(data[date_field].replace('Z', '+00:00'))
                        combined[date_field] = date.isoformat()
                        sources[date_field] = platform
                except (ValueError, TypeError):
                    pass
        
        # Contact information
        for contact_type in ["registrant", "admin", "technical"]:
            if contact_type in data:
                contact = data[contact_type]
                if isinstance(contact, dict):
                    for field in ["name", "organization", "email"]:
                        if contact.get(field) and not combined[contact_type][field]:
                            combined[contact_type][field] = contact[field]
                            sources[f"{contact_type}_{field}"] = platform
    
    # Add source information
    combined["_sources"] = sources
    
    return combined
