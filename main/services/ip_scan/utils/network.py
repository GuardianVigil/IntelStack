"""
Network information utilities for IP analysis
"""
from typing import Dict, Any, List

def combine_network_info(network_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Combine network information from multiple sources
    
    Args:
        network_data: List of network data from different platforms
        
    Returns:
        Combined network information
    """
    combined = {
        "asn": None,
        "isp": None,
        "organization": None,
        "usage_type": None,
        "privacy": {
            "is_vpn": False,
            "is_proxy": False,
            "is_tor": False,
            "is_datacenter": False,
            "is_hosting": False
        },
        "network": {
            "network": None,
            "prefix": None,
            "country": None,
            "region": None,
            "city": None,
            "coordinates": {
                "latitude": None,
                "longitude": None
            }
        }
    }
    
    # Track which platforms provided which fields
    sources = {}
    
    for data in network_data:
        if not data:
            continue
            
        platform = data.get("source", "unknown")
        
        # Basic network fields
        for field in ["asn", "isp", "organization", "usage_type"]:
            if data.get(field) and not combined[field]:
                combined[field] = data[field]
                sources[field] = platform
        
        # Privacy flags
        if "privacy" in data:
            privacy = data["privacy"]
            for flag in ["is_vpn", "is_proxy", "is_tor", "is_datacenter", "is_hosting"]:
                if privacy.get(flag):
                    combined["privacy"][flag] = True
                    sources[f"privacy_{flag}"] = platform
        
        # Network location information
        if "network" in data:
            network = data["network"]
            for field in ["network", "prefix", "country", "region", "city"]:
                if network.get(field) and not combined["network"][field]:
                    combined["network"][field] = network[field]
                    sources[f"network_{field}"] = platform
            
            # Coordinates
            if "latitude" in network and "longitude" in network:
                if not combined["network"]["coordinates"]["latitude"]:
                    combined["network"]["coordinates"].update({
                        "latitude": network["latitude"],
                        "longitude": network["longitude"]
                    })
                    sources["network_coordinates"] = platform
    
    # Add source information
    combined["_sources"] = sources
    
    return combined
