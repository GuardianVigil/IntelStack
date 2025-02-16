"""
Utility functions for calculating threat and confidence scores
"""
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

def calculate_threat_score(platform_results: Dict[str, Any]) -> float:
    """
    Calculate overall threat score from platform results
    
    Args:
        platform_results: Dictionary containing results from each platform
        
    Returns:
        Threat score between 0-100
    """
    try:
        total_score = 0
        weights = 0
        
        for platform, result in platform_results.items():
            if result.get("status") == "success" and "data" in result:
                # Get platform-specific score if available
                platform_score = _get_platform_score(platform, result["data"])
                if platform_score is not None:
                    weight = _get_platform_weight(platform)
                    total_score += platform_score * weight
                    weights += weight
        
        # Return weighted average if we have scores
        if weights > 0:
            return round(total_score / weights, 2)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error calculating threat score: {str(e)}")
        return 0

def calculate_confidence_score(platform_results: Dict[str, Any]) -> float:
    """
    Calculate confidence score based on number of responding platforms and their reliability
    
    Args:
        platform_results: Dictionary containing results from each platform
        
    Returns:
        Confidence score between 0-100
    """
    try:
        total_weight = 0
        available_weight = 0
        
        for platform, result in platform_results.items():
            weight = _get_platform_weight(platform)
            available_weight += weight
            
            if result.get("status") == "success" and "data" in result:
                total_weight += weight
        
        if available_weight > 0:
            return round((total_weight / available_weight) * 100, 2)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error calculating confidence score: {str(e)}")
        return 0

def _get_platform_score(platform: str, data: Dict[str, Any]) -> float:
    """Get normalized threat score (0-100) from platform-specific data"""
    try:
        if platform == "virustotal":
            return _normalize_virustotal_score(data)
        # Add other platform-specific score calculations here
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting platform score for {platform}: {str(e)}")
        return None

def _get_platform_weight(platform: str) -> float:
    """Get weight for platform (0-1) based on reliability and completeness"""
    weights = {
        "virustotal": 1.0,
        "abuseipdb": 0.8,
        "greynoise": 0.7,
        "crowdsec": 0.6,
        "securitytrails": 0.7,
        "ipinfo": 0.5,
        "metadefender": 0.8,
        "pulsedive": 0.6,
        "alienvault": 0.7
    }
    return weights.get(platform, 0.5)

def _normalize_virustotal_score(data: Dict[str, Any]) -> float:
    """Normalize VirusTotal data to a 0-100 score"""
    try:
        total_score = 0
        components = 0
        
        # Score from URLs
        for url_data in data.get("urls", []):
            if "malicious" in url_data and "total" in url_data:
                score = (url_data["malicious"] / url_data["total"]) * 100
                total_score += score
                components += 1
        
        # Score from attachments
        for attachment_data in data.get("attachments", []):
            if "malicious" in attachment_data and "total" in attachment_data:
                score = (attachment_data["malicious"] / attachment_data["total"]) * 100
                total_score += score
                components += 1
        
        # Return average if we have components
        if components > 0:
            return round(total_score / components, 2)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error normalizing VirusTotal score: {str(e)}")
        return 0
