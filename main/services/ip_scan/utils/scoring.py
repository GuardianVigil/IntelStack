"""
Scoring utilities for IP analysis
"""
from typing import Dict, Any, Optional

PLATFORM_WEIGHTS = {
    # Existing Platforms
    'virustotal': 0.15,     # Comprehensive malware analysis
    'abuseipdb': 0.10,      # Abuse reporting
    'greynoise': 0.10,      # Network intelligence
    'crowdsec': 0.10,       # Real-time threats
    'securitytrails': 0.10, # Historical data
    
    # New Platforms
    'alienvault': 0.15,     # Threat intelligence
    'metadefender': 0.10,   # Multi-engine scanning
    'pulsedive': 0.10,      # Risk analysis
    'ipinfo': 0.10          # Network context
}

def calculate_combined_score(platform_scores: Dict[str, Optional[float]]) -> Dict[str, Any]:
    """
    Calculate combined threat score from multiple platforms
    
    Args:
        platform_scores: Dictionary of platform names and their scores
        
    Returns:
        Dictionary containing:
            - overall_score: Combined threat score (0-100)
            - confidence: Confidence in the score (0-100)
            - platform_scores: Individual platform scores and weights
    """
    final_score = {
        "overall_score": 0,
        "confidence": 0,
        "platform_scores": {},
        "risk_factors": []
    }
    
    total_weight = 0
    weighted_score = 0
    
    for platform, score in platform_scores.items():
        if score is not None:
            weight = PLATFORM_WEIGHTS.get(platform, 0)
            weighted_score += score * weight
            total_weight += weight
            
            final_score["platform_scores"][platform] = {
                "score": score,
                "weight": weight
            }
    
    if total_weight > 0:
        # Normalize the score based on available platforms
        final_score["overall_score"] = round(weighted_score / total_weight)
        final_score["confidence"] = (total_weight / sum(PLATFORM_WEIGHTS.values())) * 100
    
    return final_score

def get_risk_level(score: Optional[float]) -> Dict[str, str]:
    """
    Get risk level and recommendation based on score
    
    Args:
        score: Threat score between 0-100
        
    Returns:
        Dictionary containing risk level and recommendation
    """
    if score is None:
        return {
            'level': 'Unknown',
            'recommendation': 'Unable to determine risk level. Please check individual platform results.'
        }
        
    if score >= 80:
        return {
            'level': 'Critical',
            'recommendation': 'Immediate action required. Block this IP immediately and investigate any connections.'
        }
    elif score >= 60:
        return {
            'level': 'High',
            'recommendation': 'Strong recommendation to block this IP and monitor related activities.'
        }
    elif score >= 40:
        return {
            'level': 'Medium',
            'recommendation': 'Consider blocking this IP and investigate any suspicious activities.'
        }
    elif score >= 20:
        return {
            'level': 'Low',
            'recommendation': 'Monitor activities from this IP for any suspicious behavior.'
        }
    else:
        return {
            'level': 'Safe',
            'recommendation': 'No immediate action required. Continue standard monitoring.'
        }
