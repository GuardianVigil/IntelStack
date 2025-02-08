"""
Threat scoring module for IP analysis
"""

def calculate_threat_score(platform_scores):
    """
    Calculate overall threat score based on weighted platform scores
    Returns None if no valid scores are available
    """
    if not platform_scores or not isinstance(platform_scores, dict):
        return None
        
    weights = {
        'virustotal': 0.35,
        'abuseipdb': 0.25,
        'greynoise': 0.25,
        'securitytrails': 0.15
    }
    
    total_score = 0
    total_weight = 0
    
    for platform, score in platform_scores.items():
        if score is not None and platform in weights:
            total_score += score * weights[platform]
            total_weight += weights[platform]
    
    if total_weight == 0:
        return None
        
    final_score = total_score / total_weight
    return round(final_score, 2)

def get_threat_details(score):
    """
    Get threat level and recommendation based on score
    Returns a default response if score is None
    """
    if score is None:
        return {
            'threat_level': 'Unknown',
            'recommendation': 'Unable to determine threat level. Please check individual platform results for more information.'
        }
        
    # Determine threat level
    if score >= 80:
        threat_level = "Critical"
        recommendation = "Immediate action required. Block this IP immediately and investigate any connections."
    elif score >= 60:
        threat_level = "High"
        recommendation = "Strong recommendation to block this IP and monitor related activities."
    elif score >= 40:
        threat_level = "Medium"
        recommendation = "Consider blocking this IP and investigate any suspicious activities."
    elif score >= 20:
        threat_level = "Low"
        recommendation = "Monitor activities from this IP for any suspicious behavior."
    else:
        threat_level = "Safe"
        recommendation = "No significant threats detected. Continue routine monitoring."

    return {
        'threat_level': threat_level,
        'recommendation': recommendation
    }
