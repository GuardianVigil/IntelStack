"""
Platform-specific scoring utilities
"""
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

def calculate_platform_scores(data: Dict[str, Any], platform: str) -> Optional[float]:
    """
    Calculate threat scores for each platform
    
    Args:
        data: Platform-specific response data
        platform: Platform name
        
    Returns:
        Threat score between 0-100, or None if score cannot be calculated
    """
    if not platform or not data:
        return None
        
    try:
        if "error" in data:
            return None
            
        if platform == 'virustotal':
            if not isinstance(data, dict) or 'data' not in data:
                return None
                
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            if not last_analysis_stats:
                return None
                
            total_scans = sum(last_analysis_stats.values())
            if total_scans == 0:
                return None
                
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            
            # Weight malicious results higher than suspicious
            score = ((malicious * 1.0) + (suspicious * 0.5)) / total_scans * 100
            return min(100, score)
            
        elif platform == 'abuseipdb':
            if not isinstance(data.get('data', {}), dict):
                return None
                
            abuse_confidence_score = data.get('data', {}).get('abuseConfidenceScore')
            if abuse_confidence_score is None:
                return None
                
            return float(abuse_confidence_score)
            
        elif platform == 'greynoise':
            if not isinstance(data, dict):
                return None
                
            classification = data.get('classification', '').lower()
            noise = data.get('noise', False)
            riot = data.get('riot', False)
            
            base_score = {
                'malicious': 100,
                'suspicious': 50,
                'unknown': 25,
                'benign': 0
            }.get(classification, 0)
            
            if noise:
                base_score = min(100, base_score + 20)
            if riot:
                base_score = max(0, base_score - 30)
                
            return base_score if base_score > 0 else None
            
        elif platform == 'crowdsec':
            if not isinstance(data, dict):
                return None
                
            score = 0
            
            # Use overall score if available
            scores = data.get('scores', {}).get('overall', {})
            if scores:
                total = scores.get('total')
                if total is not None:
                    score += float(total) * 25  # Scale 0-4 to 0-100
                    
            # Add score for behaviors
            behaviors = data.get('behaviors', [])
            if behaviors:
                score += min(50, len(behaviors) * 10)  # Each behavior adds 10 points up to 50
                
            # Add score for attack details
            attack_details = data.get('attack_details', [])
            if attack_details:
                score += min(25, len(attack_details) * 5)  # Each attack detail adds 5 points up to 25
                
            return min(100, score) if score > 0 else None
            
    except Exception as e:
        logger.error(f"Error calculating {platform} score: {str(e)}")
        return None
            
    return None

def calculate_combined_score(platform_scores: Dict[str, float]) -> Dict[str, Any]:
    """
    Calculate combined threat score from multiple platforms
    
    Args:
        platform_scores: Dictionary of platform names and their scores
        
    Returns:
        Dictionary containing overall_score and platform-specific details
    """
    if not platform_scores:
        return {
            "overall_score": 0,
            "confidence": 0,
            "platform_scores": {}
        }
        
    # Platform weights
    weights = {
        'virustotal': 0.20,
        'abuseipdb': 0.15,
        'greynoise': 0.15,
        'crowdsec': 0.10,
        'securitytrails': 0.10,
        'alienvault': 0.15,
        'metadefender': 0.10,
        'pulsedive': 0.05
    }
    
    total_weight = 0
    weighted_score = 0
    
    for platform, score in platform_scores.items():
        if score is not None and platform in weights:
            weight = weights[platform]
            weighted_score += score * weight
            total_weight += weight
            
    if total_weight == 0:
        return {
            "overall_score": 0,
            "confidence": 0,
            "platform_scores": platform_scores
        }
        
    # Normalize the score based on total weight
    overall_score = weighted_score / total_weight
    
    # Calculate confidence based on number of platforms that returned scores
    max_platforms = len(weights)
    platforms_with_scores = len([s for s in platform_scores.values() if s is not None])
    confidence = (platforms_with_scores / max_platforms) * 100
    
    return {
        "overall_score": round(overall_score, 2),
        "confidence": round(confidence, 2),
        "platform_scores": platform_scores
    }
