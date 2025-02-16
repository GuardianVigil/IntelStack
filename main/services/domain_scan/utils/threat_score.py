"""
Utility for calculating threat scores from aggregated domain data
"""
from typing import Dict, Any

def calculate_threat_score(aggregated_data: Dict[str, Any]) -> int:
    """
    Calculate a threat score from 0-100 based on aggregated platform data
    
    Args:
        aggregated_data: Aggregated data from all platforms
        
    Returns:
        Threat score from 0-100
    """
    score = 0
    total_weight = 0
    
    # Platform-specific scoring weights
    PLATFORM_WEIGHTS = {
        'virustotal': 0.3,    # 30% weight
        'alienvault': 0.25,   # 25% weight
        'pulsedive': 0.2,     # 20% weight
        'metadefender': 0.15, # 15% weight
        'securitytrails': 0.1 # 10% weight
    }
    
    try:
        platform_data = aggregated_data.get('platform_data', {})
        
        for platform, data in platform_data.items():
            if not data or isinstance(data, str) or 'error' in data:
                continue
                
            weight = PLATFORM_WEIGHTS.get(platform, 0.1)
            platform_score = 0
            
            # VirusTotal scoring
            if platform == 'virustotal':
                detections = data.get('detected_urls', 0) + data.get('detected_files', 0)
                max_detections = 100  # Arbitrary max
                platform_score = min((detections / max_detections) * 100, 100)
            
            # AlienVault scoring
            elif platform == 'alienvault':
                pulse_count = data.get('pulse_count', 0)
                max_pulses = 50  # Arbitrary max
                platform_score = min((pulse_count / max_pulses) * 100, 100)
            
            # Pulsedive scoring
            elif platform == 'pulsedive':
                risk_level = data.get('risk_level', '').lower()
                platform_score = {
                    'none': 0,
                    'low': 25,
                    'medium': 50,
                    'high': 75,
                    'critical': 100
                }.get(risk_level, 0)
            
            # MetaDefender scoring
            elif platform == 'metadefender':
                detected_by = data.get('lookup_results', {}).get('detected_by', 0)
                max_detections = 20  # Typical max detections
                platform_score = min((detected_by / max_detections) * 100, 100)
            
            # SecurityTrails scoring
            elif platform == 'securitytrails':
                # Base score on associated malicious domains and SSL issues
                associated_count = len(data.get('associated_domains', {}).get('subdomains', []))
                ssl_issues = len(data.get('ssl_certificates', {}).get('certificates', []))
                max_issues = 50  # Arbitrary max
                platform_score = min(((associated_count + ssl_issues) / max_issues) * 100, 100)
            
            score += platform_score * weight
            total_weight += weight
    
    except Exception as e:
        # If there's an error, return a moderate score
        return 50
    
    # Normalize score based on total weight
    if total_weight > 0:
        final_score = int(score / total_weight)
    else:
        final_score = 0
    
    return min(max(final_score, 0), 100)  # Ensure score is between 0-100
