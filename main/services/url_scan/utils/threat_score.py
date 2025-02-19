"""
Threat score calculation utilities
"""
from typing import Dict, List, Optional

def calculate_overall_threat_score(scores: List[Optional[float]]) -> float:
    """Calculate overall threat score from multiple sources"""
    valid_scores = [s for s in scores if s is not None]
    if not valid_scores:
        return 0.0
    return sum(valid_scores) / len(valid_scores)

def get_threat_level(score: float) -> str:
    """Convert numerical score to threat level"""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    return "Clean"