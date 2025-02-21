"""Scoring module for email analysis"""
from typing import Dict, Any, List

def calculate_threat_score(analysis: Dict[str, Any]) -> int:
    """
    Calculate overall threat score based on multiple factors
    
    Args:
        analysis: Complete analysis results
        
    Returns:
        Integer score from 0-100
    """
    scores = {
        'authentication': _score_authentication(analysis['authentication']),
        'ip_reputation': _score_ip_reputation(analysis['ip_analysis']),
        'url_analysis': _score_urls(analysis['url_analysis']),
        'attachments': _score_attachments(analysis.get('attachments', [])),
        'headers': _score_headers(analysis['header_analysis'])
    }
    
    weights = {
        'authentication': 0.3,
        'ip_reputation': 0.2,
        'url_analysis': 0.2,
        'attachments': 0.2,
        'headers': 0.1
    }
    
    final_score = sum(score * weights[key] for key, score in scores.items())
    return min(round(final_score * 100), 100)  # Convert to 0-100 scale

def calculate_risk_indicators(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate list of risk indicators from analysis
    
    Args:
        analysis: Complete analysis results
        
    Returns:
        List of risk indicators with severity
    """
    indicators = []
    
    # Authentication risks
    auth = analysis['authentication']
    if auth['spf']['result'] != 'pass':
        indicators.append({
            'type': 'authentication',
            'severity': 'high',
            'message': 'SPF authentication failed'
        })
    if auth['dkim']['result'] != 'pass':
        indicators.append({
            'type': 'authentication',
            'severity': 'high',
            'message': 'DKIM signature invalid'
        })
    if auth['dmarc']['result'] != 'pass':
        indicators.append({
            'type': 'authentication',
            'severity': 'medium',
            'message': 'DMARC policy not enforced'
        })
        
    # IP reputation risks
    for ip, details in analysis['ip_analysis'].items():
        if details.get('abuse_confidence', 0) > 80:
            indicators.append({
                'type': 'ip',
                'severity': 'critical',
                'message': f'IP {ip} has high abuse confidence score'
            })
            
    # URL risks
    for url in analysis['url_analysis']:
        if url.get('virustotal_results', {}).get('malicious', 0) > 0:
            indicators.append({
                'type': 'url',
                'severity': 'critical',
                'message': f'Malicious URL detected: {url["url"]}'
            })
            
    # Attachment risks
    for attachment in analysis.get('attachments', []):
        if attachment.get('virustotal', {}).get('malicious', 0) > 0:
            indicators.append({
                'type': 'attachment',
                'severity': 'critical',
                'message': f'Malicious attachment detected: {attachment["filename"]}'
            })
            
    return indicators

def _score_authentication(auth: Dict[str, Any]) -> float:
    """Score authentication results"""
    score = 1.0
    
    if auth['spf']['result'] != 'pass':
        score -= 0.4
    if auth['dkim']['result'] != 'pass':
        score -= 0.4
    if auth['dmarc']['result'] != 'pass':
        score -= 0.2
        
    return max(score, 0)

def _score_ip_reputation(ip_analysis: Dict[str, Any]) -> float:
    """Score IP reputation"""
    if not ip_analysis:
        return 0.5  # Neutral score if no IPs
        
    scores = []
    for ip_details in ip_analysis.values():
        ip_score = 1.0
        abuse_confidence = ip_details.get('abuse_confidence', 0)
        
        if abuse_confidence > 80:
            ip_score = 0
        elif abuse_confidence > 60:
            ip_score = 0.2
        elif abuse_confidence > 40:
            ip_score = 0.4
        elif abuse_confidence > 20:
            ip_score = 0.6
            
        scores.append(ip_score)
        
    return min(scores) if scores else 0.5

def _score_urls(url_analysis: List[Dict[str, Any]]) -> float:
    """Score URL analysis results"""
    if not url_analysis:
        return 1.0  # Perfect score if no URLs
        
    scores = []
    for url in url_analysis:
        url_score = 1.0
        vt_results = url.get('virustotal_results', {})
        
        if vt_results.get('malicious', 0) > 0:
            url_score = 0
        elif vt_results.get('suspicious', 0) > 0:
            url_score = 0.3
            
        scores.append(url_score)
        
    return min(scores)

def _score_attachments(attachments: List[Dict[str, Any]]) -> float:
    """Score attachment analysis results"""
    if not attachments:
        return 1.0  # Perfect score if no attachments
        
    scores = []
    for attachment in attachments:
        att_score = 1.0
        vt_results = attachment.get('virustotal', {})
        
        if vt_results.get('malicious', 0) > 0:
            att_score = 0
        elif vt_results.get('suspicious', 0) > 0:
            att_score = 0.3
            
        scores.append(att_score)
        
    return min(scores)

def _score_headers(header_analysis: Dict[str, Any]) -> float:
    """Score header analysis results"""
    score = 1.0
    
    # Check for suspicious patterns in headers
    headers = header_analysis.get('x_headers', {})
    if 'X-Spam-Flag' in headers or 'X-Spam-Status' in headers:
        score -= 0.3
        
    return max(score, 0)
