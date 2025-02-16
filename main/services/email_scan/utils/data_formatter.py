"""
Utility functions for formatting email analysis data
"""
from typing import Dict, Any

def format_email_data(parsed_data: Dict[str, Any], platform_results: Dict[str, Any],
                     threat_score: float, confidence_score: float) -> Dict[str, Any]:
    """Format email analysis data for frontend display"""
    
    # Format basic information
    basic_info = parsed_data["basic_info"]
    
    # Format authentication results
    auth_results = {
        "spf": _format_auth_result(parsed_data["authentication"]["spf"]),
        "dkim": _format_auth_result(parsed_data["authentication"]["dkim"]),
        "dmarc": _format_auth_result(parsed_data["authentication"]["dmarc"])
    }
    
    # Format IP analysis
    ip_analysis = _format_ip_analysis(parsed_data["ips"], platform_results)
    
    # Format URL analysis
    url_analysis = _format_url_analysis(parsed_data["urls"], platform_results)
    
    # Format attachment analysis
    attachment_analysis = _format_attachment_analysis(parsed_data["attachments"], platform_results)
    
    # Calculate risk indicators
    risk_indicators = _calculate_risk_indicators(threat_score)
    
    return {
        "basic_info": basic_info,
        "authentication": auth_results,
        "ip_analysis": ip_analysis,
        "url_analysis": url_analysis,
        "attachment_analysis": attachment_analysis,
        "threat_score": threat_score,
        "confidence_score": confidence_score,
        "risk_indicators": risk_indicators,
        "raw_headers": parsed_data["raw_headers"]
    }

def _format_auth_result(auth_data: Dict[str, str]) -> Dict[str, Any]:
    """Format authentication result data"""
    return {
        "result": auth_data["result"],
        "status": _get_status_from_result(auth_data["result"]),
        "details": auth_data["details"]
    }

def _format_ip_analysis(ips: list, platform_results: Dict[str, Any]) -> Dict[str, Any]:
    """Format IP analysis results"""
    ip_analysis = {}
    
    for ip in ips:
        ip_data = {
            "analysis": {},
            "geolocation": None,
            "reputation": None,
            "is_malicious": False
        }
        
        # Collect results from each platform
        for platform, results in platform_results.items():
            if "status" in results and results["status"] == "success":
                platform_ip_data = results["data"].get("ip_analysis", {}).get(ip, {})
                if platform_ip_data:
                    ip_data["analysis"][platform] = platform_ip_data
                    
                    # Update geolocation if available
                    if "geolocation" in platform_ip_data:
                        ip_data["geolocation"] = platform_ip_data["geolocation"]
                    
                    # Update reputation if available
                    if "reputation" in platform_ip_data:
                        ip_data["reputation"] = platform_ip_data["reputation"]
                    
                    # Update malicious status
                    if platform_ip_data.get("is_malicious", False):
                        ip_data["is_malicious"] = True
        
        ip_analysis[ip] = ip_data
    
    return ip_analysis

def _format_url_analysis(urls: list, platform_results: Dict[str, Any]) -> list:
    """Format URL analysis results"""
    url_analysis = []
    
    for url in urls:
        url_data = {
            "url": url,
            "analysis": {},
            "status": "unknown",
            "reputation": None,
            "is_malicious": False
        }
        
        # Collect results from each platform
        for platform, results in platform_results.items():
            if "status" in results and results["status"] == "success":
                platform_url_data = next(
                    (u for u in results["data"].get("urls", []) if u.get("url") == url),
                    None
                )
                if platform_url_data:
                    url_data["analysis"][platform] = platform_url_data
                    
                    # Update status based on platform results
                    if platform_url_data.get("status"):
                        url_data["status"] = platform_url_data["status"]
                    
                    # Update reputation if available
                    if "reputation" in platform_url_data:
                        url_data["reputation"] = platform_url_data["reputation"]
                    
                    # Update malicious status
                    if platform_url_data.get("is_malicious", False):
                        url_data["is_malicious"] = True
        
        url_analysis.append(url_data)
    
    return url_analysis

def _format_attachment_analysis(attachments: list, platform_results: Dict[str, Any]) -> list:
    """Format attachment analysis results"""
    attachment_analysis = []
    
    for attachment in attachments:
        att_data = {
            "filename": attachment["filename"],
            "content_type": attachment["content_type"],
            "size": attachment["size"],
            "hashes": {
                "md5": attachment["md5"],
                "sha1": attachment["sha1"],
                "sha256": attachment["sha256"]
            },
            "analysis": {},
            "status": "unknown",
            "is_malicious": False
        }
        
        # Collect results from each platform
        for platform, results in platform_results.items():
            if "status" in results and results["status"] == "success":
                platform_att_data = next(
                    (a for a in results["data"].get("attachments", [])
                     if a.get("md5") == attachment["md5"]),
                    None
                )
                if platform_att_data:
                    att_data["analysis"][platform] = platform_att_data
                    
                    # Update status based on platform results
                    if platform_att_data.get("status"):
                        att_data["status"] = platform_att_data["status"]
                    
                    # Update malicious status
                    if platform_att_data.get("is_malicious", False):
                        att_data["is_malicious"] = True
        
        attachment_analysis.append(att_data)
    
    return attachment_analysis

def _get_status_from_result(result: str) -> str:
    """Convert authentication result to status"""
    result = result.lower()
    if result in ["pass", "valid"]:
        return "success"
    elif result in ["fail", "invalid"]:
        return "danger"
    elif result in ["neutral", "softfail"]:
        return "warning"
    else:
        return "secondary"

def _calculate_risk_indicators(threat_score: float) -> Dict[str, str]:
    """Calculate risk indicators based on threat score"""
    if threat_score >= 70:
        return {
            "level": "high",
            "color": "danger",
            "message": "High risk - immediate attention required"
        }
    elif threat_score >= 40:
        return {
            "level": "medium",
            "color": "warning",
            "message": "Medium risk - review recommended"
        }
    else:
        return {
            "level": "low",
            "color": "success",
            "message": "Low risk - appears safe"
        }
