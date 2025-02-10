"""
Views for IP analysis service
"""
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from .ip_analysis import IPAnalysisService
from .utils.data_aggregation import (
    aggregate_threats,
    aggregate_activity,
    aggregate_malware_info
)

@login_required
@require_http_methods(["GET"])
def ip_analysis_view(request):
    """Render IP analysis page"""
    return render(request, 'threat/ip_analysis/ip_analysis.html')

@login_required
@require_http_methods(["GET"])
async def analyze_ip(request, ip_address):
    """
    Analyze IP address and return results
    
    Args:
        request: HTTP request
        ip_address: IP address to analyze
        
    Returns:
        JsonResponse containing analysis results
    """
    try:
        async with IPAnalysisService(request.user) as service:
            results = await service.analyze_ip(ip_address)
            
            # Get summary data
            summary = results.get('summary', {})
            threat_score = summary.get('threat_score', 0)
            confidence = summary.get('confidence', 0)
            platform_scores = summary.get('platform_scores', {})
            risk_level = summary.get('risk_level', {}).get('level', 'Unknown')
            
            # Get network and WHOIS data
            network = results.get('network', {})
            whois = results.get('whois', {})
            
            # Get platform data
            platform_data = results.get('platform_data', {})
            
            # Aggregate data
            threats = aggregate_threats(platform_data)
            activities = aggregate_activity(platform_data)
            malware = aggregate_malware_info(platform_data)
            
            context = {
                'ip_address': ip_address,
                'threat_score': threat_score,
                'confidence': confidence,
                'risk_level': risk_level,
                'platform_scores': platform_scores,
                'network': network,
                'whois': whois,
                'threats': threats,
                'activities': activities,
                'malware': malware,
                'platform_data': platform_data
            }
            
            return render(request, 'threat/ip_analysis/detailed_view.html', context)
            
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
async def get_ip_data(request, ip_address):
    """
    Get IP analysis data in JSON format
    
    Args:
        request: HTTP request
        ip_address: IP address to analyze
        
    Returns:
        JsonResponse containing analysis results
    """
    try:
        async with IPAnalysisService(request.user) as service:
            results = await service.analyze_ip(ip_address)
            return JsonResponse(results)
            
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)
