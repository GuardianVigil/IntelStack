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
from .utils.data_formatter import DataFormatter

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
            raw_results = await service.analyze_ip(ip_address)
            
            # Format the platform data
            formatted_data = DataFormatter.process_platform_data(raw_results.get('platform_data', {}))
            
            # Prepare the response
            response_data = {
                'summary': raw_results.get('summary', {}),
                'platform_data': formatted_data
            }
            
            return JsonResponse(response_data)
    except Exception as e:
        logger.error(f"Error analyzing IP {ip_address}: {str(e)}")
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
