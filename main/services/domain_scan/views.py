"""
Views for domain reputation analysis service
"""
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from .domain_analysis import DomainAnalysisService
from .utils.cache_manager import CacheManager

@login_required
@require_http_methods(["GET"])
def domain_reputation_view(request):
    """Render domain reputation analysis page"""
    return render(request, 'threat/domain_reputation/domain_reputation.html')

@login_required
@require_http_methods(["GET"])
async def analyze_domain(request, domain):
    """
    Analyze domain and return results
    
    Args:
        request: HTTP request
        domain: Domain to analyze
        
    Returns:
        JsonResponse containing analysis results
    """
    try:
        async with DomainAnalysisService(request.user) as service:
            results = await service.analyze_domain(domain)
            return JsonResponse(results)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["GET"])
def get_domain_data(request, domain):
    """
    Get cached domain analysis data
    
    Args:
        request: HTTP request
        domain: Domain to get data for
        
    Returns:
        JsonResponse containing cached analysis results
    """
    try:
        cached_results = CacheManager.get_cached_results(domain, request.user.id)
        if cached_results:
            return JsonResponse(cached_results)
        return JsonResponse({'error': 'No cached data found'}, status=404)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)
