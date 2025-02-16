"""
URL patterns for domain reputation service
"""
from django.urls import path
from . import views

urlpatterns = [
    # Frontend page
    path('domain-reputation/', views.domain_reputation_view, name='domain_reputation'),
    
    # API endpoints
    path('api/domain-reputation/<str:domain>/', views.analyze_domain, name='analyze_domain'),
    path('api/domain-reputation/data/<str:domain>/', views.get_domain_data, name='get_domain_data'),
]
