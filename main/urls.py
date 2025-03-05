from django.urls import path, include
from . import views

urlpatterns = [
    # Authentication URLs
    path('auth/login/', views.login_view, name='login'),
    path('auth/register/', views.register_view, name='register'),
    path('auth/logout/', views.logout_view, name='logout'),
    
    # Main app URLs (all require login)
    path('', views.index, name='index'),  # Main dashboard page

    # Header Menu URLs
    path('sandbox/', views.sandbox_view, name='sandbox'),
    path('sandbox/analyze/', views.sandbox_analyze, name='sandbox_analyze'),
    path('hunting/', views.hunting, name='hunting'),
    path('threat-feed/', views.threat_feed, name='threat_feed'),
    path('refresh-threat-feeds/', views.refresh_threat_feeds, name='refresh_threat_feeds'),
    path('mitre-attack/', views.mitre, name='mitre'),

    # Threat Intelligence URLs
    path('threat/', include([
        path('hash-analysis/', views.hash_analysis, name='hash_analysis'),  # Moved here
        path('ip-analysis/', views.ip_analysis, name='ip_analysis'),
        path('domain-reputation/', views.domain_reputation, name='domain_reputation'),
        path('email-investigation/', views.email_investigation, name='email_investigation'),
        path('email-investigation/analyze/', views.analyze_email, name='analyze_email'),
    ])),

    # URL Scan URLs
    path('threat/url-scan/', views.url_scan, name='url_scan'),
    path('api/url-scan/analyze/', views.analyze_url, name='analyze_url'),

    # Reports URLs
    path('reports/investigation-history/', views.investigation_history, name='investigation_history'),
    path('reports/threat-reports/', views.threat_reports, name='threat_reports'),
    path('reports/export-findings/', views.export_findings, name='export_findings'),
    
    # Settings URLs
    path('settings/api-configuration/', views.api_configuration, name='api_configuration'),
    path('settings/user-profile/', views.user_profile, name='user_profile'),
    path('settings/security-settings/', views.security_settings, name='security_settings'),
    path('settings/load-api-keys/', views.load_api_keys, name='load_api_keys'),
    path('settings/save-api-key/', views.save_api_key, name='save_api_key'),
    path('settings/test-api-key/', views.test_api_key, name='test_api_key'),
    path('settings/delete-api-key/', views.delete_api_key, name='delete_api_key'),
    
    # Domain Reputation URLs
    path('services/domain-scan/', include('main.services.domain_scan.urls')),

    # Health check endpoint for Docker
    path('health/', views.health_check, name='health_check'),
    
    # API Endpoints
    path('api/threat/', include([
        path('hash-analysis/', views.analyze_hash, name='analyze_hash_api'),  # Fixed API endpoint
        path('ip-analysis/analyze/<str:ip_address>/', views.analyze_ip_api, name='analyze_ip_api'),
    ])),

    # Threat Feed URLs
    path('feeds/virustotal/', views.virustotal, name='virustotal'),
    path('feeds/abuseipdb/', views.abuseipdb, name='abuseipdb'),
    path('feeds/alienvault-otx/', views.alienvault_otx, name='alienvault_otx'),
    path('feeds/ibm-xforce/', views.ibm_xforce, name='ibm_xforce'),

    # Documentation URLs
    path('docs/', views.docs_home, name='docs_home'),
    path('docs/<str:article_path>/', views.docs_article, name='docs_article'),

    # User URLs
    path('users/profile/', views.user_profile_view, name='user_profile'),
    path('users/change-password/', views.change_password_view, name='change_password'),
]