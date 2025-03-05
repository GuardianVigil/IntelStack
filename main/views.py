"""Views for the stack project"""
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash
from functools import wraps
import asyncio
import ipaddress
import logging
import json
import base64
import os
import math
import requests
from asgiref.sync import async_to_sync, sync_to_async
from .models import APIKey
from .services.ip_scan.ip_analysis import IPAnalysisService
from .services.hash_scan.hash_analysis import HashAnalysisService
from .services.url_scan.platforms.domain_info import get_domain_info
from .services.url_scan.urlscan import URLScanner
from .services.email_scan.email_analyzer import EmailAnalyzer
from .services.threat_feed.threat_feed import ThreatFeedService
from datetime import datetime, timedelta
from django.contrib.auth.hashers import check_password

logger = logging.getLogger(__name__)

def async_view(view):
    """
    Decorator to make a view function async-aware.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        return async_to_sync(view)(*args, **kwargs)
    return wrapped

# Create your views here.
@login_required
def index(request):
    return render(request, 'index.html')

def docs_home(request):
    return render(request, 'docs/knowledge-base.html', {
        'sections': [
            {
                'title': 'Getting Started',
                'icon': 'book-open',
                'description': 'Learn the basics of using Stack',
                'articles': [
                    {'title': 'Introduction to Stack', 'url': '/docs/getting-started'},
                    {'title': 'API Key Configuration', 'url': '/docs/api-keys'},
                    {'title': 'Basic Usage', 'url': '/docs/basic-usage'},
                ]
            },
            {
                'title': 'Features & Integrations',
                'icon': 'puzzle',
                'description': 'Explore Stack features and integrations',
                'articles': [
                    {'title': 'Threat Intelligence', 'url': '/docs/threat-intelligence'},
                    {'title': 'Sandbox Analysis', 'url': '/docs/sandbox'},
                    {'title': 'MITRE ATT&CK', 'url': '/docs/mitre-attack'},
                ]
            },
            {
                'title': 'API Documentation',
                'icon': 'code',
                'description': 'Learn how to integrate with Stack API',
                'articles': [
                    {'title': 'API Overview', 'url': '/docs/api-overview'},
                    {'title': 'Authentication', 'url': '/docs/api-auth'},
                    {'title': 'Endpoints', 'url': '/docs/api-endpoints'},
                ]
            }
        ]
    })

def docs_article(request, article_path):
    # Map article paths to markdown files
    article_map = {
        'getting-started': 'user-guide/getting-started.md',
        'api-keys': 'user-guide/api-key-configuration.md',
        'api-overview': 'api/overview.md'
    }
    
    if article_path not in article_map:
        return render(request, 'docs/404.html')
        
    docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs')
    md_file = os.path.join(docs_dir, article_map[article_path])
    
    try:
        with open(md_file, 'r') as f:
            content = f.read()
            html_content = markdown.markdown(content)
            return render(request, 'docs/article.html', {
                'content': html_content,
                'title': content.split('\n')[0].replace('# ', '')
            })
    except FileNotFoundError:
        return render(request, 'docs/404.html')


@login_required
def api_configuration(request):
    return render(request, 'settings/api_configuration.html')

@login_required
@csrf_exempt
@require_http_methods(['POST'])
def save_api_key(request):
    try:
        data = json.loads(request.body)
        platform = data.get('platform')
        api_key = data.get('api_key')
        api_secret = data.get('api_secret')  # For platforms that require two keys
        
        if not platform or not api_key:
            return JsonResponse({'success': False, 'message': 'Platform and API key are required'})
        
        # Create or update API key
        api_key_obj, created = APIKey.objects.get_or_create(
            user=request.user,
            platform=platform,
            defaults={
                'api_key': api_key,
                'api_secret': api_secret
            }
        )
        
        if not created:
            api_key_obj.api_key = api_key
            api_key_obj.api_secret = api_secret
            api_key_obj.save()
        
        return JsonResponse({
            'success': True,
            'message': 'API key saved successfully',
            'created': created
        })
    except ValidationError as e:
        return JsonResponse({'success': False, 'message': str(e)})
    except Exception as e:
        return JsonResponse({'success': False, 'message': 'An error occurred while saving the API key'})

@login_required
@require_http_methods(['GET'])
def load_api_keys(request):
    try:
        api_keys = {}
        user_api_keys = APIKey.objects.filter(user=request.user, is_active=True)
        
        def mask_key(key):
            if not key:
                return ""
            if len(key) <= 8:
                return "*" * len(key)
            return key[:4] + "*" * (len(key) - 8) + key[-4:]
        
        for key in user_api_keys:
            if key.platform == 'hybrid_analysis':
                api_keys[key.platform] = {
                    'api_key': mask_key(key.api_key),
                    'api_secret': mask_key(key.api_secret)
                }
            elif key.platform == 'ibm_xforce':
                api_keys[key.platform] = {
                    'api_key': mask_key(key.api_key),
                    'api_password': mask_key(key.api_secret)
                }
            else:
                api_keys[key.platform] = mask_key(key.api_key)
        
        return JsonResponse({'success': True, 'api_keys': api_keys})
    except Exception as e:
        return JsonResponse({'success': False, 'message': 'An error occurred while loading API keys'})

@login_required
@require_http_methods(['GET'])
def test_api_key(request):
    platform = request.GET.get('platform')
    
    if not platform:
        return JsonResponse({'success': False, 'message': 'Platform is required'})
    
    try:
        api_key = APIKey.objects.get(user=request.user, platform=platform, is_active=True)
        key = api_key.api_key
        secret = api_key.api_secret if platform == 'hybrid_analysis' else None
        
        # Test API key based on platform
        if platform == 'virustotal':
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params={'apikey': key, 'resource': 'www.google.com'}
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})
        
        elif platform == 'abuseipdb':
            headers = {'Key': key, 'Accept': 'application/json'}
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params={'ipAddress': '8.8.8.8'}
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})
        
        elif platform == 'greynoise':
            headers = {'key': key, 'Accept': 'application/json'}
            response = requests.get(
                'https://api.greynoise.io/v3/community/8.8.8.8',
                headers=headers
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})
        
        elif platform == 'urlscan':
            headers = {'API-Key': key, 'Content-Type': 'application/json'}
            response = requests.get(
                'https://urlscan.io/user/quotas',
                headers=headers
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})
        
        elif platform == 'hybrid_analysis':
            headers = {
                'api-key': key,
                'user-agent': 'Falcon Sandbox',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            response = requests.get(
                'https://www.hybrid-analysis.com/api/v2/key/current',
                headers=headers
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})

        elif platform == 'cloudmersive':
            headers = {'Apikey': key}
            response = requests.get(
                'https://api.cloudmersive.com/virus/scan/website',
                headers=headers,
                params={'url': 'https://www.google.com'}
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})

        elif platform == 'metadefender':
            headers = {'apikey': key}
            response = requests.get(
                'https://api.metadefender.com/v4/status',
                headers=headers
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})

        elif platform == 'ipinfo':
            response = requests.get(
                f'https://ipinfo.io/8.8.8.8?token={key}'
            )
            if response.status_code == 200:
                return JsonResponse({'success': True, 'message': 'API key is valid'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid API key'})

        elif platform == 'threatminer':
            # ThreatMiner doesn't require an API key
            return JsonResponse({'success': True, 'message': 'No API key required for ThreatMiner'})
        
        # Default response for platforms without specific test
        return JsonResponse({'success': True, 'message': 'API key saved (validation not implemented)'})
        
    except APIKey.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'API key not found'})
    except requests.exceptions.RequestException as e:
        return JsonResponse({'success': False, 'message': 'Error testing API key: Network error'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error testing API key: {str(e)}'})

@login_required
@csrf_exempt
@require_http_methods(['POST'])
def delete_api_key(request):
    try:
        data = json.loads(request.body)
        platform = data.get('platform')
        
        if not platform:
            return JsonResponse({'success': False, 'message': 'Platform is required'})
        
        # Delete API key
        APIKey.objects.filter(user=request.user, platform=platform).delete()
        
        return JsonResponse({
            'success': True,
            'message': 'API key deleted successfully'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'message': 'An error occurred while deleting the API key'})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('index')
        
    if request.method == 'POST':
        login_identifier = request.POST.get('username')  # This could be email or username
        password = request.POST.get('password')
        print(f"Login attempt - Identifier: {login_identifier}")  # Debug print
        
        # First try authenticating with the identifier as username
        user = authenticate(request, username=login_identifier, password=password)
        
        # If that fails, try to find user by email
        if user is None:
            try:
                user_obj = User.objects.get(email=login_identifier)
                user = authenticate(request, username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None
        
        print(f"Authentication result - User: {user}")  # Debug print
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', '/')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username/email or password')
    
    return render(request, 'auth/login.html')

def register_view(request):
    if request.user.is_authenticated:
        return redirect('index')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return render(request, 'auth/register.html')
            
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return render(request, 'auth/register.html')
            
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
            return render(request, 'auth/register.html')
            
        user = User.objects.create_user(username=username, email=email, password=password)
        messages.success(request, 'Registration successful. Please login.')
        return redirect('login')
        
    return render(request, 'auth/register.html')

def logout_view(request):
    logout(request)
    messages.success(request, 'Logged out successfully')
    return redirect('login')

# Threat Intelligence Views
@login_required
def hunting(request):
    context = {
        'results': None  # Will be populated when a hunt is performed
    }
    return render(request, 'threat/hunting.html', context)

@login_required
def threat_feed(request):
    context = {
        'stats': {
            'malware_count': 150,
            'phishing_count': 75,
            'apt_count': 12,
            'vuln_count': 45
        },
        'feeds': [
            {
                'name': 'Emerging Threats',
                'category': 'Malware',
                'provider': 'ProofPoint',
                'last_update': '2025-02-02',
                'status': 'active',
                'description': 'Malware and botnet C&C servers'
            },
            # Add more sample feeds
        ]
    }
    return render(request, 'threat/feed.html', context)

@login_required
@ensure_csrf_cookie
def sandbox(request):
    if request.method == 'POST':
        # Handle file upload and analysis
        from .services.sandbox.sandbox import handle_sandbox_analysis
        return handle_sandbox_analysis(request)
    
    # GET request - render the sandbox page
    return render(request, 'threat/sandbox.html')

@login_required
def mitre(request):
    context = {
        'tactics': [
            {'name': 'Reconnaissance'},
            {'name': 'Resource Development'},
            {'name': 'Initial Access'},
            # Add more tactics
        ],
        'techniques': [
            {
                'id': 'T1595',
                'name': 'Active Scanning',
                'tactic': 'Reconnaissance'
            },
            # Add more techniques
        ],
        'groups': [
            {
                'name': 'APT28',
                'aliases': ['Fancy Bear', 'Sofacy'],
                'description': 'Russian state-sponsored threat actor',
                'techniques': ['T1595', 'T1592']
            },
            # Add more groups
        ]
    }
    return render(request, 'threat/mitre_attack.html', context)

@login_required
@login_required
def investigation_history(request):
    context = {
        'history': [
            {
                'id': '1',
                'date': '2025-02-02',
                'time': '14:30',
                'type': 'ip',
                'target': '192.168.1.1',
                'description': 'Suspicious IP investigation',
                'status': 'completed',
                'risk_score': 85
            },
            # Add more sample history items
        ]
    }
    return render(request, 'reports/investigation_history.html', context)

@login_required
def threat_reports(request):
    context = {
        'stats': {
            'apt_reports': 12,
            'malware_reports': 45,
            'incident_reports': 8,
            'vuln_reports': 23
        },
        'reports': [
            {
                'id': '1',
                'title': 'APT29 Campaign Analysis',
                'category': 'apt',
                'summary': 'Detailed analysis of recent APT29 activities targeting critical infrastructure.',
                'author': 'John Doe',
                'author_avatar': 'path/to/avatar.jpg',
                'date': '2025-02-02'
            },
            # Add more sample reports
        ]
    }
    return render(request, 'reports/threat_reports.html', context)

@login_required
def export_findings(request):
    context = {
        'exports': [
            {
                'id': '1',
                'name': 'Q1 2025 Threat Report',
                'date': '2025-02-02',
                'size': '2.5 MB',
                'format': 'pdf'
            },
            # Add more sample exports
        ]
    }
    return render(request, 'reports/export_findings.html', context)

@login_required
def ip_analysis(request):
    """Render the IP analysis page."""
    return render(request, 'threat/ip_analysis/ip_analysis.html')  # Updated template path

@login_required
@async_view
async def analyze_ip_api(request, ip_address):
    """API endpoint to analyze an IP address."""
    try:
        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return JsonResponse({'error': 'Invalid IP address format'}, status=400)

        # Get threat intelligence data
        async with IPAnalysisService() as service:  # Removed request.user parameter
            results = await service.analyze_ip(ip_address)
            
            if not results:
                return JsonResponse({
                    'error': 'No results from any threat intelligence platforms'
                }, status=404)

            return JsonResponse(results)

    except Exception as e:
        logger.error(f"Error analyzing IP: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def hash_analysis(request):
    return render(request, 'threat/hash_analysis/hash_analysis.html')

@login_required
def domain_reputation(request):
    return render(request, 'threat/domain_reputation/domain_reputation.html')

@login_required
def url_scan(request):
    return render(request, 'threat/url_scan/url_scan.html')

@login_required
def email_investigation(request):
    return render(request, 'threat/email_investigation/email_investigation.html')

@csrf_exempt
@require_http_methods(['POST'])
def analyze_email(request):
    """
    API endpoint for analyzing emails.
    Expects a POST request with JSON body containing:
    {
        "emailContent": "raw email content or headers"
    }
    """
    try:
        logger.info("Received email analysis request")
        data = json.loads(request.body)
        email_content = data.get('emailContent')
        
        if not email_content:
            logger.warning("No email content provided")
            return JsonResponse({'error': 'No email content provided'}, status=400)

        # Initialize analyzer
        logger.info("Initializing analyzer")
        analyzer = EmailAnalyzer()
        
        try:
            # Convert content to bytes and analyze
            content = email_content.encode('utf-8')
            results = analyzer.analyze_email(content, 'headers')
            
            # Format response
            response_data = {
                'headers': results.headers,
                'authentication': {
                    'spf': 'pass' if 'pass' in results.authentication['spf'].lower() else 
                           'fail' if 'fail' in results.authentication['spf'].lower() else 'neutral',
                    'dkim': 'pass' if results.authentication['dkim'] and 'fail' not in results.authentication['dkim'].lower() else 
                           'fail' if 'fail' in results.authentication['dkim'].lower() else 'neutral',
                    'dmarc': 'pass' if 'pass' in results.authentication['dmarc'].lower() else 
                            'fail' if 'fail' in results.authentication['dmarc'].lower() else 'neutral'
                },
                'body': results.body,
                'raw_email': {
                    'headers': dict(results.headers.items()),
                    'body': results.body,
                    'attachments': results.attachments
                },
                'urls': [{'url': url, 'malicious': False} for url in results.iocs['urls']],
                'attachments': results.attachments,
                'iocs': {
                    'urls': results.iocs['urls'],
                    'ips': results.iocs['ips'],
                    'hashes': results.iocs['hashes']
                },
                'risk_assessment': {
                    'threat_score': results.threat_score,
                    'risk_level': 'high' if results.threat_score > 70 else 'medium' if results.threat_score > 30 else 'low',
                    'risk_factors': results.risk_factors
                }
            }
            
            logger.info("Analysis completed successfully")
            return JsonResponse(response_data)
            
        except Exception as e:
            logger.error(f"Error during email analysis: {str(e)}")
            raise
            
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request: {str(e)}")
        return JsonResponse({
            'error': 'Invalid JSON in request',
            'details': str(e)
        }, status=400)
        
    except Exception as e:
        logger.error(f"Error in analyze_email view: {str(e)}")
        return JsonResponse({
            'error': str(e),
            'headers': {'headers': {}, 'received_chain': []},
            'authentication': {'spf': 'neutral', 'dkim': 'neutral', 'dmarc': 'neutral'},
            'urls': [],
            'attachments': [],
            'sender_ip': {'ip': '', 'analysis': {}},
            'risk_assessment': {
                'threat_score': 0,
                'risk_level': 'unknown',
                'risk_factors': [],
                'indicators': {
                    'authentication_failed': False,
                    'suspicious_urls': 0,
                    'malicious_attachments': 0,
                    'suspicious_sender': False
                }
            }
        })

# Hash Analysis View
@csrf_exempt
@require_http_methods(["POST"])
async def analyze_hash(request):
    """
    API endpoint for analyzing file hashes.
    Expects a POST request with JSON body containing:
    {
        "hash": "hash_value",
        "platforms": ["platform1", "platform2"]  // optional
    }
    """
    try:
        data = json.loads(request.body)
        file_hash = data.get('hash')
        platforms = data.get('platforms')  # Optional

        if not file_hash:
            return JsonResponse(
                {'error': 'Hash value is required'}, 
                status=400
            )

        service = HashAnalysisService()
        results = await service.analyze_hash(file_hash, platforms)
        
        return JsonResponse(results)

    except ValueError as e:
        logger.error(f"Invalid input: {str(e)}")
        return JsonResponse(
            {'error': str(e)}, 
            status=400
        )
    except Exception as e:
        logger.error(f"Failed to analyze hash: {str(e)}")
        return JsonResponse(
            {'error': f"Failed to analyze hash: {str(e)}"}, 
            status=500
        )


from django.views.decorators.csrf import ensure_csrf_cookie

@ensure_csrf_cookie
@require_http_methods(["POST"])
def refresh_threat_feeds(request):
    """Endpoint to refresh threat feeds"""
    try:
        logger.info("Refreshing threat feeds")
        service = ThreatFeedService()
        result = service.refresh_feeds()  # Use refresh_feeds which handles cache clearing
        
        if result is None:
            logger.error("ThreatFeedService.refresh_feeds returned None")
            return JsonResponse({
                'error': 'Failed to fetch threat feeds',
                'threats': [],
                'stats': {
                    'total': 0,
                    'today': 0,
                    'trend': 0,
                    'critical': 0,
                    'high': 0,
                    'malware': 0,
                    'sources': {'otx': False, 'threatfox': False, 'pulsedive': False}
                },
                'message': 'An error occurred while fetching threat feeds.'
            }, status=500)
        
        # Log the result structure for debugging
        logger.debug(f"Refresh threat feeds result keys: {result.keys()}")
        
        # Add a message if no API keys are configured
        if not result.get('threats') and not result.get('active_platforms'):
            result['message'] = 'No API keys configured. Please configure API keys in settings.'
            logger.warning("No API keys configured for threat feeds")
        else:
            logger.info(f"Successfully refreshed {len(result.get('threats', []))} threats from {len(result.get('active_platforms', []))} platforms")
            
        return JsonResponse(result)
    except KeyError as e:
        logger.error(f"KeyError in refresh_threat_feeds view: {str(e)}", exc_info=True)
        # Log the actual data structure that caused the KeyError
        if 'result' in locals():
            logger.error(f"Result structure that caused KeyError: {result.keys() if isinstance(result, dict) else type(result)}")
        
        return JsonResponse({
            'error': f"Data structure error: {str(e)}",
            'threats': [],
            'stats': {
                'total': 0,
                'today': 0,
                'trend': 0,
                'critical': 0,
                'high': 0,
                'malware': 0,
                'sources': {'otx': False, 'threatfox': False, 'pulsedive': False}
            },
            'message': 'An error occurred while processing threat feed data. Please check API configurations.'
        }, status=500)
    except Exception as e:
        logger.error(f"Error in refresh_threat_feeds view: {str(e)}", exc_info=True)
        return JsonResponse({
            'error': str(e),
            'threats': [],
            'stats': {
                'total': 0,
                'today': 0,
                'trend': 0,
                'critical': 0,
                'high': 0,
                'malware': 0,
                'sources': {'otx': False, 'threatfox': False, 'pulsedive': False}
            },
            'message': 'An error occurred while fetching threat feeds. Please try again.'
        }, status=500)



# Threat Feed Views
@login_required
def virustotal(request):
    return render(request, 'feeds/virustotal.html')

@login_required
def abuseipdb(request):
    return render(request, 'feeds/abuseipdb.html')

@login_required
def alienvault_otx(request):
    return render(request, 'feeds/alienvault_otx.html')

@login_required
def ibm_xforce(request):
    return render(request, 'feeds/ibm_xforce.html')

# Report Views
@login_required
def investigation_history(request):
    return render(request, 'reports/investigation_history.html')

@login_required
def threat_reports(request):
    return render(request, 'reports/threat_reports.html')

@login_required
def export_findings(request):
    return render(request, 'reports/export_findings.html')

# Settings Views
@login_required
def api_configuration(request):
    return render(request, 'settings/api_configuration.html')

@login_required
def user_profile(request):
    return render(request, 'settings/user_profile.html')

@login_required
def security_settings(request):
    return render(request, 'settings/security_settings.html')

@login_required
@require_http_methods(["GET"])
def url_scan(request):
    """Render the URL scan page"""
    return render(request, 'threat/url_scan/url_scan.html')

from asgiref.sync import sync_to_async
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
import json
import logging
from .services.url_scan.urlscan import URLScanner

logger = logging.getLogger(__name__)

@login_required
@require_http_methods(["POST"])
async def analyze_url(request):
    """
    Analyze a URL using multiple threat intelligence platforms.
    Expects a POST request with JSON body containing a 'url' field.
    """
    try:
        # Parse JSON data
        data = json.loads(request.body)
        url = data.get('url')
        
        if not url:
            return JsonResponse({'error': 'URL is required'}, status=400)

        # Get API keys asynchronously
        api_keys = {}
        for platform in ['hybrid_analysis', 'urlscan', 'virustotal']:
            try:
                api_key = await sync_to_async(APIKey.objects.get)(platform=platform, user=request.user)
                decrypted_key = await sync_to_async(getattr)(api_key, 'api_key')
                if not decrypted_key:
                    return JsonResponse(
                        {'error': f'API key for {platform} is invalid or not properly configured.'}, 
                        status=400
                    )
                api_keys[platform] = decrypted_key
            except APIKey.DoesNotExist:
                return JsonResponse(
                    {'error': f'API key for {platform} is not configured. Please configure it in API settings.'}, 
                    status=400
                )
        # Initialize scanner and scan URL
        try:
            async with URLScanner(api_keys) as scanner:
                results = await scanner.scan_url(url)
                return JsonResponse({'results': results})
        except Exception as e:
            logger.error(f"Error during URL scan: {str(e)}")
            return JsonResponse(
                {'error': 'Error occurred while scanning the URL. Please try again.'}, 
                status=500
            )
            
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data in request'}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error in URL scan: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@login_required
@require_http_methods(["POST"])
def sandbox_analyze(request):
    """Handle file upload and analysis in sandbox."""
    if not request.FILES.get('file'):
        messages.error(request, 'No file uploaded')
        return redirect('sandbox')

    uploaded_file = request.FILES['file']
    
    try:
        api_key_obj = APIKey.objects.get(platform='virustotal', user=request.user)
        api_key = api_key_obj.api_key
        if not api_key:
            messages.error(request, 'VirusTotal API key is invalid. Please reconfigure it in API Configuration.')
            return redirect('sandbox')
    except APIKey.DoesNotExist:
        messages.error(request, 'VirusTotal API key not configured. Please add it in API Configuration.')
        return redirect('sandbox')

    temp_dir = os.path.join(settings.BASE_DIR, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, uploaded_file.name)

    try:
        # Save the uploaded file to a temporary location
        with open(temp_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)

        # Log the file details for debugging
        logger.info(f"Processing file: {uploaded_file.name}, Size: {uploaded_file.size} bytes")
        
        from .services.sandbox.sandbox import SandboxAnalyzer
        analyzer = SandboxAnalyzer(api_key)
        
        # Log before analysis
        logger.info(f"Starting analysis for file: {uploaded_file.name}")
        
        results = analyzer.analyze_file(temp_path)
        
        # Log after analysis
        logger.info(f"Analysis completed for file: {uploaded_file.name}")
        
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.unlink(temp_path)

        if not results.get('success'):
            messages.error(request, results.get('error', 'Analysis failed or timed out'))
            return redirect('sandbox')

        # Format file size for display
        if 'results' in results and 'file_info' in results['results'] and 'size' in results['results']['file_info']:
            size_bytes = results['results']['file_info']['size']
            if size_bytes == 0:
                formatted_size = '0 Bytes'
            else:
                k = 1024
                sizes = ['Bytes', 'KB', 'MB', 'GB']
                i = int(math.floor(math.log(size_bytes) / math.log(k)))
                formatted_size = f"{round(size_bytes / (k ** i), 2)} {sizes[i]}"
            results['results']['file_info']['size_formatted'] = formatted_size

        # Log the response structure for debugging
        logger.info(f"Response structure: {json.dumps(results, default=str)[:500]}...")
        
        # Render the template with results
        try:
            return render(request, 'threat/sandbox.html', {
                'results': results['results'],
                'has_api_key': True
            })
        except Exception as e:
            logger.error(f"Error in sandbox analysis: {str(e)}", exc_info=True)
            messages.error(request, f"Error displaying results: {str(e)}")
            return redirect('sandbox')

    except Exception as e:
        logger.error(f"Error in sandbox analysis: {str(e)}", exc_info=True)
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        messages.error(request, f'Analysis failed: {str(e)}')
        return redirect('sandbox')

@login_required
def sandbox_view(request):
    """Render the sandbox analysis page."""
    # Get VirusTotal API key status
    has_api_key = APIKey.objects.filter(platform='virustotal', user=request.user).exists()
    
    return render(request, 'threat/sandbox.html', {
        'has_api_key': has_api_key
    })

@login_required
def user_profile_view(request):
    """Render the user profile page"""
    return render(request, 'users/profile.html')

@login_required
@require_http_methods(["POST"])
def change_password_view(request):
    """Handle password change"""
    old_password = request.POST.get('old_password')
    new_password = request.POST.get('new_password')
    confirm_password = request.POST.get('confirm_password')
    
    user = request.user
    
    # Validate old password
    if not check_password(old_password, user.password):
        messages.error(request, 'Current password is incorrect')
        return redirect('user_profile')
    
    # Check if new passwords match
    if new_password != confirm_password:
        messages.error(request, 'New passwords do not match')
        return redirect('user_profile')
    
    # Validate password strength (add your own criteria)
    if len(new_password) < 8:
        messages.error(request, 'Password must be at least 8 characters long')
        return redirect('user_profile')
    
    # Update password
    try:
        user.set_password(new_password)
        user.save()
        messages.success(request, 'Password updated successfully')
        
        # Update session to prevent logout
        update_session_auth_hash(request, user)
        
        return redirect('user_profile')
    except Exception as e:
        messages.error(request, 'Error updating password. Please try again.')
        return redirect('user_profile')