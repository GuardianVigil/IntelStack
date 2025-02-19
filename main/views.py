"""Views for the stack project"""
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from functools import wraps
import asyncio
import ipaddress
import logging
import json
import requests
from asgiref.sync import async_to_sync
from .models import APIKey
from .services.ip_scan.ip_analysis import IPAnalysisService
from .services.hash_scan.hash_analysis import HashAnalysisService

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

def analytics(request):
    return render(request, 'analytics.html')

def finance(request):
    return render(request, 'finance.html')

def crypto(request):
    return render(request, 'crypto.html')


def charts(request):
    return render(request, 'charts.html')

def widgets(request):
    return render(request, 'widgets.html')

def font_icons(request):
    return render(request, 'font-icons.html')

def dragndrop(request):
    return render(request, 'dragndrop.html')

def tables(request):
    return render(request, 'tables.html')


def apps_chat(request):
    return render(request, 'apps/chat.html')

def apps_mailbox(request):
    return render(request, 'apps/mailbox.html')

def apps_todolist(request):
    return render(request, 'apps/todolist.html')

def apps_notes(request):
    return render(request, 'apps/notes.html')

def apps_scrumboard(request):
    return render(request, 'apps/scrumboard.html')

def apps_contacts(request):
    return render(request, 'apps/contacts.html')

def apps_calendar(request):
    return render(request, 'apps/calendar.html')

def apps_invoice_add(request):
    return render(request, 'apps/invoice/add.html')

def apps_invoice_edit(request):
    return render(request, 'apps/invoice/edit.html')

def apps_invoice_list(request):
    return render(request, 'apps/invoice/list.html')

def apps_invoice_preview(request):
    return render(request, 'apps/invoice/preview.html')


def components_tabs(request):
    return render(request, 'ui-components/tabs.html')

def components_accordions(request):
    return render(request, 'ui-components/accordions.html')

def components_modals(request):
    return render(request, 'ui-components/modals.html')

def components_cards(request):
    return render(request, 'ui-components/cards.html')

def components_carousel(request):
    return render(request, 'ui-components/carousel.html')

def components_countdown(request):
    return render(request, 'ui-components/countdown.html')

def components_counter(request):
    return render(request, 'ui-components/counter.html')

def components_sweetalert(request):
    return render(request, 'ui-components/sweetalert.html')

def components_timeline(request):
    return render(request, 'ui-components/timeline.html')

def components_notifications(request):
    return render(request, 'ui-components/notifications.html')

def components_media_object(request):
    return render(request, 'ui-components/media-object.html')

def components_list_group(request):
    return render(request, 'ui-components/list-group.html')

def components_pricing_table(request):
    return render(request, 'ui-components/pricing-table.html')

def components_lightbox(request):
    return render(request, 'ui-components/lightbox.html')



def elements_alerts(request):
    return render(request, 'elements/alerts.html')

def elements_avatar(request):
    return render(request, 'elements/avatar.html')

def elements_badges(request):
    return render(request, 'elements/badges.html')

def elements_breadcrumbs(request):
    return render(request, 'elements/breadcrumbs.html')

def elements_buttons(request):
    return render(request, 'elements/buttons.html')

def elements_buttons_group(request):
    return render(request, 'elements/buttons-group.html')

def elements_color_library(request):
    return render(request, 'elements/color-library.html')

def elements_dropdown(request):
    return render(request, 'elements/dropdown.html')

def elements_infobox(request):
    return render(request, 'elements/infobox.html')

def elements_jumbotron(request):
    return render(request, 'elements/jumbotron.html')

def elements_loader(request):
    return render(request, 'elements/loader.html')

def elements_pagination(request):
    return render(request, 'elements/pagination.html')

def elements_popovers(request):
    return render(request, 'elements/popovers.html')

def elements_progress_bar(request):
    return render(request, 'elements/progress-bar.html')

def elements_search(request):
    return render(request, 'elements/search.html')

def elements_tooltips(request):
    return render(request, 'elements/tooltips.html')

def elements_treeview(request):
    return render(request, 'elements/treeview.html')

def elements_typography(request):
    return render(request, 'elements/typography.html')


def datatables_advanced(request):
    return render(request, 'datatables/advanced.html')

def datatables_alt_pagination(request):
    return render(request, 'datatables/alt-pagination.html')

def datatables_basic(request):
    return render(request, 'datatables/basic.html')

def datatables_order_sorting(request):
    return render(request, 'datatables/order-sorting.html')

def datatables_multi_column(request):
    return render(request, 'datatables/multi-column.html')

def datatables_multiple_tables(request):
    return render(request, 'datatables/multiple-tables.html')

def datatables_checkbox(request):
    return render(request, 'datatables/checkbox.html')

def datatables_clone_header(request):
    return render(request, 'datatables/clone-header.html')

def datatables_column_chooser(request):
    return render(request, 'datatables/column-chooser.html')

def datatables_range_search(request):
    return render(request, 'datatables/range-search.html')

def datatables_export(request):
    return render(request, 'datatables/export.html')

def datatables_skin(request):
    return render(request, 'datatables/skin.html')

def datatables_sticky_header(request):
    return render(request, 'datatables/sticky-header.html')


def forms_basic(request):
    return render(request, 'forms/basic.html')

def forms_input_group(request):
    return render(request, 'forms/input-group.html')

def forms_layouts(request):
    return render(request, 'forms/layouts.html')

def forms_validation(request):
    return render(request, 'forms/validation.html')

def forms_input_mask(request):
    return render(request, 'forms/input-mask.html')

def forms_select2(request):
    return render(request, 'forms/select2.html')

def forms_touchspin(request):
    return render(request, 'forms/touchspin.html')

def forms_checkbox_radio(request):
    return render(request, 'forms/checkbox-radio.html')

def forms_switches(request):
    return render(request, 'forms/switches.html')

def forms_wizards(request):
    return render(request, 'forms/wizards.html')

def forms_file_upload(request):
    return render(request, 'forms/file-upload.html')

def forms_quill_editor(request):
    return render(request, 'forms/quill-editor.html')

def forms_markdown_editor(request):
    return render(request, 'forms/markdown-editor.html')

def forms_date_picker(request):
    return render(request, 'forms/date-picker.html')

def forms_clipboard(request):
    return render(request, 'forms/clipboard.html')


    
def pages_knowledge_base(request):
    return render(request, 'pages/knowledge-base.html')

def pages_faq(request):
    return render(request, 'pages/faq.html')

def pages_contact_us_boxed(request):
    return render(request, 'pages/contact-us-boxed.html')

def pages_contact_us_cover(request):
    return render(request, 'pages/contact-us-cover.html')

def pages_coming_soon_boxed(request):
    return render(request, 'pages/coming-soon-boxed.html')

def pages_coming_soon_cover(request):
    return render(request, 'pages/coming-soon-cover.html')

def pages_error404(request):
    return render(request, 'pages/error404.html')

def pages_error500(request):
    return render(request, 'pages/error500.html')

def pages_error503(request):
    return render(request, 'pages/error503.html')

def pages_maintenence(request):
    return render(request, 'pages/maintenence.html')



def users_profile(request):
    return render(request, 'users/profile.html')

def users_user_account_settings(request):
    return render(request, 'users/user-account-settings.html')



def auth_boxed_signin(request):
    return render(request, 'auth/boxed-signin.html')

def auth_boxed_signup(request):
    return render(request, 'auth/boxed-signup.html')

def auth_boxed_lockscreen(request):
    return render(request, 'auth/boxed-lockscreen.html')

def auth_boxed_password_reset(request):
    return render(request, 'auth/boxed-password-reset.html')

def auth_cover_login(request):
    return render(request, 'auth/cover-login.html')

def auth_cover_register(request):
    return render(request, 'auth/cover-register.html')

def auth_cover_lockscreen(request):
    return render(request, 'auth/cover-lockscreen.html')

def auth_cover_password_reset(request):
    return render(request, 'auth/cover-password-reset.html')

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
def sandbox(request):
    context = {
        'analyses': [
            {
                'id': '1',
                'submission_time': '2025-02-02 10:00:00',
                'type': 'file',
                'name': 'suspicious.exe',
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'risk_score': 85,
                'status': 'completed'
            },
            # Add more sample analyses
        ]
    }
    return render(request, 'threat/sandbox.html', context)

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

# Hash Analysis View
@csrf_exempt
@require_http_methods(["POST"])
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
