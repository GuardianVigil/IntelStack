from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ValidationError
from django.conf import settings
import json
import requests
from functools import wraps
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages

# Create your views here.
@login_required
def index(request):
    return render(request, 'index.html')

def api_configuration(request):
    return render(request, 'settings/api_configuration.html')

@csrf_exempt
@require_http_methods(['POST'])
def save_api_key(request):
    try:
        data = json.loads(request.body)
        platform = data.get('platform')
        api_key = data.get('api_key')
        
        if not platform or not api_key:
            return JsonResponse({'success': False, 'message': 'Platform and API key are required'})
        
        # Here you would typically save the API key securely
        # For now, we'll just return success
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})

@require_http_methods(['GET'])
def load_api_keys(request):
    try:
        # Here you would typically load the saved API keys
        # For now, return empty values
        api_keys = {
            'virustotal': '',
            'crowdsec': '',
            'greynoise': '',
            'abuseipdb': '',
            'hybrid_analysis': {
                'api_key': '',
                'api_secret': ''
            },
            'alienvault': '',
            'pulsedive': '',
            'filescan': '',
            'urlscan': '',
            'securitytrails': '',
            'phishtank': '',
            'malwarebazaar': '',
            'threatfox': '',
            'urlhaus': '',
            'cisco_talos': '',
            'threatminer': '',
            'spamhaus': '',
            'cleantalk': '',
            'phishstats': ''
        }
        return JsonResponse({'success': True, 'api_keys': api_keys})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})

@require_http_methods(['GET'])
def test_api_key(request):
    platform = request.GET.get('platform')
    
    if not platform:
        return JsonResponse({'success': False, 'message': 'Platform is required'})
    
    # Here you would typically test the API key
    # For now, return success
    return JsonResponse({'success': True})

@csrf_exempt
@require_http_methods(['POST'])
def delete_api_key(request):
    try:
        data = json.loads(request.body)
        platform = data.get('platform')
        
        if not platform:
            return JsonResponse({'success': False, 'message': 'Platform is required'})
        
        # Here you would typically delete the API key
        # For now, return success
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})

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
            next_url = request.GET.get('next', 'index')
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
    context = {}
    
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        if ip_address:
            try:
                # Initialize results dictionary
                context['ip_address'] = ip_address
                context['results'] = {
                    'virustotal': {
                        'country': 'United States',
                        'as_owner': 'AS15169 Google LLC',
                        'network': '8.8.8.0/24',
                        'reputation': 0,
                        'last_analysis_stats': {
                            'harmless': 80,
                            'malicious': 0,
                            'suspicious': 0,
                            'undetected': 10,
                            'timeout': 0
                        },
                        'last_analysis_results': {
                            'Kaspersky': {
                                'category': 'harmless',
                                'result': 'clean',
                                'update_date': '2025-02-02'
                            },
                            'McAfee': {
                                'category': 'harmless',
                                'result': 'clean',
                                'update_date': '2025-02-02'
                            }
                        }
                    },
                    'categories': {
                        'Malware': 0,
                        'Phishing': 0,
                        'Spam': 0,
                        'Botnet': 0
                    }
                }
                
                # Calculate threat score
                malicious_count = context['results']['virustotal']['last_analysis_stats']['malicious']
                total_count = sum(context['results']['virustotal']['last_analysis_stats'].values())
                
                threat_score = (malicious_count / total_count * 100) if total_count > 0 else 0
                
                # Set threat level and class based on score
                if threat_score >= 80:
                    threat_level = 'Critical Risk'
                    threat_class = 'bg-danger'
                elif threat_score >= 60:
                    threat_level = 'High Risk'
                    threat_class = 'bg-warning'
                elif threat_score >= 40:
                    threat_level = 'Medium Risk'
                    threat_class = 'bg-info'
                else:
                    threat_level = 'Low Risk'
                    threat_class = 'bg-success'
                
                context.update({
                    'final_score': threat_score,
                    'threat_level': threat_level,
                    'threat_class': threat_class,
                    'confidence': 95,
                    'provider_scores': {
                        'virustotal': {'score': 0, 'weight': 40},
                        'greynoise': {'score': 0, 'weight': 20},
                        'abuseipdb': {'score': 0, 'weight': 20},
                        'crowdsec': {'score': 0, 'weight': 20}
                    }
                })
                
            except Exception as e:
                context['error_message'] = f"Error analyzing IP address: {str(e)}"
    
    return render(request, 'threat/ip_analysis.html', context)

@login_required
def hash_analysis(request):
    return render(request, 'threat/hash_analysis.html')

@login_required
def domain_reputation(request):
    return render(request, 'threat/domain_reputation.html')

@login_required
def url_scan(request):
    return render(request, 'threat/url_scan.html')

@login_required
def email_investigation(request):
    return render(request, 'threat/email_investigation.html')

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
