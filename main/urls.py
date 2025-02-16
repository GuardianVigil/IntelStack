from django.urls import path, include
from . import views

urlpatterns = [
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main app URLs (all require login)
    path('', views.index, name='index'),  # Main dashboard page
    path('analytics/', views.analytics, name='analytics'),
    path('finance/', views.finance, name='finance'),
    path('crypto/', views.crypto, name='crypto'),

    path('apps/chat/', views.apps_chat, name='chat'),
    path('apps/mailbox/', views.apps_mailbox, name='mailbox'),
    path('apps/todolist/', views.apps_todolist, name='todolist'),
    path('apps/notes/', views.apps_notes, name='notes'),
    path('apps/contacts/', views.apps_contacts, name='contacts'),
    path('apps/calendar/', views.apps_calendar, name='calendar'),
    path('apps/scrumboard/', views.apps_scrumboard, name='scrumboard'),
    path('apps/invoice/add/', views.apps_invoice_add, name='invoice_add'),
    path('apps/invoice/edit/', views.apps_invoice_edit, name='invoice_edit'),
    path('apps/invoice/list/', views.apps_invoice_list, name='invoice_list'),
    path('apps/invoice/preview/', views.apps_invoice_preview, name='invoice_preview'),

    path('components/tabs/', views.components_tabs, name='components_tabs'),
    path('components/accordions/', views.components_accordions, name='components_accordions'),
    path('components/modals/', views.components_modals, name='components_modals'),
    path('components/cards/', views.components_cards, name='components_cards'),
    path('components/carousel/', views.components_carousel, name='components_carousel'),
    path('components/countdown/', views.components_countdown, name='components_countdown'),
    path('components/counter/', views.components_counter, name='components_counter'),
    path('components/sweetalert/', views.components_sweetalert, name='components_sweetalert'),
    path('components/timeline/', views.components_timeline, name='components_timeline'),
    path('components/notifications/', views.components_notifications, name='components_notifications'),
    path('components/media-object/', views.components_media_object, name='components_media_object'),
    path('components/list-group/', views.components_list_group, name='components_list_group'),
    path('components/pricing-table/', views.components_pricing_table, name='components_pricing_table'),
    path('components/lightbox/', views.components_lightbox, name='components_lightbox'),

    path('elements/alerts/', views.elements_alerts, name='elements_alerts'),
    path('elements/avatar/', views.elements_avatar, name='elements_avatar'),
    path('elements/badges/', views.elements_badges, name='elements_badges'),
    path('elements/breadcrumbs/', views.elements_breadcrumbs, name='elements_breadcrumbs'),
    path('elements/buttons/', views.elements_buttons, name='elements_buttons'),
    path('elements/buttons-group/', views.elements_buttons_group, name='elements_buttons_group'),
    path('elements/color-library/', views.elements_color_library, name='elements_color_library'),
    path('elements/dropdown/', views.elements_dropdown, name='elements_dropdown'),
    path('elements/infobox/', views.elements_infobox, name='elements_infobox'),
    path('elements/jumbotron/', views.elements_jumbotron, name='elements_jumbotron'),
    path('elements/loader/', views.elements_loader, name='elements_loader'),
    path('elements/pagination/', views.elements_pagination, name='elements_pagination'),
    path('elements/popovers/', views.elements_popovers, name='elements_popovers'),
    path('elements/progress-bar/', views.elements_progress_bar, name='elements_progress_bar'),
    path('elements/search/', views.elements_search, name='elements_search'),
    path('elements/tooltips/', views.elements_tooltips, name='elements_tooltips'),
    path('elements/treeview/', views.elements_treeview, name='elements_treeview'),
    path('elements/typography/', views.elements_typography, name='elements_typography'),

    path('datatables/advanced/', views.datatables_advanced, name='datatables_advanced'),
    path('datatables/alt-pagination/', views.datatables_alt_pagination, name='datatables_alt_pagination'),
    path('datatables/basic/', views.datatables_basic, name='datatables_basic'),
    path('datatables/checkbox/', views.datatables_checkbox, name='datatables_checkbox'),
    path('datatables/clone-header/', views.datatables_clone_header, name='datatables_clone_header'),
    path('datatables/column-chooser/', views.datatables_column_chooser, name='datatables_column_chooser'),
    path('datatables/export/', views.datatables_export, name='datatables_export'),
    path('datatables/multi-column/', views.datatables_multi_column, name='datatables_multi_column'),
    path('datatables/multiple-tables/', views.datatables_multiple_tables, name='datatables_multiple_tables'),
    path('datatables/order-sorting/', views.datatables_order_sorting, name='datatables_order_sorting'),
    path('datatables/range-search/', views.datatables_range_search, name='datatables_range_search'),
    path('datatables/skin/', views.datatables_skin, name='datatables_skin'),
    path('datatables/sticky-header/', views.datatables_sticky_header, name='datatables_sticky_header'),

    path('forms/basic/', views.forms_basic, name='forms_basic'),
    path('forms/input-group/', views.forms_input_group, name='forms_input_group'),
    path('forms/layouts/', views.forms_layouts, name='forms_layouts'),
    path('forms/validation/', views.forms_validation, name='forms_validation'),
    path('forms/input-mask/', views.forms_input_mask, name='forms_input_mask'),
    path('forms/select2/', views.forms_select2, name='forms_select2'),
    path('forms/touchspin/', views.forms_touchspin, name='forms_touchspin'),
    path('forms/checkbox-radio/', views.forms_checkbox_radio, name='forms_checkbox_radio'),
    path('forms/switches/', views.forms_switches, name='forms_switches'),
    path('forms/wizards/', views.forms_wizards, name='forms_wizards'),
    path('forms/file-upload/', views.forms_file_upload, name='forms_file_upload'),
    path('forms/quill-editor/', views.forms_quill_editor, name='forms_quill_editor'),
    path('forms/markdown-editor/', views.forms_markdown_editor, name='forms_markdown_editor'),
    path('forms/date-picker/', views.forms_date_picker, name='forms_date_picker'),
    path('forms/clipboard/', views.forms_clipboard, name='forms_clipboard'),

    path('pages/knowledge-base/', views.pages_knowledge_base, name='pages_knowledge_base'),
    path('pages/faq/', views.pages_faq, name='pages_faq'),
    path('pages/contact-us-boxed/', views.pages_contact_us_boxed, name='pages_contact_us_boxed'),
    path('pages/contact-us-cover/', views.pages_contact_us_cover, name='pages_contact_us_cover'),
    path('pages/coming-soon-boxed/', views.pages_coming_soon_boxed, name='pages_coming_soon_boxed'),
    path('pages/coming-soon-cover/', views.pages_coming_soon_cover, name='pages_coming_soon_cover'),
    path('pages/error404/', views.pages_error404, name='pages_error404'),
    path('pages/error500/', views.pages_error500, name='pages_error500'),
    path('pages/error503/', views.pages_error503, name='pages_error503'),
    path('pages/maintenence/', views.pages_maintenence, name='pages_maintenence'),

    path('users/profile/', views.users_profile, name='users_profile'),
    path('users/user-account-settings/', views.users_user_account_settings, name='users_user_account_settings'),

    path('auth/boxed-signin/', views.auth_boxed_signin, name='auth_boxed_signin'),
    path('auth/boxed-signup/', views.auth_boxed_signup, name='auth_boxed_signup'),
    path('auth/boxed-lockscreen/', views.auth_boxed_lockscreen, name='auth_boxed_lockscreen'),
    path('auth/boxed-password-reset/', views.auth_boxed_password_reset, name='auth_boxed_password_reset'),
    path('auth/cover-login/', views.auth_cover_login, name='cover_login'),
    path('auth/cover-register/', views.auth_cover_register, name='cover_register'),
    path('auth/cover-lockscreen/', views.auth_cover_lockscreen, name='cover_lockscreen'),
    path('auth/cover-password-reset/', views.auth_cover_password_reset , name='cover_password_reset'),

    path('charts/', views.charts, name='charts'),
    path('widgets/', views.widgets, name='widgets'),
    path('font-icons/', views.font_icons, name='font_icons'),
    path('dragndrop/', views.dragndrop, name='dragndrop'),
    path('tables/', views.tables, name='tables'), 

    # Threat Intelligence URLs
    path('threat/ip-analysis/', views.ip_analysis, name='ip_analysis'),
    path('threat/ip-analysis/analyze/<str:ip_address>/', views.analyze_ip_api, name='analyze_ip_api'),
    path('threat/hash-analysis/', views.hash_analysis, name='hash_analysis'),
    path('api/threat/hash-analysis/', views.analyze_hash, name='analyze_hash_api'),  # Match the frontend URL
    path('threat/domain-reputation/', views.domain_reputation, name='domain_reputation'),
    path('threat/url-scan/', views.url_scan, name='url_scan'),
    path('threat/email-investigation/', views.email_investigation, name='email_investigation'),
    # Header Menu URLs
    path('hunting/', views.hunting, name='hunting'),
    path('threat-feed/', views.threat_feed, name='threat_feed'),
    path('sandbox/', views.sandbox, name='sandbox'),
    path('mitre-attack/', views.mitre, name='mitre'),

    # Reports URLs
    path('reports/investigation-history/', views.investigation_history, name='investigation_history'),
    path('reports/threat-reports/', views.threat_reports, name='threat_reports'),
    path('reports/export-findings/', views.export_findings, name='export_findings'),
    
    # Settings URLs
    path('settings/api-configuration/', views.api_configuration, name='api_configuration'),
    path('settings/api-configuration/save/', views.save_api_key, name='save_api_key'),
    path('settings/api-configuration/load/', views.load_api_keys, name='load_api_keys'),
    path('settings/api-configuration/test/', views.test_api_key, name='test_api_key'),
    path('settings/api-configuration/delete/', views.delete_api_key, name='delete_api_key'),

    # Documentation URLs
    path('docs/', views.docs_home, name='docs_home'),
    path('docs/<str:article_path>/', views.docs_article, name='docs_article'),

    # API Endpoints
    path('api/analyze-ip/<str:ip_address>/', views.analyze_ip_api, name='analyze_ip_api'),
    path('api/analyze-hash/', views.analyze_hash, name='analyze_hash'),

    # Threat Feed URLs
    path('feeds/virustotal/', views.virustotal, name='virustotal'),
    path('feeds/abuseipdb/', views.abuseipdb, name='abuseipdb'),
    path('feeds/alienvault-otx/', views.alienvault_otx, name='alienvault_otx'),
    path('feeds/ibm-xforce/', views.ibm_xforce, name='ibm_xforce'),
    
    # Report URLs
    path('reports/investigation-history/', views.investigation_history, name='investigation_history'),
    path('reports/threat-reports/', views.threat_reports, name='threat_reports'),
    path('reports/export-findings/', views.export_findings, name='export_findings'),
    
    # Settings URLs
    path('settings/api-configuration/', views.api_configuration, name='api_configuration'),
    path('settings/user-profile/', views.user_profile, name='user_profile'),
    path('settings/security-settings/', views.security_settings, name='security_settings'),
    
    # Domain Reputation URLs
    path('services/domain-scan/', include('main.services.domain_scan.urls')),
]
