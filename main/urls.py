from django.urls import path
from . import views

urlpatterns = [
    # Authentication URLs
    path('', views.login_view, name='login'),  # Make login the default landing page
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main app URLs (all require login)
    path('dashboard/', views.index, name='index'),
    path('dashboard/analytics', views.analytics, name='analytics'),
    path('dashboard/finance', views.finance, name='finance'),
    path('dashboard/crypto', views.crypto, name='crypto'),

    path('dashboard/apps/chat', views.apps_chat, name='chat'),
    path('dashboard/apps/mailbox', views.apps_mailbox, name='mailbox'),
    path('dashboard/apps/todolist', views.apps_todolist, name='todolist'),
    path('dashboard/apps/notes', views.apps_notes, name='notes'),
    path('dashboard/apps/contacts', views.apps_contacts, name='contacts'),
    path('dashboard/apps/calendar', views.apps_calendar, name='calendar'),
    path('dashboard/apps/scrumboard', views.apps_scrumboard, name='scrumboard'),
    path('dashboard/apps/invoice/add', views.apps_invoice_add, name='invoice_add'),
    path('dashboard/apps/invoice/edit', views.apps_invoice_edit, name='invoice_edit'),
    path('dashboard/apps/invoice/list', views.apps_invoice_list, name='invoice_list'),
    path('dashboard/apps/invoice/preview', views.apps_invoice_preview, name='invoice_preview'),

    path('dashboard/components/tabs', views.components_tabs, name='components_tabs'),
    path('dashboard/components/accordions', views.components_accordions, name='components_accordions'),
    path('dashboard/components/modals', views.components_modals, name='components_modals'),
    path('dashboard/components/cards', views.components_cards, name='components_cards'),
    path('dashboard/components/carousel', views.components_carousel, name='components_carousel'),
    path('dashboard/components/countdown', views.components_countdown, name='components_countdown'),
    path('dashboard/components/counter', views.components_counter, name='components_counter'),
    path('dashboard/components/sweetalert', views.components_sweetalert, name='components_sweetalert'),
    path('dashboard/components/timeline', views.components_timeline, name='components_timeline'),
    path('dashboard/components/notifications', views.components_notifications, name='components_notifications'),
    path('dashboard/components/media-object', views.components_media_object, name='components_media_object'),
    path('dashboard/components/list-group', views.components_list_group, name='components_list_group'),
    path('dashboard/components/pricing-table', views.components_pricing_table, name='components_pricing_table'),
    path('dashboard/components/lightbox', views.components_lightbox, name='components_lightbox'),

    path('dashboard/elements/alerts', views.elements_alerts, name='elements_alerts'),
    path('dashboard/elements/avatar', views.elements_avatar, name='elements_avatar'),
    path('dashboard/elements/badges', views.elements_badges, name='elements_badges'),
    path('dashboard/elements/breadcrumbs', views.elements_breadcrumbs, name='elements_breadcrumbs'),
    path('dashboard/elements/buttons', views.elements_buttons, name='elements_buttons'),
    path('dashboard/elements/buttons-group', views.elements_buttons_group, name='elements_buttons_group'),
    path('dashboard/elements/color-library', views.elements_color_library, name='elements_color_library'),
    path('dashboard/elements/dropdown', views.elements_dropdown, name='elements_dropdown'),
    path('dashboard/elements/infobox', views.elements_infobox, name='elements_infobox'),
    path('dashboard/elements/jumbotron', views.elements_jumbotron, name='elements_jumbotron'),
    path('dashboard/elements/loader', views.elements_loader, name='elements_loader'),
    path('dashboard/elements/pagination', views.elements_pagination, name='elements_pagination'),
    path('dashboard/elements/popovers', views.elements_popovers, name='elements_popovers'),
    path('dashboard/elements/progress-bar', views.elements_progress_bar, name='elements_progress_bar'),
    path('dashboard/elements/search', views.elements_search, name='elements_search'),
    path('dashboard/elements/tooltips', views.elements_tooltips, name='elements_tooltips'),
    path('dashboard/elements/treeview', views.elements_treeview, name='elements_treeview'),
    path('dashboard/elements/typography', views.elements_typography, name='elements_typography'),

    path('dashboard/datatables/advanced', views.datatables_advanced, name='datatables_advanced'),
    path('dashboard/datatables/alt-pagination', views.datatables_alt_pagination, name='datatables_alt_pagination'),
    path('dashboard/datatables/basic', views.datatables_basic, name='datatables_basic'),
    path('dashboard/datatables/checkbox', views.datatables_checkbox, name='datatables_checkbox'),
    path('dashboard/datatables/clone-header', views.datatables_clone_header, name='datatables_clone_header'),
    path('dashboard/datatables/column-chooser', views.datatables_column_chooser, name='datatables_column_chooser'),
    path('dashboard/datatables/export', views.datatables_export, name='datatables_export'),
    path('dashboard/datatables/multi-column', views.datatables_multi_column, name='datatables_multi_column'),
    path('dashboard/datatables/multiple-tables', views.datatables_multiple_tables, name='datatables_multiple_tables'),
    path('dashboard/datatables/order-sorting', views.datatables_order_sorting, name='datatables_order_sorting'),
    path('dashboard/datatables/range-search', views.datatables_range_search, name='datatables_range_search'),
    path('dashboard/datatables/skin', views.datatables_skin, name='datatables_skin'),
    path('dashboard/datatables/sticky-header', views.datatables_sticky_header, name='datatables_sticky_header'),

    path('dashboard/forms/basic', views.forms_basic, name='forms_basic'),
    path('dashboard/forms/input-group', views.forms_input_group, name='forms_input_group'),
    path('dashboard/forms/layouts', views.forms_layouts, name='forms_layouts'),
    path('dashboard/forms/validation', views.forms_validation, name='forms_validation'),
    path('dashboard/forms/input-mask', views.forms_input_mask, name='forms_input_mask'),
    path('dashboard/forms/select2', views.forms_select2, name='forms_select2'),
    path('dashboard/forms/touchspin', views.forms_touchspin, name='forms_touchspin'),
    path('dashboard/forms/checkbox-radio', views.forms_checkbox_radio, name='forms_checkbox_radio'),
    path('dashboard/forms/switches', views.forms_switches, name='forms_switches'),
    path('dashboard/forms/wizards', views.forms_wizards, name='forms_wizards'),
    path('dashboard/forms/file-upload', views.forms_file_upload, name='forms_file_upload'),
    path('dashboard/forms/quill-editor', views.forms_quill_editor, name='forms_quill_editor'),
    path('dashboard/forms/markdown-editor', views.forms_markdown_editor, name='forms_markdown_editor'),
    path('dashboard/forms/date-picker', views.forms_date_picker, name='forms_date_picker'),
    path('dashboard/forms/clipboard', views.forms_clipboard, name='forms_clipboard'),

    path('dashboard/pages/knowledge-base', views.pages_knowledge_base, name='pages_knowledge_base'),
    path('dashboard/pages/faq', views.pages_faq, name='pages_faq'),
    path('dashboard/pages/contact-us-boxed', views.pages_contact_us_boxed, name='pages_contact_us_boxed'),
    path('dashboard/pages/contact-us-cover', views.pages_contact_us_cover, name='pages_contact_us_cover'),
    path('dashboard/pages/coming-soon-boxed', views.pages_coming_soon_boxed, name='pages_coming_soon_boxed'),
    path('dashboard/pages/coming-soon-cover', views.pages_coming_soon_cover, name='pages_coming_soon_cover'),
    path('dashboard/pages/error404', views.pages_error404, name='pages_error404'),
    path('dashboard/pages/error500', views.pages_error500, name='pages_error500'),
    path('dashboard/pages/error503', views.pages_error503, name='pages_error503'),
    path('dashboard/pages/maintenence', views.pages_maintenence, name='pages_maintenence'),

    path('dashboard/users/profile', views.users_profile, name='users_profile'),
    path('dashboard/users/user-account-settings', views.users_user_account_settings, name='users_user_account_settings'),

    path('dashboard/auth/boxed-signin', views.auth_boxed_signin, name='auth_boxed_signin'),
    path('dashboard/auth/boxed-signup', views.auth_boxed_signup, name='auth_boxed_signup'),
    path('dashboard/auth/boxed-lockscreen', views.auth_boxed_lockscreen, name='auth_boxed_lockscreen'),
    path('dashboard/auth/boxed-password-reset', views.auth_boxed_password_reset, name='auth_boxed_password_reset'),
    path('dashboard/auth/cover-login', views.auth_cover_login, name='cover_login'),
    path('dashboard/auth/cover-register', views.auth_cover_register, name='cover_register'),
    path('dashboard/auth/cover-lockscreen', views.auth_cover_lockscreen, name='cover_lockscreen'),
    path('dashboard/auth/cover-password-reset', views.auth_cover_password_reset , name='cover_password_reset'),

    path('dashboard/charts', views.charts, name='charts'),
    path('dashboard/widgets', views.widgets, name='widgets'),
    path('dashboard/font-icons', views.font_icons, name='font_icons'),
    path('dashboard/dragndrop', views.dragndrop, name='dragndrop'),
    path('dashboard/tables', views.tables, name='tables'), 

    # Threat Intelligence URLs
    path('dashboard/threat/ip-analysis/', views.ip_analysis, name='ip_analysis'),
    path('dashboard/threat/hash-analysis/', views.hash_analysis, name='hash_analysis'),
    path('dashboard/threat/domain-reputation/', views.domain_reputation, name='domain_reputation'),
    path('dashboard/threat/url-scan/', views.url_scan, name='url_scan'),
    path('dashboard/threat/email-investigation/', views.email_investigation, name='email_investigation'),
    # Header Menu URLs
    path('hunting/', views.hunting, name='hunting'),
    path('threat-feed/', views.threat_feed, name='threat_feed'),
    path('sandbox/', views.sandbox, name='sandbox'),
    path('mitre-attack/', views.mitre, name='mitre'),

    # Reports URLs
    path('dashboard/reports/investigation-history/', views.investigation_history, name='investigation_history'),
    path('dashboard/reports/threat-reports/', views.threat_reports, name='threat_reports'),
    path('dashboard/reports/export-findings/', views.export_findings, name='export_findings'),
    
    # Settings URLs
    path('dashboard/settings/api-configuration/', views.api_configuration, name='api_configuration'),
    path('dashboard/settings/api-configuration/save/', views.save_api_key, name='save_api_key'),
    path('dashboard/settings/api-configuration/load/', views.load_api_keys, name='load_api_keys'),
    path('dashboard/settings/api-configuration/test/', views.test_api_key, name='test_api_key'),
    path('dashboard/settings/api-configuration/delete/', views.delete_api_key, name='delete_api_key'),

    # Threat Feed URLs
    path('dashboard/feeds/virustotal/', views.virustotal, name='virustotal'),
    path('dashboard/feeds/abuseipdb/', views.abuseipdb, name='abuseipdb'),
    path('dashboard/feeds/alienvault-otx/', views.alienvault_otx, name='alienvault_otx'),
    path('dashboard/feeds/ibm-xforce/', views.ibm_xforce, name='ibm_xforce'),
    
    # Report URLs
    path('dashboard/reports/investigation-history/', views.investigation_history, name='investigation_history'),
    path('dashboard/reports/threat-reports/', views.threat_reports, name='threat_reports'),
    path('dashboard/reports/export-findings/', views.export_findings, name='export_findings'),
    
    # Settings URLs
    path('dashboard/settings/api-configuration/', views.api_configuration, name='api_configuration'),
    path('dashboard/settings/user-profile/', views.user_profile, name='user_profile'),
    path('dashboard/settings/security-settings/', views.security_settings, name='security_settings'),
    
]
