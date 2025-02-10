from django.contrib import admin
from django.utils.html import format_html
from .models import APIKey

# Register your models here.

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('platform', 'key_preview', 'created_at', 'updated_at')
    list_filter = ('platform',)
    search_fields = ('platform',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('platform',)
    
    def key_preview(self, obj):
        """Show first few characters of the decrypted API key"""
        try:
            key = obj.api_key
            if key:
                preview = key[:4] + '***' if len(key) > 4 else '***'
                return format_html(
                    '<span title="Use the edit page to view/edit the full key">{}</span>',
                    preview
                )
            return '(No key set)'
        except Exception as e:
            return f'(Error: {str(e)})'
    key_preview.short_description = 'API Key Preview'
    
    fieldsets = (
        (None, {
            'fields': ('platform', 'encrypted_api_key')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        """Encrypt the API key before saving"""
        # The model's save() method handles encryption
        super().save_model(request, obj, form, change)
    
    class Media:
        css = {
            'all': ('admin/css/api_key_admin.css',)
        }
