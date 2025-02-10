from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ValidationError
from cryptography.fernet import Fernet
from .services.encryption import encrypt_api_key, decrypt_api_key

class APIKey(models.Model):
    PLATFORM_CHOICES = [
        ('virustotal', 'VirusTotal'),
        ('crowdsec', 'CrowdSec'),
        ('greynoise', 'GreyNoise'),
        ('abuseipdb', 'AbuseIPDB'),
        ('hybrid_analysis', 'Hybrid Analysis'),
        ('alienvault', 'AlienVault OTX'),
        ('pulsedive', 'Pulsedive'),
        ('filescan', 'FileScan.io'),
        ('urlscan', 'URLScan.io'),
        ('securitytrails', 'SecurityTrails'),
        ('malwarebazaar', 'MalwareBazaar'),
        ('threatfox', 'ThreatFox'),
        ('urlhaus', 'URLhaus'),
        ('cisco_talos', 'Cisco Talos'),
        ('threatminer', 'ThreatMiner'),
        ('spamhaus', 'SpamHaus'),
        ('cleantalk', 'CleanTalk'),
        ('phishstats', 'PhishStats'),
        ('cloudmersive', 'Cloudmersive'),
        ('metadefender', 'MetaDefender'),
        ('ipinfo', 'IPInfo'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    platform = models.CharField(max_length=50, choices=PLATFORM_CHOICES)
    encrypted_api_key = models.BinaryField(null=True)  # Changed from api_key to encrypted_api_key
    encrypted_api_secret = models.BinaryField(null=True, blank=True)  # Changed from api_secret to encrypted_api_secret
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    key = models.TextField(null=True)  # Added for backward compatibility

    class Meta:
        unique_together = ['user', 'platform']
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'

    def __str__(self):
        return f'{self.get_platform_display()} API Key for {self.user.username}'

    @property
    def api_key(self) -> str:
        """Get the decrypted API key."""
        if self.key:  # For backward compatibility
            return self.key
        if not self.encrypted_api_key:
            return None
        return decrypt_api_key(self.encrypted_api_key)

    @api_key.setter
    def api_key(self, value: str):
        """Set and encrypt the API key."""
        if not value:
            self.encrypted_api_key = None
            return
        self.encrypted_api_key = encrypt_api_key(value)

    @property
    def api_secret(self) -> str:
        """Get the decrypted API secret."""
        if not self.encrypted_api_secret:
            return None
        return decrypt_api_key(self.encrypted_api_secret)

    @api_secret.setter
    def api_secret(self, value: str):
        """Set and encrypt the API secret."""
        if not value:
            self.encrypted_api_secret = None
            return
        self.encrypted_api_secret = encrypt_api_key(value)

    def save(self, *args, **kwargs):
        # For backward compatibility, copy key to encrypted_api_key if exists
        if self.key and not self.encrypted_api_key:
            self.api_key = self.key
            self.key = None
        super().save(*args, **kwargs)

class ProviderSettings(models.Model):
    """Model to store provider API keys and settings."""
    
    provider_name = models.CharField(max_length=50)
    api_key = models.CharField(max_length=500)
    is_enabled = models.BooleanField(default=True)
    last_validated = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('provider_name',)
        verbose_name = 'Provider Settings'
        verbose_name_plural = 'Provider Settings'

    def __str__(self):
        return f"{self.provider_name} Settings"

    def save(self, *args, **kwargs):
        """Encrypt API key before saving."""
        if not self.pk:  # Only encrypt on creation
            self.api_key = encrypt_api_key(self.api_key)
        super().save(*args, **kwargs)

    def get_decrypted_api_key(self):
        """Get the decrypted API key."""
        return decrypt_api_key(self.api_key)

    @classmethod
    def get_api_key(cls, provider_name):
        """Get API key for a provider."""
        try:
            provider = cls.objects.get(provider_name=provider_name, is_enabled=True)
            return provider.get_decrypted_api_key()
        except cls.DoesNotExist:
            return None

# Create your models here.
