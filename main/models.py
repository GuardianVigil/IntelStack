from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ValidationError
from cryptography.fernet import Fernet

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
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    platform = models.CharField(max_length=50, choices=PLATFORM_CHOICES)
    api_key = models.TextField()
    api_secret = models.TextField(null=True, blank=True)  # For platforms that require two keys
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ['user', 'platform']
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'

    def __str__(self):
        return f'{self.get_platform_display()} API Key for {self.user.username}'

    def save(self, *args, **kwargs):
        if not hasattr(settings, 'ENCRYPTION_KEY'):
            raise ValidationError('ENCRYPTION_KEY must be set in settings')

        # Encrypt API keys before saving
        f = Fernet(settings.ENCRYPTION_KEY)
        self.api_key = f.encrypt(self.api_key.encode()).decode()
        if self.api_secret:
            self.api_secret = f.encrypt(self.api_secret.encode()).decode()

        super().save(*args, **kwargs)

    def get_decrypted_api_key(self):
        f = Fernet(settings.ENCRYPTION_KEY)
        return f.decrypt(self.api_key.encode()).decode()

    def get_decrypted_api_secret(self):
        if self.api_secret:
            f = Fernet(settings.ENCRYPTION_KEY)
            return f.decrypt(self.api_secret.encode()).decode()
        return None

# Create your models here.
