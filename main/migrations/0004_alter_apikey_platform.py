# Generated by Django 5.1.6 on 2025-02-09 20:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0003_providersettings'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apikey',
            name='platform',
            field=models.CharField(choices=[('virustotal', 'VirusTotal'), ('crowdsec', 'CrowdSec'), ('greynoise', 'GreyNoise'), ('abuseipdb', 'AbuseIPDB'), ('hybrid_analysis', 'Hybrid Analysis'), ('alienvault', 'AlienVault OTX'), ('pulsedive', 'Pulsedive'), ('filescan', 'FileScan.io'), ('urlscan', 'URLScan.io'), ('securitytrails', 'SecurityTrails'), ('malwarebazaar', 'MalwareBazaar'), ('threatfox', 'ThreatFox'), ('urlhaus', 'URLhaus'), ('cisco_talos', 'Cisco Talos'), ('threatminer', 'ThreatMiner'), ('spamhaus', 'SpamHaus'), ('cleantalk', 'CleanTalk'), ('phishstats', 'PhishStats'), ('cloudmersive', 'Cloudmersive'), ('metadefender', 'MetaDefender'), ('ipinfo', 'IPInfo')], max_length=50),
        ),
    ]
