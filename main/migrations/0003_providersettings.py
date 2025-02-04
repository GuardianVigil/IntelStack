# Generated by Django 5.1.5 on 2025-02-04 01:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_alter_apikey_platform'),
    ]

    operations = [
        migrations.CreateModel(
            name='ProviderSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('provider_name', models.CharField(max_length=50)),
                ('api_key', models.CharField(max_length=500)),
                ('is_enabled', models.BooleanField(default=True)),
                ('last_validated', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Provider Settings',
                'verbose_name_plural': 'Provider Settings',
                'unique_together': {('provider_name',)},
            },
        ),
    ]
