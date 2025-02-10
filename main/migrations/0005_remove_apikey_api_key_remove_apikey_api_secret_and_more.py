# Generated by Django 5.1.6 on 2025-02-09 22:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0004_alter_apikey_platform'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='apikey',
            name='api_key',
        ),
        migrations.RemoveField(
            model_name='apikey',
            name='api_secret',
        ),
        migrations.AddField(
            model_name='apikey',
            name='encrypted_api_key',
            field=models.BinaryField(null=True),
        ),
        migrations.AddField(
            model_name='apikey',
            name='encrypted_api_secret',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='apikey',
            name='key',
            field=models.TextField(null=True),
        ),
    ]
