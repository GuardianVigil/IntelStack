"""Encryption utilities for API keys and sensitive data"""
import os
from cryptography.fernet import Fernet
from django.conf import settings
import base64
import logging

logger = logging.getLogger(__name__)

def get_encryption_key():
    """Get Fernet encryption key"""
    if not hasattr(settings, 'ENCRYPTION_KEY'):
        key = Fernet.generate_key()
        setattr(settings, 'ENCRYPTION_KEY', key)
        return key
    
    key = settings.ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode()
    return key

def encrypt_api_key(api_key: str) -> bytes:
    """Encrypt an API key"""
    if not api_key:
        return None
    
    try:
        if isinstance(api_key, bytes):
            api_key = api_key.decode()
        
        f = Fernet(get_encryption_key())
        return f.encrypt(api_key.encode())
    except Exception as e:
        logger.error(f"Error encrypting API key: {str(e)}")
        raise

def decrypt_api_key(encrypted_key: bytes) -> str:
    """Decrypt an encrypted API key"""
    if not encrypted_key:
        return None
        
    try:
        if isinstance(encrypted_key, str):
            encrypted_key = encrypted_key.encode()
            
        if isinstance(encrypted_key, memoryview):
            encrypted_key = encrypted_key.tobytes()
            
        f = Fernet(get_encryption_key())
        decrypted_data = f.decrypt(encrypted_key)
        return decrypted_data.decode()
    except Exception as e:
        logger.error(f"Error decrypting API key: {str(e)}, type: {type(encrypted_key)}")
        raise

def rotate_encryption_key(old_key: bytes, new_key: bytes):
    """Rotate encryption key and re-encrypt all API keys"""
    from main.models import APIKey
    
    try:
        old_fernet = Fernet(old_key)
        new_fernet = Fernet(new_key)
        
        for api_key in APIKey.objects.all():
            if api_key.encrypted_api_key:
                # Decrypt with old key
                decrypted = old_fernet.decrypt(api_key.encrypted_api_key)
                # Re-encrypt with new key
                api_key.encrypted_api_key = new_fernet.encrypt(decrypted)
                api_key.save()
                
            if api_key.encrypted_api_secret:
                # Decrypt with old key
                decrypted = old_fernet.decrypt(api_key.encrypted_api_secret)
                # Re-encrypt with new key
                api_key.encrypted_api_secret = new_fernet.encrypt(decrypted)
                api_key.save()
    except Exception as e:
        logger.error(f"Error rotating encryption key: {str(e)}")
        raise
