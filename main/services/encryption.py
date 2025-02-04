"""Encryption utilities for API keys and sensitive data"""

from cryptography.fernet import Fernet
from django.conf import settings
import base64
import logging

logger = logging.getLogger(__name__)

def get_encryption_key():
    """Get or create Fernet encryption key"""
    try:
        key = settings.ENCRYPTION_KEY
        if isinstance(key, str):
            key = key.encode()
        return base64.urlsafe_b64encode(key.ljust(32)[:32])
    except Exception as e:
        logger.error(f"Error getting encryption key: {str(e)}")
        raise

def encrypt_api_key(api_key: str) -> str:
    """Encrypt an API key"""
    try:
        if not api_key:
            return None
            
        f = Fernet(get_encryption_key())
        encrypted_data = f.encrypt(api_key.encode())
        return encrypted_data.decode()
        
    except Exception as e:
        logger.error(f"Error encrypting API key: {str(e)}")
        raise

def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt an encrypted API key"""
    try:
        if not encrypted_key:
            return None
            
        f = Fernet(get_encryption_key())
        decrypted_data = f.decrypt(encrypted_key.encode())
        return decrypted_data.decode()
        
    except Exception as e:
        logger.error(f"Error decrypting API key: {str(e)}")
        raise

def rotate_encryption_key(old_key: bytes, new_key: bytes):
    """Rotate encryption key and re-encrypt all API keys"""
    from main.models import APIKey
    
    try:
        old_fernet = Fernet(old_key)
        new_fernet = Fernet(new_key)
        
        # Re-encrypt all API keys with new key
        for api_key in APIKey.objects.all():
            # Decrypt with old key
            decrypted_key = old_fernet.decrypt(api_key.encrypted_key.encode())
            
            # Encrypt with new key
            api_key.encrypted_key = new_fernet.encrypt(decrypted_key).decode()
            api_key.save()
            
        logger.info("Successfully rotated encryption key")
        
    except Exception as e:
        logger.error(f"Error rotating encryption key: {str(e)}")
        raise
