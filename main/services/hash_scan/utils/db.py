import logging
from typing import Dict, Optional
from django.contrib.auth.models import User
from main.models import APIKey
from asgiref.sync import sync_to_async
from django.core.exceptions import ObjectDoesNotExist

logger = logging.getLogger(__name__)

@sync_to_async
def get_api_key(platform_name: str) -> str:
    """Get API key for a specific platform."""
    try:
        api_key = APIKey.objects.filter(platform=platform_name).first()
        if api_key:
            return api_key.api_key
    except ObjectDoesNotExist:
        return None
    except Exception as e:
        logger.error(f"Error fetching API key for {platform_name}: {str(e)}")
        return None

@sync_to_async
def get_api_keys() -> dict:
    """Get all API keys."""
    try:
        api_keys = {}
        for key in APIKey.objects.all():
            api_keys[key.platform] = key.api_key
        return api_keys
    except Exception as e:
        logger.error(f"Error fetching API keys: {str(e)}")
        return {}

async def get_api_key(platform: str, user: User = None) -> Optional[str]:
    """
    Get API key for a specific platform and user.
    
    Args:
        platform: Platform name
        user: Django User object
        
    Returns:
        API key string if found, None otherwise
    """
    try:
        query = APIKey.objects.filter(platform=platform, is_active=True)
        if user:
            query = query.filter(user=user)
        api_key = query.first()
        return api_key.api_key if api_key else None
    except Exception as e:
        logger.error(f"Error fetching API key for {platform}: {str(e)}")
        return None

async def set_api_key(platform: str, api_key: str, user: User) -> bool:
    """
    Set or update an API key for a platform and user.
    
    Args:
        platform: Platform name
        api_key: API key value
        user: Django User object
        
    Returns:
        bool indicating success
    """
    try:
        api_key_obj, created = APIKey.objects.get_or_create(platform=platform, user=user)
        api_key_obj.api_key = api_key
        api_key_obj.save()
        return True
    except Exception as e:
        logger.error(f"Error setting API key for {platform}: {str(e)}")
        return False

async def delete_api_key(platform: str, user: User) -> bool:
    """
    Delete an API key for a platform and user.
    
    Args:
        platform: Platform name
        user: Django User object
        
    Returns:
        bool indicating success
    """
    try:
        api_key = APIKey.objects.filter(platform=platform, user=user).first()
        if api_key:
            api_key.delete()
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting API key for {platform}: {str(e)}")
        return False
