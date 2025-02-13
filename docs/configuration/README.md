# Configuration Guide

## Overview
This guide covers all configuration aspects of GuardianVigil, including environment setup, platform integration, and system settings.

## Table of Contents
1. [Environment Variables](#environment-variables)
2. [Database Configuration](#database-configuration)
3. [Redis Configuration](#redis-configuration)
4. [Platform API Keys](#platform-api-keys)
5. [System Settings](#system-settings)
6. [Logging Configuration](#logging-configuration)
7. [Security Settings](#security-settings)
8. [Performance Tuning](#performance-tuning)

## Environment Variables

### Core Settings
```env
# Application Settings
DEBUG=False
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,example.com
CORS_ORIGINS=http://localhost:3000,https://example.com

# Database
DB_NAME=guardianvigil
DB_USER=dbuser
DB_PASSWORD=dbpassword
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=redispassword

# Celery
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

### Platform API Keys
```env
# VirusTotal
VIRUSTOTAL_API_KEY=your-vt-api-key
VIRUSTOTAL_API_URL=https://www.virustotal.com/vtapi/v3

# Hybrid Analysis
HYBRID_ANALYSIS_API_KEY=your-ha-api-key
HYBRID_ANALYSIS_API_URL=https://www.hybrid-analysis.com/api/v2

# MalwareBazaar
MALWAREBAZAAR_API_KEY=your-mb-api-key
MALWAREBAZAAR_API_URL=https://mb-api.abuse.ch/api/v1

# ThreatFox
THREATFOX_API_KEY=your-tf-api-key
THREATFOX_API_URL=https://threatfox-api.abuse.ch/api/v1

# MetaDefender
METADEFENDER_API_KEY=your-md-api-key
METADEFENDER_API_URL=https://api.metadefender.com/v4
```

## Database Configuration

### PostgreSQL Settings
```python
# settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT'),
        'CONN_MAX_AGE': 600,
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'require'
        }
    }
}
```

### Database Optimization
```postgresql
-- postgresql.conf
max_connections = 100
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 20MB
maintenance_work_mem = 512MB
random_page_cost = 1.1
effective_io_concurrency = 200
```

## Redis Configuration

### Redis Settings
```conf
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
timeout 300
tcp-keepalive 60
databases 16
save 900 1
save 300 10
save 60 10000
```

### Cache Configuration
```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'RETRY_ON_TIMEOUT': True,
            'MAX_CONNECTIONS': 1000,
            'CONNECTION_POOL_CLASS': 'redis.connection.BlockingConnectionPool',
        }
    }
}
```

## Platform API Keys

### API Key Management
```python
# utils/key_manager.py
class APIKeyManager:
    def __init__(self):
        self.key_store = KeyStore()
    
    def get_platform_key(self, platform: str) -> str:
        return self.key_store.get_key(platform)
    
    def rotate_key(self, platform: str, new_key: str):
        self.key_store.update_key(platform, new_key)
```

### Rate Limiting
```python
# settings.py
PLATFORM_RATE_LIMITS = {
    'virustotal': {
        'requests_per_minute': 4,
        'burst': 4
    },
    'hybrid_analysis': {
        'requests_per_minute': 200,
        'burst': 10
    }
}
```

## System Settings

### Application Settings
```python
# settings.py
# Security Settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# File Upload Settings
MAX_UPLOAD_SIZE = 52428800  # 50MB
ALLOWED_UPLOAD_EXTENSIONS = ['.txt', '.pdf', '.doc', '.docx', '.exe', '.dll']

# Analysis Settings
ANALYSIS_TIMEOUT = 300  # seconds
MAX_PARALLEL_ANALYSES = 10
CACHE_DURATION = 3600  # 1 hour
```

### Celery Configuration
```python
# celery.py
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

CELERY_TASK_ROUTES = {
    'analysis.tasks.analyze_hash': {'queue': 'hash_analysis'},
    'analysis.tasks.analyze_ip': {'queue': 'ip_analysis'},
    'analysis.tasks.analyze_url': {'queue': 'url_analysis'},
    'analysis.tasks.analyze_domain': {'queue': 'domain_analysis'}
}
```

## Logging Configuration

### Logging Settings
```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/guardianvigil.log',
            'formatter': 'verbose'
        },
        'sentry': {
            'level': 'ERROR',
            'class': 'raven.contrib.django.handlers.SentryHandler',
        }
    },
    'loggers': {
        'guardianvigil': {
            'handlers': ['file', 'sentry'],
            'level': 'INFO',
            'propagate': True,
        },
    }
}
```

### Sentry Integration
```python
# settings.py
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn="your-sentry-dsn",
    integrations=[DjangoIntegration()],
    traces_sample_rate=1.0,
    send_default_pii=False
)
```

## Security Settings

### Authentication Configuration
```python
# settings.py
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True
}
```

### CORS Settings
```python
# settings.py
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://example.com"
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
```

## Performance Tuning

### Caching Strategy
```python
# settings.py
CACHING_STRATEGY = {
    'hash_analysis': {
        'ttl': 3600,  # 1 hour
        'max_size': 10000
    },
    'ip_analysis': {
        'ttl': 1800,  # 30 minutes
        'max_size': 5000
    },
    'url_analysis': {
        'ttl': 900,   # 15 minutes
        'max_size': 5000
    },
    'domain_analysis': {
        'ttl': 3600,  # 1 hour
        'max_size': 5000
    }
}
```

### Queue Configuration
```python
# settings.py
QUEUE_CONFIG = {
    'hash_analysis': {
        'max_retries': 3,
        'retry_delay': 300,  # 5 minutes
        'priority': 'high'
    },
    'ip_analysis': {
        'max_retries': 2,
        'retry_delay': 180,  # 3 minutes
        'priority': 'medium'
    }
}
```

### Connection Pooling
```python
# settings.py
DB_POOL_OPTIONS = {
    'max_overflow': 10,
    'pool_size': 5,
    'recycle': 300
}

REDIS_POOL_OPTIONS = {
    'max_connections': 100,
    'timeout': 20
}
```

## Monitoring Configuration

### Prometheus Metrics
```python
# monitoring.py
from prometheus_client import Counter, Histogram

REQUEST_COUNT = Counter(
    'request_count',
    'App Request Count',
    ['method', 'endpoint', 'http_status']
)

REQUEST_LATENCY = Histogram(
    'request_latency_seconds',
    'Request latency',
    ['endpoint']
)
```

### Health Checks
```python
# health.py
HEALTH_CHECK_CONFIG = {
    'database': {
        'timeout': 3,
        'retries': 2
    },
    'redis': {
        'timeout': 2,
        'retries': 2
    },
    'platforms': {
        'timeout': 5,
        'retries': 1
    }
}
```
