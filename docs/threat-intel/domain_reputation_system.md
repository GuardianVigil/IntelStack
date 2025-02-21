# Domain Reputation Analysis System

## Overview
The Domain Reputation Analysis System is a comprehensive solution that aggregates threat intelligence from multiple platforms to provide a detailed security analysis of any domain. The system integrates with various threat intelligence platforms, implements rate limiting and caching, and provides a modern, responsive user interface.

## Architecture

### Frontend Components
- **Location**: `/main/templates/threat/domain_reputation/domain_reputation.html`
- **Framework**: Alpine.js for reactive UI
- **Features**:
  - Real-time domain analysis
  - Interactive threat score display
  - Detailed platform-specific results
  - Error handling with toast notifications
  - Loading states and animations

### Backend Components

#### Core Service
- **Location**: `/main/services/domain_scan/domain_analysis.py`
- **Features**:
  - Asynchronous domain analysis
  - Multi-platform integration
  - Result aggregation
  - Threat score calculation
  - Error handling and logging

#### Platform Integrations
All platform integrations are located in `/main/services/domain_scan/platforms/`

1. **AlienVault OTX** (`alienvault.py`)
   - Domain reputation data
   - Known malicious activities
   - Threat indicators

2. **VirusTotal** (`virustotal.py`)
   - Malware analysis
   - URL scanning
   - Domain reputation

3. **Pulsedive** (`pulsedive.py`)
   - Threat intelligence
   - Risk scoring
   - Associated indicators

4. **MetaDefender** (`metadefender.py`)
   - Multi-scanning results
   - Threat detection
   - Domain analysis

5. **SecurityTrails** (`securitytrails.py`)
   - DNS history
   - Associated domains
   - SSL certificate information

#### Utilities

1. **Rate Limiting** (`/utils/rate_limiter.py`)
   ```python
   Platform Rate Limits:
   - AlienVault: 60 requests/minute
   - VirusTotal: 240 requests/minute
   - Pulsedive: 30 requests/minute
   - MetaDefender: 120 requests/minute
   - SecurityTrails: 60 requests/minute
   ```

2. **Caching** (`/utils/cache_manager.py`)
   ```python
   Cache Timeouts:
   - Full domain results: 1 hour
   - Platform-specific results: 30 minutes
   ```

3. **Data Aggregation** (`/utils/data_aggregation.py`)
   - Combines results from all platforms
   - Normalizes data formats
   - Calculates aggregate scores

4. **Data Formatting** (`/utils/data_formatter.py`)
   - Structures data for frontend
   - Formats dates and scores
   - Prepares platform-specific displays

## API Endpoints

### URL Configuration
- **Base Path**: `/services/domain-scan/`
- **URL Patterns**:
  ```python
  urlpatterns = [
      path('domain-reputation/', views.domain_reputation_view, name='domain_reputation'),
      path('api/domain-reputation/<str:domain>/', views.analyze_domain, name='analyze_domain'),
      path('api/domain-reputation/data/<str:domain>/', views.get_domain_data, name='get_domain_data'),
  ]
  ```

### Response Format
```json
{
    "domain": "example.com",
    "threat_score": 85,
    "summary": {
        "risk_level": "High",
        "categories": ["malware", "phishing"],
        "first_seen": "2024-01-01T00:00:00Z"
    },
    "whois": {
        "registrar": "Example Registrar",
        "creation_date": "2020-01-01",
        "expiration_date": "2025-01-01"
    },
    "security_analysis": {
        "blacklist_status": "Clean",
        "ssl_info": {...},
        "dns_records": {...}
    },
    "platform_data": {
        "alienvault": {...},
        "virustotal": {...},
        "pulsedive": {...},
        "metadefender": {...},
        "securitytrails": {...}
    }
}
```

## Database Schema

### API Keys Table
```sql
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    platform VARCHAR(50) NOT NULL,
    api_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Usage Examples

### Frontend
```javascript
// Initialize domain analysis
const domain = 'example.com';
const response = await fetch(`/services/domain-scan/api/domain-reputation/${encodeURIComponent(domain)}/`);
const results = await response.json();

// Display threat score
document.getElementById('threat-score').textContent = `${results.threat_score}%`;

// Update security status
const status = results.security_analysis.blacklist_status;
const statusElement = document.getElementById('security-status');
statusElement.textContent = status;
statusElement.className = `badge badge-${status.toLowerCase()}`;
```

### Backend
```python
# Initialize service
service = DomainAnalysisService(user)

# Analyze domain
results = await service.analyze_domain('example.com')

# Get cached results
cached_results = CacheManager.get_cached_results('example.com', user.id)

# Check rate limits
can_request, wait_time = RateLimiter.can_make_request('virustotal', user.id)
```

## Performance Considerations

### Caching Strategy
1. Check full domain cache first
2. Fall back to platform-specific caches
3. Make API calls only for uncached data
4. Cache new results at both levels

### Rate Limiting
1. Track requests per user per platform
2. Implement waiting when limits are reached
3. Provide feedback to users about wait times
4. Cache results to minimize API calls

## Security Considerations

1. **API Key Management**
   - Store keys in database
   - Per-user key isolation
   - Encrypted storage

2. **Rate Limiting**
   - Per-user limits
   - Platform-specific quotas
   - Protection against abuse

3. **Data Privacy**
   - Cache isolation per user
   - Secure transmission
   - Limited data retention

## Future Improvements

1. **Cache Optimization**
   - Implement cache warming
   - Add cache invalidation triggers
   - Optimize cache storage

2. **Rate Limit Management**
   - Add usage monitoring
   - Implement adaptive limits
   - Add user notifications

3. **Platform Integration**
   - Add more platforms
   - Implement failover
   - Add result verification

4. **UI Enhancements**
   - Add detailed analysis views
   - Implement trend analysis
   - Add export functionality
