# Threat Intelligence Platforms

This document provides detailed information about the threat intelligence platforms integrated into our system, including API specifications, implementation details, and best practices.

## Overview

Our system integrates with multiple threat intelligence platforms to provide comprehensive IP analysis. Each platform provides unique insights and data points that contribute to our overall threat assessment.

## Platform Details

### CrowdSec

**Base URL**: `https://cti.api.crowdsec.net/v2`

**Authentication**:
- Header: `x-api-key`
- Key Format: CTI API key (different from regular CrowdSec API key)
- Get Key: [CrowdSec Console](https://app.crowdsec.net)

**Endpoints**:
- IP Lookup: `GET /smoke/{ip}`

**Response Structure**:
```json
{
    "ip": "string",
    "reputation": "malicious|suspicious|known",
    "scores": {
        "overall": {
            "aggressiveness": 0-5,
            "threat": 0-5,
            "trust": 0-5,
            "anomaly": 0-5,
            "total": 0-5
        }
    },
    "behaviors": [
        {
            "name": "string",
            "label": "string",
            "description": "string"
        }
    ],
    "attack_details": [...],
    "classifications": {...},
    "mitre_techniques": [...]
}
```

**Score Calculation**:
- Base score from overall.total (scaled 0-100)
- Additional points for behaviors (10 points each, max 50)
- Additional points for attack details (5 points each, max 25)
- Final score capped at 100

### IPInfo

**Base URL**: `https://ipinfo.io`

**Authentication**:
- Query Parameter: `token`
- Get Key: [IPInfo Dashboard](https://ipinfo.io/account)

**Endpoints**:
- Basic Info: `GET /{ip}/json`
- Privacy Info: `GET /{ip}/privacy` (requires paid subscription)

**Response Structure**:
```json
{
    "ip": "string",
    "hostname": "string",
    "city": "string",
    "region": "string",
    "country": "string",
    "loc": "lat,long",
    "org": "string",
    "postal": "string",
    "timezone": "string"
}
```

**Error Handling**:
- Privacy module 403 errors are expected for free tier
- Basic info works on free tier
- Handle rate limits with exponential backoff

## Implementation Details

### API Key Management

Keys are stored in the database using the `APIKey` model:
- Encrypted storage using Fernet encryption
- Access via `api_key` property which handles decryption
- Keys can be managed via Django admin interface at `/admin/main/apikey/`

### Base Scanner Class

All platform scanners inherit from `BaseScanner` which provides:
- Common HTTP client handling
- Rate limiting and backoff
- Error handling and logging
- Abstract methods for platform-specific implementations

### Score Normalization

Each platform's scores are normalized to 0-100 scale:
1. Raw scores are extracted from platform-specific response formats
2. Platform-specific scoring algorithms applied
3. Results combined with weighted averaging
4. Final score capped at 100

### Error Handling

Common error scenarios and handling:
1. API Authentication
   - Invalid/expired keys
   - Missing permissions
   - Rate limits
2. Network Issues
   - Timeouts
   - Connection errors
3. Response Parsing
   - Invalid JSON
   - Missing fields
   - Unexpected formats

### Recent Changes (2025-02-09)

1. CrowdSec Integration Updates:
   - Fixed API key format (now using CTI API key)
   - Updated scoring algorithm to use official scores
   - Improved error messages and logging
   - Added support for new response fields (behaviors, attack details)

2. IPInfo Integration Updates:
   - Made privacy module optional
   - Improved error handling for subscription limitations
   - Added detailed logging for API responses

3. General Improvements:
   - Added API key management in Django admin
   - Enhanced logging across all platforms
   - Improved score calculation accuracy

## Best Practices

1. API Key Security:
   - Never log full API keys
   - Use preview format (first 4 chars + ***)
   - Store encrypted in database
   - Rotate keys periodically

2. Rate Limiting:
   - Implement exponential backoff
   - Cache responses when possible
   - Monitor usage against quotas

3. Error Handling:
   - Log detailed error information
   - Provide user-friendly error messages
   - Fail gracefully when services unavailable

4. Scoring:
   - Document scoring algorithms
   - Normalize all scores to 0-100
   - Consider platform reliability in weights

## Future Improvements

1. Caching:
   - Implement response caching
   - Add Redis/Memcached support
   - Configure TTL per platform

2. Monitoring:
   - Add API quota monitoring
   - Track response times
   - Alert on high error rates

3. Features:
   - Add bulk IP scanning
   - Implement webhook notifications
   - Add more threat intel sources
