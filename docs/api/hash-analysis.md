# Hash Analysis API

## Endpoint Overview

### Hash Analysis
```http
POST /api/v1/analysis/hash
```

Analyzes a file hash across multiple threat intelligence platforms and returns comprehensive analysis results.

## Request

### Headers
```http
Content-Type: application/json
Authorization: Bearer <your_api_token>
```

### Parameters
```json
{
    "hash": "string",         // Required: MD5, SHA-1, or SHA-256 hash
    "platforms": [            // Optional: List of platforms to query
        "virustotal",
        "hybridanalysis",
        "metadefender",
        "malwarebazaar",
        "threatfox",
        "filescan"
    ],
    "extended": boolean,      // Optional: Include extended analysis data
    "cache": boolean         // Optional: Use cached results if available
}
```

## Response

### Success Response
```json
{
    "status": "success",
    "data": {
        "file_info": {
            "hash": "string",
            "type": "string",
            "size": number,
            "magic": "string",
            "mime_type": "string"
        },
        "threat_metrics": {
            "threat_score": number,
            "confidence_score": number,
            "risk_level": "string",
            "detection_rate": number
        },
        "platform_data": {
            "virustotal": {
                "summary": {
                    "total_scans": number,
                    "malicious": number,
                    "suspicious": number,
                    "undetected": number,
                    "detection_rate": "string"
                },
                "detections": [
                    {
                        "engine": "string",
                        "category": "string",
                        "result": "string",
                        "method": "string"
                    }
                ],
                "malware_info": {
                    "family": "string",
                    "type": "string",
                    "behavior": ["string"],
                    "campaigns": ["string"]
                },
                "threat_intel": {
                    "first_seen": "string",
                    "last_seen": "string",
                    "distribution": ["string"],
                    "related_samples": ["string"]
                }
            }
            // Similar structure for other platforms
        }
    }
}
```

### Error Response
```json
{
    "status": "error",
    "error": {
        "code": "string",
        "message": "string",
        "details": {
            "platform": "string",
            "reason": "string"
        }
    }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400  | Invalid request parameters |
| 401  | Unauthorized - Invalid API token |
| 403  | Forbidden - Insufficient permissions |
| 404  | Hash not found in any platform |
| 429  | Rate limit exceeded |
| 500  | Internal server error |
| 503  | Platform service unavailable |

## Rate Limiting

- Default rate limit: 100 requests per minute
- Extended analysis: 50 requests per minute
- Bulk analysis: 20 requests per minute

Headers included in response:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1613589600
```

## Caching

- Default cache duration: 1 hour
- Extended analysis cache: 24 hours
- Cache can be bypassed using `cache: false`

## Examples

### Basic Analysis Request
```bash
curl -X POST "https://api.guardianvigil.com/v1/analysis/hash" \
     -H "Authorization: Bearer your_api_token" \
     -H "Content-Type: application/json" \
     -d '{
         "hash": "d41d8cd98f00b204e9800998ecf8427e",
         "platforms": ["virustotal", "hybridanalysis"]
     }'
```

### Extended Analysis Request
```bash
curl -X POST "https://api.guardianvigil.com/v1/analysis/hash" \
     -H "Authorization: Bearer your_api_token" \
     -H "Content-Type: application/json" \
     -d '{
         "hash": "d41d8cd98f00b204e9800998ecf8427e",
         "platforms": ["virustotal", "hybridanalysis"],
         "extended": true,
         "cache": false
     }'
```

## Best Practices

1. **Error Handling**
   - Implement exponential backoff for rate limits
   - Handle platform-specific errors gracefully
   - Cache frequently requested hashes

2. **Performance**
   - Use the cache parameter when real-time data isn't required
   - Limit the platforms parameter to only needed sources
   - Batch requests when possible

3. **Security**
   - Rotate API tokens regularly
   - Use HTTPS for all requests
   - Validate input hashes before submission

## Webhook Support

Register for real-time updates:
```http
POST /api/v1/webhooks/register
Content-Type: application/json

{
    "url": "https://your-server.com/webhook",
    "events": ["hash.analyzed", "hash.updated"],
    "platforms": ["virustotal", "hybridanalysis"]
}
```
