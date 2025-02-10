# API Overview

Stack provides a comprehensive API for integrating threat intelligence capabilities into your existing security infrastructure.

## Authentication

All API requests require authentication using an API key. You can generate an API key from the Settings > API Configuration page.

Example:
```bash
curl -X GET "https://api.stack.local/v1/ip/analyze" \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json"
```

## Available Endpoints

### Threat Intelligence

#### IP Analysis
- `GET /v1/ip/analyze` - Analyze an IP address
- `GET /v1/ip/reputation` - Get IP reputation data
- `GET /v1/ip/history` - Get historical data for an IP

#### Domain Analysis
- `GET /v1/domain/analyze` - Analyze a domain
- `GET /v1/domain/reputation` - Get domain reputation
- `GET /v1/domain/whois` - Get WHOIS information

#### URL Analysis
- `GET /v1/url/analyze` - Analyze a URL
- `GET /v1/url/scan` - Submit URL for scanning
- `GET /v1/url/screenshot` - Get URL screenshot

#### File Analysis
- `POST /v1/file/analyze` - Submit file for analysis
- `GET /v1/file/report/{hash}` - Get analysis report
- `GET /v1/file/reputation/{hash}` - Get file reputation

### Hunting

- `POST /v1/hunting/search` - Search for threats
- `GET /v1/hunting/rules` - List YARA rules
- `POST /v1/hunting/rules` - Create YARA rule

### Reporting

- `GET /v1/reports` - List threat reports
- `POST /v1/reports` - Create new report
- `GET /v1/reports/{id}` - Get report details
- `GET /v1/reports/export` - Export findings

## Rate Limiting

API requests are rate-limited to:
- 100 requests per minute for standard tier
- 1000 requests per minute for enterprise tier

## Error Handling

The API uses standard HTTP status codes and returns detailed error messages in JSON format:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded. Please try again later.",
    "status": 429
  }
}
```

For detailed API documentation and examples, see the [API Reference](reference.md).
