# Threat Intelligence System Documentation

## System Overview

Our threat intelligence system integrates multiple threat intelligence platforms to provide comprehensive IP analysis and scoring. The system is built with:

- **Framework**: Django + aiohttp for async operations
- **Database**: PostgreSQL for API key storage
- **Encryption**: Fernet symmetric encryption for API keys
- **Architecture**: Modular scanner design with base class

## Core Components

### 1. Base Scanner (`base_scanner.py`)

```python
class BaseScanner:
    def __init__(self, session: aiohttp.ClientSession, api_key: Optional[str] = None):
        self.session = session
        self.api_key = api_key
        self.rate_limit_delay = 1.0  # Default delay
```

Key Features:
- Async HTTP client management
- Rate limiting with exponential backoff
- Common error handling
- Response parsing utilities

### 2. API Key Management

Located in `models.py`:
```python
class APIKey(models.Model):
    platform = models.CharField(max_length=50)
    encrypted_api_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

Features:
- Encrypted storage using Fernet
- Auto timestamps
- Platform-specific validation
- Admin interface integration

### 3. IP Analysis Service

Core service in `ip_analysis.py` that:
- Manages multiple scanners
- Aggregates results
- Calculates combined scores
- Handles async operations

## Platform Implementations

### 1. CrowdSec Scanner

**Purpose**: Advanced threat detection focusing on behavior patterns and attack signatures.

**API Details**:
```python
BASE_URL = "https://cti.api.crowdsec.net/v2"
ENDPOINTS = {
    "smoke": "/smoke/{ip}",  # Quick IP check
    "metrics": "/metrics/{ip}",  # Detailed metrics
    "decisions": "/decisions/{ip}"  # Active blocks
}
```

**Authentication**:
- Type: API Key (CTI API)
- Header: `x-api-key: <key>`
- Format: Base64 encoded string

**Response Processing**:
```python
def process_behaviors(behaviors: List[Dict]) -> Dict:
    return {
        "attack_types": [b["name"] for b in behaviors],
        "descriptions": [b["description"] for b in behaviors],
        "severity": calculate_behavior_severity(behaviors)
    }
```

**Scoring Algorithm**:
```python
def calculate_score(data: Dict) -> float:
    score = 0
    # Overall score (0-4 scale)
    if scores := data.get("scores", {}).get("overall", {}):
        total = scores.get("total", 0)
        score += float(total) * 25  # Scale to 0-100
        
    # Behaviors (up to 50 points)
    if behaviors := data.get("behaviors", []):
        score += min(50, len(behaviors) * 10)
        
    # Attack details (up to 25 points)
    if attack_details := data.get("attack_details", []):
        score += min(25, len(attack_details) * 5)
        
    return min(100, score)
```

**Error Handling**:
```python
ERRORS = {
    401: "Invalid API key format",
    403: "API key lacks permissions",
    429: "Rate limit exceeded",
    500: "CrowdSec service error"
}
```

**Rate Limiting**:
- Default: 1 request/second
- Burst: Up to 10 requests
- Backoff: Exponential with max 30s

### 2. IPInfo Scanner

**Purpose**: Geolocation and network intelligence.

**API Structure**:
```python
ENDPOINTS = {
    "basic": "/{ip}/json",  # Basic info
    "privacy": "/{ip}/privacy",  # Privacy detection
    "asn": "/{ip}/asn",  # ASN details
    "company": "/{ip}/company"  # Company info
}
```

**Authentication**:
- Type: Token
- Location: Query parameter
- Format: `?token=<key>`

**Response Processing**:
```python
def extract_network_info(data: Dict) -> Dict:
    return {
        "asn": data.get("org", "").split()[0],
        "organization": " ".join(data.get("org", "").split()[1:]),
        "network_type": determine_network_type(data),
        "geolocation": {
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "location": data.get("loc"),
            "timezone": data.get("timezone")
        }
    }
```

**Privacy Detection**:
```python
def analyze_privacy(data: Dict) -> Dict:
    return {
        "is_vpn": data.get("vpn", False),
        "is_proxy": data.get("proxy", False),
        "is_tor": data.get("tor", False),
        "is_datacenter": data.get("datacenter", False),
        "hosting": data.get("hosting", False)
    }
```

**Error Handling**:
```python
class IPInfoError(Exception):
    ERROR_CODES = {
        401: "Invalid API token",
        403: {
            "privacy": "Privacy module not available",
            "asn": "ASN module not available",
            "company": "Company module not available"
        },
        429: "Rate limit exceeded"
    }
```

## Integration Examples

### 1. Basic IP Scan
```python
async def scan_ip(ip: str) -> Dict:
    async with aiohttp.ClientSession() as session:
        scanners = [
            CrowdSecScanner(session, api_key),
            IPInfoScanner(session, api_key)
        ]
        results = await asyncio.gather(
            *[scanner.scan(ip) for scanner in scanners]
        )
        return combine_results(results)
```

### 2. Detailed Analysis
```python
async def analyze_ip(ip: str) -> Dict:
    results = await scan_ip(ip)
    return {
        "threat_score": calculate_combined_score(results),
        "network_info": extract_network_info(results),
        "security_flags": identify_security_flags(results),
        "recommendations": generate_recommendations(results)
    }
```

## Scoring System

### 1. Individual Platform Weights
```python
PLATFORM_WEIGHTS = {
    "crowdsec": 0.35,    # Behavioral analysis
    "ipinfo": 0.15,      # Network context
    "abuseipdb": 0.20,   # Community reports
    "virustotal": 0.30   # Multi-engine detection
}
```

### 2. Score Normalization
```python
def normalize_score(score: float, platform: str) -> float:
    if platform == "crowdsec":
        return score * 25 if score <= 4 else 100
    elif platform == "abuseipdb":
        return score  # Already 0-100
    elif platform == "virustotal":
        return (score / total_engines) * 100
```

## Error Recovery

### 1. Rate Limit Handling
```python
async def handle_rate_limit(response: aiohttp.ClientResponse) -> None:
    retry_after = int(response.headers.get("Retry-After", 60))
    await asyncio.sleep(min(retry_after, MAX_RETRY_DELAY))
```

### 2. Failover Strategy
```python
def get_failover_score(results: Dict) -> float:
    available_scores = [
        score for platform, score in results.items()
        if score is not None
    ]
    return statistics.mean(available_scores) if available_scores else None
```

## Best Practices

### 1. API Key Rotation
- Rotate keys every 90 days
- Use separate keys for development/production
- Monitor key usage and implement alerts

### 2. Response Caching
```python
CACHE_TTL = {
    "crowdsec": 3600,    # 1 hour
    "ipinfo": 86400,     # 24 hours
    "abuseipdb": 3600,   # 1 hour
    "virustotal": 3600   # 1 hour
}
```

### 3. Error Thresholds
```python
ERROR_THRESHOLDS = {
    "max_consecutive_failures": 5,
    "error_rate_threshold": 0.1,  # 10% error rate
    "recovery_time": 300  # 5 minutes
}
```

## Monitoring and Alerts

### 1. Health Metrics
```python
HEALTH_METRICS = {
    "response_time": {"warning": 1.0, "critical": 3.0},
    "error_rate": {"warning": 0.05, "critical": 0.10},
    "success_rate": {"warning": 0.95, "critical": 0.90}
}
```

### 2. Usage Tracking
```python
def track_usage(platform: str, response: Dict) -> None:
    metrics = {
        "timestamp": datetime.utcnow(),
        "platform": platform,
        "response_time": response["duration"],
        "status": response["status"],
        "error": response.get("error"),
        "quota_remaining": response.get("quota")
    }
    save_metrics(metrics)
```

## Future Improvements

### 1. Enhanced Caching
- Implement Redis for distributed caching
- Add cache warming for common IPs
- Implement intelligent cache invalidation

### 2. Machine Learning Integration
- Train models on historical data
- Implement anomaly detection
- Add predictive scoring

### 3. Advanced Analytics
- Add trend analysis
- Implement correlation detection
- Add network relationship mapping

## Troubleshooting Guide

### 1. Common Issues

#### API Authentication Failures
```python
async def diagnose_auth_failure(scanner: BaseScanner) -> str:
    # Test API key format
    if not is_valid_key_format(scanner.api_key):
        return "Invalid API key format"
    
    # Test API key permissions
    auth_test = await scanner.test_auth()
    if not auth_test["success"]:
        return f"Permission denied: {auth_test['error']}"
```

#### Rate Limiting
```python
def handle_rate_limit(scanner: BaseScanner) -> None:
    # Implement exponential backoff
    scanner.rate_limit_delay *= 2
    scanner.rate_limit_delay = min(
        scanner.rate_limit_delay,
        scanner.MAX_RETRY_DELAY
    )
```

### 2. Performance Issues
- Monitor response times
- Track API quotas
- Implement circuit breakers

## Development Guidelines

### 1. Adding New Platforms
1. Inherit from BaseScanner
2. Implement required methods
3. Add platform-specific error handling
4. Document API specifications
5. Add unit tests

### 2. Testing
```python
def test_scanner(scanner_class: Type[BaseScanner]) -> None:
    # Test basic functionality
    assert scanner.scan("1.1.1.1")
    
    # Test error handling
    with pytest.raises(RateLimitError):
        scanner.scan("rate-limit-test.com")
        
    # Test response parsing
    result = scanner.scan("test.com")
    assert "score" in result
```

## Security Considerations

### 1. API Key Protection
- Use environment variables
- Implement key rotation
- Monitor for unauthorized usage

### 2. Data Privacy
- Implement data retention policies
- Handle PII appropriately
- Follow GDPR guidelines

## Deployment

### 1. Configuration
```yaml
threat_intel:
  rate_limits:
    crowdsec: 60/minute
    ipinfo: 1000/day
    abuseipdb: 1000/day
  timeouts:
    connect: 5
    read: 30
  retries:
    max_attempts: 3
    backoff_factor: 2
```

### 2. Monitoring
```python
def monitor_health():
    return {
        "api_status": check_api_status(),
        "quota_usage": get_quota_usage(),
        "error_rates": calculate_error_rates(),
        "response_times": get_response_times()
    }
```

## API Documentation

### 1. Endpoints

#### Scan IP
```http
GET /api/v1/threat/ip/{ip_address}
Authorization: Bearer <token>
```

Response:
```json
{
    "threat_score": 85,
    "network_info": {
        "asn": "AS15169",
        "organization": "Google LLC",
        "country": "US"
    },
    "security_flags": [
        "tor_exit_node",
        "known_attacker"
    ],
    "raw_data": {
        "crowdsec": {...},
        "ipinfo": {...}
    }
}
```

#### Batch Scan
```http
POST /api/v1/threat/ip/batch
Content-Type: application/json

{
    "ips": ["1.1.1.1", "8.8.8.8"],
    "platforms": ["crowdsec", "ipinfo"]
}
```

## Maintenance

### 1. Regular Tasks
- API key rotation (90 days)
- Cache cleanup (daily)
- Metrics aggregation (hourly)
- Error log review (daily)

### 2. Monitoring
- Response time alerts
- Error rate thresholds
- Quota usage warnings
- System health checks
