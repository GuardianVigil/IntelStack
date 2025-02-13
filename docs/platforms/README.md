# Platform Integration Guide

## Supported Platforms

### 1. VirusTotal
- **Website**: [VirusTotal](https://www.virustotal.com)
- **API Documentation**: [VirusTotal API v3](https://developers.virustotal.com/v3.0/reference)
- **Features**:
  - File hash analysis
  - URL scanning
  - Domain analysis
  - IP address analysis
- **Getting API Key**:
  1. Create account at [VirusTotal](https://www.virustotal.com)
  2. Go to your profile
  3. Navigate to API key section
  4. Copy your API key
- **Rate Limits**:
  - Public API: 4 requests/minute
  - Premium API: Varies by subscription
- **Example Usage**:
  ```python
  from services.platforms import VirusTotal
  
  vt = VirusTotal(api_key="your_key")
  result = await vt.analyze_hash("hash_value")
  ```

### 2. Hybrid Analysis
- **Website**: [Hybrid Analysis](https://www.hybrid-analysis.com)
- **API Documentation**: [Hybrid Analysis API](https://www.hybrid-analysis.com/docs/api/v2)
- **Features**:
  - Dynamic malware analysis
  - Static analysis
  - Sandbox analysis
  - YARA rule matching
- **Getting API Key**:
  1. Register at [Hybrid Analysis](https://www.hybrid-analysis.com)
  2. Submit business email verification
  3. Access API key in account settings
- **Rate Limits**:
  - Free tier: 200 requests/day
  - Enterprise: Custom limits
- **Example Usage**:
  ```python
  from services.platforms import HybridAnalysis
  
  ha = HybridAnalysis(api_key="your_key")
  result = await ha.analyze_file("file_hash")
  ```

### 3. MalwareBazaar
- **Website**: [MalwareBazaar](https://bazaar.abuse.ch)
- **API Documentation**: [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- **Features**:
  - Malware sample queries
  - Hash lookups
  - Tag-based searches
  - Recent submissions
- **Getting API Key**:
  1. Register at [MalwareBazaar](https://bazaar.abuse.ch)
  2. Complete email verification
  3. Request API key
- **Rate Limits**:
  - Standard: 1000 requests/day
- **Example Usage**:
  ```python
  from services.platforms import MalwareBazaar
  
  mb = MalwareBazaar(api_key="your_key")
  result = await mb.query_hash("hash_value")
  ```

### 4. ThreatFox
- **Website**: [ThreatFox](https://threatfox.abuse.ch)
- **API Documentation**: [ThreatFox API](https://threatfox.abuse.ch/api/)
- **Features**:
  - IOC database access
  - Malware tracking
  - Threat intelligence sharing
- **Getting API Key**:
  1. Register at [ThreatFox](https://threatfox.abuse.ch)
  2. Complete verification
  3. Access API key in profile
- **Rate Limits**:
  - Default: 500 requests/day
- **Example Usage**:
  ```python
  from services.platforms import ThreatFox
  
  tf = ThreatFox(api_key="your_key")
  result = await tf.search_ioc("indicator")
  ```

### 5. MetaDefender
- **Website**: [MetaDefender](https://metadefender.opswat.com)
- **API Documentation**: [MetaDefender API](https://docs.opswat.com/mdcloud/api)
- **Features**:
  - Multi-scanning engine
  - File reputation
  - Vulnerability scanning
  - Sanitization
- **Getting API Key**:
  1. Create account at [OPSWAT Portal](https://portal.opswat.com)
  2. Choose subscription plan
  3. Access API key in dashboard
- **Rate Limits**:
  - Free: 20 requests/day
  - Premium: Based on plan
- **Example Usage**:
  ```python
  from services.platforms import MetaDefender
  
  md = MetaDefender(api_key="your_key")
  result = await md.scan_hash("hash_value")
  ```

## Integration Best Practices

### 1. API Key Management
```python
# Use environment variables
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("PLATFORM_API_KEY")
```

### 2. Rate Limiting
```python
from services.utils import RateLimiter

limiter = RateLimiter(max_requests=100, time_window=60)

async def make_request():
    async with limiter:
        # Make API request
        pass
```

### 3. Error Handling
```python
try:
    result = await platform.analyze("indicator")
except RateLimitError:
    # Handle rate limiting
    await asyncio.sleep(60)
except AuthenticationError:
    # Handle auth issues
    logger.error("API key invalid")
except ConnectionError:
    # Handle connection issues
    logger.error("Platform unavailable")
```

### 4. Caching
```python
from services.cache import Cache

cache = Cache()

async def get_analysis(indicator):
    # Check cache first
    cached = await cache.get(indicator)
    if cached:
        return cached
    
    # Perform analysis
    result = await platform.analyze(indicator)
    
    # Cache result
    await cache.set(indicator, result)
    return result
```

## Platform-Specific Features

### 1. Hash Analysis
```python
# Available for all platforms
async def analyze_hash(hash_value):
    results = {}
    for platform in platforms:
        try:
            result = await platform.analyze_hash(hash_value)
            results[platform.name] = result
        except Exception as e:
            logger.error(f"Error with {platform.name}: {e}")
    return results
```

### 2. URL Analysis
```python
# Available for VirusTotal, Hybrid Analysis, MetaDefender
async def analyze_url(url):
    results = {}
    for platform in url_platforms:
        result = await platform.analyze_url(url)
        results[platform.name] = result
    return results
```

### 3. IP Analysis
```python
# Available for VirusTotal, ThreatFox
async def analyze_ip(ip_address):
    results = {}
    for platform in ip_platforms:
        result = await platform.analyze_ip(ip_address)
        results[platform.name] = result
    return results
```

### 4. Domain Analysis
```python
# Available for VirusTotal, MetaDefender
async def analyze_domain(domain):
    results = {}
    for platform in domain_platforms:
        result = await platform.analyze_domain(domain)
        results[platform.name] = result
    return results
```

## Configuration Examples

### 1. Platform Configuration
```yaml
# config/platforms.yaml
virustotal:
  api_key: ${VIRUSTOTAL_API_KEY}
  rate_limit: 4
  timeout: 30

hybrid_analysis:
  api_key: ${HYBRID_ANALYSIS_API_KEY}
  rate_limit: 200
  timeout: 60

malwarebazaar:
  api_key: ${MALWAREBAZAAR_API_KEY}
  rate_limit: 1000
  timeout: 30
```

### 2. Rate Limit Configuration
```yaml
# config/rate_limits.yaml
default:
  requests: 100
  window: 60

premium:
  requests: 1000
  window: 60

enterprise:
  requests: 5000
  window: 60
```

## Monitoring and Logging

### 1. Platform Health Checks
```python
async def check_platform_health():
    for platform in platforms:
        try:
            await platform.health_check()
            logger.info(f"{platform.name} is healthy")
        except Exception as e:
            logger.error(f"{platform.name} health check failed: {e}")
```

### 2. Usage Monitoring
```python
async def log_platform_usage():
    for platform in platforms:
        metrics = await platform.get_usage_metrics()
        logger.info(f"{platform.name} usage: {metrics}")
```

## Security Considerations

1. **API Key Protection**
   - Use environment variables
   - Encrypt stored keys
   - Regular key rotation

2. **Request Validation**
   - Sanitize inputs
   - Validate indicators
   - Check response integrity

3. **Error Handling**
   - Handle timeouts
   - Manage rate limits
   - Log security events
