# IoC Analysis Platforms Documentation

This document provides comprehensive information about various threat intelligence platforms and their APIs for IoC analysis.

## 1. IP Analysis Platforms

### VirusTotal
- **API Documentation**: https://virustotal.github.io/vt-py/
- **Python SDK**: `vt-py` (https://github.com/VirusTotal/vt-py)
- **Features**:
  - IP reputation analysis
  - Historical data
  - Associated domains
  - File samples
  - SSL certificates
- **Rate Limits**: Varies by subscription level
- **Authentication**: API key required

### AbuseIPDB
- **API Documentation**: https://docs.abuseipdb.com/
- **Integration**: REST API (no official Python SDK)
- **Features**:
  - IP address reputation
  - Recent reports
  - Blacklist check
  - Report submission
- **Rate Limits**: Varies by subscription
- **Authentication**: API key required

### SecurityTrails
- **API Documentation**: https://docs.securitytrails.com/
- **Python SDK**: `pysecuritytrails`
- **Features**:
  - Historical DNS data
  - Associated domains
  - SSL certificates
  - WHOIS data
- **Rate Limits**: Based on subscription
- **Authentication**: API key required

### CrowdSec
- **API Documentation**: https://doc.crowdsec.net/u/cti_api/intro/
- **Features**:
  - IP reputation
  - Threat scoring
  - Community-driven data
  - Real-time alerts
- **Rate Limits**: Documented in API
- **Authentication**: API key required

### GreyNoise
- **API Documentation**: https://docs.greynoise.io/
- **Python SDK**: `pygreynoise`
- **Features**:
  - Internet-wide scanner detection
  - IP context and classification
  - RIOT (Rule them out) dataset
- **Rate Limits**: Based on subscription level
- **Authentication**: API key required

### Cisco Talos
- **API Documentation**: https://talosintelligence.com/reputation_center/
- **Features**:
  - IP and Domain reputation
  - Email reputation
  - File reputation
  - Network threat intelligence
  - Threat data feeds
- **Rate Limits**: Based on subscription
- **Authentication**: API key required
- **Integration**: REST API
- **Notes**: 
  - Provides comprehensive threat intelligence
  - Strong focus on network security
  - Real-time threat detection

### ThreatMiner
- **API Documentation**: https://www.threatminer.org/api.php
- **Features**:
  - Domain information
  - IP address information
  - Sample analysis
  - SSL certificate search
  - WHOIS data
  - APT reports
- **Rate Limits**: Free service with fair usage policy
- **Authentication**: No API key required
- **Integration**: REST API
- **Notes**:
  - Free threat intelligence platform
  - Data analytics platform for threat research
  - Historical threat information

### SpamHaus
- **API Documentation**: https://docs.spamhaus.com/
- **Features**:
  - IP reputation
  - Domain reputation
  - Botnet tracking
  - Malware hash database
  - Zero-day malware detection
- **Rate Limits**: Based on subscription level
- **Authentication**: API key required
- **Integration**: REST API and DNS-based queries
- **Notes**:
  - Industry standard for spam and malware detection
  - Real-time threat intelligence
  - Multiple integration methods

### CleanTalk
- **API Documentation**: https://cleantalk.org/wiki/doku.php?id=api
- **Features**:
  - IP reputation check
  - Email address validation
  - Domain reputation
  - JavaScript checking
  - Real-time blacklists
- **Rate Limits**: Based on subscription
- **Authentication**: API key required
- **Integration**: REST API
- **Notes**:
  - Focus on anti-spam and anti-fraud
  - Real-time protection
  - Community-driven database

### PhishStats
- **API Documentation**: https://phishstats.info/api
- **Features**:
  - Phishing URL detection
  - Domain intelligence
  - IP reputation
  - SSL certificate information
  - WHOIS data
- **Rate Limits**: Fair usage policy
  - Free tier available
  - Premium options for higher limits
- **Authentication**: API key required for premium features
- **Integration**: REST API
- **Notes**:
  - Specialized in phishing detection
  - Real-time phishing feeds
  - Community-driven threat intelligence

### FileScan.io
- **API Documentation**: https://filescan.io/api/docs
- **Features**:
  - File reputation scanning
  - Malware detection
  - YARA rule matching
  - Static and dynamic analysis
  - Automated file analysis
- **Rate Limits**: Based on subscription
- **Authentication**: API key required
- **Integration**: REST API
- **Notes**:
  - Specialized in file analysis
  - Cloud-based scanning
  - Multiple analysis methods

### URLScan.io
- **API Documentation**: https://urlscan.io/docs/api/
- **Features**:
  - URL scanning and analysis
  - Screenshot capture
  - DOM analysis
  - Certificate chain analysis
  - Related indicators
- **Rate Limits**: 
  - Free tier: 2,000 scans per day
  - Pro tier: Higher limits available
- **Authentication**: API key required
  - Public API available with limitations
  - Pro API for additional features
- **Integration**: REST API
- **Notes**:
  - Specialized in URL analysis
  - Visual site inspection
  - Rich metadata collection

## 2. File Analysis Platforms

### Hybrid Analysis
- **API Documentation**: https://www.hybrid-analysis.com/docs/api/v2
- **Python SDK**: VxAPI
- **Features**:
  - Dynamic file analysis
  - Static analysis
  - Sandbox environment
  - YARA rule matching
- **Rate Limits**: Subscription based
- **Authentication**: API key required

### Pulsedive
- **API Documentation**: https://pulsedive-py.readthedocs.io/
- **Python SDK**: `pulsedive-py`
- **Features**:
  - Threat intelligence
  - IOC enrichment
  - Risk scoring
- **Rate Limits**: Based on subscription
- **Authentication**: API key required

## Additional Recommended Platforms

### AlienVault OTX
- **API Documentation**: https://otx.alienvault.com/api
- **Python SDK**: `OTXv2`
- **Features**:
  - Threat intelligence feeds
  - IOC lookup
  - Pulse creation
- **Rate Limits**: Based on subscription
- **Authentication**: API key required

### URLhaus
- **API Documentation**: https://urlhaus-api.abuse.ch/
- **Features**:
  - Malicious URL database
  - Recent payloads
  - URL status check
- **Rate Limits**: Fair usage policy
- **Authentication**: Free, no API key required

### MalwareBazaar
- **API Documentation**: https://bazaar.abuse.ch/api/
- **Features**:
  - Malware sample sharing
  - Hash lookups
  - Recent additions
- **Rate Limits**: Fair usage policy
- **Authentication**: API key for some features

### ThreatFox
- **API Documentation**: https://threatfox.abuse.ch/api/
- **Features**:
  - IOC database
  - Malware tracking
  - Threat feed
- **Rate Limits**: Fair usage policy
- **Authentication**: API key for some features

## Integration Considerations

When implementing IoC analysis backend:

1. **Rate Limiting**:
   - Implement proper rate limiting handling
   - Cache results where appropriate
   - Use bulk queries when available

2. **Error Handling**:
   - Handle API timeouts
   - Implement retry mechanisms
   - Log failed requests

3. **Data Normalization**:
   - Normalize responses from different platforms
   - Create consistent scoring system
   - Implement confidence ratings

4. **Performance**:
   - Use async requests where possible
   - Implement request pooling
   - Cache frequently accessed data

5. **Authentication**:
   - Secure API key storage
   - Implement key rotation
   - Monitor usage and quotas

## Integration Best Practices

### API Key Management
1. Store API keys securely using encryption
2. Implement key rotation mechanisms
3. Monitor key usage and quotas
4. Use environment variables for key storage

### Rate Limit Handling
1. Implement exponential backoff
2. Use request queuing
3. Cache responses where appropriate
4. Monitor API usage

### Error Handling
1. Implement retry mechanisms
2. Log failed requests
3. Handle timeouts gracefully
4. Validate responses

### Performance Optimization
1. Use async/await for concurrent requests
2. Implement connection pooling
3. Cache frequently accessed data
4. Use bulk queries when available

### Data Normalization
1. Standardize response formats
2. Implement consistent scoring
3. Normalize timestamps
4. Handle missing data

## Python Implementation Example

```python
from typing import Dict, Any
import aiohttp
import asyncio
import logging

class ThreatIntelligence:
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.session = None
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def query_platform(self, platform: str, endpoint: str, params: Dict[str, Any]) -> Dict:
        """Generic platform query method with retry logic"""
        if platform not in self.api_keys:
            raise ValueError(f"No API key configured for {platform}")

        retries = 3
        for attempt in range(retries):
            try:
                async with self.session.get(
                    endpoint,
                    params=params,
                    headers={"Authorization": f"Bearer {self.api_keys[platform]}"},
                    timeout=30
                ) as response:
                    if response.status == 429:  # Rate limit
                        retry_after = int(response.headers.get("Retry-After", 60))
                        await asyncio.sleep(retry_after)
                        continue
                    
                    response.raise_for_status()
                    return await response.json()
                    
            except Exception as e:
                self.logger.error(f"Error querying {platform}: {str(e)}")
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)

    async def enrich_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Enrich IoC using multiple platforms"""
        tasks = []
        platforms = self._get_platforms_for_ioc_type(ioc_type)
        
        for platform in platforms:
            task = self.query_platform(
                platform,
                self._get_endpoint(platform, ioc_type),
                {"value": value}
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._normalize_results(results)

## Required Python Packages

```bash
# Core requirements
pip install aiohttp       # For async HTTP requests
pip install cryptography  # For API key encryption
pip install tenacity     # For retry mechanisms
pip install cachetools   # For caching

# Platform-specific SDKs
pip install vt-py        # VirusTotal
pip install greynoise    # GreyNoise
pip install OTXv2        # AlienVault OTX
pip install pulsedive    # Pulsedive
pip install vxapi        # Hybrid Analysis
