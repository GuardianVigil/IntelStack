# Hash Analysis Development Guide

## Architecture Overview

### Component Structure
```
services/hash_scan/
├── platforms/           # Platform-specific implementations
│   ├── base.py         # Base platform class
│   ├── virustotal.py   # VirusTotal implementation
│   ├── hybrid.py       # Hybrid Analysis implementation
│   └── ...
├── utils/
│   ├── cache.py        # Caching utilities
│   ├── data_formatter_hash.py  # Data formatting
│   └── validators.py   # Input validation
└── hash_analysis.py    # Main analysis logic
```

## Key Components

### 1. Platform Base Class
The `BasePlatform` class in `base.py` defines the interface for all platform implementations:

```python
class BasePlatform:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = self._init_session()

    async def analyze_hash(self, hash_value: str) -> Dict:
        """Execute hash analysis and return results."""
        raise NotImplementedError

    async def _make_request(self, endpoint: str, params: Dict) -> Dict:
        """Make API request with rate limiting and error handling."""
        pass
```

### 2. Data Formatter
The `data_formatter_hash.py` module handles data normalization:

```python
def format_platform_data(platform_name: str, data: Dict) -> Dict:
    """Format platform-specific data into standardized structure."""
    formatted_data = {
        "summary": {},
        "detections": [],
        "malware_info": {},
        "threat_intel": {}
    }
    # Platform-specific formatting logic
    return formatted_data
```

### 3. Frontend Components
The hash analysis template uses Alpine.js for dynamic content:

```html
<div x-data="hashAnalysis">
    <!-- Analysis form -->
    <div class="panel">
        <!-- Platform-specific content -->
        <template x-for="platform in platforms">
            <!-- Display components -->
        </template>
    </div>
</div>
```

## Implementation Guide

### 1. Adding a New Platform

1. Create a new platform class:
```python
# platforms/new_platform.py
from .base import BasePlatform

class NewPlatform(BasePlatform):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.base_url = "https://api.newplatform.com/v1"

    async def analyze_hash(self, hash_value: str) -> Dict:
        endpoint = f"/file/{hash_value}"
        response = await self._make_request(endpoint, {})
        return self._process_response(response)
```

2. Add formatter function:
```python
# utils/data_formatter_hash.py
def format_new_platform_data(data: Dict) -> Dict:
    return {
        "summary": {
            "total_scans": data.get("total", 0),
            "malicious": data.get("detected", 0)
        },
        "detections": [
            {
                "engine": engine,
                "result": result
            } for engine, result in data.get("scans", {}).items()
        ]
    }
```

3. Update frontend template:
```html
<!-- Add platform-specific display logic -->
<div x-show="results.platformData.newPlatform">
    <!-- Platform content -->
</div>
```

### 2. Implementing Caching

1. Configure Redis cache:
```python
# utils/cache.py
class HashCache:
    def __init__(self):
        self.redis = Redis(host='localhost', port=6379)
        self.default_ttl = 3600  # 1 hour

    async def get(self, hash_value: str, platform: str) -> Optional[Dict]:
        key = f"hash:{hash_value}:{platform}"
        return await self.redis.get(key)

    async def set(self, hash_value: str, platform: str, data: Dict):
        key = f"hash:{hash_value}:{platform}"
        await self.redis.set(key, json.dumps(data), ex=self.default_ttl)
```

### 3. Error Handling

1. Define custom exceptions:
```python
class PlatformError(Exception):
    def __init__(self, platform: str, message: str):
        self.platform = platform
        self.message = message

class RateLimitError(PlatformError):
    pass
```

2. Implement error handling:
```python
async def _make_request(self, endpoint: str, params: Dict) -> Dict:
    try:
        async with self.session.get(endpoint, params=params) as response:
            if response.status == 429:
                raise RateLimitError(self.name, "Rate limit exceeded")
            data = await response.json()
            return data
    except Exception as e:
        raise PlatformError(self.name, str(e))
```

## Testing

### 1. Unit Tests
```python
# test/test_hash_analysis.py
async def test_platform_analysis():
    platform = NewPlatform("test_key")
    result = await platform.analyze_hash("test_hash")
    assert "summary" in result
    assert "detections" in result
```

### 2. Integration Tests
```python
async def test_full_analysis():
    analyzer = HashAnalyzer()
    result = await analyzer.analyze("test_hash", platforms=["newplatform"])
    assert result["status"] == "success"
    assert "platform_data" in result["data"]
```

## Performance Optimization

1. **Parallel Processing**
```python
async def analyze_all_platforms(hash_value: str, platforms: List[str]) -> Dict:
    tasks = [
        platform.analyze_hash(hash_value)
        for platform in self._get_platform_instances(platforms)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return self._combine_results(results)
```

2. **Caching Strategy**
```python
async def get_analysis(self, hash_value: str, force_refresh: bool = False):
    if not force_refresh:
        cached = await self.cache.get(hash_value)
        if cached:
            return cached
    result = await self._perform_analysis(hash_value)
    await self.cache.set(hash_value, result)
    return result
```

## Monitoring and Logging

1. **Performance Metrics**
```python
async def analyze_hash(self, hash_value: str) -> Dict:
    start_time = time.time()
    try:
        result = await self._analyze(hash_value)
        duration = time.time() - start_time
        self.metrics.record_analysis_time(duration)
        return result
    except Exception as e:
        self.metrics.record_error(str(e))
        raise
```

2. **Logging**
```python
import logging

logger = logging.getLogger(__name__)

async def _make_request(self, endpoint: str, params: Dict) -> Dict:
    logger.info(f"Making request to {endpoint}")
    try:
        response = await self.session.get(endpoint, params=params)
        logger.debug(f"Response status: {response.status}")
        return await response.json()
    except Exception as e:
        logger.error(f"Request failed: {str(e)}")
        raise
```

## Security Considerations

1. **API Key Management**
```python
from cryptography.fernet import Fernet

class KeyManager:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_api_key(self, api_key: str) -> bytes:
        return self.cipher_suite.encrypt(api_key.encode())

    def decrypt_api_key(self, encrypted_key: bytes) -> str:
        return self.cipher_suite.decrypt(encrypted_key).decode()
```

2. **Input Validation**
```python
def validate_hash(hash_value: str) -> bool:
    patterns = {
        "md5": r"^[a-fA-F0-9]{32}$",
        "sha1": r"^[a-fA-F0-9]{40}$",
        "sha256": r"^[a-fA-F0-9]{64}$"
    }
    return any(re.match(pattern, hash_value) for pattern in patterns.values())
```
