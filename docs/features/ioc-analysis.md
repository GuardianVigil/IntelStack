# IOC Analysis Features

## Overview
This document details all IOC (Indicators of Compromise) analysis features available in GuardianVigil, including hash analysis, IP analysis, URL analysis, and domain analysis.

## 1. Hash Analysis

### Supported Hash Types
- MD5
- SHA-1
- SHA-256
- SHA-512
- SSDEEP (Fuzzy Hashing)

### Analysis Features
1. **Multi-Platform Scanning**
   - VirusTotal results
   - Hybrid Analysis sandbox results
   - MalwareBazaar database lookup
   - MetaDefender multi-scanning
   - ThreatFox intelligence data

2. **File Information**
   ```json
   {
       "file_info": {
           "hash": "d41d8cd98f00b204e9800998ecf8427e",
           "type": "PE32 executable",
           "size": 2097152,
           "magic": "PE32+ executable",
           "mime_type": "application/x-dosexec"
       }
   }
   ```

3. **Threat Metrics**
   - Threat Score (0-100)
   - Confidence Score
   - Risk Level (Safe, Low, Medium, High, Critical)
   - Detection Rate

4. **Malware Analysis**
   - Malware Family Classification
   - Behavior Analysis
   - MITRE ATT&CK Mapping
   - Related Samples

### Usage Example
```python
from services.analysis import HashAnalyzer

analyzer = HashAnalyzer()
result = await analyzer.analyze("d41d8cd98f00b204e9800998ecf8427e")
```

## 2. IP Analysis

### Supported IP Types
- IPv4
- IPv6
- IP Ranges (CIDR)

### Analysis Features
1. **Reputation Data**
   - Threat Score
   - Geographic Location
   - ASN Information
   - ISP Details

2. **Activity Analysis**
   ```json
   {
       "activity": {
           "malicious_activity": ["malware_c2", "spam"],
           "last_seen": "2025-02-13T22:16:16Z",
           "first_seen": "2025-01-01T00:00:00Z"
       }
   }
   ```

3. **Network Context**
   - Associated Domains
   - Related IPs
   - SSL Certificates
   - Open Ports

4. **Threat Intelligence**
   - Known Malware Associations
   - Botnet Participation
   - Attack Patterns
   - Blacklist Status

### Usage Example
```python
from services.analysis import IPAnalyzer

analyzer = IPAnalyzer()
result = await analyzer.analyze("8.8.8.8")
```

## 3. URL Analysis

### Supported URL Types
- HTTP/HTTPS URLs
- FTP URLs
- Data URLs
- Custom Scheme URLs

### Analysis Features
1. **URL Components Analysis**
   ```json
   {
       "url_parts": {
           "scheme": "https",
           "domain": "example.com",
           "path": "/path/to/resource",
           "query": "param=value"
       }
   }
   ```

2. **Security Checks**
   - SSL/TLS Validation
   - Domain Reputation
   - Redirect Chain Analysis
   - Content Type Verification

3. **Threat Detection**
   - Phishing Detection
   - Malware Distribution
   - Command & Control
   - Exploit Kit Detection

4. **Content Analysis**
   - Screenshot Capture
   - HTML Analysis
   - JavaScript Analysis
   - Download Analysis

### Usage Example
```python
from services.analysis import URLAnalyzer

analyzer = URLAnalyzer()
result = await analyzer.analyze("https://example.com")
```

## 4. Domain Analysis

### Supported Features
1. **Domain Information**
   - WHOIS Data
   - Registration Details
   - Name Servers
   - SSL Certificates

2. **DNS Records**
   ```json
   {
       "dns_records": {
           "a": ["1.2.3.4"],
           "mx": ["mail.example.com"],
           "ns": ["ns1.example.com"],
           "txt": ["v=spf1 include:_spf.example.com ~all"]
       }
   }
   ```

3. **Threat Intelligence**
   - Domain Age
   - Registration Changes
   - Related Domains
   - Historical Data

4. **Malicious Activity**
   - Phishing History
   - Malware Distribution
   - Spam Operations
   - Botnet Association

### Usage Example
```python
from services.analysis import DomainAnalyzer

analyzer = DomainAnalyzer()
result = await analyzer.analyze("example.com")
```

## 5. Common Features Across All IOC Types

### 1. Batch Analysis
```python
# Analyze multiple IOCs at once
async def batch_analyze(iocs: List[str], ioc_type: str):
    results = {}
    async with aiohttp.ClientSession() as session:
        tasks = [
            analyze_single(session, ioc, ioc_type)
            for ioc in iocs
        ]
        results = await asyncio.gather(*tasks)
    return results
```

### 2. Export Capabilities
- JSON Export
- CSV Export
- PDF Reports
- STIX Format
- MISP Format

### 3. Correlation Analysis
```python
# Find relationships between different IOCs
async def correlate_iocs(ioc_list: List[Dict]):
    graph = nx.Graph()
    for ioc in ioc_list:
        # Add nodes and edges based on relationships
        graph.add_node(ioc["value"], type=ioc["type"])
    return graph
```

### 4. Alerting System
```python
# Configure alerts for IOC matches
async def setup_alert(ioc: str, conditions: Dict):
    alert = Alert(
        ioc=ioc,
        conditions=conditions,
        notification_channels=["email", "slack"]
    )
    await alert.save()
```

## 6. Advanced Features

### 1. YARA Rule Integration
```python
# Apply YARA rules to files
def apply_yara_rules(file_path: str):
    rules = yara.compile(filepath="rules/malware.yar")
    matches = rules.match(filepath=file_path)
    return matches
```

### 2. Machine Learning Analysis
```python
# ML-based threat detection
class MLAnalyzer:
    def __init__(self):
        self.model = load_model("models/threat_detector.pkl")
    
    def predict_threat(self, features: Dict):
        return self.model.predict(features)
```

### 3. Sandbox Integration
```python
# Submit files to sandbox
async def sandbox_analyze(file_hash: str):
    sandbox = SandboxAnalyzer()
    report = await sandbox.submit_and_analyze(file_hash)
    return report
```

### 4. Threat Hunting
```python
# Proactive threat hunting
async def hunt_threats(indicators: List[str]):
    hunter = ThreatHunter()
    results = await hunter.search_threats(indicators)
    return results
```

## 7. Configuration Options

### 1. Analysis Depth
```yaml
# config/analysis.yaml
analysis_depth:
  quick:
    platforms: ["virustotal"]
    timeout: 30
  standard:
    platforms: ["virustotal", "hybrid-analysis"]
    timeout: 60
  deep:
    platforms: ["all"]
    timeout: 120
```

### 2. Platform Selection
```yaml
# config/platforms.yaml
enabled_platforms:
  hash:
    - virustotal
    - hybrid-analysis
  ip:
    - virustotal
    - threatfox
  url:
    - virustotal
    - urlscan
  domain:
    - virustotal
    - whois
```

### 3. Caching Settings
```yaml
# config/cache.yaml
cache:
  enabled: true
  ttl:
    hash: 3600
    ip: 1800
    url: 900
    domain: 3600
```

## 8. Integration Examples

### 1. REST API
```python
@app.route("/api/v1/analyze/<ioc_type>", methods=["POST"])
async def analyze_ioc(ioc_type):
    data = request.get_json()
    analyzer = get_analyzer(ioc_type)
    result = await analyzer.analyze(data["value"])
    return jsonify(result)
```

### 2. CLI Tool
```python
@click.command()
@click.argument("ioc")
@click.option("--type", type=click.Choice(["hash", "ip", "url", "domain"]))
def analyze(ioc, type):
    result = asyncio.run(analyze_ioc(ioc, type))
    click.echo(json.dumps(result, indent=2))
```

### 3. Web Interface
```javascript
async function analyzeIOC() {
    const response = await fetch("/api/v1/analyze", {
        method: "POST",
        body: JSON.stringify({
            type: iocType,
            value: iocValue
        })
    });
    const result = await response.json();
    displayResults(result);
}
```
