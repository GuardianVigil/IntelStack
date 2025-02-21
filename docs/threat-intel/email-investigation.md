# Email Investigation Module

## Overview
The Email Investigation module is a comprehensive security analysis tool that combines multiple threat intelligence capabilities to provide in-depth analysis of email threats. It integrates IP scanning, hash analysis, URL scanning, and domain reputation checks into a unified analysis platform.

## Core Features

### 1. Email Header Analysis
- **Header Parsing & Visualization**
  - Detailed tabular view of all email headers
  - Hop-by-hop analysis with timeline visualization
  - Time zone analysis for suspicious patterns
  - Message path visualization
  - Original header preservation and formatting

- **Authentication Verification**
  - SPF (Sender Policy Framework) validation
  - DKIM (DomainKeys Identified Mail) verification
  - DMARC (Domain-based Message Authentication) checks
  - Email alignment analysis
  - Spoofing detection mechanisms

### 2. Integrated Threat Intelligence

- **IP Analysis**
  - Geolocation mapping
  - ASN and network information
  - Reputation scoring from multiple sources
  - Historical IP activity
  - Reverse DNS validation
  - Integration with platforms:
    - AbuseIPDB
    - VirusTotal
    - GreyNoise
    - AlienVault OTX

- **Domain Analysis**
  - WHOIS information
  - Domain age and registration details
  - SSL certificate validation
  - DNS record analysis
  - Domain reputation checks
  - Typosquatting detection
  - Look-alike domain identification

- **URL Analysis**
  - URL reputation checking
  - Phishing URL detection
  - URL unshortening
  - Landing page analysis
  - Redirect chain tracking
  - Screenshot capture
  - Integration with:
    - URLScan.io
    - Google Safe Browsing
    - PhishTank
    - Web Risk API

### 3. File & Attachment Analysis
- **File Processing**
  - Support for .eml and .msg formats
  - Automatic attachment extraction
  - File type detection
  - MIME type validation
  - Embedded file analysis

- **Hash Analysis**
  - Multiple hash generation (MD5, SHA1, SHA256)
  - Hash reputation checking
  - NSRL database comparison
  - Integration with:
    - VirusTotal
    - Malware Bazaar
    - Hybrid Analysis

- **Advanced Analysis**
  - Macro detection
  - Sandbox analysis integration
  - Static code analysis
  - String extraction
  - Entropy analysis

### 4. Phishing & Fraud Detection
- Machine learning-based detection
- Known phishing template matching
- Brand impersonation detection
- Language analysis
- Social engineering indicator detection
- Urgency analysis
- Sentiment analysis

### 5. Visualization & Reporting
- **Interactive Dashboard**
  - Threat score summary
  - Risk indicators
  - Authentication status
  - Key findings
  - Visual timeline

- **Detailed Analysis Views**
  - Collapsible detailed sections
  - Interactive data tables
  - Network visualizations
  - Threat maps
  - Time-based analysis

- **Export Capabilities**
  - PDF reports
  - CSV exports
  - JSON data
  - IOC feeds
  - MISP format

## Technical Architecture

### Frontend Components
1. **Main Interface** (`/templates/threat/email_investigation/`)
   - `email_investigation.html`: Main analysis interface
   - Alpine.js for reactive UI components
   - TailwindCSS for styling
   - D3.js for visualizations

2. **UI Features**
   - Drag-and-drop file upload
   - Real-time analysis feedback
   - Interactive data tables
   - Collapsible sections
   - Progress indicators
   - Error handling

### Backend Services
1. **Core Analysis** (`/services/email_scan/`)
   - `email_analyzer.py`: Main analysis engine
   - `email_analysis.py`: Analysis orchestration
   - `api.py`: REST API endpoints

2. **Platform Integrations** (`/services/email_scan/platforms/`)
   - Individual modules for each threat intelligence platform
   - Rate limiting and caching
   - API key management
   - Error handling

3. **Utility Services** (`/services/email_scan/utils/`)
   - Header parsing utilities
   - File handling
   - Data normalization
   - Cache management

## API Integration Details

### Required API Keys
```json
{
  "virustotal": "VT_API_KEY",
  "abuseipdb": "ABUSEIPDB_API_KEY",
  "urlscan": "URLSCAN_API_KEY",
  "greynoise": "GREYNOISE_API_KEY",
  "alienvault": "OTX_API_KEY"
}
```

### Sample Analysis Response
```json
{
  "analysis_id": "ea123456-7890-abcd-ef12-34567890abcd",
  "timestamp": "2025-02-21T17:23:39Z",
  "threat_score": 85,
  "risk_level": "high",
  "findings": {
    "authentication": {
      "spf": "fail",
      "dkim": "pass",
      "dmarc": "none"
    },
    "threats_detected": {
      "suspicious_ips": 2,
      "malicious_urls": 1,
      "suspicious_attachments": 1
    },
    "indicators": {
      "phishing_probability": 0.92,
      "spam_score": 0.3,
      "brand_impersonation": true
    }
  }
}
```

## Future Enhancements
1. **Machine Learning Improvements**
   - Enhanced phishing detection
   - Automated threat classification
   - Pattern recognition
   - Behavioral analysis

2. **Integration Expansions**
   - Additional threat feeds
   - Custom intelligence integration
   - SIEM integration
   - Automated response capabilities

3. **Analysis Capabilities**
   - Deep content analysis
   - Natural language processing
   - Advanced correlation
   - Threat hunting features

4. **User Experience**
   - Customizable dashboards
   - Saved searches
   - Automated reporting
   - Bulk analysis capabilities
