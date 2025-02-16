# Email Investigation Module

## Overview
The Email Investigation module is a comprehensive security analysis tool designed to help cyber security analysts examine email headers, detect threats, and identify potential phishing or malicious activities.

## Features

### 1. Header Analysis & Authentication
- SPF, DKIM, and DMARC validation
- Authentication results display
- Alignment status verification
- Spoofing detection
- Hop analysis with timestamps

### 2. Threat Intelligence Integration
- IP analysis including:
  - GeoIP location
  - Reverse DNS
  - Reputation checks
  - ASN information
  - Historical data
- WHOIS domain lookup
- Blocklist verification

### 3. URL & Attachment Analysis
- URL analysis features:
  - Reputation checking
  - Domain age verification
  - SSL validation
  - Landing page analysis
  - Redirection detection
- Attachment scanning:
  - Hash generation (MD5, SHA-1, SHA-256)
  - Threat intelligence checks
  - File type verification
  - Static analysis
  - Sandbox analysis

### 4. Phishing & Fraud Detection
- Display name spoofing checks
- Look-alike domain detection
- Phishing keyword analysis
- Urgency indicator checks
- Brand impersonation detection
- Pattern analysis

### 5. Visual Interface
- Dashboard with threat score
- Color-coded risk indicators
- Detailed analysis tables
- Interactive timeline
- Export capabilities

### 6. API Integrations
- VirusTotal
- AbuseIPDB
- URLscan.io
- MaxMind GeoIP
- Custom threat feeds

## User Interface
The interface is organized into several sections:
1. Header Input Section
   - Text area for email header input
   - Upload option for .eml files
   - Quick paste options

2. Analysis Dashboard
   - Overall threat score
   - Authentication status
   - Key findings summary
   - Risk level indicator

3. Detailed Analysis Tabs
   - Header Analysis
   - IP Investigation
   - URL Analysis
   - Attachment Analysis
   - Threat Intelligence
   - Timeline View

4. Export Options
   - PDF Report
   - JSON Data
   - CSV Summary

## Sample Data Format
```json
{
  "header_analysis": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass",
    "return_path": "sender@domain.com",
    "from": "Sender Name <sender@domain.com>",
    "subject": "Important: Account Security Update",
    "date": "2025-02-14 01:15:04 UTC"
  },
  "authentication": {
    "status": "authenticated",
    "alignment": true,
    "spoofing_indicators": false
  },
  "ip_analysis": {
    "sender_ip": "192.168.1.1",
    "location": "San Francisco, US",
    "asn": "AS15169",
    "reputation": "good",
    "blocklist_status": "clean"
  }
}
```

## Implementation Status
- ✅ Frontend UI Design
- ⏳ Backend Integration
- ⏳ API Connections
- ⏳ Threat Intelligence Integration
