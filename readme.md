# IntelStack - Threat Intelligence & Security Operations Platform

IntelStack is an advanced threat intelligence and security analysis platform by GuardianVigil that empowers security teams with comprehensive threat detection, analysis, and response capabilities.

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#docker-deployment">Docker</a> •
  <a href="#troubleshooting">Troubleshooting</a> •
  <a href="#contact">Contact</a>
</p>

## 🌟 Features

IntelStack is a powerful security operations platform that integrates multiple threat intelligence sources and analysis tools into a unified interface. The platform provides security analysts with comprehensive capabilities for threat detection, investigation, and response.

### 🔍 Threat Intelligence & Analysis

#### 🔹 IP Analysis
- Multi-source IP reputation checking
- Geolocation data with visual mapping
- Historical threat intelligence data
- Network infrastructure insights
- Comprehensive threat scoring
- Integration with VirusTotal, AbuseIPDB, and other threat intelligence platforms

#### 🔹 Domain Reputation
- Domain reputation scoring across multiple platforms
- WHOIS information retrieval
- SSL certificate analysis
- Associated infrastructure mapping
- DNS record analysis and history
- Integration with VirusTotal, AlienVault, Pulsedive, and SecurityTrails

#### 🔹 URL Scanning
- URL safety verification
- Phishing detection
- Malicious content identification
- Screenshot capture and analysis
- Redirect chain analysis
- Integration with VirusTotal, URLScan.io, and Hybrid Analysis

#### 🔹 Hash Analysis
- File hash reputation checking
- Malware family identification
- Detection ratio across antivirus engines
- File metadata extraction
- YARA rule matching
- Support for MD5, SHA-1, and SHA-256 hash formats

#### 🔹 Email Investigation
- Email header analysis
- Attachment scanning
- Sender reputation checking
- Phishing indicators detection
- SPF, DKIM, and DMARC validation
- Support for .eml and .msg file formats

#### 🔹 Sandbox Analysis
- Secure file detonation environment
- Behavioral analysis of suspicious files
- Network traffic monitoring
- Registry and file system changes tracking
- MITRE ATT&CK mapping of observed behaviors
- Support for multiple file types (executables, documents, scripts, archives)

#### 🔹 MITRE ATT&CK Framework
- Comprehensive tactics and techniques reference
- Threat actor group profiles
- Technique relationships and dependencies
- Mitigation recommendations
- Interactive ATT&CK matrix
- Support for Enterprise, Mobile, and ICS frameworks

#### 🔹 Threat Hunting
- IOC search across your environment
- Custom query builders
- Saved hunt templates
- Scheduled hunts with alerting
- Historical hunt results

### 📊 Intelligence Management

- Threat intelligence feed aggregation
- Indicator management and enrichment
- Custom intelligence source integration
- Automated indicator scoring
- Intelligence sharing capabilities

### 🔄 Workflow Automation

- Customizable analysis workflows
- Automated enrichment of indicators
- Playbook-based response actions
- Integration with ticketing systems
- Alert triage automation

### � Integrations

- Support for major threat intelligence platforms
- SIEM integration capabilities
- Endpoint security tool connections
- Custom API integrations
- Webhook support for notifications

## 📋 Prerequisites

- Python 3.8+
- Redis Server 6.0+
- Modern web browser (Chrome, Firefox, Edge recommended)

## � Installation

### Standard Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/GuardianVigil/IntelStack.git
   cd IntelStack
   ```

2. Run the setup script:
   ```bash
   python setup.py
   ```
   
   This will:
   - Create a virtual environment
   - Install all required dependencies
   - Set up the database
   - Create a superuser account

3. Start the application:
   ```bash
   python run.py
   ```

4. Access the application at http://localhost:8000

### Environment Variables

The following environment variables can be configured:

```
DEBUG=True
SECRET_KEY=your-secret-key
ALLOWED_HOSTS=localhost,127.0.0.1
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

## 🐳 Docker Deployment

IntelStack can be easily deployed using Docker:

1. Make sure Docker and Docker Compose are installed on your system

2. Build and start the containers:
   ```bash
   docker-compose up -d
   ```

3. Access the application at http://localhost:8000

The Docker setup includes:
- Alpine Linux as base image
- Python 3, Redis, and Supervisor in a single container
- Proper volume mapping for database and storage
- Environment variables for customization
- Supervisor for process management

## � Usage

1. Log in with your credentials at http://localhost:8000
2. Navigate to the desired analysis module from the sidebar
3. Submit indicators (IP, domain, URL, hash, email, or file) for analysis
4. Review the comprehensive results from multiple intelligence sources
5. Export or share findings as needed

### IP Analysis

1. Navigate to Threat > IP Analysis
2. Enter an IP address (e.g., 8.8.8.8)
3. Review the comprehensive threat intelligence from multiple sources
4. Examine geolocation data, reputation scores, and associated infrastructure

### Domain Reputation

1. Navigate to Threat > Domain Reputation
2. Enter a domain name (e.g., example.com)
3. Review WHOIS information, SSL certificates, and reputation data
4. Examine associated DNS records and infrastructure

### URL Scanning

1. Navigate to Threat > URL Scan
2. Enter a URL to analyze
3. Review safety ratings, screenshots, and content analysis
4. Examine redirect chains and associated infrastructure

### Hash Analysis

1. Navigate to Threat > Hash Analysis
2. Enter an MD5, SHA-1, or SHA-256 hash
3. Review detection ratios across antivirus engines
4. Examine file metadata and malware family information

### Email Investigation

1. Navigate to Threat > Email Investigation
2. Upload an .eml/.msg file or paste email headers
3. Review sender reputation and authentication results
4. Examine attachments and links for malicious content

### Sandbox Analysis

1. Navigate to Threat > Sandbox
2. Upload a suspicious file for analysis
3. Review behavioral analysis results
4. Examine network connections, file system changes, and registry modifications

## ⚠️ Troubleshooting

### Redis Connection Issues

If you encounter Redis connection errors:

1. Ensure Redis is running:
   ```bash
   # Linux
   sudo systemctl status redis
   
   # Windows
   sc query redis
   ```

2. Verify Redis connection settings in your environment variables

### Database Migration Issues

If you encounter database errors:

1. Reset migrations:
   ```bash
   python manage.py migrate --fake-initial
   ```

2. Apply migrations again:
   ```bash
   python manage.py migrate
   ```

### API Key Configuration

For full functionality, configure API keys for external services:

1. Navigate to Settings > API Configuration
2. Enter your API keys for the services you use
3. Test the connection to ensure proper configuration

## 📞 Contact

- Email: intelstack@guardianvigil.io
- Website: [https://guardianvigil.io/](https://guardianvigil.io/)

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
