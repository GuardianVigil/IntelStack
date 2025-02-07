# IP Threat Analysis Report

## IP Address: `80.64.30.85`

### 1. VirusTotal
- **API URL**: `https://www.virustotal.com/api/v3/ip_addresses/{ip_address}`
- **Key Insights**:
  - **Reputation Score**: `data.attributes.reputation` (0)
  - **WHOIS Data**: `data.attributes.whois`
  - **Last Analysis**: `data.attributes.last_analysis_date` (2025-02-07)
  - **Malicious Engines**: `data.attributes.last_analysis_stats.malicious` (7)
  - **Suspicious Engines**: `data.attributes.last_analysis_stats.suspicious` (2)
  - **Harmless Engines**: `data.attributes.last_analysis_stats.harmless` (56)
  - **ASN**: `data.attributes.asn` (59425)
  - **ISP**: `data.attributes.as_owner` (Horizon LLC, Russia)
  - **Last Analysis Results**: `data.attributes.last_analysis_results`
  - **Tags**: `data.attributes.tags`
  - **Regional Internet Registry**: `data.attributes.regional_internet_registry` (RIPE NCC)
  - **Continent**: `data.attributes.continent` (EU)
  - **Total Votes**: `data.attributes.total_votes` (harmless: 0, malicious: 0)
  - **Network**: `data.attributes.network` (80.64.30.0/24)
  - **Last Modification Date**: `data.attributes.last_modification_date` (2025-02-07)

### 2. AbuseIPDB
- **API URL**: `https://api.abuseipdb.com/api/v2/check`
- **Key Insights**:
  - **Abuse Confidence Score**: `data.abuseConfidenceScore` (100)
  - **Total Reports**: `data.totalReports` (92)
  - **Distinct Users**: `data.numDistinctUsers` (52)
  - **Last Reported**: `data.lastReportedAt` (2025-02-07)
  - **ISP**: `data.isp` (Horizon LLC, Russia)
  - **Country Code**: `data.countryCode` (RU)
  - **Is Public**: `data.isPublic` (True)
  - **IP Version**: `data.ipVersion` (4)
  - **Is Whitelisted**: `data.isWhitelisted` (False)
  - **Usage Type**: `data.usageType` (Commercial)
  - **Domain**: `data.domain` (gorizontllc.ru)
  - **Is Tor**: `data.isTor` (False)

### 3. GreyNoise
- **API URL**: `https://api.greynoise.io/v3/community/{ip_address}`
- **Key Insights**:
  - **Classification**: `classification` (Malicious)
  - **Noise**: `noise` (True)
  - **Riot**: `riot` (False)
  - **Last Seen**: `last_seen` (2025-02-07)
  - **Link**: `link` ([GreyNoise Visualization](https://viz.greynoise.io/ip/80.64.30.85))
  - **Message**: `message` (Success)

### 4. CrowdSec
- **API URL**: `https://cti.api.crowdsec.net/v2/smoke/{ip_address}`
- **Key Insights**:
  - **Reputation**: `reputation` (Malicious)
  - **Behaviors**: `behaviors` (HTTP DoS, SMB/RDP Bruteforce, HTTP Scanning)
  - **First Seen**: `history.first_seen` (2024-10-18)
  - **Last Seen**: `history.last_seen` (2025-02-06)
  - **ASN**: `as_num` (59425)
  - **ISP**: `as_name` (Chang Way Technologies Co. Limited)
  - **Target Countries**: `target_countries` (US, DE, FR, SG, IN, JP, GB, CA, IE, NL)
  - **Background Noise**: `background_noise` (Medium)
  - **Confidence**: `confidence` (High)
  - **IP Range**: `ip_range` (80.64.30.0/24)
  - **IP Range Reputation**: `ip_range_24_reputation` (Malicious)
  - **Location**: `location` (Country: RU, City: None, Latitude: 55.7386, Longitude: 37.6068)
  - **Attack Details**: `attack_details` (HTTP DOS with invalid HTTP version, Windows Bruteforce)
  - **MITRE Techniques**: `mitre_techniques` (T1498: Network Denial of Service, T1110: Brute Force)
  - **CVEs**: `cves` (None)
  - **Scores**: `scores` (Overall: Aggressiveness: 4, Threat: 4, Trust: 5, Anomaly: 3, Total: 4)

### 5. SecurityTrails
- **API URL**: `https://api.securitytrails.com/v1/ips/nearby/{ip_address}`
- **Key Insights**:
  - **Nearby IPs**: `blocks` (Scanned for open ports: 445, 135, 3389, 22)
  - **Active Egress**: `blocks.active_egress` (Some IPs in the range are actively communicating externally)
  - **Hostnames**: `blocks.hostnames` (`walgoneidconnect.com`, `patchpharos.com`, `www.patchpharos.com`)
  - **Ports**: `blocks.ports` (e.g., 445, 135, 3389, 22)
  - **Sites**: `blocks.sites` (Number of sites associated with each IP)
  - **Endpoint**: `endpoint` (/v1/ips/nearby/80.64.30.85)

## Summary
This IP address (`80.64.30.85`) has been flagged as malicious by multiple platforms, with evidence of abusive behavior, active scanning, and exploitation attempts. It is associated with Horizon LLC in Russia and has been reported for activities such as HTTP DoS, SMB/RDP bruteforce, and HTTP scanning.
