# Changelog

All notable changes to Stack will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enhanced API key management in Django admin interface
  - Added preview functionality for API keys
  - Improved encryption handling
  - Added metadata display (created/updated timestamps)
- Enhanced API key management
  - Added show/hide functionality for all API key fields
  - Improved handling of dual-key platforms (IBM X-Force, Hybrid Analysis)
  - Added comprehensive API key configuration documentation

### Fixed
- Fixed CrowdSec integration
  - Updated to use CTI API key format
  - Improved scoring algorithm using official scores
  - Enhanced error handling and logging
  - Added support for behaviors and attack details
- Fixed IPInfo integration
  - Made privacy module optional
  - Improved error handling for subscription limitations
  - Enhanced response logging
- Fixed IBM X-Force API key display issue in frontend
- Fixed Hybrid Analysis API key and secret handling

### Added
- Comprehensive threat intelligence documentation
  - Added platform-specific API details
  - Documented scoring algorithms
  - Added implementation details and best practices
- Modern UI for threat intelligence pages
  - Hunting page with advanced search capabilities
  - Threat Feed page with real-time updates
  - Sandbox Analysis page for malware investigation
  - MITRE ATT&CK integration
- Comprehensive reporting system
  - Investigation History tracking
  - Threat Report generation
  - Findings Export functionality
- Enhanced analysis capabilities
  - IP analysis with multiple data sources
  - Domain reputation checking
  - URL scanning and analysis
  - File hash investigation
  - Email header analysis
- Integration with major threat intelligence providers
  - VirusTotal
  - GreyNoise
  - AbuseIPDB
  - CrowdSec
  - Hybrid Analysis
  - IBM X-Force
  - AlienVault OTX
  - PulseDive

### Changed
- Complete UI overhaul with modern design
- Improved navigation with intuitive header menu
- Enhanced data visualization

### Security
- Implemented secure API key management
- Added user authentication and authorization
- Enhanced input validation and sanitization
