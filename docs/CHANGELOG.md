# Changelog

All notable changes to this project will be documented in this file.

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

## [1.2.0] - 2025-02-13

### Added
- Enhanced hash analysis frontend display with comprehensive data visualization
- New data categories in hash analysis results:
  - Detailed malware information
  - Extended threat intelligence data
  - Platform-specific analysis results
- Dynamic table headers for detection results
- Improved array and complex data type handling
- Better formatting for field names and values

### Changed
- Restructured hash analysis template for better organization
- Updated data formatter to handle additional platform data
- Improved error handling and display
- Enhanced documentation with detailed implementation guides

### Fixed
- Table layout issues in platform-specific panels
- Array display formatting in threat intelligence section
- Field name capitalization and spacing

## [1.1.0] - 2025-01-15

### Added
- Multi-platform integration for hash analysis
- Cache system for API responses
- Rate limiting and retry mechanisms
- Basic threat intelligence display

### Changed
- Unified data structure for platform responses
- Enhanced error handling system
- Updated API endpoint structure

### Fixed
- Platform connection timeout issues
- Cache invalidation bugs
- API response formatting

## [1.0.0] - 2024-12-01

### Added
- Initial release
- Basic hash analysis functionality
- VirusTotal integration
- Simple frontend display
- Basic documentation structure
