"""
Data formatting utilities for domain analysis
"""
from typing import Dict, Any, List
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class DataFormatter:
    """Formats domain analysis data for frontend consumption"""
    
    @staticmethod
    def format_domain_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format domain analysis data for frontend
        
        Args:
            data: Aggregated domain analysis data
            
        Returns:
            Formatted data structure matching frontend requirements
        """
        try:
            formatted = {
                'quickStats': {
                    'threatScore': DataFormatter._calculate_threat_score(data),
                    'riskLevel': data.get('summary', {}).get('risk_level', 'Unknown'),
                    'totalDetections': data.get('summary', {}).get('total_detections', 0)
                },
                'whois': DataFormatter._format_whois_data(data.get('whois', {})),
                'security': DataFormatter._format_security_analysis(data.get('security_analysis', {})),
                'platforms': DataFormatter._format_platform_data(data.get('raw_platform_data', {}))
            }
            return formatted
        except Exception as e:
            logger.error(f"Error formatting domain data: {str(e)}")
            # Return a safe default structure
            return {
                'quickStats': {
                    'threatScore': 0,
                    'riskLevel': 'Unknown',
                    'totalDetections': 0
                },
                'whois': {
                    'registrar': 'N/A',
                    'createdDate': 'N/A',
                    'expiryDate': 'N/A',
                    'nameServers': [],
                    'status': 'N/A'
                },
                'security': {
                    'blacklistStatus': 'Unknown',
                    'blacklistDetails': 'Error processing data',
                    'sslStatus': 'Unknown',
                    'sslDetails': 'Error processing data',
                    'malwareStatus': 'Unknown',
                    'malwareDetails': 'Error processing data'
                },
                'platforms': {}
            }
    
    @staticmethod
    def _calculate_threat_score(data: Dict[str, Any]) -> int:
        """Calculate threat score percentage"""
        try:
            # Base calculation on risk level
            base_score = {
                'High': 80,
                'Medium': 50,
                'Low': 20,
                'Unknown': 0
            }.get(data.get('summary', {}).get('risk_level', 'Unknown'), 0)
            
            # Adjust based on detections
            summary = data.get('summary', {})
            if summary.get('detection_engines', 0) > 0:
                detection_ratio = summary.get('malicious_engines', 0) / summary.get('detection_engines', 1)
                base_score = min(100, base_score + (detection_ratio * 20))
            
            return round(base_score)
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return 0
    
    @staticmethod
    def _format_whois_data(whois_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format WHOIS data"""
        try:
            return {
                'registrar': whois_data.get('registrar', 'N/A'),
                'createdDate': DataFormatter._format_date(whois_data.get('creation_date')),
                'expiryDate': DataFormatter._format_date(whois_data.get('expiration_date')),
                'nameServers': whois_data.get('name_servers', []),
                'status': whois_data.get('status', 'N/A')
            }
        except Exception as e:
            logger.error(f"Error formatting WHOIS data: {str(e)}")
            return {
                'registrar': 'N/A',
                'createdDate': 'N/A',
                'expiryDate': 'N/A',
                'nameServers': [],
                'status': 'N/A'
            }
    
    @staticmethod
    def _format_security_analysis(security_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format security analysis data"""
        try:
            return {
                'blacklistStatus': security_data.get('blacklist_status', 'Unknown'),
                'blacklistDetails': security_data.get('blacklist_details', 'No details available'),
                'sslStatus': security_data.get('ssl_status', 'Unknown'),
                'sslDetails': security_data.get('ssl_details', 'Certificate information not available'),
                'malwareStatus': security_data.get('malware_status', 'Unknown'),
                'malwareDetails': security_data.get('malware_details', 'No threats detected')
            }
        except Exception as e:
            logger.error(f"Error formatting security analysis: {str(e)}")
            return {
                'blacklistStatus': 'Unknown',
                'blacklistDetails': 'Error processing data',
                'sslStatus': 'Unknown',
                'sslDetails': 'Error processing data',
                'malwareStatus': 'Unknown',
                'malwareDetails': 'Error processing data'
            }
    
    @staticmethod
    def _format_platform_data(platform_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format individual platform data"""
        try:
            formatted = {}
            
            for platform, data in platform_data.items():
                if isinstance(data, dict):
                    if error := data.get('error'):
                        formatted[platform] = {
                            'status': 'Error',
                            'error': str(error)
                        }
                    else:
                        formatted[platform] = {
                            'status': DataFormatter._determine_platform_status(data),
                            'lastAnalysisDate': DataFormatter._extract_analysis_date(data),
                            'detections': DataFormatter._extract_detections(data),
                            'details': data  # Store full response for detailed view
                        }
                else:
                    formatted[platform] = {
                        'status': 'Error',
                        'error': 'Invalid platform data'
                    }
            
            return formatted
        except Exception as e:
            logger.error(f"Error formatting platform data: {str(e)}")
            return {}
    
    @staticmethod
    def _determine_platform_status(data: Dict[str, Any]) -> str:
        """Determine status from platform data"""
        try:
            # Check for explicit status indicators
            if data.get('malicious', 0) > 0:
                return 'Malicious'
            if data.get('suspicious', 0) > 0:
                return 'Suspicious'
            
            # Check nested data
            if stats := data.get('last_analysis_stats', {}):
                if stats.get('malicious', 0) > 0:
                    return 'Malicious'
                if stats.get('suspicious', 0) > 0:
                    return 'Suspicious'
            
            return 'Clean'
        except Exception as e:
            logger.error(f"Error determining platform status: {str(e)}")
            return 'Unknown'
    
    @staticmethod
    def _extract_analysis_date(data: Dict[str, Any]) -> str:
        """Extract last analysis date from platform data"""
        try:
            # Try common date fields
            for field in ['last_analysis_date', 'scan_date', 'updated', 'timestamp']:
                if date := data.get(field):
                    return DataFormatter._format_date(date)
            return 'N/A'
        except Exception as e:
            logger.error(f"Error extracting analysis date: {str(e)}")
            return 'N/A'
    
    @staticmethod
    def _extract_detections(data: Dict[str, Any]) -> Dict[str, int]:
        """Extract detection counts from platform data"""
        try:
            if stats := data.get('last_analysis_stats', {}):
                return {
                    'total': sum(stats.values()),
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'clean': stats.get('harmless', 0)
                }
            return {
                'total': 0,
                'malicious': 0,
                'suspicious': 0,
                'clean': 0
            }
        except Exception as e:
            logger.error(f"Error extracting detections: {str(e)}")
            return {
                'total': 0,
                'malicious': 0,
                'suspicious': 0,
                'clean': 0
            }
    
    @staticmethod
    def _format_date(date_value: Any) -> str:
        """Format date value to string"""
        try:
            if isinstance(date_value, (int, float)):
                return datetime.fromtimestamp(date_value).isoformat()
            elif isinstance(date_value, str):
                return date_value
            elif isinstance(date_value, datetime):
                return date_value.isoformat()
            return 'N/A'
        except Exception as e:
            logger.error(f"Error formatting date: {str(e)}")
            return 'N/A'
