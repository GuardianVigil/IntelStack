"""
Data aggregation utilities for domain analysis
"""
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

def aggregate_platform_data(platform_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aggregate data from multiple platforms into a unified format
    
    Args:
        platform_data: Raw data from all platforms
        
    Returns:
        Aggregated data structure
    """
    # Initialize aggregated data structure
    aggregated = {
        'summary': {
            'total_detections': 0,
            'risk_level': 'Unknown',
            'categories': [],  
            'detection_engines': 0,
            'malicious_engines': 0
        },
        'whois': {},
        'security_analysis': {
            'blacklist_status': 'Unknown',
            'ssl_status': 'Unknown',
            'malware_status': 'Unknown'
        },
        'threat_indicators': [],
        'raw_platform_data': platform_data
    }
    
    try:
        # Process VirusTotal data
        if vt_data := platform_data.get('virustotal'):
            if not isinstance(vt_data, dict) or vt_data.get('error'):
                logger.warning(f"Invalid VirusTotal data: {vt_data}")
            else:
                _process_virustotal_data(vt_data, aggregated)
        
        # Process AlienVault data
        if av_data := platform_data.get('alienvault'):
            if not isinstance(av_data, dict) or av_data.get('error'):
                logger.warning(f"Invalid AlienVault data: {av_data}")
            else:
                _process_alienvault_data(av_data, aggregated)
                
        # Process Pulsedive data
        if pd_data := platform_data.get('pulsedive'):
            if not isinstance(pd_data, dict) or pd_data.get('error'):
                logger.warning(f"Invalid Pulsedive data: {pd_data}")
            else:
                _process_pulsedive_data(pd_data, aggregated)
                
        # Process MetaDefender data
        if md_data := platform_data.get('metadefender'):
            if not isinstance(md_data, dict) or md_data.get('error'):
                logger.warning(f"Invalid MetaDefender data: {md_data}")
            else:
                _process_metadefender_data(md_data, aggregated)
                
        # Process SecurityTrails data
        if st_data := platform_data.get('securitytrails'):
            if not isinstance(st_data, dict) or st_data.get('error'):
                logger.warning(f"Invalid SecurityTrails data: {st_data}")
            else:
                _process_securitytrails_data(st_data, aggregated)
        
        # Calculate overall risk level
        if any(platform_data.values()):
            aggregated['summary']['risk_level'] = _calculate_risk_level(aggregated)
            
        # Convert any remaining sets to lists for JSON serialization
        if isinstance(aggregated['summary']['categories'], set):
            aggregated['summary']['categories'] = list(aggregated['summary']['categories'])
            
        return aggregated
        
    except Exception as e:
        logger.error(f"Error aggregating platform data: {str(e)}")
        return {
            'error': f"Error processing platform data: {str(e)}",
            'raw_data': platform_data
        }

def _process_virustotal_data(vt_data: Dict[str, Any], aggregated: Dict[str, Any]):
    """Process VirusTotal data"""
    try:
        if stats := vt_data.get('last_analysis_stats', {}):
            aggregated['summary']['detection_engines'] = sum(stats.values())
            aggregated['summary']['malicious_engines'] = stats.get('malicious', 0)
            
            # Update security analysis
            if stats.get('malicious', 0) > 0:
                aggregated['security_analysis']['blacklist_status'] = 'Blacklisted'
            elif stats.get('suspicious', 0) > 0:
                aggregated['security_analysis']['blacklist_status'] = 'Suspicious'
            else:
                aggregated['security_analysis']['blacklist_status'] = 'Clean'
    except Exception as e:
        logger.error(f"Error processing VirusTotal data: {str(e)}")

def _process_alienvault_data(av_data: Dict[str, Any], aggregated: Dict[str, Any]):
    """Process AlienVault data"""
    try:
        if general := av_data.get('general', {}):
            if pulse_info := general.get('pulse_info', {}):
                # Add threat indicators
                for pulse in pulse_info.get('pulses', []):
                    aggregated['threat_indicators'].append({
                        'name': pulse.get('name', 'Unknown'),
                        'description': pulse.get('description', ''),
                        'tags': pulse.get('tags', []),
                        'created': pulse.get('created', '')
                    })
                
                # Update categories
                if industries := pulse_info.get('industries', []):
                    aggregated['summary']['categories'].extend(industries)
            
            # Update WHOIS data if available
            if whois := av_data.get('whois', {}):
                aggregated['whois'].update(whois)
    except Exception as e:
        logger.error(f"Error processing AlienVault data: {str(e)}")

def _process_pulsedive_data(pd_data: Dict[str, Any], aggregated: Dict[str, Any]):
    """Process Pulsedive data"""
    try:
        if isinstance(pd_data, dict):
            # Update threat indicators
            if risks := pd_data.get('risks', []):
                for risk in risks:
                    aggregated['threat_indicators'].append({
                        'name': risk.get('name', 'Unknown'),
                        'description': risk.get('description', ''),
                        'tags': [risk.get('type', 'unknown')],
                        'created': risk.get('stamp', '')
                    })
    except Exception as e:
        logger.error(f"Error processing Pulsedive data: {str(e)}")

def _process_metadefender_data(md_data: Dict[str, Any], aggregated: Dict[str, Any]):
    """Process MetaDefender data"""
    try:
        if lookup_results := md_data.get('lookup_results', {}):
            detected = lookup_results.get('detected_by', 0)
            if detected > 0:
                aggregated['security_analysis']['malware_status'] = 'Detected'
                aggregated['summary']['malicious_engines'] += detected
    except Exception as e:
        logger.error(f"Error processing MetaDefender data: {str(e)}")

def _process_securitytrails_data(st_data: Dict[str, Any], aggregated: Dict[str, Any]):
    """Process SecurityTrails data"""
    try:
        # Update WHOIS data if available
        if whois := st_data.get('whois', {}):
            aggregated['whois'].update(whois)
    except Exception as e:
        logger.error(f"Error processing SecurityTrails data: {str(e)}")

def _calculate_risk_level(data: Dict[str, Any]) -> str:
    """
    Calculate overall risk level based on aggregated data
    
    Args:
        data: Aggregated data
        
    Returns:
        Risk level string (Low, Medium, High)
    """
    try:
        score = 0
        max_score = 0
        
        # Factor in malicious engine detections
        if data['summary']['detection_engines'] > 0:
            detection_ratio = data['summary']['malicious_engines'] / data['summary']['detection_engines']
            score += detection_ratio * 50
            max_score += 50
        
        # Factor in blacklist status
        if data['security_analysis']['blacklist_status'] != 'Unknown':
            status_scores = {
                'Clean': 0,
                'Suspicious': 25,
                'Blacklisted': 50
            }
            score += status_scores.get(data['security_analysis']['blacklist_status'], 0)
            max_score += 50
        
        # Calculate final risk level
        if max_score == 0:
            return 'Unknown'
        
        percentage = (score / max_score) * 100
        if percentage >= 70:
            return 'High'
        elif percentage >= 30:
            return 'Medium'
        else:
            return 'Low'
    except Exception as e:
        logger.error(f"Error calculating risk level: {str(e)}")
        return 'Unknown'
