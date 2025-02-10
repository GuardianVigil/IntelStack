"""
Data aggregation utilities for IP analysis
"""
from typing import Dict, Any, List
from collections import defaultdict

def aggregate_threats(platform_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Aggregate threat information from all platforms
    
    Args:
        platform_data: Dictionary containing data from all platforms
        
    Returns:
        List of threat dictionaries with source, type, and confidence
    """
    threats = []
    
    for platform, data in platform_data.items():
        if platform == 'virustotal':
            analyses = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            for engine, result in analyses.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    threats.append({
                        'source': f"VirusTotal:{engine}",
                        'type': result.get('result', 'Unknown'),
                        'confidence': 'High' if result.get('category') == 'malicious' else 'Medium'
                    })
                    
        elif platform == 'abuseipdb':
            reports = data.get('data', {}).get('reports', [])
            for report in reports:
                threats.append({
                    'source': 'AbuseIPDB',
                    'type': report.get('category', 'Unknown'),
                    'confidence': 'High' if report.get('confidence', 0) > 80 else 'Medium'
                })
                
        elif platform == 'greynoise':
            if data.get('classification') in ['malicious', 'suspicious']:
                threats.append({
                    'source': 'GreyNoise',
                    'type': data.get('classification'),
                    'confidence': 'High' if data.get('confidence', 0) > 80 else 'Medium'
                })
                
        elif platform == 'crowdsec':
            for decision in data.get('decisions', []):
                threats.append({
                    'source': 'CrowdSec',
                    'type': decision.get('type', 'Unknown'),
                    'confidence': decision.get('confidence', 'Medium')
                })
                
        elif platform == 'securitytrails':
            for tag in data.get('tags', []):
                if tag.get('risk', 0) > 50:
                    threats.append({
                        'source': 'SecurityTrails',
                        'type': tag.get('name', 'Unknown'),
                        'confidence': 'High' if tag.get('risk', 0) > 80 else 'Medium'
                    })
                    
        elif platform == 'alienvault':
            pulses = data.get('general', {}).get('pulse_info', {}).get('pulses', [])
            for pulse in pulses:
                threats.append({
                    'source': 'AlienVault',
                    'type': pulse.get('name', 'Unknown'),
                    'confidence': pulse.get('confidence', 'Medium')
                })
                
        elif platform == 'metadefender':
            results = data.get('lookup', {}).get('lookup_results', {})
            for source in results.get('sources', []):
                threats.append({
                    'source': f"MetaDefender:{source.get('provider')}",
                    'type': source.get('threat_type', 'Unknown'),
                    'confidence': source.get('confidence', 'Medium')
                })
                
        elif platform == 'pulsedive':
            for threat in data.get('threats', []):
                threats.append({
                    'source': 'Pulsedive',
                    'type': threat.get('name', 'Unknown'),
                    'confidence': threat.get('risk', 'Medium')
                })
    
    return threats

def aggregate_activity(platform_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Aggregate activity information from all platforms
    
    Args:
        platform_data: Dictionary containing data from all platforms
        
    Returns:
        Dictionary of activity types and their occurrences
    """
    activities = defaultdict(list)
    
    for platform, data in platform_data.items():
        if platform == 'greynoise':
            if data.get('classification'):
                activities['Classification'].append(f"GreyNoise: {data['classification']}")
            if data.get('tags'):
                activities['Tags'].extend([f"GreyNoise: {tag}" for tag in data['tags']])
                
        elif platform == 'crowdsec':
            if data.get('behaviors'):
                activities['Behaviors'].extend([f"CrowdSec: {b}" for b in data['behaviors']])
                
        elif platform == 'securitytrails':
            if data.get('tags'):
                activities['Tags'].extend([f"SecurityTrails: {t['name']}" for t in data['tags']])
                
        elif platform == 'alienvault':
            if data.get('general', {}).get('tags'):
                activities['Tags'].extend([f"AlienVault: {t}" for t in data['general']['tags']])
                
        elif platform == 'pulsedive':
            if data.get('attributes'):
                activities['Attributes'].extend([f"Pulsedive: {a}" for a in data['attributes']])
    
    return dict(activities)

def aggregate_malware_info(platform_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Aggregate malware information from all platforms
    
    Args:
        platform_data: Dictionary containing data from all platforms
        
    Returns:
        List of malware dictionaries with name, type, and platform
    """
    malware = []
    
    for platform, data in platform_data.items():
        if platform == 'virustotal':
            analyses = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            for engine, result in analyses.items():
                if result.get('category') == 'malicious':
                    malware.append({
                        'name': result.get('result', 'Unknown'),
                        'type': 'Malware',
                        'platform': f"VirusTotal:{engine}"
                    })
                    
        elif platform == 'alienvault':
            samples = data.get('malware', {}).get('samples', [])
            for sample in samples:
                malware.append({
                    'name': sample.get('name', 'Unknown'),
                    'type': sample.get('type', 'Malware'),
                    'platform': 'AlienVault'
                })
                
        elif platform == 'metadefender':
            results = data.get('lookup', {}).get('lookup_results', {})
            for detection in results.get('detected_by', []):
                malware.append({
                    'name': detection.get('threat_name', 'Unknown'),
                    'type': detection.get('threat_type', 'Malware'),
                    'platform': f"MetaDefender:{detection.get('source')}"
                })
    
    return malware
