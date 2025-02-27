from typing import Dict, Any, List

def format_virustotal_data(vt_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format VirusTotal data for frontend display
    """
    analysis_report = vt_data.get('analysis_report', {})
    behavior_summary = vt_data.get('behavior_summary', {})
    
    # Extract basic stats
    stats = analysis_report.get('data', {}).get('attributes', {}).get('stats', {})
    file_info = analysis_report.get('meta', {}).get('file_info', {})
    
    # Calculate threat score (0-100)
    total_scans = sum(stats.values())
    malicious_count = stats.get('malicious', 0)
    suspicious_count = stats.get('suspicious', 0)
    threat_score = ((malicious_count + suspicious_count) / total_scans * 100) if total_scans > 0 else 0
    
    # Format behavior data
    behavior_data = behavior_summary.get('data', {})
    
    return {
        'quick_summary': {
            'threat_score': round(threat_score, 1),
            'detection_stats': {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total_scans': total_scans
            },
            'file_info': {
                'sha256': file_info.get('sha256', ''),
                'md5': file_info.get('md5', ''),
                'size': file_info.get('size', 0),
                'type': file_info.get('type', '')
            }
        },
        'behavior_analysis': {
            'processes': format_process_data(behavior_data.get('processes_created', [])),
            'network_activity': format_network_data(behavior_data.get('network', {})),
            'file_operations': format_file_operations(
                behavior_data.get('files_written', []),
                behavior_data.get('files_opened', [])
            ),
            'registry_activity': format_registry_data(behavior_data.get('registry_keys_set', [])),
            'mitre_techniques': format_mitre_data(behavior_data.get('mitre_attack_techniques', []))
        },
        'scan_results': format_scan_results(
            analysis_report.get('data', {}).get('attributes', {}).get('results', {})
        )
    }

def format_process_data(processes: List[str]) -> List[Dict[str, str]]:
    """Format process creation data"""
    formatted_processes = []
    for process in processes:
        # Clean up process path and extract relevant info
        process = process.replace('"', '').replace('\\\\', '\\')
        formatted_processes.append({
            'path': process,
            'name': process.split('\\')[-1]
        })
    return formatted_processes

def format_network_data(network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format network connection data"""
    connections = []
    for conn in network_data.get('connections', []):
        connections.append({
            'protocol': conn.get('protocol', ''),
            'destination': conn.get('dst', ''),
            'port': conn.get('dport', ''),
            'process': conn.get('process_name', '')
        })
    return connections

def format_file_operations(written_files: List[str], opened_files: List[str]) -> Dict[str, List[str]]:
    """Format file operation data"""
    return {
        'written': written_files,
        'opened': opened_files
    }

def format_registry_data(registry_keys: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Format registry operation data"""
    return [{
        'path': key.get('path', ''),
        'value': key.get('value', ''),
        'operation': key.get('operation', '')
    } for key in registry_keys]

def format_mitre_data(mitre_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format MITRE ATT&CK data"""
    return [{
        'id': technique.get('id', ''),
        'description': technique.get('signature_description', ''),
        'severity': technique.get('severity', 'INFO')
    } for technique in mitre_data]

def format_scan_results(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format antivirus scan results"""
    formatted_results = []
    for engine, data in results.items():
        if data.get('category') in ['malicious', 'suspicious']:
            formatted_results.append({
                'engine': engine,
                'result': data.get('result', ''),
                'category': data.get('category', ''),
                'engine_version': data.get('engine_version', '')
            })
    return formatted_results