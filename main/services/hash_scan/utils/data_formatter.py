from typing import Dict, List, Any, Union
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class DataFormatter:
    """Formats raw data from various threat intelligence platforms for display."""

    def process_platform_data(self, data: Dict) -> Dict:
        """Process and format data from various platforms."""
        formatted_data = {}
        
        for platform, platform_data in data.items():
            if platform == 'virustotal':
                formatted_data[platform] = self._format_virustotal_data(platform_data)
            elif platform == 'hybrid_analysis':
                formatted_data[platform] = self._format_hybrid_analysis_data(platform_data)
            elif platform == 'pulsedive':
                formatted_data[platform] = self._format_pulsedive_data(platform_data)
            elif platform == 'greynoise':
                formatted_data[platform] = self._format_greynoise_data(platform_data)

        return formatted_data

    def _format_virustotal_data(self, data: Dict) -> List[Dict]:
        """Format VirusTotal data."""
        if 'error' in data:
            return [{'name': 'Error', 'type': 'error', 'message': data['error']}]

        formatted_sections = []
        
        # Detection Statistics
        stats = {
            'name': 'Detection Statistics',
            'type': 'table',
            'headers': ['Status', 'Count'],
            'rows': [
                ['Malicious', data.get('malicious', 0)],
                ['Suspicious', data.get('suspicious', 0)],
                ['Undetected', data.get('undetected', 0)],
                ['Total Scans', data.get('total_scans', 0)]
            ]
        }
        formatted_sections.append(stats)

        # File Information
        file_info = {
            'name': 'File Information',
            'type': 'table',
            'headers': ['Property', 'Value'],
            'rows': [
                ['Type', data.get('type', 'N/A')],
                ['Size', f"{data.get('size', 0)} bytes"],
                ['Scan Date', data.get('scan_date', 'N/A')],
                ['Names', ', '.join(data.get('names', ['N/A']))]
            ]
        }
        formatted_sections.append(file_info)

        # Analysis Results
        if data.get('analysis_results'):
            results = {
                'name': 'Analysis Results',
                'type': 'table',
                'headers': ['Engine', 'Category', 'Result'],
                'rows': []
            }
            for engine, result in data['analysis_results'].items():
                results['rows'].append([
                    engine,
                    result.get('category', 'N/A'),
                    result.get('result', 'N/A')
                ])
            formatted_sections.append(results)

        return formatted_sections

    def _format_hybrid_analysis_data(self, data: Dict) -> List[Dict]:
        """Format Hybrid Analysis data."""
        if 'error' in data:
            return [{'name': 'Error', 'type': 'error', 'message': data['error']}]

        formatted_sections = []
        
        # Basic Information
        basic_info = {
            'name': 'Basic Information',
            'type': 'table',
            'headers': ['Property', 'Value'],
            'rows': [
                ['Type', data.get('type', 'N/A')],
                ['Size', f"{data.get('size', 0)} bytes"],
                ['Verdict', data.get('verdict', 'N/A')],
                ['Threat Score', str(data.get('threat_score', 'N/A'))],
                ['Last Seen', data.get('last_seen', 'N/A')]
            ]
        }
        formatted_sections.append(basic_info)

        # Analysis Details
        if data.get('analysis'):
            analysis = {
                'name': 'Analysis Details',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': []
            }
            for key, value in data['analysis'].items():
                if isinstance(value, (str, int, bool)):
                    analysis['rows'].append([key, str(value)])
            formatted_sections.append(analysis)

        return formatted_sections

    def _format_pulsedive_data(self, data: Dict) -> List[Dict]:
        """Format Pulsedive data."""
        if 'error' in data:
            return [{'name': 'Error', 'type': 'error', 'message': data['error']}]

        formatted_sections = []
        
        # Risk Assessment
        risk_info = {
            'name': 'Risk Assessment',
            'type': 'table',
            'headers': ['Property', 'Value'],
            'rows': [
                ['Risk Level', data.get('risk', 'N/A')],
                ['Recommended Risk', data.get('risk_recommended', 'N/A')],
                ['Manual Risk', data.get('manualrisk', 'N/A')],
                ['Retired', 'Yes' if data.get('retired', False) else 'No']
            ]
        }
        formatted_sections.append(risk_info)

        # Timestamps
        time_info = {
            'name': 'Timeline',
            'type': 'table',
            'headers': ['Event', 'Date'],
            'rows': [
                ['Added', data.get('stamp_added', 'N/A')],
                ['Updated', data.get('stamp_updated', 'N/A')]
            ]
        }
        formatted_sections.append(time_info)

        # Threats
        if data.get('threats'):
            threats = {
                'name': 'Associated Threats',
                'type': 'table',
                'headers': ['Threat', 'Category'],
                'rows': []
            }
            for threat in data['threats']:
                if isinstance(threat, dict):
                    threats['rows'].append([
                        threat.get('name', 'N/A'),
                        threat.get('category', 'N/A')
                    ])
            formatted_sections.append(threats)

        return formatted_sections

    def _format_greynoise_data(self, data: Dict) -> List[Dict]:
        """Format GreyNoise data."""
        if 'error' in data:
            return [{'name': 'Error', 'type': 'error', 'message': data['error']}]

        formatted_sections = []
        
        # Basic Information
        basic_info = {
            'name': 'Basic Information',
            'type': 'table',
            'headers': ['Property', 'Value'],
            'rows': [
                ['Seen', 'Yes' if data.get('seen', False) else 'No'],
                ['Classification', data.get('classification', 'N/A')],
                ['Confidence', f"{data.get('confidence', 0)}%"],
                ['First Seen', data.get('first_seen', 'N/A')],
                ['Last Seen', data.get('last_seen', 'N/A')]
            ]
        }
        formatted_sections.append(basic_info)

        # Metadata
        if data.get('metadata'):
            metadata = {
                'name': 'Metadata',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': []
            }
            for key, value in data['metadata'].items():
                if isinstance(value, (str, int, bool)):
                    metadata['rows'].append([key, str(value)])
            formatted_sections.append(metadata)

        return formatted_sections

    def format_timestamp(self, timestamp: Union[int, str, float]) -> str:
        """Format timestamp to human-readable format."""
        try:
            if isinstance(timestamp, str):
                try:
                    return datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')
                except ValueError:
                    timestamp = float(timestamp)
            
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            
            return str(timestamp)
        except Exception as e:
            logger.error(f"Error formatting timestamp: {str(e)}")
            return str(timestamp)

    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> List[List[str]]:
        """Flatten a nested dictionary for table display."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep))
            else:
                items.append([new_key, str(v)])
        return items
