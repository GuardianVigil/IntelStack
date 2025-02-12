from typing import Dict, List
from datetime import datetime

class DataFormatter:
    """Formats raw data from various threat intelligence platforms for display."""

    def process_platform_data(self, data: Dict) -> Dict:
        """
        Process and format data from various platforms.
        
        Args:
            data: Raw data from platforms
            
        Returns:
            Dict containing formatted data for each platform
        """
        formatted_data = {}
        
        for platform, platform_data in data.items():
            if platform == 'hybrid_analysis':
                formatted_data[platform] = self._format_hybrid_analysis_data(platform_data)
            elif platform == 'pulsedive':
                formatted_data[platform] = self._format_pulsedive_data(platform_data)
            elif platform == 'virustotal':
                formatted_data[platform] = self._format_virustotal_data(platform_data)
            elif platform == 'greynoise':
                formatted_data[platform] = self._format_greynoise_data(platform_data)

            # If platform data couldn't be formatted, display raw data in a simple table
            if not formatted_data[platform]:
                formatted_data[platform] = [{
                    'name': 'Raw Data',
                    'type': 'table',
                    'headers': ['Property', 'Value'],
                    'rows': self._flatten_dict(platform_data)
                }]

        return formatted_data

    def _format_hybrid_analysis_data(self, data: Dict) -> List[Dict]:
        """Format Hybrid Analysis data."""
        formatted_data = []
        
        if isinstance(data, dict):
            # Basic Information
            if 'submit' in data:
                submit_info = data['submit']
                basic_info = [
                    ['File Name', submit_info.get('filename', 'N/A')],
                    ['File Type', submit_info.get('filetype', 'N/A')],
                    ['File Size', f"{submit_info.get('size', 0)} bytes"],
                    ['Environment', submit_info.get('environment_id', 'N/A')],
                    ['Analysis Date', self.format_timestamp(submit_info.get('date', ''))]
                ]
                formatted_data.append({
                    'name': 'Basic Information',
                    'type': 'table',
                    'headers': ['Property', 'Value'],
                    'rows': basic_info
                })

            # Analysis Results
            if 'analysis' in data:
                analysis = data['analysis']
                result_info = [
                    ['Verdict', analysis.get('verdict', 'N/A')],
                    ['Threat Score', str(analysis.get('threat_score', 'N/A'))],
                    ['Threat Level', analysis.get('threat_level', 'N/A')],
                    ['Detection Rate', f"{analysis.get('detection_rate', 0)}%"]
                ]
                formatted_data.append({
                    'name': 'Analysis Results',
                    'type': 'table',
                    'headers': ['Property', 'Value'],
                    'rows': result_info
                })

            # Signatures
            if 'signatures' in data:
                sig_rows = []
                for sig in data['signatures']:
                    sig_rows.append([
                        sig.get('name', 'N/A'),
                        sig.get('description', 'N/A'),
                        sig.get('severity', 'N/A')
                    ])
                if sig_rows:
                    formatted_data.append({
                        'name': 'Detected Signatures',
                        'type': 'datatable',
                        'headers': ['Name', 'Description', 'Severity'],
                        'rows': sig_rows
                    })

        return formatted_data

    def _format_pulsedive_data(self, data: Dict) -> List[Dict]:
        """Format Pulsedive data."""
        formatted_data = []
        
        if isinstance(data, dict):
            # Basic Information
            basic_info = [
                ['Risk', data.get('risk', 'N/A')],
                ['Risk Factor', str(data.get('risk_factor', 'N/A'))],
                ['First Seen', self.format_timestamp(data.get('stamp_seen', ''))],
                ['Last Seen', self.format_timestamp(data.get('stamp_updated', ''))]
            ]
            formatted_data.append({
                'name': 'Basic Information',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': basic_info
            })

            # Threats
            if 'threats' in data and data['threats']:
                threat_rows = []
                for threat in data['threats']:
                    threat_rows.append([
                        threat.get('name', 'N/A'),
                        threat.get('category', 'N/A'),
                        threat.get('description', 'N/A')
                    ])
                formatted_data.append({
                    'name': 'Threats',
                    'type': 'datatable',
                    'headers': ['Name', 'Category', 'Description'],
                    'rows': threat_rows
                })

        return formatted_data

    def _format_virustotal_data(self, data: Dict) -> List[Dict]:
        """Format VirusTotal data."""
        formatted_data = []
        
        if isinstance(data, dict):
            # Basic Information
            if 'attributes' in data:
                attrs = data['attributes']
                basic_info = [
                    ['Type Description', attrs.get('type_description', 'N/A')],
                    ['Size', f"{attrs.get('size', 0)} bytes"],
                    ['First Submission', self.format_timestamp(attrs.get('first_submission_date', ''))],
                    ['Last Analysis', self.format_timestamp(attrs.get('last_analysis_date', ''))]
                ]
                formatted_data.append({
                    'name': 'Basic Information',
                    'type': 'table',
                    'headers': ['Property', 'Value'],
                    'rows': basic_info
                })

            # Analysis Stats
            if 'attributes' in data and 'last_analysis_stats' in data['attributes']:
                stats = data['attributes']['last_analysis_stats']
                stats_rows = [
                    ['Malicious', str(stats.get('malicious', 0))],
                    ['Suspicious', str(stats.get('suspicious', 0))],
                    ['Harmless', str(stats.get('harmless', 0))],
                    ['Undetected', str(stats.get('undetected', 0))]
                ]
                formatted_data.append({
                    'name': 'Analysis Statistics',
                    'type': 'table',
                    'headers': ['Category', 'Count'],
                    'rows': stats_rows
                })

            # Detailed Results
            if 'attributes' in data and 'last_analysis_results' in data['attributes']:
                results = data['attributes']['last_analysis_results']
                result_rows = []
                for engine, result in results.items():
                    result_rows.append([
                        engine,
                        result.get('category', 'N/A'),
                        result.get('result', 'N/A'),
                        self.format_timestamp(result.get('update', ''))
                    ])
                formatted_data.append({
                    'name': 'Analysis Results',
                    'type': 'datatable',
                    'headers': ['Engine', 'Category', 'Result', 'Updated'],
                    'rows': result_rows
                })

        return formatted_data

    def _format_greynoise_data(self, data: Dict) -> List[Dict]:
        """Format GreyNoise data."""
        formatted_data = []
        
        if isinstance(data, dict):
            # Basic Information
            basic_info = [
                ['Classification', data.get('classification', 'N/A')],
                ['First Seen', self.format_timestamp(data.get('first_seen', ''))],
                ['Last Seen', self.format_timestamp(data.get('last_seen', ''))],
                ['Actor', data.get('actor', 'N/A')]
            ]
            formatted_data.append({
                'name': 'Basic Information',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': basic_info
            })

            # Tags and Categories
            if 'tags' in data or 'categories' in data:
                metadata = []
                if data.get('tags'):
                    metadata.append(['Tags', ', '.join(data['tags'])])
                if data.get('categories'):
                    metadata.append(['Categories', ', '.join(data['categories'])])
                
                formatted_data.append({
                    'name': 'Classification',
                    'type': 'table',
                    'headers': ['Property', 'Value'],
                    'rows': metadata
                })

        return formatted_data

    @staticmethod
    def _flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> List[List[str]]:
        """Flatten a nested dictionary into a list of [key, value] pairs."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(DataFormatter._flatten_dict(v, new_key, sep))
            else:
                items.append([new_key, str(v)])
        return items

    @staticmethod
    def format_timestamp(timestamp) -> str:
        """Format a timestamp into a human-readable string."""
        if not timestamp:
            return 'N/A'
        try:
            if isinstance(timestamp, (int, float)):
                dt = datetime.fromtimestamp(timestamp)
            else:
                dt = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, TypeError):
            return str(timestamp)
