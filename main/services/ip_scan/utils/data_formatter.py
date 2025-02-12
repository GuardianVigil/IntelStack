from typing import Dict, List, Any, Union
from datetime import datetime
import json

class DataFormatter:
    @staticmethod
    def format_timestamp(timestamp: Union[int, str, float]) -> str:
        """Convert various timestamp formats to a readable date string."""
        try:
            if isinstance(timestamp, str):
                try:
                    # Try parsing as ISO format
                    return datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')
                except ValueError:
                    # Try parsing as unix timestamp
                    timestamp = float(timestamp)
            
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            
            return str(timestamp)
        except Exception:
            return str(timestamp)

    @staticmethod
    def format_value(value: Any) -> str:
        """Format a value for display."""
        if value is None:
            return "N/A"
        return str(value)

    @staticmethod
    def process_array_of_objects(data: List[Dict]) -> Dict:
        """Convert an array of objects into a table structure."""
        if not data or not isinstance(data[0], dict):
            return {"type": "simple_array", "values": data}

        headers = list(data[0].keys())
        rows = []
        for item in data:
            row = []
            for header in headers:
                value = item.get(header)
                if isinstance(value, dict):
                    row.append(DataFormatter.format_value(value))
                elif isinstance(value, list):
                    if value and isinstance(value[0], dict):
                        row.append(DataFormatter.process_array_of_objects(value))
                    else:
                        row.append(", ".join(map(str, value)))
                else:
                    row.append(DataFormatter.format_value(value))
            rows.append(row)

        return {
            "type": "table",
            "headers": [h.replace('_', ' ').title() for h in headers],
            "rows": rows
        }

    @staticmethod
    def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> str:
        """Flatten a dictionary into a string representation."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(DataFormatter.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return ", ".join(f"{k}: {v}" for k, v in items)

    @staticmethod
    def truncate_text(text: str, max_length: int = 100) -> str:
        """Truncate text to specified length."""
        if not text or len(text) <= max_length:
            return text
        return text[:max_length] + "..."

    @staticmethod
    def format_categories(categories: List[int]) -> str:
        """Format AbuseIPDB categories to readable text."""
        category_map = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted",
        }
        return ", ".join(category_map.get(cat, str(cat)) for cat in categories)

    @staticmethod
    def process_virustotal_data(data: Dict) -> List[Dict]:
        """Process VirusTotal data into organized sections."""
        tables = []
        
        if "data" in data and "attributes" in data["data"]:
            attrs = data["data"]["attributes"]
            
            # Last Analysis Stats
            if "last_analysis_stats" in attrs:
                tables.append({
                    "name": "Analysis Statistics",
                    "type": "table",
                    "headers": ["Category", "Count"],
                    "rows": [[k.replace('_', ' ').title(), v] for k, v in attrs["last_analysis_stats"].items()]
                })
            
            # Last Analysis Results
            if "last_analysis_results" in attrs:
                results = attrs["last_analysis_results"]
                tables.append({
                    "name": "Analysis Results",
                    "type": "datatable",
                    "headers": ["Engine", "Category", "Result", "Method"],
                    "rows": [[
                        engine,
                        data.get("category", "N/A"),
                        data.get("result", "N/A"),
                        data.get("method", "N/A")
                    ] for engine, data in results.items()]
                })
            
            # Network Info
            network_info = {k: v for k, v in attrs.items() 
                          if any(x in k for x in ["asn", "network", "as_owner", "country"])}
            if network_info:
                tables.append({
                    "name": "Network Information",
                    "type": "table",
                    "headers": ["Property", "Value"],
                    "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in network_info.items()]
                })
            
            # Other attributes
            other_attrs = {k: v for k, v in attrs.items() 
                         if k not in ["last_analysis_stats", "last_analysis_results", 
                                    "asn", "network", "as_owner", "country"]}
            if other_attrs:
                tables.append({
                    "name": "Additional Information",
                    "type": "table",
                    "headers": ["Property", "Value"],
                    "rows": [[k.replace('_', ' ').title(), 
                             DataFormatter.format_timestamp(v) if k.endswith('_date') else str(v)
                            ] for k, v in other_attrs.items()]
                })
        
        return tables

    @staticmethod
    def process_abuseipdb_data(data: Dict) -> List[Dict]:
        """Process AbuseIPDB data into organized sections."""
        tables = []
        
        if "data" in data:
            data = data["data"]
            
            # IP Information
            ip_info = {k: v for k, v in data.items() if k != "reports"}
            if ip_info:
                tables.append({
                    "name": "IP Information",
                    "type": "table",
                    "headers": ["Property", "Value"],
                    "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in ip_info.items()]
                })
            
            # Reports
            if "reports" in data:
                reports_table = {
                    "name": "Abuse Reports",
                    "type": "datatable",
                    "headers": ["Reported At", "Categories", "Reporter", "Country", "Comment"],
                    "rows": []
                }
                
                for report in data["reports"]:
                    reports_table["rows"].append([
                        DataFormatter.format_timestamp(report.get("reportedAt")),
                        DataFormatter.format_categories(report.get("categories", [])),
                        f"{report.get('reporterCountryName', 'Unknown')} ({report.get('reporterCountryCode', 'N/A')})",
                        report.get("reporterCountryName", "N/A"),
                        DataFormatter.truncate_text(report.get("comment", ""), 100)
                    ])
                
                tables.append(reports_table)
        
        return tables

    @staticmethod
    def process_whois_data(whois_data: Dict) -> List[Dict]:
        """Process WHOIS data into organized sections."""
        if not whois_data or not isinstance(whois_data, dict):
            return [{"name": "WHOIS Information", "type": "single", "value": "No WHOIS data available"}]

        sections = []

        # Network Information
        network_info = {
            k: v for k, v in whois_data.items()
            if not isinstance(v, dict) and any(x in k.lower() for x in ["network", "netname", "nettype", "netrange", "cidr", "ip"])
        }
        if network_info:
            sections.append({
                "name": "Network Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in network_info.items()]
            })

        # Organization Information
        org_info = {
            k: v for k, v in whois_data.items()
            if not isinstance(v, dict) and any(x in k.lower() for x in ["org", "organization", "orgname", "orgid", "customer", "registrar"])
        }
        if org_info:
            sections.append({
                "name": "Organization Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in org_info.items()]
            })

        # Contact Information
        for contact_type in ["registrant", "admin", "technical"]:
            if contact_type in whois_data and isinstance(whois_data[contact_type], dict):
                contact_data = whois_data[contact_type]
                if any(contact_data.values()):  # Only add if there's any non-None value
                    sections.append({
                        "name": f"{contact_type.title()} Contact",
                        "type": "table",
                        "headers": ["Property", "Value"],
                        "rows": [
                            [k.replace('_', ' ').title(), str(v) if v is not None else "N/A"]
                            for k, v in contact_data.items()
                        ]
                    })

        # Dates
        date_info = {
            k: v for k, v in whois_data.items()
            if not isinstance(v, dict) and any(x in k.lower() for x in ["date", "created", "updated", "expires"])
        }
        if date_info:
            sections.append({
                "name": "Registration Dates",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [
                    [k.replace('_', ' ').title(), 
                     DataFormatter.format_timestamp(v) if v else "N/A"]
                    for k, v in date_info.items()
                ]
            })

        # Other Information
        used_keys = set()
        for section in sections:
            used_keys.update(row[0].lower().replace(' ', '_') for row in section.get("rows", []))
        
        other_info = {
            k: v for k, v in whois_data.items()
            if not isinstance(v, dict) and k.lower() not in used_keys and k != "_sources"
        }
        if other_info:
            sections.append({
                "name": "Additional Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in other_info.items()]
            })

        return sections

    @staticmethod
    def process_alienvault_data(data: Dict) -> List[Dict]:
        """Process AlienVault data into organized sections."""
        tables = []
        
        if "pulse_info" in data:
            pulse_info = data["pulse_info"]
            
            # Summary Information
            summary_info = {
                "Total Pulses": pulse_info.get("count", 0),
                "Total References": len(pulse_info.get("references", [])),
                "Related Indicators": ", ".join(f"{k}: {v}" for k, v in pulse_info.get("related_indicator_type", {}).items())
            }
            
            tables.append({
                "name": "Pulse Summary",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k, str(v)] for k, v in summary_info.items()]
            })
            
            # Pulses Table
            if "pulses" in pulse_info and pulse_info["pulses"]:
                pulses_table = {
                    "name": "Threat Intelligence Pulses",
                    "type": "datatable",
                    "headers": [
                        "Name", "Description", "Tags", "TLP", "Modified",
                        "Adversary", "Malware Families", "Industries",
                        "Attack IDs", "Indicator Count", "References"
                    ],
                    "rows": []
                }
                
                for pulse in pulse_info["pulses"]:
                    # Process malware families
                    malware_families = []
                    if isinstance(pulse.get("malware_families"), dict) and "rows" in pulse["malware_families"]:
                        malware_families = [row[1] for row in pulse["malware_families"]["rows"]]
                    
                    # Process attack IDs
                    attack_ids = []
                    if isinstance(pulse.get("attack_ids"), dict) and "rows" in pulse["attack_ids"]:
                        attack_ids = [f"{row[1]} ({row[0]})" for row in pulse["attack_ids"]["rows"]]
                    
                    # Create row
                    row = [
                        pulse.get("name", "N/A"),
                        DataFormatter.truncate_text(pulse.get("description", ""), 100),
                        ", ".join(pulse.get("tags", [])) or "N/A",
                        pulse.get("tlp", "N/A"),
                        DataFormatter.format_timestamp(pulse.get("modified")),
                        pulse.get("adversary", "N/A"),
                        ", ".join(malware_families) or "N/A",
                        ", ".join(pulse.get("industries", [])) or "N/A",
                        ", ".join(attack_ids) or "N/A",
                        str(pulse.get("indicator_count", 0)),
                        ", ".join(pulse.get("references", [])) or "N/A"
                    ]
                    pulses_table["rows"].append(row)
                
                tables.append(pulses_table)
            
            # References
            if pulse_info.get("references"):
                tables.append({
                    "name": "References",
                    "type": "table",
                    "headers": ["Reference URL"],
                    "rows": [[ref] for ref in pulse_info["references"]]
                })
        
        return tables

    @staticmethod
    def process_platform_data(platform_data: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Format platform data for frontend display"""
        formatted_data = {}
        
        for platform, data in platform_data.items():
            if not data:
                continue

            formatted_data[platform] = []
            
            if platform == 'virustotal':
                if isinstance(data, dict) and 'data' in data:
                    vt_data = data['data']
                    # Basic Info
                    if 'attributes' in vt_data:
                        attrs = vt_data['attributes']
                        basic_info = {
                            'Last Analysis Date': DataFormatter.format_timestamp(attrs.get('last_analysis_date', '')),
                            'Times Submitted': attrs.get('times_submitted', 'N/A'),
                            'Total Votes': f"Harmless: {attrs.get('total_votes', {}).get('harmless', 0)}, Malicious: {attrs.get('total_votes', {}).get('malicious', 0)}",
                            'Regional Internet Registry': attrs.get('regional_internet_registry', 'N/A'),
                            'Network': attrs.get('network', 'N/A')
                        }
                        formatted_data[platform].append({
                            'name': 'Basic Information',
                            'type': 'table',
                            'headers': ['Property', 'Value'],
                            'rows': [[k, v] for k, v in basic_info.items()]
                        })
                        
                        # Analysis Results
                        if 'last_analysis_results' in attrs:
                            results = []
                            for engine, result in attrs['last_analysis_results'].items():
                                results.append([
                                    engine,
                                    result.get('category', 'N/A'),
                                    result.get('result', 'N/A'),
                                    result.get('method', 'N/A')
                                ])
                            formatted_data[platform].append({
                                'name': 'Analysis Results',
                                'type': 'datatable',
                                'headers': ['Engine', 'Category', 'Result', 'Method'],
                                'rows': results
                            })

            elif platform == 'abuseipdb':
                if isinstance(data, dict) and 'data' in data:
                    abuse_data = data['data']
                    # General Info
                    general_info = {
                        'Abuse Confidence': f"{abuse_data.get('abuseConfidenceScore', 0)}%",
                        'Total Reports': abuse_data.get('totalReports', 'N/A'),
                        'Last Reported': DataFormatter.format_timestamp(abuse_data.get('lastReportedAt', '')),
                        'ISP': abuse_data.get('isp', 'N/A'),
                        'Usage Type': abuse_data.get('usageType', 'N/A'),
                        'Domain': abuse_data.get('domain', 'N/A'),
                        'Country': abuse_data.get('countryName', 'N/A'),
                        'Is Tor': 'Yes' if abuse_data.get('isTor', False) else 'N/A'
                    }
                    formatted_data[platform].append({
                        'name': 'AbuseIPDB Information',
                        'type': 'table',
                        'headers': ['Property', 'Value'],
                        'rows': [[k, v] for k, v in general_info.items()]
                    })
                    
                    # Reports
                    if 'reports' in abuse_data:
                        reports = []
                        for report in abuse_data['reports']:
                            reports.append([
                                DataFormatter.format_timestamp(report.get('reportedAt', '')),
                                DataFormatter.format_categories(report.get('categories', [])),
                                report.get('comment', 'N/A'),
                                report.get('reporterCountryName', 'N/A')
                            ])
                        formatted_data[platform].append({
                            'name': 'Recent Reports',
                            'type': 'datatable',
                            'headers': ['Reported At', 'Categories', 'Comment', 'Reporter Country'],
                            'rows': reports
                        })

            elif platform == 'greynoise':
                if isinstance(data, dict):
                    # Basic Info
                    basic_info = {
                        'Classification': data.get('classification', 'N/A'),
                        'Last Seen': DataFormatter.format_timestamp(data.get('last_seen', '')),
                        'Intent': data.get('intent', 'N/A'),
                        'First Seen': DataFormatter.format_timestamp(data.get('first_seen', '')),
                        'IP': data.get('ip', 'N/A'),
                        'Organization': data.get('organization', 'N/A')
                    }
                    formatted_data[platform].append({
                        'name': 'GreyNoise Information',
                        'type': 'table',
                        'headers': ['Property', 'Value'],
                        'rows': [[k, v] for k, v in basic_info.items()]
                    })
                    
                    # Tags and Metadata
                    if 'tags' in data:
                        formatted_data[platform].append({
                            'name': 'Tags',
                            'type': 'table',
                            'headers': ['Tags'],
                            'rows': [[', '.join(data['tags'])]]
                        })

            elif platform == 'crowdsec':
                if isinstance(data, dict):
                    # Basic Information
                    basic_info = {
                        'Reputation': data.get('reputation', 'N/A'),
                        'Confidence': data.get('confidence', 'N/A'),
                        'Background Noise': data.get('background_noise', 'N/A'),
                        'AS Name': data.get('as_name', 'N/A'),
                        'AS Number': data.get('as_num', 'N/A'),
                        'Reverse DNS': data.get('reverse_dns', 'N/A'),
                    }
                    formatted_data[platform] = [{
                        'name': 'Basic Information',
                        'type': 'table',
                        'headers': ['Property', 'Value'],
                        'rows': [[k, v] for k, v in basic_info.items()]
                    }]

                    # Location Information
                    if 'location' in data and isinstance(data['location'], dict):
                        location = data['location']
                        formatted_data[platform].append({
                            'name': 'Location Information',
                            'type': 'table',
                            'headers': ['Property', 'Value'],
                            'rows': [
                                ['Country', location.get('country', 'N/A')],
                                ['City', location.get('city', 'N/A')],
                                ['Latitude', str(location.get('latitude', 'N/A'))],
                                ['Longitude', str(location.get('longitude', 'N/A'))]
                            ]
                        })

                    # History Information
                    if 'history' in data and isinstance(data['history'], dict):
                        history = data['history']
                        formatted_data[platform].append({
                            'name': 'History',
                            'type': 'table',
                            'headers': ['Property', 'Value'],
                            'rows': [
                                ['First Seen', DataFormatter.format_timestamp(history.get('first_seen', ''))],
                                ['Last Seen', DataFormatter.format_timestamp(history.get('last_seen', ''))],
                                ['Days Active', f"{history.get('days_age', 'N/A')} days"]
                            ]
                        })

                    # Behaviors
                    if 'behaviors' in data and isinstance(data['behaviors'], list):
                        behaviors = data['behaviors']
                        formatted_data[platform].append({
                            'name': 'Observed Behaviors',
                            'type': 'datatable',
                            'headers': ['Name', 'Label', 'Description'],
                            'rows': [[b.get('name', 'N/A'), b.get('label', 'N/A'), b.get('description', 'N/A')] for b in behaviors]
                        })

                    # Attack Details
                    if 'attack_details' in data and isinstance(data['attack_details'], list):
                        attack_details = data['attack_details']
                        formatted_data[platform].append({
                            'name': 'Attack Details',
                            'type': 'datatable',
                            'headers': ['Name', 'Label', 'Description'],
                            'rows': [[a.get('name', 'N/A'), a.get('label', 'N/A'), a.get('description', 'N/A')] for a in attack_details]
                        })

                    # CVEs
                    if 'cves' in data and isinstance(data['cves'], list) and data['cves']:
                        formatted_data[platform].append({
                            'name': 'CVEs',
                            'type': 'table',
                            'headers': ['CVE'],
                            'rows': [[cve] for cve in data['cves']]
                        })

                    # Target Countries
                    if 'target_countries' in data and isinstance(data['target_countries'], dict):
                        target_countries = data['target_countries']
                        formatted_data[platform].append({
                            'name': 'Target Countries',
                            'type': 'table',
                            'headers': ['Country', 'Attack Count'],
                            'rows': [[country, str(count)] for country, count in target_countries.items()]
                        })

                    # MITRE Techniques
                    if 'mitre_techniques' in data and isinstance(data['mitre_techniques'], list):
                        mitre = data['mitre_techniques']
                        formatted_data[platform].append({
                            'name': 'MITRE ATT&CK Techniques',
                            'type': 'datatable',
                            'headers': ['ID', 'Name', 'Description'],
                            'rows': [[m.get('name', 'N/A'), m.get('label', 'N/A'), m.get('description', 'N/A')] for m in mitre]
                        })

                    # Scores
                    if 'scores' in data and isinstance(data['scores'], dict):
                        scores = data['scores']
                        score_rows = []
                        for period, metrics in scores.items():
                            if isinstance(metrics, dict):
                                score_rows.extend([
                                    [f"{period.replace('_', ' ').title()} - Aggressiveness", metrics.get('aggressiveness', 'N/A')],
                                    [f"{period.replace('_', ' ').title()} - Threat", metrics.get('threat', 'N/A')],
                                    [f"{period.replace('_', ' ').title()} - Trust", metrics.get('trust', 'N/A')],
                                    [f"{period.replace('_', ' ').title()} - Anomaly", metrics.get('anomaly', 'N/A')],
                                    [f"{period.replace('_', ' ').title()} - Total", metrics.get('total', 'N/A')]
                                ])
                        
                        if score_rows:
                            formatted_data[platform].append({
                                'name': 'Threat Scores',
                                'type': 'table',
                                'headers': ['Metric', 'Score'],
                                'rows': score_rows
                            })

            elif platform == 'ipinfo':
                if isinstance(data, dict):
                    # Format WHOIS data into a table
                    whois_info = []
                    if data.get('ip'):
                        whois_info.append(['IP Address', data['ip']])
                    if data.get('hostname'):
                        whois_info.append(['Hostname', data['hostname']])
                    if data.get('city'):
                        whois_info.append(['City', data['city']])
                    if data.get('region'):
                        whois_info.append(['Region', data['region']])
                    if data.get('country'):
                        whois_info.append(['Country', data['country']])
                    if data.get('loc'):
                        whois_info.append(['Location', data['loc']])
                    if data.get('org'):
                        org_parts = data['org'].split(' ', 1)
                        if len(org_parts) > 1:
                            whois_info.append(['ASN', org_parts[0]])
                            whois_info.append(['Organization', org_parts[1]])
                        else:
                            whois_info.append(['Organization', data['org']])
                    if data.get('postal'):
                        whois_info.append(['Postal Code', data['postal']])
                    if data.get('timezone'):
                        whois_info.append(['Timezone', data['timezone']])
                    
                    formatted_data[platform] = [{
                        'name': 'WHOIS Information',
                        'type': 'table',
                        'headers': ['Property', 'Value'],
                        'rows': whois_info
                    }]

            elif platform == 'securitytrails':
                formatted_data[platform] = DataFormatter._format_securitytrails_data(data)

            elif platform == 'metadefender':
                if isinstance(data, dict):
                    formatted_data[platform] = []

                    # Basic Information
                    if 'lookup_results' in data:
                        lookup = data['lookup_results']
                        formatted_data[platform].append({
                            'name': 'Scan Summary',
                            'type': 'table',
                            'headers': ['Property', 'Value'],
                            'rows': [
                                ['IP Address', data.get('address', 'N/A')],
                                ['Start Time', DataFormatter.format_timestamp(lookup.get('start_time', ''))],
                                ['Detected By', str(lookup.get('detected_by', 'N/A'))]
                            ]
                        })

                    # Geo Information
                    if 'geo_info' in data:
                        geo = data['geo_info']
                        geo_rows = []
                        
                        if 'country' in geo and isinstance(geo['country'], dict):
                            geo_rows.append(['Country', geo['country'].get('name', 'N/A')])
                        
                        if 'city' in geo and isinstance(geo['city'], dict):
                            geo_rows.append(['City', geo['city'].get('name', 'N/A')])
                        
                        if 'subdivisions' in geo and isinstance(geo['subdivisions'], list) and geo['subdivisions']:
                            geo_rows.append(['Region', geo['subdivisions'][0].get('name', 'N/A')])
                        
                        if 'location' in geo and isinstance(geo['location'], dict):
                            geo_rows.append(['Latitude', str(geo['location'].get('latitude', 'N/A'))])
                            geo_rows.append(['Longitude', str(geo['location'].get('longitude', 'N/A'))])

                        if geo_rows:
                            formatted_data[platform].append({
                                'name': 'Geographic Information',
                                'type': 'table',
                                'headers': ['Property', 'Value'],
                                'rows': geo_rows
                            })

                    # Sources Information
                    if 'lookup_results' in data and 'sources' in data['lookup_results']:
                        sources = data['lookup_results']['sources']
                        source_rows = []
                        
                        status_map = {
                            0: 'Unknown',
                            1: 'Clean',
                            2: 'Suspicious',
                            3: 'Malicious',
                            4: 'Error',
                            5: 'Not Found'
                        }
                        
                        for source in sources:
                            status = status_map.get(source.get('status', 0), 'Unknown')
                            source_rows.append([
                                source.get('provider', 'N/A'),
                                status,
                                source.get('assessment', 'N/A') or 'No Assessment',
                                DataFormatter.format_timestamp(source.get('update_time', ''))
                            ])

                        if source_rows:
                            formatted_data[platform].append({
                                'name': 'Source Analysis',
                                'type': 'datatable',
                                'headers': ['Provider', 'Status', 'Assessment', 'Last Updated'],
                                'rows': source_rows
                            })

            elif platform == 'alienvault':
                formatted_data[platform] = DataFormatter._format_alienvault_data(data)

            # If platform data couldn't be formatted, display raw data in a simple table
            if not formatted_data[platform]:
                formatted_data[platform] = [{
                    'name': f'{platform.title()} Raw Data',
                    'type': 'table',
                    'headers': ['Property', 'Value'],
                    'rows': [[k, str(v)] for k, v in data.items() if not isinstance(v, (dict, list))]
                }]

        return formatted_data

    @staticmethod
    def _format_securitytrails_data(data: Dict) -> List[Dict]:
        sections = []
        if 'blocks' in data:
            sections.append({
                'name': 'Site Distribution',
                'type': 'table',
                'headers': ['Block', 'Sites'],
                'rows': [[f'Block {idx}', block.get('sites', 0)] 
                        for idx, block in enumerate(data['blocks'])]
            })
        return sections

    @staticmethod
    def _format_metadefender_data(data: Dict) -> List[Dict]:
        sections = []
        if 'lookup_results' in data:
            results = data['lookup_results']
            sections.append({
                'name': 'Scan Results',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': [
                    ['Detected By', str(results.get('detected_by', 'N/A'))],
                    ['Start Time', str(results.get('start_time', 'N/A'))]
                ]
            })
        return sections

    @staticmethod
    def _format_alienvault_data(data):
        formatted_data = []
        
        # General Information
        if 'general' in data:
            general = data['general']
            basic_info = [
                ['IP Address', general.get('indicator', 'N/A')],
                ['Type', general.get('type_title', 'N/A')],
                ['Reputation Score', str(general.get('reputation', 'N/A'))],
                ['ASN', general.get('asn', 'N/A')],
                ['WHOIS', general.get('whois', 'N/A')]
            ]
            if 'pulse_info' in general:
                basic_info.append(['Total Pulses', str(general['pulse_info'].get('count', 0))])
            
            formatted_data.append({
                'name': 'General Information',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': basic_info
            })

        # Geographic Information
        if 'geo' in data:
            geo = data['geo']
            geo_rows = [
                ['Country', f"{geo.get('country_name', 'N/A')} ({geo.get('country_code', 'N/A')})"],
                ['City', geo.get('city', 'N/A')],
                ['Region', geo.get('region', 'N/A')],
                ['Subdivision', geo.get('subdivision', 'N/A')],
                ['Postal Code', geo.get('postal_code', 'N/A')],
                ['Latitude', str(geo.get('latitude', 'N/A'))],
                ['Longitude', str(geo.get('longitude', 'N/A'))],
                ['Accuracy Radius', f"{str(geo.get('accuracy_radius', 'N/A'))} meters"]
            ]
            formatted_data.append({
                'name': 'Geographic Information',
                'type': 'table',
                'headers': ['Property', 'Value'],
                'rows': geo_rows
            })

        # Pulse Information
        if 'general' in data and 'pulse_info' in data['general']:
            pulse_info = data['general']['pulse_info']
            
            # Recent Activities
            activities = []
            for pulse in pulse_info.get('pulses', []):
                activity = [
                    pulse.get('name', 'N/A'),
                    DataFormatter.format_timestamp(pulse.get('modified', '')),
                    pulse.get('description', 'N/A')[:100] + '...' if pulse.get('description', 'N/A') else 'N/A',
                    ', '.join(pulse.get('tags', [])) or 'N/A'
                ]
                activities.append(activity)

            if activities:
                formatted_data.append({
                    'name': 'Recent Activities',
                    'type': 'datatable',
                    'headers': ['Name', 'Last Modified', 'Description', 'Tags'],
                    'rows': activities[:5]  # Show only the 5 most recent activities
                })

            # Threat Intelligence Summary
            threat_info = []
            
            # Collect all unique malware families
            malware_families = set()
            for pulse in pulse_info.get('pulses', []):
                for malware in pulse.get('malware_families', []):
                    if isinstance(malware, dict):
                        malware_families.add(malware.get('display_name', ''))
                    else:
                        malware_families.add(str(malware))
            
            # Collect all unique attack techniques
            attack_techniques = set()
            for pulse in pulse_info.get('pulses', []):
                for attack in pulse.get('attack_ids', []):
                    if isinstance(attack, dict):
                        attack_techniques.add(attack.get('display_name', ''))

            # Collect unique industries and countries
            industries = set()
            targeted_countries = set()
            for pulse in pulse_info.get('pulses', []):
                industries.update(pulse.get('industries', []))
                targeted_countries.update(pulse.get('targeted_countries', []))

            if malware_families:
                threat_info.append(['Malware Families', ', '.join(sorted(malware_families))])
            if attack_techniques:
                threat_info.append(['Attack Techniques', ', '.join(sorted(attack_techniques))])
            if industries:
                threat_info.append(['Targeted Industries', ', '.join(sorted(industries))])
            if targeted_countries:
                threat_info.append(['Targeted Countries', ', '.join(sorted(targeted_countries))])

            if threat_info:
                formatted_data.append({
                    'name': 'Threat Intelligence',
                    'type': 'table',
                    'headers': ['Category', 'Details'],
                    'rows': threat_info
                })

            # References
            references = pulse_info.get('references', [])
            if references:
                formatted_data.append({
                    'name': 'References',
                    'type': 'table',
                    'headers': ['Reference'],
                    'rows': [[ref] for ref in references if ref]
                })

        return formatted_data
