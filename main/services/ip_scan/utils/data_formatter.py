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
    def process_platform_data(platform_data: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Process platform data into a structured format for display."""
        formatted_data = {}

        for platform, data in platform_data.items():
            # Handle empty or error data
            if not data or isinstance(data, str):
                formatted_data[platform] = []
                continue

            if platform == "whois":
                whois_data = []
                if isinstance(data, dict):
                    # Network Information
                    network_info = {k: v for k, v in data.items() if k in ["ip", "network", "netname", "nettype", "netrange", "cidr"]}
                    if network_info:
                        whois_data.append({
                            "name": "Network Information",
                            "type": "table",
                            "headers": ["Property", "Value"],
                            "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in network_info.items()]
                        })

                    # Organization Information
                    org_info = {k: v for k, v in data.items() if k in ["org", "organization", "orgname", "orgid", "customer", "registrar"]}
                    if org_info:
                        whois_data.append({
                            "name": "Organization Information",
                            "type": "table",
                            "headers": ["Property", "Value"],
                            "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in org_info.items()]
                        })

                    # Contact Information
                    for contact_type in ["registrant", "admin", "technical"]:
                        if contact_type in data and isinstance(data[contact_type], dict):
                            contact_data = data[contact_type]
                            if any(contact_data.values()):
                                whois_data.append({
                                    "name": f"{contact_type.title()} Contact",
                                    "type": "table",
                                    "headers": ["Property", "Value"],
                                    "rows": [[k.replace('_', ' ').title(), str(v) if v else "N/A"] for k, v in contact_data.items()]
                                })

                    # Dates
                    date_info = {k: v for k, v in data.items() if any(x in k.lower() for x in ["date", "created", "updated", "expires"])}
                    if date_info:
                        whois_data.append({
                            "name": "Registration Dates",
                            "type": "table",
                            "headers": ["Property", "Value"],
                            "rows": [[k.replace('_', ' ').title(), DataFormatter.format_timestamp(v) if v else "N/A"] for k, v in date_info.items()]
                        })

                formatted_data[platform] = whois_data

            elif platform == "virustotal":
                vt_data = []
                if isinstance(data, dict):
                    # Last Analysis Stats
                    if "last_analysis_stats" in data:
                        stats = data["last_analysis_stats"]
                        vt_data.append({
                            "name": "Analysis Summary",
                            "type": "table",
                            "headers": ["Category", "Count"],
                            "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in stats.items()]
                        })

                    # Last Analysis Results
                    if "last_analysis_results" in data:
                        results = data["last_analysis_results"]
                        rows = []
                        for engine, result in results.items():
                            if isinstance(result, dict):
                                rows.append([
                                    engine,
                                    result.get("category", "N/A"),
                                    result.get("result", "N/A"),
                                    result.get("method", "N/A"),
                                    result.get("engine_name", "N/A")
                                ])
                        if rows:
                            vt_data.append({
                                "name": "Scan Results",
                                "type": "datatable",
                                "headers": ["Engine", "Category", "Result", "Method", "Engine Name"],
                                "rows": rows
                            })

                formatted_data[platform] = vt_data

            elif platform == "abuseipdb":
                abuse_data = []
                if isinstance(data, dict):
                    # General Information
                    general_info = {k: v for k, v in data.items() if k in ["ipAddress", "isPublic", "ipVersion", "isWhitelisted", "abuseConfidenceScore"]}
                    if general_info:
                        abuse_data.append({
                            "name": "General Information",
                            "type": "table",
                            "headers": ["Property", "Value"],
                            "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in general_info.items()]
                        })

                    # Usage Type
                    if "usageType" in data:
                        abuse_data.append({
                            "name": "Usage Type",
                            "type": "single",
                            "value": data["usageType"]
                        })

                    # Reports
                    if "reports" in data and isinstance(data["reports"], list):
                        rows = []
                        for report in data["reports"]:
                            if isinstance(report, dict):
                                rows.append([
                                    report.get("reportedAt", "N/A"),
                                    report.get("comment", "N/A"),
                                    str(report.get("categories", [])),
                                    report.get("reporterId", "N/A")
                                ])
                        if rows:
                            abuse_data.append({
                                "name": "Abuse Reports",
                                "type": "datatable",
                                "headers": ["Reported At", "Comment", "Categories", "Reporter ID"],
                                "rows": rows
                            })

                formatted_data[platform] = abuse_data

            elif platform == "ipinfo":
                ipinfo_data = []
                if isinstance(data, dict):
                    # Location Information
                    location_info = {k: v for k, v in data.items() if k in ["city", "region", "country", "loc", "timezone", "postal"]}
                    if location_info:
                        ipinfo_data.append({
                            "name": "Location Information",
                            "type": "table",
                            "headers": ["Property", "Value"],
                            "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in location_info.items()]
                        })

                    # Network Information
                    network_info = {k: v for k, v in data.items() if k in ["hostname", "org", "asn", "network"]}
                    if network_info:
                        ipinfo_data.append({
                            "name": "Network Information",
                            "type": "table",
                            "headers": ["Property", "Value"],
                            "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in network_info.items()]
                        })

                formatted_data[platform] = ipinfo_data

            else:
                # Generic data processing for other platforms
                platform_data = []
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, dict):
                            platform_data.append({
                                "name": key.replace('_', ' ').title(),
                                "type": "table",
                                "headers": ["Property", "Value"],
                                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in value.items()]
                            })
                        elif isinstance(value, list):
                            if value and isinstance(value[0], dict):
                                headers = list(value[0].keys())
                                platform_data.append({
                                    "name": key.replace('_', ' ').title(),
                                    "type": "datatable",
                                    "headers": [h.replace('_', ' ').title() for h in headers],
                                    "rows": [[str(item.get(h, '')) for h in headers] for item in value]
                                })
                            else:
                                platform_data.append({
                                    "name": key.replace('_', ' ').title(),
                                    "type": "single",
                                    "value": ", ".join(map(str, value))
                                })
                        else:
                            platform_data.append({
                                "name": key.replace('_', ' ').title(),
                                "type": "single",
                                "value": str(value)
                            })
                    formatted_data[platform] = platform_data
                else:
                    formatted_data[platform] = [{
                        "name": "Information",
                        "type": "single",
                        "value": str(data)
                    }]

        return formatted_data

    @staticmethod
    def process_greynoise_data(data: Dict) -> List[Dict]:
        """Process GreyNoise data into organized sections."""
        if not data or not isinstance(data, dict):
            return [{"name": "GreyNoise Information", "type": "single", "value": "No data available"}]

        tables = []

        # Classification Information
        classification_info = {k: v for k, v in data.items() if k in ["classification", "actor", "cve", "name", "category"]}
        if classification_info:
            tables.append({
                "name": "Classification",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in classification_info.items()]
            })

        # IP Information
        ip_info = {k: v for k, v in data.items() if k in ["ip", "first_seen", "last_seen", "seen", "bot"]}
        if ip_info:
            tables.append({
                "name": "IP Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), 
                         DataFormatter.format_timestamp(v) if 'seen' in k else str(v)]
                        for k, v in ip_info.items()]
            })

        # Tags and Metadata
        if "tags" in data and data["tags"]:
            tables.append({
                "name": "Tags",
                "type": "single",
                "value": ", ".join(data["tags"])
            })

        # Raw Data
        raw_data = {k: v for k, v in data.items() 
                   if k not in ["classification", "actor", "cve", "name", "category", "ip", 
                              "first_seen", "last_seen", "seen", "bot", "tags"]}
        if raw_data:
            tables.append({
                "name": "Additional Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in raw_data.items()]
            })

        return tables

    @staticmethod
    def process_ipinfo_data(data: Dict) -> List[Dict]:
        """Process IPInfo data into organized sections."""
        if not data or not isinstance(data, dict):
            return [{"name": "IPInfo Information", "type": "single", "value": "No data available"}]

        tables = []

        # Location Information
        location_info = {k: v for k, v in data.items() if k in ["city", "region", "country", "loc", "timezone", "postal"]}
        if location_info:
            tables.append({
                "name": "Location Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in location_info.items()]
            })

        # Network Information
        network_info = {k: v for k, v in data.items() if k in ["hostname", "org", "asn", "network"]}
        if network_info:
            tables.append({
                "name": "Network Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in network_info.items()]
            })

        # Privacy Information
        privacy_info = {k: v for k, v in data.items() if k in ["privacy", "abuse", "domains"]}
        if privacy_info:
            tables.append({
                "name": "Privacy Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in privacy_info.items()]
            })

        # Other Information
        other_info = {k: v for k, v in data.items() 
                     if k not in ["city", "region", "country", "loc", "timezone", "postal",
                                "hostname", "org", "asn", "network",
                                "privacy", "abuse", "domains"]}
        if other_info:
            tables.append({
                "name": "Additional Information",
                "type": "table",
                "headers": ["Property", "Value"],
                "rows": [[k.replace('_', ' ').title(), str(v)] for k, v in other_info.items()]
            })

        return tables

    @staticmethod
    def process_platform_data(platform_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format platform data for frontend display"""
        formatted_data = {}
        
        for platform, data in platform_data.items():
            if not data or not isinstance(data, dict):
                continue
                
            formatted_data[platform] = {}
            
            # Process IPInfo WHOIS data
            if platform == 'ipinfo':
                formatted_data[platform] = DataFormatter._format_ipinfo_data(data)
            
            # Process Pulsedive data
            elif platform == 'pulsedive':
                formatted_data[platform] = DataFormatter._format_pulsedive_data(data)
            
            # Process other platforms
            else:
                formatted_data[platform] = DataFormatter._format_generic_data(data)
        
        return formatted_data
    
    @staticmethod
    def _format_ipinfo_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Format IPInfo data"""
        if not data:
            return {}
            
        formatted = {}
        # Extract basic fields
        basic_fields = ['ip', 'hostname', 'city', 'region', 'country', 'postal', 'timezone']
        for field in basic_fields:
            if field in data:
                formatted[field] = data[field]
        
        # Handle organization and ASN info
        if 'org' in data:
            org_parts = data['org'].split(' ', 1) if data['org'] else ['', '']
            formatted['asn'] = org_parts[0]
            formatted['organization'] = org_parts[1] if len(org_parts) > 1 else ''
        
        # Handle location data
        if 'loc' in data and data['loc']:
            try:
                lat, lon = data['loc'].split(',')
                formatted['latitude'] = float(lat)
                formatted['longitude'] = float(lon)
            except (ValueError, TypeError):
                formatted['latitude'] = None
                formatted['longitude'] = None
        
        return formatted
    
    @staticmethod
    def _format_pulsedive_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Format Pulsedive data"""
        if not data:
            return {}
            
        formatted = {
            'risk_level': data.get('risk', 'unknown'),
            'threats': [],
            'attributes': {},
            'whois': {}
        }
        
        # Extract threats
        if 'threats' in data and isinstance(data['threats'], list):
            formatted['threats'] = [
                {
                    'name': threat.get('name'),
                    'category': threat.get('category'),
                    'risk': threat.get('risk')
                }
                for threat in data['threats']
            ]
        
        # Extract attributes
        if 'attributes' in data and isinstance(data['attributes'], dict):
            formatted['attributes'] = data['attributes']
        
        # Format WHOIS data
        if 'properties' in data and 'whois' in data['properties']:
            whois_data = data['properties']['whois']
            if isinstance(whois_data, dict):
                formatted['whois'] = whois_data
        
        return formatted
    
    @staticmethod
    def _format_generic_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Format generic platform data"""
        formatted = {}
        
        def process_value(value):
            if isinstance(value, (str, int, float, bool)):
                return value
            elif isinstance(value, dict):
                return {k: process_value(v) for k, v in value.items() if not isinstance(v, (dict, list))}
            elif isinstance(value, list):
                return [process_value(item) for item in value if not isinstance(item, (dict, list))]
            return str(value)
        
        # Process top-level fields that aren't complex objects
        for key, value in data.items():
            if not isinstance(value, (dict, list)):
                formatted[key] = value
            elif isinstance(value, dict) and not any(isinstance(v, (dict, list)) for v in value.values()):
                formatted[key] = value
        
        return formatted
