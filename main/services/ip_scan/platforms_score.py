"""
Platform scoring module for IP analysis
"""

def calculate_platform_scores(data, platform=None):
    if not platform or not data or isinstance(data, dict) and 'error' in data:
        return None
        
    try:
        if platform == 'virustotal':
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            total_scans = sum(last_analysis_stats.values())
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            
            if total_scans == 0:
                return None
            
            score = ((malicious * 1.0) + (suspicious * 0.5)) / total_scans * 100
            return min(100, score)
                
        elif platform == 'abuseipdb':
            if not isinstance(data.get('data', {}), dict):
                return None
            abuse_confidence_score = data.get('data', {}).get('abuseConfidenceScore')
            return float(abuse_confidence_score) if abuse_confidence_score is not None else None
                
        elif platform == 'greynoise':
            if 'error' in data or not isinstance(data, dict):
                return None
                
            classification = data.get('classification', '').lower()
            noise = data.get('noise', False)
            riot = data.get('riot', False)
            
            # Base score on classification
            base_score = {
                'malicious': 100,
                'suspicious': 50,
                'unknown': 25,
                'benign': 0
            }.get(classification, 0)
            
            # Adjust score based on noise and riot flags
            if noise:
                base_score = min(100, base_score + 20)
            if riot:
                base_score = max(0, base_score - 20)
                
            return base_score
                
        elif platform == 'securitytrails':
            if not isinstance(data, dict) or data.get('error'):
                return None
                
            # SecurityTrails doesn't provide a direct risk score
            # We'll base it on various indicators
            score = 0
            
            # Check current DNS records
            if data.get('current_dns'):
                score += 10  # Base score for having DNS records
                
            # Check historical data
            history = data.get('history', {})
            if history.get('ip_history'):
                score += min(30, len(history['ip_history']) * 5)  # Cap at 30 points
            if history.get('dns_history'):
                score += min(30, len(history['dns_history']) * 5)  # Cap at 30 points
                
            # Check for tags
            tags = data.get('tags', [])
            if tags:
                score += min(20, len(tags) * 10)  # Cap at 20 points
                
            # Check for subdomains
            subdomains = data.get('subdomains', [])
            if subdomains:
                score += min(10, len(subdomains) * 2)  # Cap at 10 points
            
            return min(100, score)
            
    except Exception as e:
        print(f"Error calculating {platform} score: {str(e)}")
        return None
            
    return None

def extract_whois_info(virustotal_data):
    """Extract WHOIS information from VirusTotal data"""
    try:
        if not isinstance(virustotal_data, dict) or 'error' in virustotal_data:
            return None
            
        attributes = virustotal_data.get('data', {}).get('attributes', {})
        if not attributes:
            return None
            
        # Try to parse registrar from WHOIS data
        whois_text = attributes.get('whois', '')
        registrar = None
        if whois_text:
            for line in whois_text.split('\n'):
                if 'registrar:' in line.lower():
                    registrar = line.split(':', 1)[1].strip()
                    break
        
        # Get the date registered
        date_registered = None
        if whois_text:
            for line in whois_text.split('\n'):
                if any(x in line.lower() for x in ['creation date', 'registered on', 'registration date']):
                    try:
                        date_part = line.split(':', 1)[1].strip()
                        # This is a basic extraction, you might want to parse it into a proper date
                        date_registered = date_part
                    except:
                        pass
        
        whois_data = {
            'country': attributes.get('country'),
            'as_owner': attributes.get('as_owner'),
            'asn': str(attributes.get('asn')) if attributes.get('asn') else None,
            'network': attributes.get('network'),
            'last_analysis_date': attributes.get('last_analysis_date'),
            'registrar': registrar,
            'date_registered': date_registered,
            'hostname': attributes.get('hostname'),
            'total_votes': {
                'harmless': attributes.get('total_votes', {}).get('harmless', 0),
                'malicious': attributes.get('total_votes', {}).get('malicious', 0)
            },
            'reputation': attributes.get('reputation'),
            'tags': attributes.get('tags', []),
            'regional_internet_registry': attributes.get('regional_internet_registry'),
        }
        
        # Remove None values
        return {k: v for k, v in whois_data.items() if v is not None}
    except Exception as e:
        print(f"Error extracting WHOIS info: {str(e)}")
        return None
