"""
Platform scoring module for IP analysis
"""

def calculate_platform_scores(data, platform=None):
    """Calculate threat scores for each platform"""
    if not platform or not data:
        return None
        
    try:
        if platform == 'virustotal':
            if not isinstance(data, dict) or 'data' not in data:
                return None
                
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            total_scans = sum(last_analysis_stats.values() or [0])
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
            if not isinstance(data, dict):
                return None
                
            classification = data.get('classification', '').lower()
            noise = data.get('noise', False)
            riot = data.get('riot', False)
            
            base_score = {
                'malicious': 100,
                'suspicious': 50,
                'unknown': 25,
                'benign': 0
            }.get(classification, 0)
            
            if noise:
                base_score = min(100, base_score + 20)
            if riot:
                base_score = max(0, base_score - 20)
                
            return base_score

        elif platform == 'crowdsec':
            if not isinstance(data, dict):
                return None

            # Get score from scores.overall.score
            score = data.get('scores', {}).get('overall', {}).get('score')
            if score is not None:
                return float(score)

            # Calculate score based on decisions and behaviors
            base_score = 0
            
            decisions = data.get('decisions', [])
            if decisions:
                base_score += len(decisions) * 25  # 25 points per decision
            
            behaviors = data.get('behaviors', [])
            if behaviors:
                base_score += len(behaviors) * 15  # 15 points per behavior
            
            classifications = data.get('classifications', [])
            if classifications:
                base_score += len(classifications) * 20  # 20 points per classification
            
            return min(100, base_score) if base_score > 0 else None
                
        elif platform == 'securitytrails':
            if not isinstance(data, dict):
                return None
                
            # SecurityTrails scoring based on available data
            score = 0
            
            # Check neighbors
            neighbors = data.get('neighbors', [])
            if neighbors:
                score += min(30, len(neighbors) * 5)  # Up to 30 points for neighbors
            
            # Check historical data
            history = data.get('history', {})
            if history:
                score += 20  # Base score for having history
                
            # Check for associated domains
            associated = data.get('associated', {})
            if associated:
                score += min(30, len(associated) * 5)  # Up to 30 points
                
            # Check for tags
            tags = data.get('tags', [])
            if tags:
                score += min(20, len(tags) * 10)  # Up to 20 points
            
            return score if score > 0 else None
            
    except Exception as e:
        print(f"Error calculating {platform} score: {str(e)}")
        return None
            
    return None

def extract_whois_info(virustotal_data):
    """Extract WHOIS information from VirusTotal data"""
    try:
        if not isinstance(virustotal_data, dict):
            return None
            
        attributes = virustotal_data.get('data', {}).get('attributes', {})
        if not attributes:
            return None
            
        whois_data = {
            'country': attributes.get('country', 'N/A'),
            'as_owner': attributes.get('as_owner', 'N/A'),
            'asn': str(attributes.get('asn', 'N/A')),
            'network': attributes.get('network', 'N/A'),
            'last_analysis_date': attributes.get('last_analysis_date'),
            'registrar': attributes.get('registrar', 'N/A'),
            'date_registered': attributes.get('creation_date', 'N/A'),
            'hostname': attributes.get('last_dns_records', [{}])[0].get('hostname', 'N/A') if attributes.get('last_dns_records') else 'N/A',
            'total_votes': {
                'harmless': attributes.get('total_votes', {}).get('harmless', 0),
                'malicious': attributes.get('total_votes', {}).get('malicious', 0)
            },
            'reputation': attributes.get('reputation', 'N/A'),
            'tags': attributes.get('tags', []),
            'regional_internet_registry': attributes.get('regional_internet_registry', 'N/A'),
        }
        
        return whois_data
    except Exception as e:
        print(f"Error extracting WHOIS info: {str(e)}")
        return None
