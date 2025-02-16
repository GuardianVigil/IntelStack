import re
import email
from email import policy
from typing import Dict, List, Any
import dns.resolver
import requests
from datetime import datetime
import ipaddress
from urllib.parse import urlparse

class EmailHeaderAnalyzer:
    def __init__(self):
        self.threat_feeds = {
            'abuseipdb': 'YOUR_ABUSEIPDB_API_KEY',
            'virustotal': 'YOUR_VIRUSTOTAL_API_KEY',
            'greynoise': 'YOUR_GREYNOISE_API_KEY'
        }

    def parse_headers(self, header_content: str) -> Dict[str, Any]:
        """Parse email headers and return analysis results."""
        email_message = email.message_from_string(header_content, policy=policy.default)
        
        results = {
            'basic_info': self._get_basic_info(email_message),
            'authentication': self._analyze_authentication(email_message),
            'ip_analysis': self._analyze_ips(email_message),
            'urls': self._analyze_urls(email_message),
            'threat_score': self._calculate_threat_score(),
            'raw_headers': self._get_raw_headers(email_message)
        }
        
        return results

    def _get_basic_info(self, email_message) -> Dict[str, str]:
        """Extract basic information from email headers."""
        return {
            'from': email_message.get('From', ''),
            'to': email_message.get('To', ''),
            'subject': email_message.get('Subject', ''),
            'date': email_message.get('Date', ''),
            'message_id': email_message.get('Message-ID', ''),
            'return_path': email_message.get('Return-Path', '')
        }

    def _analyze_authentication(self, email_message) -> Dict[str, Any]:
        """Analyze email authentication results (SPF, DKIM, DMARC)."""
        auth_results = email_message.get('Authentication-Results', '')
        
        return {
            'spf': self._parse_spf(auth_results),
            'dkim': self._parse_dkim(auth_results),
            'dmarc': self._parse_dmarc(auth_results),
            'alignment': self._check_alignment(email_message),
            'spoofing_detected': self._check_spoofing(email_message)
        }

    def _parse_spf(self, auth_results: str) -> Dict[str, str]:
        """Parse SPF results from Authentication-Results header."""
        spf_match = re.search(r'spf=(\w+)', auth_results)
        return {
            'result': spf_match.group(1) if spf_match else 'unknown',
            'details': self._extract_spf_details(auth_results)
        }

    def _parse_dkim(self, auth_results: str) -> Dict[str, str]:
        """Parse DKIM results from Authentication-Results header."""
        dkim_match = re.search(r'dkim=(\w+)', auth_results)
        return {
            'result': dkim_match.group(1) if dkim_match else 'unknown',
            'details': self._extract_dkim_details(auth_results)
        }

    def _parse_dmarc(self, auth_results: str) -> Dict[str, str]:
        """Parse DMARC results from Authentication-Results header."""
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
        return {
            'result': dmarc_match.group(1) if dmarc_match else 'unknown',
            'details': self._extract_dmarc_details(auth_results)
        }

    def _check_alignment(self, email_message) -> Dict[str, bool]:
        """Check alignment between From, Return-Path, and DKIM signatures."""
        from_domain = self._extract_domain(email_message.get('From', ''))
        return_path_domain = self._extract_domain(email_message.get('Return-Path', ''))
        dkim_domain = self._extract_dkim_domain(email_message)

        return {
            'spf_alignment': from_domain == return_path_domain,
            'dkim_alignment': from_domain == dkim_domain
        }

    def _analyze_ips(self, email_message) -> Dict[str, Any]:
        """Analyze IP addresses found in the email headers."""
        ips = self._extract_ips(email_message)
        ip_analysis = {}

        for ip in ips:
            ip_analysis[ip] = {
                'geolocation': self._get_ip_geolocation(ip),
                'reputation': self._check_ip_reputation(ip),
                'reverse_dns': self._get_reverse_dns(ip),
                'asn_info': self._get_asn_info(ip)
            }

        return ip_analysis

    def _analyze_urls(self, email_message) -> List[Dict[str, Any]]:
        """Analyze URLs found in the email headers and body."""
        urls = self._extract_urls(email_message)
        url_analysis = []

        for url in urls:
            url_analysis.append({
                'url': url,
                'reputation': self._check_url_reputation(url),
                'domain_age': self._get_domain_age(url),
                'ssl_info': self._check_ssl_certificate(url)
            })

        return url_analysis

    def _calculate_threat_score(self) -> Dict[str, Any]:
        """Calculate overall threat score based on various factors."""
        # Implement threat scoring logic
        return {
            'score': 0.5,  # Example score between 0 and 1
            'confidence': 'medium',
            'factors': ['authentication_results', 'ip_reputation', 'url_analysis']
        }

    def _get_raw_headers(self, email_message) -> Dict[str, str]:
        """Get raw headers in a structured format."""
        raw_headers = {}
        for key, value in email_message.items():
            # Convert header lines to proper XML format
            if isinstance(value, str):
                # Check if the value contains XML
                if '<' in value and '>' in value:
                    # Keep XML structure but clean it up
                    raw_headers[key] = value.strip()
                else:
                    raw_headers[key] = value.strip()
            else:
                raw_headers[key] = str(value).strip()
        return raw_headers

    # Helper methods
    def _extract_domain(self, address: str) -> str:
        """Extract domain from email address."""
        match = re.search(r'@([\w.-]+)', address)
        return match.group(1) if match else ''

    def _extract_ips(self, email_message) -> List[str]:
        """Extract IP addresses from Received headers."""
        received_headers = email_message.get_all('Received', [])
        ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        ips = []
        
        for header in received_headers:
            matches = re.findall(ip_pattern, header)
            ips.extend(matches)
        
        return list(set(ips))  # Remove duplicates

    def _extract_urls(self, email_message) -> List[str]:
        """Extract URLs from email headers and body."""
        # Implement URL extraction logic
        return []

    def _get_ip_geolocation(self, ip: str) -> Dict[str, str]:
        """Get geolocation information for an IP address."""
        # Implement IP geolocation logic
        return {}

    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation against various threat feeds."""
        # Implement IP reputation checking logic
        return {}

    def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS record for an IP address."""
        try:
            return str(dns.resolver.resolve_address(ip)[0])
        except:
            return "No reverse DNS record found"

    def _get_asn_info(self, ip: str) -> Dict[str, str]:
        """Get ASN information for an IP address."""
        # Implement ASN lookup logic
        return {}

    def _check_url_reputation(self, url: str) -> Dict[str, str]:
        """Check URL reputation against threat feeds."""
        # Implement URL reputation checking logic
        return {}

    def _get_domain_age(self, url: str) -> str:
        """Get domain age information."""
        # Implement domain age checking logic
        return "Unknown"

    def _check_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Check SSL certificate information for a URL."""
        # Implement SSL certificate checking logic
        return {}
