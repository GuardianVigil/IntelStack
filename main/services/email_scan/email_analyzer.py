"""
Email Analysis Service for threat detection and IOC extraction
"""
import email
import re
import hashlib
import base64
from dataclasses import dataclass
from typing import List, Dict, Any
from email import policy
from email.parser import BytesParser
from datetime import datetime
from bs4 import BeautifulSoup

@dataclass
class EmailAnalysisResult:
    threat_score: int
    authentication: Dict[str, str]  # SPF, DKIM, DMARC status
    headers: Dict[str, Any]
    body: str
    attachments: List[Dict[str, Any]]
    iocs: Dict[str, List[str]]  # IPs, URLs, hashes
    risk_factors: List[str]

class EmailAnalyzer:
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.hash_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
        self.suspicious_domains = []

    def analyze_email(self, content: str | bytes, file_type: str = 'raw') -> EmailAnalysisResult:
        try:
            # Parse email content
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            
            msg = email.message_from_string(content)
            
            # Extract headers
            headers = dict(msg.items())
            
            # Extract body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif part.get_content_type() == "text/html":
                        # Convert HTML to plain text if no text/plain part found
                        if not body:
                            soup = BeautifulSoup(part.get_payload(decode=True).decode('utf-8', errors='ignore'), 'html.parser')
                            body = soup.get_text()
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            # Clean body
            body = body.strip()
            
            # Extract attachments
            attachments = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue
                    if part.get('Content-Disposition') is None:
                        continue
                    
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True)),
                            'hash': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
                        })
            
            # Extract IOCs
            iocs = {
                'urls': re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body),
                'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body),
                'hashes': re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', body)
            }
            
            # Calculate risk factors
            risk_factors = []
            
            # Check authentication
            auth_results = headers.get('Authentication-Results', '')
            if 'dmarc=fail' in auth_results.lower():
                risk_factors.append('DMARC authentication failed')
            if 'spf=fail' in auth_results.lower():
                risk_factors.append('SPF authentication failed')
            if 'dkim=fail' in auth_results.lower():
                risk_factors.append('DKIM authentication failed')
            
            # Check for suspicious attachments
            suspicious_extensions = ['.exe', '.bat', '.ps1', '.vbs', '.js', '.jar', '.dll']
            for attachment in attachments:
                if any(attachment['filename'].lower().endswith(ext) for ext in suspicious_extensions):
                    risk_factors.append(f"Suspicious attachment found: {attachment['filename']}")
            
            # Check for suspicious URLs
            suspicious_keywords = ['login', 'password', 'account', 'verify', 'wallet', 'bank']
            for url in iocs['urls']:
                if any(keyword in url.lower() for keyword in suspicious_keywords):
                    risk_factors.append(f"Suspicious URL found: {url}")
            
            # Check for suspicious sender
            sender = headers.get('From', '')
            if sender and '@' in sender:
                sender_domain = sender.split('@')[1].strip('>')
                if sender_domain in self.suspicious_domains:
                    risk_factors.append(f"Suspicious sender domain: {sender_domain}")
            
            # Calculate threat score
            threat_score = 0
            threat_score += len(risk_factors) * 20  # Each risk factor adds 20 points
            threat_score += len(iocs['urls']) * 5   # Each URL adds 5 points
            threat_score += len(iocs['ips']) * 5    # Each IP adds 5 points
            threat_score = min(threat_score, 100)   # Cap at 100
            
            # Extract authentication results
            authentication = {
                'spf': 'pass' if 'spf=pass' in auth_results.lower() else 'fail' if 'spf=fail' in auth_results.lower() else 'neutral',
                'dkim': 'pass' if 'dkim=pass' in auth_results.lower() else 'fail' if 'dkim=fail' in auth_results.lower() else 'neutral',
                'dmarc': 'pass' if 'dmarc=pass' in auth_results.lower() else 'fail' if 'dmarc=fail' in auth_results.lower() else 'neutral'
            }
            
            return EmailAnalysisResult(
                headers=headers,
                body=body,
                attachments=attachments,
                authentication=authentication,
                iocs=iocs,
                threat_score=threat_score,
                risk_factors=risk_factors
            )
        except Exception as e:
            raise Exception(f"Failed to analyze email: {str(e)}")

    def _extract_headers(self, email_message) -> Dict[str, Any]:
        """Extract and normalize email headers"""
        return dict(email_message.items())

    def _extract_body(self, email_message) -> str:
        """Extract email body, handling multipart messages"""
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode()
        return email_message.get_payload(decode=True).decode()

    def _extract_attachments(self, email_message) -> List[Dict[str, Any]]:
        """Extract and analyze attachments"""
        attachments = []
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue

                filename = part.get_filename()
                if filename:
                    content = part.get_payload(decode=True)
                    attachment = {
                        'filename': filename,
                        'size': len(content),
                        'content_type': part.get_content_type(),
                        'md5': hashlib.md5(content).hexdigest(),
                        'sha256': hashlib.sha256(content).hexdigest()
                    }
                    attachments.append(attachment)
        return attachments

    def _extract_iocs(self, headers: Dict[str, Any], body: str) -> Dict[str, List[str]]:
        """Extract IOCs from email content"""
        text_content = str(headers) + body
        return {
            'ips': list(set(self.ip_pattern.findall(text_content))),
            'urls': list(set(self.url_pattern.findall(text_content))),
            'hashes': list(set(self.hash_pattern.findall(text_content)))
        }

    def _check_authentication(self, headers: Dict[str, Any]) -> Dict[str, str]:
        """Check email authentication results"""
        auth_results = {
            'spf': 'neutral',
            'dkim': 'neutral',
            'dmarc': 'neutral'
        }

        # Check Authentication-Results header
        auth_header = headers.get('Authentication-Results', '')
        
        if 'spf=pass' in auth_header.lower():
            auth_results['spf'] = 'pass'
        elif 'spf=fail' in auth_header.lower():
            auth_results['spf'] = 'fail'

        if 'dkim=pass' in auth_header.lower():
            auth_results['dkim'] = 'pass'
        elif 'dkim=fail' in auth_header.lower():
            auth_results['dkim'] = 'fail'

        if 'dmarc=pass' in auth_header.lower():
            auth_results['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_header.lower():
            auth_results['dmarc'] = 'fail'

        return auth_results

    def _assess_risks(self, headers: Dict[str, Any], body: str, 
                     attachments: List[Dict[str, Any]], 
                     iocs: Dict[str, List[str]]) -> List[str]:
        """Assess email for potential risks"""
        risks = []

        # Check authentication
        auth_results = self._check_authentication(headers)
        if 'fail' in auth_results.values():
            risks.append('Email authentication failure detected')

        # Check for suspicious patterns
        suspicious_patterns = [
            'urgent', 'password', 'account', 'suspended', 'verify',
            'banking', 'security', 'update required', 'click here'
        ]
        
        body_lower = body.lower()
        for pattern in suspicious_patterns:
            if pattern in body_lower:
                risks.append(f'Suspicious keyword detected: {pattern}')

        # Check attachments
        suspicious_extensions = ['.exe', '.bat', '.ps1', '.vbs', '.js']
        for attachment in attachments:
            filename = attachment['filename'].lower()
            if any(filename.endswith(ext) for ext in suspicious_extensions):
                risks.append(f'Suspicious attachment type: {attachment["filename"]}')

        # Check for excessive IOCs
        if len(iocs['urls']) > 5:
            risks.append('Multiple URLs detected')
        if len(iocs['ips']) > 3:
            risks.append('Multiple IP addresses detected')

        return risks

    def _calculate_threat_score(self, auth_results: Dict[str, str], 
                              iocs: Dict[str, List[str]], 
                              risk_factors: List[str]) -> int:
        """Calculate overall threat score"""
        score = 0

        # Authentication scoring
        auth_score = sum(result == 'fail' for result in auth_results.values()) * 20
        score += auth_score

        # IOC scoring
        ioc_score = (len(iocs['ips']) * 5 + 
                    len(iocs['urls']) * 5 + 
                    len(iocs['hashes']) * 5)
        score += min(ioc_score, 30)  # Cap at 30

        # Risk factor scoring
        score += len(risk_factors) * 10

        return min(score, 100)  # Cap at 100
