#!/usr/bin/env python3
"""
📧 MAIL ACCESS EXTRACTOR - Federal-Grade Email Intelligence
Extract SMTP, IMAP, POP3, Webmail credentials and configurations
"""

import re
from typing import List, Dict, Any


class MailAccessExtractor:
    """
    Comprehensive mail access extractor
    
    Features:
    - SMTP server detection (Gmail, Outlook, Yahoo, custom)
    - IMAP/POP3 server detection
    - Webmail credentials (OAuth, session tokens)
    - Mail client configuration files
    - Email credential pairing with server info
    """
    
    def __init__(self):
        # Common mail servers
        self.mail_servers = {
            'gmail': {
                'smtp': 'smtp.gmail.com:587',
                'imap': 'imap.gmail.com:993',
                'pop3': 'pop.gmail.com:995'
            },
            'outlook': {
                'smtp': 'smtp-mail.outlook.com:587',
                'imap': 'outlook.office365.com:993',
                'pop3': 'outlook.office365.com:995'
            },
            'yahoo': {
                'smtp': 'smtp.mail.yahoo.com:587',
                'imap': 'imap.mail.yahoo.com:993',
                'pop3': 'pop.mail.yahoo.com:995'
            },
            'hotmail': {
                'smtp': 'smtp-mail.outlook.com:587',
                'imap': 'outlook.office365.com:993',
                'pop3': 'outlook.office365.com:995'
            },
            'aol': {
                'smtp': 'smtp.aol.com:587',
                'imap': 'imap.aol.com:993',
                'pop3': 'pop.aol.com:995'
            },
            'icloud': {
                'smtp': 'smtp.mail.me.com:587',
                'imap': 'imap.mail.me.com:993',
                'pop3': None
            },
            'zoho': {
                'smtp': 'smtp.zoho.com:587',
                'imap': 'imap.zoho.com:993',
                'pop3': 'pop.zoho.com:995'
            },
            'protonmail': {
                'smtp': 'smtp.protonmail.com:587',
                'imap': 'imap.protonmail.com:1143',
                'pop3': None
            }
        }
        
        # SMTP patterns
        self.smtp_patterns = [
            r'smtp[._-]?server[:\s=]+([^\s;,]+)',
            r'smtp[._-]?host[:\s=]+([^\s;,]+)',
            r'smtp[:\s]+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d+)',
            r'smtp\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        ]
        
        # IMAP patterns
        self.imap_patterns = [
            r'imap[._-]?server[:\s=]+([^\s;,]+)',
            r'imap[._-]?host[:\s=]+([^\s;,]+)',
            r'imap[:\s]+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d+)',
            r'imap\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        ]
        
        # POP3 patterns
        self.pop3_patterns = [
            r'pop3?[._-]?server[:\s=]+([^\s;,]+)',
            r'pop3?[._-]?host[:\s=]+([^\s;,]+)',
            r'pop3?[:\s]+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d+)',
            r'pop\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        ]
        
        # Email credential patterns
        self.email_patterns = [
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:\s]+([^\s]{4,})',
            r'email[:\s=]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'username[:\s=]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        ]
        
        # OAuth token patterns
        self.oauth_patterns = [
            r'(?:access_token|accessToken)[:\s=]+["\'"]?([a-zA-Z0-9_-]{20,})["\'"]?',
            r'(?:refresh_token|refreshToken)[:\s=]+["\'"]?([a-zA-Z0-9_-]{20,})["\'"]?',
            r'Bearer\s+([a-zA-Z0-9_-]{20,})',
        ]
    
    def extract_all(self, content: str, source_file: str = "") -> Dict[str, Any]:
        """
        Extract all mail access information
        
        Returns:
            Dictionary with SMTP, IMAP, POP3, credentials, tokens
        """
        result = {
            'smtp_servers': self.extract_smtp_servers(content),
            'imap_servers': self.extract_imap_servers(content),
            'pop3_servers': self.extract_pop3_servers(content),
            'email_credentials': self.extract_email_credentials(content),
            'mail_accounts': self.link_credentials_to_servers(content),
            'oauth_tokens': self.extract_oauth_tokens(content),
            'mail_configs': self.parse_mail_client_configs(content),
            'source_file': source_file
        }
        
        return result
    
    def extract_smtp_servers(self, content: str) -> List[str]:
        """Extract SMTP server addresses"""
        servers = set()
        
        for pattern in self.smtp_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    server = match.strip().strip('"\'').strip(',;')
                    if server and len(server) > 5:
                        servers.add(server)
            except:
                continue
        
        return sorted(list(servers))
    
    def extract_imap_servers(self, content: str) -> List[str]:
        """Extract IMAP server addresses"""
        servers = set()
        
        for pattern in self.imap_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    server = match.strip().strip('"\'').strip(',;')
                    if server and len(server) > 5:
                        servers.add(server)
            except:
                continue
        
        return sorted(list(servers))
    
    def extract_pop3_servers(self, content: str) -> List[str]:
        """Extract POP3 server addresses"""
        servers = set()
        
        for pattern in self.pop3_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    server = match.strip().strip('"\'').strip(',;')
                    if server and len(server) > 5:
                        servers.add(server)
            except:
                continue
        
        return sorted(list(servers))
    
    def extract_email_credentials(self, content: str) -> List[Dict]:
        """Extract email credentials"""
        credentials = []
        seen = set()
        
        # Pattern for email:password
        email_pass_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:\s]+([^\s]{4,})'
        matches = re.findall(email_pass_pattern, content, re.IGNORECASE)
        
        for email, password in matches:
            key = f"{email}:{password}"
            if key not in seen and len(password) >= 4:
                seen.add(key)
                
                # Determine provider
                provider = self._get_mail_provider(email)
                
                credentials.append({
                    'email': email,
                    'password': password,
                    'provider': provider
                })
        
        return credentials
    
    def extract_oauth_tokens(self, content: str) -> List[Dict]:
        """Extract OAuth tokens"""
        tokens = []
        
        for pattern in self.oauth_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) >= 20:
                        tokens.append({
                            'token': match,
                            'type': 'oauth'
                        })
            except:
                continue
        
        return tokens
    
    def link_credentials_to_servers(self, content: str) -> List[Dict]:
        """Link email credentials to detected mail servers"""
        accounts = []
        
        credentials = self.extract_email_credentials(content)
        smtp_servers = self.extract_smtp_servers(content)
        imap_servers = self.extract_imap_servers(content)
        pop3_servers = self.extract_pop3_servers(content)
        
        for cred in credentials:
            email = cred['email']
            provider = cred['provider']
            
            account = {
                'email': email,
                'password': cred['password'],
                'provider': provider,
                'smtp': None,
                'imap': None,
                'pop3': None
            }
            
            # Try to match with detected servers
            email_domain = email.split('@')[1].lower() if '@' in email else ''
            
            for server in smtp_servers:
                if email_domain in server.lower():
                    account['smtp'] = server
                    break
            
            for server in imap_servers:
                if email_domain in server.lower():
                    account['imap'] = server
                    break
            
            for server in pop3_servers:
                if email_domain in server.lower():
                    account['pop3'] = server
                    break
            
            # If no servers detected, use known defaults
            if not account['smtp'] and provider in self.mail_servers:
                account['smtp'] = self.mail_servers[provider]['smtp']
                account['imap'] = self.mail_servers[provider]['imap']
                account['pop3'] = self.mail_servers[provider]['pop3']
            
            accounts.append(account)
        
        return accounts
    
    def parse_mail_client_configs(self, content: str) -> List[Dict]:
        """Parse mail client configuration data"""
        configs = []
        
        # Outlook configuration
        outlook_pattern = r'(?:outlook|office365).*?email[:\s=]+([^\s;,]+).*?password[:\s=]+([^\s;,]+)'
        matches = re.findall(outlook_pattern, content, re.IGNORECASE | re.DOTALL)
        for email, password in matches:
            configs.append({
                'client': 'Outlook',
                'email': email.strip(),
                'password': password.strip()
            })
        
        # Thunderbird configuration
        thunderbird_pattern = r'thunderbird.*?email[:\s=]+([^\s;,]+).*?password[:\s=]+([^\s;,]+)'
        matches = re.findall(thunderbird_pattern, content, re.IGNORECASE | re.DOTALL)
        for email, password in matches:
            configs.append({
                'client': 'Thunderbird',
                'email': email.strip(),
                'password': password.strip()
            })
        
        return configs
    
    def _get_mail_provider(self, email: str) -> str:
        """Determine mail provider from email address"""
        if not email or '@' not in email:
            return 'Unknown'
        
        domain = email.split('@')[1].lower()
        
        provider_map = {
            'gmail.com': 'Gmail',
            'googlemail.com': 'Gmail',
            'outlook.com': 'Outlook',
            'hotmail.com': 'Hotmail',
            'live.com': 'Outlook',
            'yahoo.com': 'Yahoo',
            'ymail.com': 'Yahoo',
            'aol.com': 'AOL',
            'icloud.com': 'iCloud',
            'me.com': 'iCloud',
            'mac.com': 'iCloud',
            'zoho.com': 'Zoho',
            'protonmail.com': 'ProtonMail',
            'pm.me': 'ProtonMail',
        }
        
        return provider_map.get(domain, domain.split('.')[0].title())
