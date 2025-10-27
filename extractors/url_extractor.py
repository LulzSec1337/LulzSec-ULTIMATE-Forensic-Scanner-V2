#!/usr/bin/env python3
"""
🔗 ADVANCED URL & ACCESS EXTRACTOR - Federal-Grade Intelligence
Extract URLs, domains, credentials with domains, and access information
"""

import re
import json
from typing import List, Dict, Any
from urllib.parse import urlparse
from collections import defaultdict


class AdvancedURLExtractor:
    """
    Advanced URL and domain access extractor
    
    Features:
    - URL extraction with context
    - Domain-specific credential linking
    - Browser history parsing
    - Bookmark extraction
    - Login panel detection
    - API endpoint discovery
    - Subdomain enumeration
    """
    
    def __init__(self):
        # Comprehensive URL patterns
        self.url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'(?:https?://)?(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(?:/[^\s]*)?',
        ]
        
        # Domain patterns
        self.domain_patterns = {
            'CRYPTO_EXCHANGE': [
                r'(?:www\.)?(binance|coinbase|kraken|bitfinex|huobi|okex|kucoin|gate\.io|bybit|ftx|gemini|crypto\.com)\.com',
                r'(?:www\.)?(bittrex|poloniex|bitmart|mexc|lbank)\.com',
            ],
            'WALLET_SERVICE': [
                r'(?:www\.)?(blockchain|metamask|trustwallet|exodus|electrum)\.(?:com|io)',
                r'(?:www\.)?(myetherwallet|mycrypto)\.com',
            ],
            'EMAIL_SERVICE': [
                r'(?:www\.)?(gmail|outlook|yahoo|protonmail|tutanota|mailbox)\.com',
                r'mail\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}',
            ],
            'SOCIAL_MEDIA': [
                r'(?:www\.)?(facebook|twitter|instagram|linkedin|reddit|discord|telegram)\.(?:com|org)',
                r'(?:www\.)?(tiktok|snapchat|whatsapp)\.com',
            ],
            'CLOUD_STORAGE': [
                r'(?:www\.)?(dropbox|drive\.google|onedrive|mega|pcloud)\.(?:com|nz)',
                r'(?:www\.)?(icloud|box)\.com',
            ],
            'PAYMENT': [
                r'(?:www\.)?(paypal|stripe|square|venmo|cashapp)\.(?:com|me)',
            ],
        }
        
        # Login page indicators
        self.login_indicators = [
            'login', 'signin', 'sign-in', 'log-in',
            'auth', 'authenticate', 'session',
            'account', 'user', 'password'
        ]
        
        # API endpoint patterns
        self.api_patterns = [
            r'https?://[^/]+/api/[^\s]+',
            r'https?://api\.[^/]+/[^\s]+',
            r'https?://[^/]+/v\d+/[^\s]+',
        ]
        
        self.results = {
            'urls': [],
            'domains': defaultdict(list),
            'credentials_with_domains': [],
            'api_endpoints': [],
            'login_pages': [],
        }
    
    def extract_all(self, content: str, source_file: str = "") -> Dict[str, Any]:
        """
        Extract all URL-related information from content
        
        Returns:
            Dictionary with URLs, domains, credentials, etc.
        """
        result = {
            'urls': self.extract_urls(content),
            'domains': self.categorize_domains(content),
            'credentials_with_domains': self.link_credentials_to_domains(content),
            'api_endpoints': self.extract_api_endpoints(content),
            'login_pages': self.find_login_pages(content),
            'browser_data': self.parse_browser_data(content),
            'source_file': source_file
        }
        
        return result
    
    def extract_urls(self, content: str) -> List[str]:
        """Extract all URLs from content"""
        urls = set()
        
        for pattern in self.url_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Clean URL
                    url = match.strip('.,;:\'\"()[]{}')
                    if len(url) > 10 and '.' in url:
                        urls.add(url)
            except:
                continue
        
        return sorted(list(urls))
    
    def categorize_domains(self, content: str) -> Dict[str, List[str]]:
        """Categorize domains by type"""
        categorized = defaultdict(list)
        
        for category, patterns in self.domain_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if match:
                            categorized[category].append(match)
                except:
                    continue
        
        # Deduplicate
        for category in categorized:
            categorized[category] = sorted(list(set(categorized[category])))
        
        return dict(categorized)
    
    def link_credentials_to_domains(self, content: str) -> List[Dict]:
        """
        Link credentials to specific domains/URLs
        Useful for targeted access
        """
        credentials_with_urls = []
        
        # Extract credentials
        cred_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:\s]+([^\s]{4,})'
        credentials = re.findall(cred_pattern, content)
        
        # Extract URLs
        urls = self.extract_urls(content)
        
        # Try to match credentials near URLs
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Check if line has URL
            url_match = None
            for url in urls:
                if url in line:
                    url_match = url
                    break
            
            if url_match:
                # Look for credentials in nearby lines (±5 lines)
                for offset in range(-5, 6):
                    idx = i + offset
                    if 0 <= idx < len(lines):
                        cred_matches = re.findall(cred_pattern, lines[idx])
                        for email, password in cred_matches:
                            credentials_with_urls.append({
                                'url': url_match,
                                'domain': urlparse(url_match).netloc,
                                'email': email,
                                'password': password,
                                'context': line.strip()[:100]
                            })
        
        # Also match by domain in email
        for email, password in credentials:
            email_domain = email.split('@')[1] if '@' in email else ''
            for url in urls:
                url_domain = urlparse(url).netloc
                if email_domain in url_domain or url_domain in email_domain:
                    credentials_with_urls.append({
                        'url': url,
                        'domain': url_domain,
                        'email': email,
                        'password': password,
                        'match_type': 'domain_match'
                    })
        
        return credentials_with_urls
    
    def extract_api_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints"""
        endpoints = set()
        
        for pattern in self.api_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                endpoints.update(matches)
            except:
                continue
        
        return sorted(list(endpoints))
    
    def find_login_pages(self, content: str) -> List[Dict]:
        """Find login/authentication pages"""
        login_pages = []
        
        urls = self.extract_urls(content)
        
        for url in urls:
            url_lower = url.lower()
            for indicator in self.login_indicators:
                if indicator in url_lower:
                    login_pages.append({
                        'url': url,
                        'type': 'login_page',
                        'indicator': indicator
                    })
                    break
        
        return login_pages
    
    def parse_browser_data(self, content: str) -> Dict:
        """
        Parse browser history, bookmarks, and saved logins
        """
        browser_data = {
            'history': [],
            'bookmarks': [],
            'saved_logins': []
        }
        
        # Chrome/Firefox history patterns
        history_pattern = r'(?:url|visit|history).*?(https?://[^\s]+)'
        matches = re.findall(history_pattern, content, re.IGNORECASE)
        browser_data['history'] = list(set(matches))[:100]  # Limit
        
        # Bookmark patterns
        bookmark_pattern = r'(?:bookmark|favorite).*?(https?://[^\s]+)'
        matches = re.findall(bookmark_pattern, content, re.IGNORECASE)
        browser_data['bookmarks'] = list(set(matches))[:50]
        
        # Saved login patterns (JSON format)
        try:
            # Try to find JSON objects with login data
            json_pattern = r'\{[^}]*"(?:username|email|user)"[^}]*"password"[^}]*\}'
            json_matches = re.findall(json_pattern, content, re.IGNORECASE)
            
            for json_str in json_matches:
                try:
                    data = json.loads(json_str)
                    if 'username' in data or 'email' in data:
                        browser_data['saved_logins'].append(data)
                except:
                    continue
        except:
            pass
        
        return browser_data
    
    def search_domain(self, content: str, target_domain: str) -> Dict:
        """
        Search for specific domain and return all related data
        
        Args:
            content: Text to search
            target_domain: Domain to search for (e.g., "binance.com")
        
        Returns:
            Dictionary with all data related to target domain
        """
        result = {
            'domain': target_domain,
            'found': False,
            'urls': [],
            'credentials': [],
            'api_endpoints': [],
            'cookies': [],
            'tokens': []
        }
        
        target_lower = target_domain.lower()
        
        # Find all URLs with this domain
        all_urls = self.extract_urls(content)
        for url in all_urls:
            if target_lower in url.lower():
                result['urls'].append(url)
                result['found'] = True
        
        # Find credentials for this domain
        cred_with_domains = self.link_credentials_to_domains(content)
        for cred in cred_with_domains:
            if target_lower in cred.get('domain', '').lower():
                result['credentials'].append(cred)
                result['found'] = True
        
        # Find API endpoints
        endpoints = self.extract_api_endpoints(content)
        for endpoint in endpoints:
            if target_lower in endpoint.lower():
                result['api_endpoints'].append(endpoint)
                result['found'] = True
        
        # Search for cookies
        cookie_pattern = rf'{re.escape(target_domain)}.*?(?:cookie|session|token).*?([a-zA-Z0-9_-]{{20,}})'
        cookies = re.findall(cookie_pattern, content, re.IGNORECASE)
        result['cookies'] = cookies
        if cookies:
            result['found'] = True
        
        # Search for auth tokens
        token_pattern = rf'{re.escape(target_domain)}.*?(?:token|auth|bearer).*?([a-zA-Z0-9_-]{{20,}})'
        tokens = re.findall(token_pattern, content, re.IGNORECASE)
        result['tokens'] = tokens
        if tokens:
            result['found'] = True
        
        return result
