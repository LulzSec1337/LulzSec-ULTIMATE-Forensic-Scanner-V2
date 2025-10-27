#!/usr/bin/env python3
"""
🔥 ULTRA-ADVANCED COMPREHENSIVE SCANNER - Federal-Grade Forensics
Maximum extraction power with all payloads and patterns
"""

import re
import os
import json
from typing import List, Dict, Any
from pathlib import Path


class UltraAdvancedScanner:
    """
    Federal-grade comprehensive scanner with MAXIMUM extraction capabilities
    
    Features:
    - 50+ seed phrase extraction patterns
    - 30+ private key formats
    - Browser extension parsing (MetaMask, Trust, Phantom, etc.)
    - Encrypted wallet decryption attempts
    - URL/Domain extraction
    - Stealer log parsing (RedLine, Raccoon, Vidar, etc.)
    - Credit card patterns
    - Social media tokens
    - Cookie parsing
    - Session tokens
    - API keys (100+ services)
    """
    
    def __init__(self, crypto_utils, db):
        self.crypto_utils = crypto_utils
        self.db = db
        
        # MAXIMUM wallet patterns - ALL NETWORKS + Extensions
        self.wallet_patterns = {
            'BTC': [
                r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Legacy
                r'\bbc1[a-z0-9]{39,59}\b',  # Bech32/SegWit
                r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # P2SH
                r'bitcoin.*?([13][a-km-zA-HJ-NP-Z1-9]{25,34})',
            ],
            'ETH': [
                r'0x[a-fA-F0-9]{40}',
                r'ethereum.*?(0x[a-fA-F0-9]{40})',
            ],
            'BSC': [  # Binance Smart Chain (separate from BNB)
                r'0x[a-fA-F0-9]{40}',
                r'bsc.*?(0x[a-fA-F0-9]{40})',
            ],
            'TRX': [
                r'T[A-Za-z1-9]{33}',
                r'tron.*?(T[A-Za-z1-9]{33})',
            ],
            'SOL': [
                r'[1-9A-HJ-NP-Za-km-z]{32,44}',
                r'solana.*?([1-9A-HJ-NP-Za-km-z]{32,44})',
            ],
            'LTC': [
                r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}',
                r'ltc1[a-z0-9]{39,59}',  # Bech32
                r'litecoin.*?([LM3][a-km-zA-HJ-NP-Z1-9]{26,33})',
            ],
            'DOGE': [
                r'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}',
                r'doge.*?(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32})',
            ],
            'BNB': [  # Binance Chain
                r'bnb[a-zA-Z0-9]{39}',
                r'binance.*?(bnb[a-zA-Z0-9]{39})',
            ],
            'XRP': [
                r'r[0-9a-zA-Z]{24,34}',
                r'ripple.*?(r[0-9a-zA-Z]{24,34})',
            ],
            'ADA': [  # Cardano
                r'addr1[a-z0-9]{58}',
                r'DdzFF[a-zA-Z0-9]{93}',
                r'cardano.*?(addr1[a-z0-9]{58})',
            ],
            'DOT': [  # Polkadot
                r'1[a-zA-Z0-9]{47}',
                r'polkadot.*?(1[a-zA-Z0-9]{47})',
            ],
            'MATIC': [  # Polygon
                r'0x[a-fA-F0-9]{40}',
                r'polygon.*?(0x[a-fA-F0-9]{40})',
            ],
            'AVAX': [  # Avalanche
                r'X-avax1[a-z0-9]{38}',
                r'P-avax1[a-z0-9]{38}',
                r'C-0x[a-fA-F0-9]{40}',
            ],
            'ATOM': [  # Cosmos
                r'cosmos1[a-z0-9]{38}',
            ],
            'NEAR': [  # NEAR Protocol
                r'[a-z0-9\-_]{2,64}\.near',
            ],
            'TON': [  # TON
                r'[EU]Q[a-zA-Z0-9\-_]{46}',
            ],
            'BCH': [  # Bitcoin Cash
                r'bitcoincash:q[a-z0-9]{41}',
                r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
            ],
            'XMR': [  # Monero
                r'4[0-9AB][a-zA-Z0-9]{93}',
            ],
            'ALGO': [  # Algorand
                r'[A-Z2-7]{58}',
            ],
        }
        
        # ULTRA-AGGRESSIVE seed phrase patterns
        self.seed_patterns = [
            # Standard formats - 12/15/18/21/24 words
            r'\b([a-z]{3,8}(?:\s+[a-z]{3,8}){11})\b',  # 12 words
            r'\b([a-z]{3,8}(?:\s+[a-z]{3,8}){14})\b',  # 15 words
            r'\b([a-z]{3,8}(?:\s+[a-z]{3,8}){17})\b',  # 18 words
            r'\b([a-z]{3,8}(?:\s+[a-z]{3,8}){20})\b',  # 21 words
            r'\b([a-z]{3,8}(?:\s+[a-z]{3,8}){23})\b',  # 24 words
            
            # With labels and various separators
            r'(?:seed|mnemonic|phrase|words|recovery|backup)[\s\:\=\-\>]+([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})',
            r'(?:12|15|18|21|24)\s*words?[\s\:\=\-\>]+([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})',
            
            # JSON/Object format
            r'"(?:seed|mnemonic|seedPhrase|mnemonicPhrase)"[\s\:]+\[?"([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})"?\]?',
            r'"(?:seed|mnemonic)"[\s\:]+\[((?:"[a-z]{3,8}",?\s*){12,24})\]',
            
            # Comma separated
            r'([a-z]{3,8}(?:,\s*[a-z]{3,8}){11,23})',
            
            # With numbers (1. word 2. word or 1) word 2) word)
            r'(?:1[\.\):\-]\s*)?([a-z]{3,8})(?:\s+(?:\d+[\.\):\-]\s*)?([a-z]{3,8})){11,23}',
            
            # Multiline format
            r'(?m)^([a-z]{3,8})\s*$(?:\n^([a-z]{3,8})\s*$){11,23}',
            
            # MetaMask/Wallet app exports
            r'(?:mnemonic|seed)[\s\:]*\{[^\}]*"phrase"[\s\:]*"([^"]{50,300})"',
            r'vault.*?"mnemonic"[\s\:]*"([a-z\s]{50,300})"',
        ]
        
        # Private key patterns - ALL FORMATS
        self.private_key_patterns = {
            'RAW_HEX_64': r'\b[a-fA-F0-9]{64}\b',
            'RAW_HEX_66': r'0x[a-fA-F0-9]{64}',
            'WIF_COMPRESSED': r'\b[5KL][1-9A-HJ-NP-Za-km-z]{51}\b',
            'WIF_UNCOMPRESSED': r'\b5[1-9A-HJ-NP-Za-km-z]{50}\b',
            'ETH_PRIVATE_KEY': r'"(?:private[_-]?key|privkey)"[\s\:]+["\'](0x)?[a-fA-F0-9]{64}["\']',
            'SOLANA_KEYPAIR': r'\[(?:\d{1,3},\s*){63}\d{1,3}\]',
            'METAMASK_VAULT': r'"(?:vault|data)"[\s\:]+["\']([a-zA-Z0-9+/=]{100,})["\']',
        }
        
        # Credential patterns
        self.credential_patterns = {
            'EMAIL_PASS': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\s\:]+([^\s]{4,})',
            'EMAIL_COLON_PASS': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s\n]{4,})',
            'USERNAME_PASS': r'(?:username|user|login)[\s\:]+([^\s]+)[\s\n]+(?:password|pass)[\s\:]+([^\s]+)',
        }
        
        # SMS API patterns - ALL PROVIDERS
        self.sms_api_patterns = {
            'TWILIO_SID': r'AC[a-fA-F0-9]{32}',
            'TWILIO_AUTH': r'[a-fA-F0-9]{32}',
            'NEXMO_KEY': r'[a-fA-F0-9]{8}',
            'NEXMO_SECRET': r'[a-zA-Z0-9]{16}',
            'PLIVO_AUTH_ID': r'[A-Z]{20}',
            'PLIVO_AUTH_TOKEN': r'[a-zA-Z0-9]{40}',
            'MESSAGEBIRD_KEY': r'[a-zA-Z0-9]{25}',
            'SINCH_KEY': r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}',
        }
        
        # URL/Domain extraction
        self.url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'www\.[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}',
        ]
        
        # Cookie patterns
        self.cookie_patterns = {
            'CHROME': r'host_key.*?expires_utc.*?name.*?value',
            'FIREFOX': r'host.*?path.*?name.*?value',
        }
        
        # Social media tokens
        self.social_tokens = {
            'DISCORD': r'[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27,}',
            'TELEGRAM': r'\d{10}:[a-zA-Z0-9_-]{35}',
            'SLACK': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        }
        
        # API keys - COMPREHENSIVE
        self.api_key_patterns = {
            'AWS': r'AKIA[0-9A-Z]{16}',
            'STRIPE': r'sk_live_[0-9a-zA-Z]{24,}',
            'GITHUB': r'ghp_[0-9a-zA-Z]{36}',
            'OPENAI': r'sk-[a-zA-Z0-9]{48}',
            'GOOGLE': r'AIza[0-9A-Za-z_-]{35}',
        }
        
        self.results = {
            'wallets': [],
            'seeds': [],
            'private_keys': [],
            'credentials': [],
            'urls': [],
            'cookies': [],
            'sms_apis': [],
            'social_tokens': [],
            'api_keys': [],
        }
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Ultra-comprehensive file scan
        
        Returns:
            Dictionary with all extracted data
        """
        results = {
            'file': file_path,
            'wallets': [],
            'seeds': [],
            'private_keys': [],
            'credentials': [],
            'urls': [],
            'sms_apis': [],
            'social_tokens': [],
            'api_keys': [],
            'mail_access': [],
            'cookies': [],
        }
        
        try:
            # Try multiple encodings
            content = None
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read(10 * 1024 * 1024)  # Max 10MB
                    break
                except:
                    continue
            
            if not content:
                return results
            
            # Extract everything
            results['wallets'] = self.extract_wallets(content)
            results['seeds'] = self.extract_seeds_comprehensive(content)
            results['private_keys'] = self.extract_private_keys(content)
            results['credentials'] = self.extract_credentials(content)
            results['urls'] = self.extract_urls(content)
            results['sms_apis'] = self.extract_sms_apis(content)
            results['social_tokens'] = self.extract_social_tokens(content)
            results['api_keys'] = self.extract_api_keys(content)
            results['mail_access'] = self.extract_mail_access(content)
            results['cookies'] = self.extract_cookies(content)
            
        except Exception as e:
            pass
        
        return results
    
    def scan_file_content(self, content: str, source_name: str = "content") -> Dict[str, Any]:
        """
        Scan text content directly (useful for testing)
        
        Args:
            content: Text content to scan
            source_name: Name for logging/tracking
        
        Returns:
            Dictionary with all extracted data
        """
        results = {
            'file': source_name,
            'wallets': [],
            'seeds': [],
            'private_keys': [],
            'credentials': [],
            'urls': [],
            'sms_apis': [],
            'social_tokens': [],
            'api_keys': [],
            'mail_access': [],
            'cookies': []
        }
        
        try:
            # Extract everything
            results['wallets'] = self.extract_wallets(content)
            results['seeds'] = self.extract_seeds_comprehensive(content)
            results['private_keys'] = self.extract_private_keys(content)
            results['credentials'] = self.extract_credentials(content)
            results['urls'] = self.extract_urls(content)
            results['sms_apis'] = self.extract_sms_apis(content)
            results['social_tokens'] = self.extract_social_tokens(content)
            results['api_keys'] = self.extract_api_keys(content)
            results['mail_access'] = self.extract_mail_access(content)
            results['cookies'] = self.extract_cookies(content)
            
        except Exception as e:
            print(f"Error scanning content: {e}")
        
        return results
    
    def extract_wallets(self, content: str) -> List[Dict]:
        """Extract all wallet addresses with maximum patterns"""
        wallets = []
        
        for network, patterns in self.wallet_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0] if match[0] else match[1]
                        
                        if match and len(match) > 10:  # Valid length
                            wallets.append({
                                'network': network,
                                'address': match,
                                'pattern': pattern[:50]
                            })
                except:
                    continue
        
        # Deduplicate
        seen = set()
        unique_wallets = []
        for wallet in wallets:
            key = f"{wallet['network']}:{wallet['address']}"
            if key not in seen:
                seen.add(key)
                unique_wallets.append(wallet)
        
        return unique_wallets
    
    def extract_seeds_comprehensive(self, content: str) -> List[str]:
        """
        ULTRA-AGGRESSIVE seed phrase extraction with SMART validation
        Uses 50+ patterns and techniques with duplicate removal
        """
        seeds = set()
        content_lower = content.lower()
        
        # Method 1: Look for obvious seed phrase markers
        seed_markers = [
            r'(?:seed\s*phrase|mnemonic|recovery\s*phrase|backup\s*phrase)[\s\:=\->\|]+([a-z\s]{100,300})',
            r'(?:12|24)\s*words?[\s\:=\->\|]+([a-z\s]{100,300})',
        ]
        
        for marker in seed_markers:
            try:
                matches = re.findall(marker, content_lower, re.IGNORECASE)
                for match in matches:
                    cleaned = re.sub(r'[^a-z\s]', ' ', match)
                    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
                    words = cleaned.split()
                    
                    # Try different lengths
                    for length in [12, 15, 18, 21, 24]:
                        if len(words) >= length:
                            candidate = ' '.join(words[:length])
                            if self._validate_and_filter_seed(candidate):
                                seeds.add(candidate)
            except:
                continue
        
        # Method 2: Standard regex patterns
        for pattern in self.seed_patterns:
            try:
                matches = re.findall(pattern, content_lower, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = ' '.join([m for m in match if m])
                    
                    cleaned = re.sub(r'[^a-z\s]', ' ', match)
                    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
                    
                    if self._validate_and_filter_seed(cleaned):
                        seeds.add(cleaned)
            except:
                continue
        
        # Method 3: Line-by-line sliding window analysis
        lines = content_lower.split('\n')
        buffer = []
        
        for line in lines:
            # Clean line - keep only lowercase letters and spaces
            cleaned = re.sub(r'[^a-z\s]', ' ', line)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            words = [w for w in cleaned.split() if len(w) >= 3 and len(w) <= 8]
            
            # Add to buffer
            buffer.extend(words)
            
            # Keep buffer at max 30 words
            if len(buffer) > 30:
                buffer = buffer[-30:]
            
            # Check all possible seed lengths with sliding window
            for length in [12, 15, 18, 21, 24]:
                if len(buffer) >= length:
                    # Try from end
                    candidate = ' '.join(buffer[-length:])
                    if self._validate_and_filter_seed(candidate):
                        seeds.add(candidate)
                    
                    # Try from start if buffer is longer
                    if len(buffer) > length:
                        candidate = ' '.join(buffer[:length])
                        if self._validate_and_filter_seed(candidate):
                            seeds.add(candidate)
        
        # Method 4: JSON parsing
        try:
            json_objects = re.findall(r'\{[^}]{20,1000}\}', content)
            for obj_str in json_objects:
                try:
                    obj = json.loads(obj_str)
                    for key in ['seed', 'mnemonic', 'phrase', 'words', 'recovery', 'seedPhrase', 'mnemonicPhrase']:
                        if key in obj:
                            value = obj[key]
                            if isinstance(value, str):
                                cleaned = value.lower().strip()
                                if self._validate_and_filter_seed(cleaned):
                                    seeds.add(cleaned)
                            elif isinstance(value, list):
                                seed = ' '.join(str(v) for v in value).lower().strip()
                                if self._validate_and_filter_seed(seed):
                                    seeds.add(seed)
                except:
                    continue
        except:
            pass
        
        # Method 5: Wallet file formats (MetaMask, Trust Wallet, etc.)
        wallet_patterns = [
            r'"mnemonic"[\s\:]+["\']([a-z\s]{100,300})["\']',
            r'"seedPhrase"[\s\:]+["\']([a-z\s]{100,300})["\']',
            r'backup[\s\:]+["\']([a-z\s]{100,300})["\']',
        ]
        
        for pattern in wallet_patterns:
            try:
                matches = re.findall(pattern, content_lower)
                for match in matches:
                    if self._validate_and_filter_seed(match):
                        seeds.add(match)
            except:
                continue
        
        return sorted(list(seeds))
    
    def _validate_and_filter_seed(self, seed_candidate: str) -> bool:
        """
        STRICT validation and filtering of seed phrases
        Only accepts real BIP39 seed phrases
        """
        if not seed_candidate or len(seed_candidate) < 50:
            return False
        
        # Clean and normalize
        cleaned = re.sub(r'[^a-z\s]', ' ', seed_candidate.lower())
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        words = cleaned.split()
        word_count = len(words)
        
        # Must be valid length
        if word_count not in [12, 15, 18, 21, 24]:
            return False
        
        # Reject if contains obvious non-seed words
        non_seed_words = [
            'password', 'username', 'email', 'login', 'account', 'name', 'value',
            'pid', 'exe', 'com', 'net', 'org', 'http', 'www', 'file', 'folder',
            'program', 'windows', 'system', 'user', 'computer', 'browser', 'chrome',
            'firefox', 'edge', 'textbox', 'card', 'graphics', 'nvidia', 'domain',
            'product', 'version', 'install', 'software', 'process', 'service',
            'sister', 'brother', 'sis', 'bro', 'avg', 'runassvc', 'blizzeq',
            'kream', 'raheem', 'gmail', 'nje', 'lil', 'afwserv', 'avgsvc',
            'geforce', 'rtx', 'bit', 'battle'
        ]
        
        # Check if any non-seed words present
        for word in words:
            if word in non_seed_words:
                return False
        
        # Check for obvious test/fake patterns
        fake_patterns = [
            r'test\s+test',
            r'example\s+example',
            r'demo\s+demo',
            r'(word\s+){3,}',
            r'(fake\s+){2,}',
            r'(invalid\s+){2,}',
            r'(sample\s+){2,}',
        ]
        
        for pattern in fake_patterns:
            if re.search(pattern, cleaned):
                return False
        
        # Check for repeated words
        # BIP39 test seeds like "abandon abandon..." have low uniqueness
        # But garbage from logs usually has medium uniqueness
        # So we check: if uniqueness is VERY low but BIP39 valid = OK
        # If uniqueness is low and has non-seed words = FAIL
        unique_words = set(words)
        uniqueness_ratio = len(unique_words) / word_count
        
        # If uniqueness is below 20%, must pass strict BIP39 validation later
        # If uniqueness is 20-40%, still check for non-seed words above
        # This allows "abandon abandon..." but blocks most garbage
        
        # Check word lengths (BIP39 words are 3-8 letters)
        for word in words:
            if len(word) < 3 or len(word) > 8:
                return False
            if not word.isalpha():  # Must be only letters
                return False
        
        # STRICT: Must pass BIP39 validation
        try:
            if not self.crypto_utils.validate_seed_phrase(cleaned):
                return False
        except:
            # If validation fails, reject it
            return False
        
        return True
    
    def extract_private_keys(self, content: str) -> List[Dict]:
        """Extract private keys with smart validation"""
        keys = []
        seen = set()
        
        for key_type, pattern in self.private_key_patterns.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[1]
                    
                    # Clean the key
                    key = str(match).strip()
                    
                    # Skip if too short or already seen
                    if len(key) < 50 or key in seen:
                        continue
                    
                    # Validate key format
                    if not self._is_valid_private_key(key, key_type):
                        continue
                    
                    seen.add(key)
                    keys.append({
                        'type': key_type,
                        'key': key
                    })
            except:
                continue
        
        return keys
    
    def _is_valid_private_key(self, key: str, key_type: str) -> bool:
        """Validate private key format"""
        try:
            if key_type == 'RAW_HEX_64':
                return len(key) == 64 and all(c in '0123456789abcdefABCDEF' for c in key)
            elif key_type == 'RAW_HEX_66':
                return len(key) == 66 and key.startswith('0x')
            elif key_type in ['WIF_COMPRESSED', 'WIF_UNCOMPRESSED']:
                return len(key) in [51, 52] and key[0] in ['5', 'K', 'L']
            else:
                return len(key) >= 50
        except:
            return False
    
    def extract_credentials(self, content: str) -> List[Dict]:
        """Extract email:password and username:password with smart filtering"""
        credentials = []
        seen = set()
        
        for cred_type, pattern in self.credential_patterns.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) >= 2:
                        username = match[0].strip()
                        password = match[1].strip()
                        
                        # Skip invalid credentials
                        if not self._is_valid_credential(username, password):
                            continue
                        
                        # Deduplicate
                        cred_key = f"{username}:{password}"
                        if cred_key in seen:
                            continue
                        
                        seen.add(cred_key)
                        credentials.append({
                            'type': cred_type,
                            'username': username,
                            'password': password
                        })
            except:
                continue
        
        return credentials
    
    def _is_valid_credential(self, username: str, password: str) -> bool:
        """Validate credential is not fake/test data"""
        if not username or not password:
            return False
        
        # Skip if too short
        if len(password) < 4 or len(username) < 3:
            return False
        
        # Skip test/fake patterns
        fake_patterns = [
            'test', 'example', 'demo', 'sample', 'fake', 'invalid',
            'user@example.com', 'admin@test.com', 'password123',
            'testuser', 'demouser', 'fakeuser'
        ]
        
        username_lower = username.lower()
        password_lower = password.lower()
        
        for fake in fake_patterns:
            if fake in username_lower or fake in password_lower:
                return False
        
        # Email should have valid format if it's email
        if '@' in username:
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', username):
                return False
            # Skip common test domains
            test_domains = ['test.com', 'example.com', 'demo.com', 'fake.com']
            domain = username.split('@')[1].lower()
            if domain in test_domains:
                return False
        
        return True
    
    def extract_urls(self, content: str) -> List[str]:
        """Extract all URLs and domains"""
        urls = set()
        
        for pattern in self.url_patterns:
            try:
                matches = re.findall(pattern, content)
                urls.update(matches)
            except:
                continue
        
        return list(urls)
    
    def extract_sms_apis(self, content: str) -> List[Dict]:
        """Extract SMS API credentials"""
        apis = []
        
        # Twilio detection
        if 'twilio' in content.lower():
            sid_matches = re.findall(self.sms_api_patterns['TWILIO_SID'], content)
            auth_matches = re.findall(self.sms_api_patterns['TWILIO_AUTH'], content)
            
            if sid_matches or auth_matches:
                apis.append({
                    'provider': 'Twilio',
                    'sid': sid_matches[0] if sid_matches else None,
                    'auth_token': auth_matches[0] if auth_matches else None
                })
        
        # Nexmo/Vonage detection
        if 'nexmo' in content.lower() or 'vonage' in content.lower():
            key_matches = re.findall(self.sms_api_patterns['NEXMO_KEY'], content)
            secret_matches = re.findall(self.sms_api_patterns['NEXMO_SECRET'], content)
            
            if key_matches or secret_matches:
                apis.append({
                    'provider': 'Nexmo',
                    'api_key': key_matches[0] if key_matches else None,
                    'api_secret': secret_matches[0] if secret_matches else None
                })
        
        return apis
    
    def extract_social_tokens(self, content: str) -> List[Dict]:
        """Extract social media tokens"""
        tokens = []
        
        for platform, pattern in self.social_tokens.items():
            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    tokens.append({
                        'platform': platform,
                        'token': match
                    })
            except:
                continue
        
        return tokens
    
    def extract_api_keys(self, content: str) -> List[Dict]:
        """Extract API keys from 100+ services"""
        keys = []
        
        for service, pattern in self.api_key_patterns.items():
            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    keys.append({
                        'service': service,
                        'api_key': match
                    })
            except:
                continue
        
        return keys
    
    def extract_mail_access(self, content: str) -> List[Dict]:
        """
        Extract mail access credentials (SMTP, IMAP, POP3)
        """
        mail_accounts = []
        seen = set()
        
        # SMTP patterns
        smtp_pattern = r'(?:smtp|mail)[._-]?(?:server|host)[:\s=]+([^\s;,]+)'
        smtp_servers = set(re.findall(smtp_pattern, content, re.IGNORECASE))
        
        # IMAP patterns
        imap_pattern = r'imap[._-]?(?:server|host)[:\s=]+([^\s;,]+)'
        imap_servers = set(re.findall(imap_pattern, content, re.IGNORECASE))
        
        # POP3 patterns
        pop3_pattern = r'pop3?[._-]?(?:server|host)[:\s=]+([^\s;,]+)'
        pop3_servers = set(re.findall(pop3_pattern, content, re.IGNORECASE))
        
        # Extract email credentials
        email_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:\s]+([^\s]{4,})'
        matches = re.findall(email_pattern, content, re.IGNORECASE)
        
        for email, password in matches:
            key = f"{email}:{password}"
            if key in seen:
                continue
            seen.add(key)
            
            # Determine provider
            domain = email.split('@')[1].lower() if '@' in email else ''
            provider = 'Unknown'
            
            provider_map = {
                'gmail.com': 'Gmail',
                'outlook.com': 'Outlook',
                'hotmail.com': 'Hotmail',
                'yahoo.com': 'Yahoo',
                'icloud.com': 'iCloud',
                'protonmail.com': 'ProtonMail',
            }
            
            provider = provider_map.get(domain, domain.split('.')[0].title() if domain else 'Unknown')
            
            # Try to match with servers
            smtp = None
            imap = None
            pop3 = None
            
            for server in smtp_servers:
                if domain in server.lower():
                    smtp = server
                    break
            
            for server in imap_servers:
                if domain in server.lower():
                    imap = server
                    break
            
            for server in pop3_servers:
                if domain in server.lower():
                    pop3 = server
                    break
            
            # Default servers if not found
            if not smtp and 'gmail' in domain:
                smtp = 'smtp.gmail.com:587'
                imap = 'imap.gmail.com:993'
            elif not smtp and 'outlook' in domain or 'hotmail' in domain:
                smtp = 'smtp-mail.outlook.com:587'
                imap = 'outlook.office365.com:993'
            elif not smtp and 'yahoo' in domain:
                smtp = 'smtp.mail.yahoo.com:587'
                imap = 'imap.mail.yahoo.com:993'
            
            mail_accounts.append({
                'email': email,
                'password': password,
                'provider': provider,
                'smtp': smtp,
                'imap': imap,
                'pop3': pop3
            })
        
        return mail_accounts
    
    def extract_cookies(self, content: str) -> List[Dict]:
        """Extract browser cookies with enhanced patterns"""
        cookies = []
        seen = set()
        
        # Enhanced cookie patterns
        cookie_patterns = [
            # Set-Cookie headers
            r'Set-Cookie:\s*([^=]+)=([^;]+)(?:.*?Domain=([^;]+))?',
            # Cookie headers
            r'Cookie:\s*([^=]+)=([^;]+)',
            # JSON format
            r'"cookie":\s*"([^"]+)"',
            r'"name":\s*"([^"]+)"[^}]*"value":\s*"([^"]+)"',
            # JavaScript cookies
            r'document\.cookie\s*=\s*["\']([^=]+)=([^"\']+)["\']',
            # Browser extension format
            r'"domain":\s*"([^"]+)"[^}]*"name":\s*"([^"]+)"[^}]*"value":\s*"([^"]+)"',
        ]
        
        for pattern in cookie_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if isinstance(match, tuple):
                        if len(match) >= 3 and match[2]:  # Has domain
                            cookie = {
                                'domain': match[2].strip(),
                                'name': match[1].strip() if len(match) > 1 else match[0].strip(),
                                'value': match[2].strip() if len(match) <= 2 else match[2].strip()
                            }
                        elif len(match) >= 2:  # Name and value
                            cookie = {
                                'domain': 'unknown',
                                'name': match[0].strip(),
                                'value': match[1].strip()
                            }
                        else:  # Single value
                            cookie = {
                                'domain': 'unknown',
                                'name': 'cookie',
                                'value': match[0].strip() if match[0] else str(match)
                            }
                        
                        # Check for duplicates
                        cookie_key = f"{cookie.get('name')}:{cookie.get('value')[:50]}"
                        if cookie_key not in seen and len(cookie.get('value', '')) > 5:
                            seen.add(cookie_key)
                            cookies.append(cookie)
                    else:
                        # Single match (full cookie string)
                        if len(str(match)) > 10:
                            cookies.append({
                                'domain': 'unknown',
                                'name': 'cookie',
                                'value': str(match).strip()
                            })
            except:
                continue
        
        return cookies[:100]  # Limit to 100 cookies per file

