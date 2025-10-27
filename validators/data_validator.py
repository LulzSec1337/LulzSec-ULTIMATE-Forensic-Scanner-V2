#!/usr/bin/env python3
"""
🔒 COMPREHENSIVE DATA VALIDATOR
Strict validation for all data types to eliminate fake/garbage data
"""

import re
from typing import Dict, List, Any


class DataValidator:
    """
    Validates all extracted data to eliminate false positives
    Ensures only real, valid data is displayed in tabs
    """
    
    def __init__(self):
        # Common fake/test/garbage patterns
        self.garbage_patterns = [
            r'example\.com',
            r'test[\s_\-]*(test|data|user)',
            r'(fake|dummy|sample|placeholder)',
            r'localhost',
            r'127\.0\.0\.1',
            r'xxx+',
            r'(qwerty|asdf|1234)',
            r'default[\s_\-]*(password|user)',
        ]
        
        # Non-crypto words (for seed validation - already in scanner)
        self.non_crypto_words = {
            'password', 'username', 'email', 'login', 'account', 'name', 'value',
            'pid', 'exe', 'com', 'net', 'org', 'http', 'www', 'file', 'folder',
            'program', 'windows', 'system', 'user', 'computer', 'browser', 'chrome'
        }
    
    def is_garbage(self, text: str) -> bool:
        """Check if text matches garbage patterns"""
        text_lower = text.lower()
        for pattern in self.garbage_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def validate_wallet_address(self, address: str, network: str) -> bool:
        """
        Strict validation for wallet addresses
        Network-specific checks
        """
        if not address or len(address) < 20:
            return False
        
        # Remove whitespace
        address = address.strip()
        
        # Check for garbage patterns
        if self.is_garbage(address):
            return False
        
        # Network-specific validation
        try:
            if network == 'BTC':
                # Bitcoin addresses
                if address.startswith('1') or address.startswith('3'):
                    # Legacy/P2SH: 25-34 chars, base58
                    if 25 <= len(address) <= 34:
                        # Check base58 charset
                        base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                        return all(c in base58_chars for c in address)
                elif address.startswith('bc1'):
                    # Bech32: 42-62 chars
                    if 39 <= len(address) <= 62:
                        # Check bech32 charset
                        return all(c in 'qpzry9x8gf2tvdw0s3jn54khce6mua7l' or c == '1' for c in address[3:].lower())
                return False
            
            elif network in ['ETH', 'BSC', 'MATIC']:
                # Ethereum-compatible addresses
                if address.startswith('0x') and len(address) == 42:
                    # Check hex chars after 0x
                    hex_part = address[2:]
                    return all(c in '0123456789abcdefABCDEF' for c in hex_part)
                return False
            
            elif network == 'TRX':
                # Tron addresses
                if address.startswith('T') and len(address) == 34:
                    # Base58 check
                    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                    return all(c in base58_chars for c in address)
                return False
            
            elif network == 'SOL':
                # Solana addresses
                if 32 <= len(address) <= 44:
                    # Base58 check
                    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                    return all(c in base58_chars for c in address)
                return False
            
            elif network == 'LTC':
                # Litecoin addresses
                if address.startswith(('L', 'M', '3')) and 26 <= len(address) <= 34:
                    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                    return all(c in base58_chars for c in address)
                elif address.startswith('ltc1') and 39 <= len(address) <= 62:
                    return True
                return False
            
            elif network == 'DOGE':
                # Dogecoin addresses
                if address.startswith('D') and 33 <= len(address) <= 34:
                    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                    return all(c in base58_chars for c in address)
                return False
            
            elif network == 'XRP':
                # Ripple addresses
                if address.startswith('r') and 25 <= len(address) <= 35:
                    return True
                return False
            
            elif network == 'ADA':
                # Cardano addresses
                if address.startswith('addr1') and len(address) >= 58:
                    return True
                elif address.startswith('DdzFF') and len(address) >= 93:
                    return True
                return False
            
            else:
                # Generic validation for other networks
                # Must be alphanumeric, reasonable length
                if 25 <= len(address) <= 100:
                    return address.isalnum() or '0x' in address
                return False
                
        except Exception as e:
            return False
    
    def validate_private_key(self, key: str, key_type: str) -> bool:
        """
        Strict validation for private keys
        Type-specific checks
        """
        if not key or len(key) < 50:
            return False
        
        key = key.strip()
        
        # Check for garbage
        if self.is_garbage(key):
            return False
        
        try:
            if key_type == 'RAW_HEX_64':
                # 64-char hex string
                if len(key) != 64:
                    return False
                return all(c in '0123456789abcdefABCDEF' for c in key)
            
            elif key_type == 'RAW_HEX_66':
                # 0x prefix + 64 hex chars
                if not key.startswith('0x') or len(key) != 66:
                    return False
                return all(c in '0123456789abcdefABCDEF' for c in key[2:])
            
            elif key_type in ['WIF_COMPRESSED', 'WIF_UNCOMPRESSED']:
                # Bitcoin WIF format
                if not key[0] in ['5', 'K', 'L']:
                    return False
                if len(key) not in [51, 52]:
                    return False
                # Base58 check
                base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                return all(c in base58_chars for c in key)
            
            elif key_type == 'SOLANA_KEYPAIR':
                # Solana keypair array format
                if not key.startswith('[') or not key.endswith(']'):
                    return False
                # Should have comma-separated numbers
                return ',' in key and key.replace('[', '').replace(']', '').replace(',', '').replace(' ', '').isdigit()
            
            else:
                # Generic: must be long enough and look like a key
                return len(key) >= 50 and (key.isalnum() or '0x' in key)
                
        except Exception as e:
            return False
    
    def validate_credential(self, username: str, password: str) -> bool:
        """
        Validate username:password credentials
        Filter out test/fake/garbage credentials
        """
        if not username or not password:
            return False
        
        username = username.strip()
        password = password.strip()
        
        # Minimum lengths
        if len(username) < 3 or len(password) < 4:
            return False
        
        # Check for garbage patterns in both
        if self.is_garbage(username) or self.is_garbage(password):
            return False
        
        # Check for common test credentials
        test_combos = [
            ('test', 'test'),
            ('admin', 'admin'),
            ('user', 'user'),
            ('demo', 'demo'),
            ('guest', 'guest'),
            ('test', 'password'),
            ('admin', 'password'),
            ('root', 'root'),
        ]
        
        username_lower = username.lower()
        password_lower = password.lower()
        
        if (username_lower, password_lower) in test_combos:
            return False
        
        # Check for repeated characters (likely fake)
        if len(set(username)) == 1 or len(set(password)) == 1:
            return False
        
        # Password shouldn't be same as username
        if username_lower == password_lower:
            return False
        
        # Check for obvious fake patterns
        fake_words = ['fake', 'test', 'dummy', 'sample', 'example', 'placeholder', 'default']
        if any(word in username_lower for word in fake_words):
            return False
        if any(word in password_lower for word in fake_words):
            return False
        
        return True
    
    def validate_cookie(self, domain: str, name: str, value: str) -> bool:
        """
        Validate cookie data
        Filter out invalid/test cookies
        """
        if not domain or not name or not value:
            return False
        
        domain = domain.strip()
        name = name.strip()
        value = value.strip()
        
        # Check for garbage
        if self.is_garbage(domain) or self.is_garbage(name):
            return False
        
        # Domain should look like a real domain
        if domain in ['localhost', '127.0.0.1', 'example.com', 'test.com']:
            return False
        
        # Value should have minimum length (allow numeric values like user IDs)
        if len(value) < 3:
            return False
        
        # Name shouldn't be empty or just whitespace
        if not name.strip():
            return False
        
        return True
    
    def validate_email(self, email: str) -> bool:
        """
        Validate email address
        Must be real format, not test/fake
        """
        if not email or len(email) < 6:
            return False
        
        email = email.strip().lower()
        
        # Check for garbage
        if self.is_garbage(email):
            return False
        
        # Must have @ and domain
        if '@' not in email:
            return False
        
        parts = email.split('@')
        if len(parts) != 2:
            return False
        
        username, domain = parts
        
        # Username and domain checks
        if len(username) < 1 or len(domain) < 4:
            return False
        
        # Domain must have at least one dot
        if '.' not in domain:
            return False
        
        # Check for test domains
        test_domains = ['test.com', 'example.com', 'fake.com', 'demo.com', 'localhost']
        if domain in test_domains:
            return False
        
        # Check for obvious fake patterns
        if any(word in email for word in ['test', 'fake', 'dummy', 'example', 'sample']):
            return False
        
        return True
    
    def validate_api_key(self, key: str, key_type: str) -> bool:
        """
        Validate API keys
        Type-specific format checks
        """
        if not key or len(key) < 10:
            return False
        
        key = key.strip()
        
        # Check for garbage
        if self.is_garbage(key):
            return False
        
        # Check for test/fake patterns
        if any(word in key.lower() for word in ['test', 'fake', 'example', 'sample']):
            return False
        
        # Type-specific validation
        if key_type == 'AWS_ACCESS_KEY':
            return key.startswith('AKIA') and len(key) == 20
        
        elif key_type == 'GOOGLE_API_KEY':
            return key.startswith('AIza') and len(key) == 39
        
        elif key_type == 'GITHUB_TOKEN':
            return (key.startswith('ghp_') or key.startswith('gho_')) and len(key) >= 36
        
        else:
            # Generic: must be alphanumeric, sufficient length
            return len(key) >= 16 and any(c.isalnum() for c in key)
    
    def validate_mail_credentials(self, email: str, password: str, server: str, port: int) -> bool:
        """
        Validate mail access credentials
        All components must be valid
        """
        # Validate email
        if not self.validate_email(email):
            return False
        
        # Password must be reasonable
        if not password or len(password) < 4:
            return False
        
        if self.is_garbage(password):
            return False
        
        # Server must look like a real server
        if not server or len(server) < 4:
            return False
        
        if self.is_garbage(server):
            return False
        
        # Port must be in valid range
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False
        
        # Common mail ports
        valid_ports = [25, 110, 143, 465, 587, 993, 995]
        if port not in valid_ports:
            # Allow non-standard ports but they should be reasonable
            if port > 10000:
                return False
        
        return True
    
    def validate_sms_api(self, api_id: str, api_type: str) -> bool:
        """
        Validate SMS API credentials
        Type and format checks
        """
        if not api_id or len(api_id) < 8:
            return False
        
        api_id = api_id.strip()
        
        # Check for garbage
        if self.is_garbage(api_id):
            return False
        
        # Check for test patterns
        if any(word in api_id.lower() for word in ['test', 'fake', 'demo', 'sample']):
            return False
        
        # Type-specific checks
        if api_type == 'TWILIO_SID':
            return api_id.startswith('AC') and len(api_id) == 34
        
        elif api_type == 'TWILIO_AUTH':
            return len(api_id) == 32 and all(c in '0123456789abcdefABCDEF' for c in api_id)
        
        else:
            # Generic: must be alphanumeric and reasonable length
            return len(api_id) >= 8 and api_id.replace('-', '').isalnum()
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL
        Must be real URL, not test/example
        """
        if not url or len(url) < 10:
            return False
        
        url_lower = url.lower()
        
        # Check for garbage
        if self.is_garbage(url_lower):
            return False
        
        # Must start with protocol or www
        if not (url_lower.startswith('http://') or url_lower.startswith('https://') or url_lower.startswith('www.')):
            return False
        
        # Check for test domains
        test_domains = ['example.com', 'test.com', 'localhost', '127.0.0.1', 'demo.com']
        if any(domain in url_lower for domain in test_domains):
            return False
        
        return True
