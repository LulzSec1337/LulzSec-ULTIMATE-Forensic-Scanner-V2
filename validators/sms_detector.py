#!/usr/bin/env python3
"""
SMS API Detector Module
Detects and validates SMS API credentials (Twilio, Nexmo, Plivo, etc.)
"""

import re
import requests
import logging
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class SMSAPIDetector:
    """
    SMS API credential detector and validator
    
    Features:
    - Twilio, Nexmo, Plivo, MessageBird, Sinch, ClickSend, Textlocal support
    - Pattern-based credential extraction
    - API validation with balance checking
    - Multi-file scanning capability
    """
    
    def __init__(self):
        # SMS API patterns and configurations
        self.api_patterns = {
            'twilio': {
                'patterns': [
                    r'TWILIO_ACCOUNT_SID["\s:=]+([A-Z0-9]{34})',
                    r'TWILIO_AUTH_TOKEN["\s:=]+([a-f0-9]{32})',
                    r'AC[a-f0-9]{32}',  # Account SID pattern
                ],
                'test_endpoint': 'https://api.twilio.com/2010-04-01/Accounts',
                'name': 'Twilio'
            },
            'nexmo': {
                'patterns': [
                    r'NEXMO_API_KEY["\s:=]+([a-f0-9]{8})',
                    r'NEXMO_API_SECRET["\s:=]+([a-zA-Z0-9]{16})',
                ],
                'test_endpoint': 'https://rest.nexmo.com/account/get-balance',
                'name': 'Vonage/Nexmo'
            },
            'plivo': {
                'patterns': [
                    r'PLIVO_AUTH_ID["\s:=]+([A-Z0-9]{20})',
                    r'PLIVO_AUTH_TOKEN["\s:=]+([a-zA-Z0-9]{40})',
                ],
                'test_endpoint': 'https://api.plivo.com/v1/Account',
                'name': 'Plivo'
            },
            'messagebird': {
                'patterns': [
                    r'MESSAGEBIRD_API_KEY["\s:=]+([a-zA-Z0-9]{25})',
                ],
                'test_endpoint': 'https://rest.messagebird.com/balance',
                'name': 'MessageBird'
            },
            'sinch': {
                'patterns': [
                    r'SINCH_APP_KEY["\s:=]+([a-f0-9-]{36})',
                    r'SINCH_APP_SECRET["\s:=]+([a-zA-Z0-9+/=]{40,})',
                ],
                'test_endpoint': 'https://api.sinch.com',
                'name': 'Sinch'
            },
            'clicksend': {
                'patterns': [
                    r'CLICKSEND_USERNAME["\s:=]+([a-zA-Z0-9@.]+)',
                    r'CLICKSEND_API_KEY["\s:=]+([A-F0-9-]{36})',
                ],
                'test_endpoint': 'https://rest.clicksend.com/v3/account',
                'name': 'ClickSend'
            },
            'textlocal': {
                'patterns': [
                    r'TEXTLOCAL_API_KEY["\s:=]+([a-zA-Z0-9]{40})',
                ],
                'test_endpoint': 'https://api.textlocal.in/balance',
                'name': 'Textlocal'
            }
        }
    
    def scan_file_for_apis(self, file_path: str) -> List[Dict]:
        """
        Scan file for SMS API credentials
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of found API credentials
        """
        found_apis = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for provider, config in self.api_patterns.items():
                for pattern in config['patterns']:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        found_apis.append({
                            'provider': config['name'],
                            'provider_key': provider,
                            'credentials': matches,
                            'file': file_path,
                            'pattern': pattern
                        })
                        logger.info(f"Found {config['name']} credentials in {file_path}")
        
        except Exception as e:
            logger.debug(f"SMS API scan error for {file_path}: {e}")
        
        return found_apis
    
    def scan_text_for_apis(self, text: str) -> List[Dict]:
        """
        Scan text content for SMS API credentials
        
        Args:
            text: Text content to scan
            
        Returns:
            List of found API credentials
        """
        found_apis = []
        
        for provider, config in self.api_patterns.items():
            for pattern in config['patterns']:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    found_apis.append({
                        'provider': config['name'],
                        'provider_key': provider,
                        'credentials': matches,
                        'pattern': pattern
                    })
        
        return found_apis
    
    # =========================================================================
    # API VALIDATION METHODS
    # =========================================================================
    
    def validate_twilio(self, account_sid: str, auth_token: str) -> Tuple[bool, Dict]:
        """
        Validate Twilio API credentials
        
        Args:
            account_sid: Twilio Account SID
            auth_token: Twilio Auth Token
            
        Returns:
            Tuple of (success, data)
        """
        try:
            url = f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json'
            response = requests.get(url, auth=(account_sid, auth_token), timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Twilio validation successful: {account_sid}")
                return True, {
                    'valid': True,
                    'balance': data.get('balance'),
                    'status': data.get('status'),
                    'type': data.get('type')
                }
            else:
                return False, {'valid': False, 'error': response.text}
        
        except Exception as e:
            logger.debug(f"Twilio validation error: {e}")
            return False, {'valid': False, 'error': str(e)}
    
    def validate_nexmo(self, api_key: str, api_secret: str) -> Tuple[bool, Dict]:
        """
        Validate Nexmo/Vonage API credentials
        
        Args:
            api_key: Nexmo API Key
            api_secret: Nexmo API Secret
            
        Returns:
            Tuple of (success, data)
        """
        try:
            url = f'https://rest.nexmo.com/account/get-balance?api_key={api_key}&api_secret={api_secret}'
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Nexmo validation successful")
                return True, {
                    'valid': True,
                    'balance': data.get('value'),
                    'auto_reload': data.get('autoReload')
                }
            else:
                return False, {'valid': False, 'error': response.text}
        
        except Exception as e:
            logger.debug(f"Nexmo validation error: {e}")
            return False, {'valid': False, 'error': str(e)}
    
    def validate_plivo(self, auth_id: str, auth_token: str) -> Tuple[bool, Dict]:
        """
        Validate Plivo API credentials
        
        Args:
            auth_id: Plivo Auth ID
            auth_token: Plivo Auth Token
            
        Returns:
            Tuple of (success, data)
        """
        try:
            url = f'https://api.plivo.com/v1/Account/{auth_id}/'
            response = requests.get(url, auth=(auth_id, auth_token), timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Plivo validation successful: {auth_id}")
                return True, {
                    'valid': True,
                    'account_type': data.get('account_type'),
                    'cash_credits': data.get('cash_credits'),
                    'state': data.get('state')
                }
            else:
                return False, {'valid': False, 'error': response.text}
        
        except Exception as e:
            logger.debug(f"Plivo validation error: {e}")
            return False, {'valid': False, 'error': str(e)}
    
    def validate_messagebird(self, api_key: str) -> Tuple[bool, Dict]:
        """
        Validate MessageBird API credentials
        
        Args:
            api_key: MessageBird API Key
            
        Returns:
            Tuple of (success, data)
        """
        try:
            url = 'https://rest.messagebird.com/balance'
            headers = {'Authorization': f'AccessKey {api_key}'}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"MessageBird validation successful")
                return True, {
                    'valid': True,
                    'balance': data.get('amount'),
                    'currency': data.get('type')
                }
            else:
                return False, {'valid': False, 'error': response.text}
        
        except Exception as e:
            logger.debug(f"MessageBird validation error: {e}")
            return False, {'valid': False, 'error': str(e)}
    
    def get_provider_info(self, provider_key: str) -> Optional[Dict]:
        """
        Get provider configuration information
        
        Args:
            provider_key: Provider identifier
            
        Returns:
            Provider configuration dictionary or None
        """
        return self.api_patterns.get(provider_key)


# Standalone test
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("SMS API DETECTOR - STANDALONE TEST")
    print("=" * 60)
    
    detector = SMSAPIDetector()
    
    print("\n1. Testing Pattern Detection:")
    print("-" * 60)
    
    # Test with sample text containing fake credentials (obfuscated for security)
    test_text = """
    TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_AUTH_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    NEXMO_API_KEY = "xxxxxxxx"
    NEXMO_API_SECRET = "xxxxxxxxxxxxxxxx"
    MESSAGEBIRD_API_KEY = "xxxxxxxxxxxxxxxxxxxxx"
    """
    
    found = detector.scan_text_for_apis(test_text)
    print(f"Found {len(found)} SMS API credential(s):")
    for api in found:
        print(f"  - {api['provider']}: {len(api['credentials'])} credential(s)")
        for cred in api['credentials']:
            print(f"    • {cred[:20]}..." if len(cred) > 20 else f"    • {cred}")
    
    print("\n2. Testing Provider Info:")
    print("-" * 60)
    for provider in ['twilio', 'nexmo', 'plivo', 'messagebird']:
        info = detector.get_provider_info(provider)
        if info:
            print(f"{info['name']}:")
            print(f"  Endpoint: {info['test_endpoint']}")
            print(f"  Patterns: {len(info['patterns'])}")
    
    print("\n3. Supported Providers:")
    print("-" * 60)
    for provider_key, config in detector.api_patterns.items():
        print(f"✅ {config['name']} ({provider_key})")
    
    print("\n" + "=" * 60)
    print("✅ SMS API detector test complete!")
    print("=" * 60)
    print("\nNote: API validation requires real credentials")
    print("Use validate_twilio(), validate_nexmo(), etc. with actual keys")
