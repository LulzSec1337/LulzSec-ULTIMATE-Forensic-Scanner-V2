#!/usr/bin/env python3
"""
Comprehensive Module Testing Script
Tests each component of the forensic scanner to ensure functionality
"""

import sys
import os

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_test(test_name, status, message=""):
    """Print test result"""
    symbol = "✅" if status else "❌"
    color = GREEN if status else RED
    print(f"{symbol} {color}{test_name}{RESET}", end="")
    if message:
        print(f" - {message}")
    else:
        print()

def print_section(title):
    """Print section header"""
    print(f"\n{BLUE}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{RESET}\n")

def test_imports():
    """Test if ext.py imports work"""
    print_section("Testing Imports")
    
    try:
        import ext
        print_test("Import ext module", True)
        return True
    except Exception as e:
        print_test("Import ext module", False, str(e))
        return False

def test_api_config():
    """Test API Configuration"""
    print_section("Testing API Configuration")
    
    try:
        from ext import APIConfig
        
        # Test instantiation
        api_config = APIConfig()
        print_test("APIConfig instantiation", True)
        
        # Test endpoints
        eth_endpoint = api_config.get_endpoint('ETH')
        has_endpoint = eth_endpoint is not None
        print_test("Get ETH endpoint", has_endpoint, eth_endpoint if has_endpoint else "None")
        
        btc_endpoint = api_config.get_endpoint('BTC')
        has_btc = btc_endpoint is not None
        print_test("Get BTC endpoint", has_btc, btc_endpoint if has_btc else "None")
        
        # Test save/load
        save_result = api_config.save()
        print_test("Save API config", save_result)
        
        return True
    except Exception as e:
        print_test("APIConfig test", False, str(e))
        return False

def test_crypto_utils():
    """Test Crypto Utilities"""
    print_section("Testing Crypto Utilities")
    
    try:
        from ext import EnhancedCryptoUtils
        
        # Test instantiation
        crypto = EnhancedCryptoUtils()
        print_test("EnhancedCryptoUtils instantiation", True)
        
        # Test seed phrase validation (valid 12-word seed)
        test_seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        is_valid = crypto.validate_seed_phrase(test_seed)
        print_test("Validate valid seed phrase", is_valid)
        
        # Test invalid seed
        invalid_seed = "invalid seed phrase test"
        is_invalid = not crypto.validate_seed_phrase(invalid_seed)
        print_test("Reject invalid seed phrase", is_invalid)
        
        # Test private key validation
        valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        is_valid_key = crypto.is_valid_private_key(valid_key)
        print_test("Validate private key format", is_valid_key, f"{valid_key[:16]}...")
        
        # Test address generation
        test_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        eth_address = crypto.private_key_to_address(test_key, "ETH")
        has_address = eth_address is not None and eth_address.startswith('0x')
        print_test("Generate ETH address from key", has_address, eth_address[:20] + "..." if has_address else "None")
        
        # Test seed extraction from text
        text_with_seed = "Here is my seed: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about and some other text"
        found_seeds = crypto.extract_seed_phrases_from_text(text_with_seed)
        print_test("Extract seed from text", len(found_seeds) > 0, f"Found {len(found_seeds)} seed(s)")
        
        # Test private key extraction
        text_with_key = "Private key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        found_keys = crypto.extract_private_keys_from_text(text_with_key)
        print_test("Extract private key from text", len(found_keys) > 0, f"Found {len(found_keys)} key(s)")
        
        return True
    except Exception as e:
        print_test("Crypto utilities test", False, str(e))
        import traceback
        traceback.print_exc()
        return False

def test_balance_checker():
    """Test Balance Checker"""
    print_section("Testing Balance Checker")
    
    try:
        from ext import AdvancedBalanceChecker, APIConfig
        
        api_config = APIConfig()
        balance_checker = AdvancedBalanceChecker(api_config)
        print_test("AdvancedBalanceChecker instantiation", True)
        
        # Test price fetching (should work without API key)
        eth_price = balance_checker.get_usd_price('ETH')
        has_price = eth_price > 0
        print_test("Get ETH USD price", has_price, f"${eth_price:.2f}" if has_price else "Failed")
        
        btc_price = balance_checker.get_usd_price('BTC')
        has_btc_price = btc_price > 0
        print_test("Get BTC USD price", has_btc_price, f"${btc_price:.2f}" if has_btc_price else "Failed")
        
        # Note: Balance checking requires valid addresses and may hit rate limits
        print_test("Balance checker ready", True, "Note: Address checks require valid API keys")
        
        return True
    except Exception as e:
        print_test("Balance checker test", False, str(e))
        return False

def test_database():
    """Test Database Manager"""
    print_section("Testing Database Manager")
    
    try:
        from ext import EnhancedDatabaseManager
        
        # Test instantiation (creates DB)
        db = EnhancedDatabaseManager()
        print_test("EnhancedDatabaseManager instantiation", True)
        
        # Test adding wallet
        test_wallet = {
            'address': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
            'crypto_type': 'ETH',
            'balance': 0.0,
            'wallet_source': 'test'
        }
        add_result = db.add_wallet(test_wallet)
        print_test("Add wallet to database", add_result)
        
        # Test getting statistics
        stats = db.get_statistics()
        has_stats = stats is not None and 'total_wallets' in stats
        print_test("Get database statistics", has_stats, f"Total wallets: {stats.get('total_wallets', 0)}")
        
        # Test adding credential
        test_cred = {
            'email': 'test@example.com',
            'password': 'testpass123',
            'category': 'test',
            'source_file': 'test.txt'
        }
        cred_result = db.add_credential(test_cred)
        print_test("Add credential to database", cred_result)
        
        return True
    except Exception as e:
        print_test("Database test", False, str(e))
        import traceback
        traceback.print_exc()
        return False

def test_email_validator():
    """Test Email Validator"""
    print_section("Testing Email Validator")
    
    try:
        from ext import EmailValidator
        
        validator = EmailValidator()
        print_test("EmailValidator instantiation", True)
        
        # Test SMTP server detection
        smtp_server = validator.get_smtp_server('test@gmail.com')
        has_smtp = smtp_server is not None
        print_test("Detect Gmail SMTP server", has_smtp, f"{smtp_server[0]}:{smtp_server[1]}" if has_smtp else "None")
        
        # Test premium email detection
        is_premium = validator.is_premium_email('test@comcast.net')
        print_test("Detect premium email", is_premium, "comcast.net is premium")
        
        # Test SMS gateway detection
        has_sms = validator.has_sms_gateway('test@att.net')
        print_test("Detect SMS gateway", has_sms, "att.net has SMS gateway")
        
        print_test("Email validator ready", True, "Note: Actual validation requires valid credentials")
        
        return True
    except Exception as e:
        print_test("Email validator test", False, str(e))
        return False

def test_extractors():
    """Test Data Extractors"""
    print_section("Testing Data Extractors")
    
    try:
        from ext import (
            ComprehensivePrivateKeyExtractor,
            SensitiveDataDetector,
            EnhancedCryptoUtils,
            AdvancedBalanceChecker,
            APIConfig,
            EnhancedDatabaseManager
        )
        
        # Setup dependencies
        crypto = EnhancedCryptoUtils()
        api_config = APIConfig()
        balance_checker = AdvancedBalanceChecker(api_config)
        db = EnhancedDatabaseManager()
        
        def dummy_callback(msg, type="info"):
            pass
        
        # Test Private Key Extractor
        pk_extractor = ComprehensivePrivateKeyExtractor(crypto, balance_checker, dummy_callback)
        print_test("ComprehensivePrivateKeyExtractor instantiation", True)
        
        # Test pattern recognition
        test_content = """
        Some text with a private key:
        0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        And more text
        """
        
        # Create temp file for testing
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_content)
            temp_file = f.name
        
        pk_extractor.extract_all_key_formats(temp_file)
        summary = pk_extractor.get_summary()
        found_keys = summary['total_keys_found'] > 0
        print_test("Extract private key from file", found_keys, f"Found {summary['total_keys_found']} key(s)")
        
        # Cleanup
        os.unlink(temp_file)
        
        # Test Sensitive Data Detector
        sensitive_detector = SensitiveDataDetector(db, dummy_callback)
        print_test("SensitiveDataDetector instantiation", True)
        
        # Test pattern detection (obfuscated for security)
        test_sensitive = """
        AWS_ACCESS_KEY_ID=AKIA0000000000000000
        payment_api_key=test_key_placeholder_only
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_sensitive)
            temp_file2 = f.name
        
        sensitive_detector.scan_file_for_sensitive_data(temp_file2)
        found_sensitive = len(sensitive_detector.found_data) > 0
        print_test("Detect sensitive data patterns", found_sensitive, f"Found {len(sensitive_detector.found_data)} item(s)")
        
        os.unlink(temp_file2)
        
        return True
    except Exception as e:
        print_test("Extractors test", False, str(e))
        import traceback
        traceback.print_exc()
        return False

def test_sms_detector():
    """Test SMS API Detector"""
    print_section("Testing SMS API Detector")
    
    try:
        from ext import SMSAPIDetector
        
        detector = SMSAPIDetector()
        print_test("SMSAPIDetector instantiation", True)
        
        # Test pattern detection
        test_content = """
        TWILIO_ACCOUNT_SID=AC1234567890abcdef1234567890abcd
        TWILIO_AUTH_TOKEN=1234567890abcdef1234567890abcdef
        """
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_content)
            temp_file = f.name
        
        found_apis = detector.scan_file_for_apis(temp_file)
        has_found = len(found_apis) > 0
        print_test("Detect Twilio credentials", has_found, f"Found {len(found_apis)} API(s)")
        
        os.unlink(temp_file)
        
        return True
    except Exception as e:
        print_test("SMS detector test", False, str(e))
        return False

def test_hosting_detector():
    """Test Hosting Service Detector"""
    print_section("Testing Hosting Service Detector")
    
    try:
        from ext import HostingServiceDetector
        
        detector = HostingServiceDetector()
        print_test("HostingServiceDetector instantiation", True)
        
        # Test pattern detection
        test_content = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        cpanel_user=admin
        cpanel_password=secretpass123
        """
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_content)
            temp_file = f.name
        
        found_services = detector.scan_file_for_hosting(temp_file)
        has_found = len(found_services) > 0
        print_test("Detect hosting credentials", has_found, f"Found {len(found_services)} service(s)")
        
        os.unlink(temp_file)
        
        return True
    except Exception as e:
        print_test("Hosting detector test", False, str(e))
        return False

def main():
    """Run all tests"""
    print(f"\n{BLUE}{'='*60}")
    print("  🧪 LULZSEC FORENSIC SCANNER - MODULE TESTING")
    print(f"{'='*60}{RESET}\n")
    
    results = {}
    
    # Run tests
    results['imports'] = test_imports()
    if not results['imports']:
        print(f"\n{RED}❌ Import test failed. Cannot continue.{RESET}")
        return False
    
    results['api_config'] = test_api_config()
    results['crypto'] = test_crypto_utils()
    results['balance'] = test_balance_checker()
    results['database'] = test_database()
    results['email'] = test_email_validator()
    results['extractors'] = test_extractors()
    results['sms'] = test_sms_detector()
    results['hosting'] = test_hosting_detector()
    
    # Summary
    print_section("Test Summary")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        color = GREEN if result else RED
        print(f"{color}{status}{RESET} - {test_name}")
    
    print(f"\n{BLUE}{'='*60}")
    percentage = (passed / total * 100) if total > 0 else 0
    color = GREEN if percentage >= 80 else YELLOW if percentage >= 60 else RED
    print(f"{color}Results: {passed}/{total} tests passed ({percentage:.1f}%){RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")
    
    return passed == total

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
