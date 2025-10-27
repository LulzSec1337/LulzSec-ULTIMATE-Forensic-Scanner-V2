#!/usr/bin/env python3
"""
Quick test to verify extraction improvements
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ultra_scanner import UltraAdvancedScanner
from core.crypto_utils import EnhancedCryptoUtils
from database.db_manager import EnhancedDatabaseManager

# Test data with real and fake patterns
test_content = """
# Real 12-word seed phrase
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

# Real 24-word seed phrase  
zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote

# Fake seed (should be filtered out)
test test test test test test test test test test test test

# Real BTC address
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Real ETH address
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

# Credentials
user@example.com:password123
realuser@gmail.com:SecurePass456
admin@test.com:test123

# Private key (hex format)
e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262

# SMS API (example patterns)
Twilio Account SID: ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Twilio Auth Token: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"""

def test_extraction():
    """Test the improved extraction"""
    print("🔥 Testing Ultra Scanner with Smart Filtering\n")
    
    crypto_utils = EnhancedCryptoUtils()
    db = EnhancedDatabaseManager()
    scanner = UltraAdvancedScanner(crypto_utils, db)
    
    print("📊 Scanning test content...\n")
    results = scanner.scan_file_content(test_content, "test_file.txt")
    
    print(f"✅ Seeds found: {len(results['seeds'])}")
    for seed in results['seeds']:
        word_count = len(seed.split())
        print(f"   🌱 {word_count}-word seed: {seed[:50]}...")
    
    print(f"\n💰 Wallets found: {len(results['wallets'])}")
    for wallet in results['wallets'][:5]:
        print(f"   {wallet['network']}: {wallet['address']}")
    
    print(f"\n🔐 Credentials found: {len(results['credentials'])}")
    for cred in results['credentials'][:5]:
        print(f"   {cred['username']}:{cred['password']}")
    
    print(f"\n🔑 Private keys found: {len(results['private_keys'])}")
    for key in results['private_keys'][:3]:
        print(f"   {key['type']}: {key['key'][:50]}...")
    
    print(f"\n📱 SMS APIs found: {len(results['sms_apis'])}")
    for api in results['sms_apis']:
        print(f"   Provider: {api['provider']}")
    
    print("\n✅ Test complete!")
    print("\nNOTE: 'test' seeds should be filtered out automatically")
    print("Real seeds should pass BIP39 validation")

if __name__ == "__main__":
    test_extraction()
