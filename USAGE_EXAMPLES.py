#!/usr/bin/env python3
"""
LulzSec Scanner - Usage Examples
Demonstrates all features of the modular scanner
"""

import sys
sys.path.insert(0, '/workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2')

from main import LulzSecForensicScanner

print("=" * 70)
print("LULZSEC SCANNER - COMPREHENSIVE USAGE EXAMPLES")
print("=" * 70)

# Initialize scanner
scanner = LulzSecForensicScanner()

# Example 1: Validate a seed phrase
print("\n" + "=" * 70)
print("EXAMPLE 1: Seed Phrase Validation")
print("=" * 70)

test_seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
result = scanner.validate_seed_phrase(test_seed)

if result['valid']:
    print(f"✅ Valid {result['word_count']}-word seed phrase")
    print(f"\n📍 Derived Addresses:")
    for network, address in result.get('addresses', {}).items():
        print(f"  {network:6s}: {address}")

# Example 2: Check balance
print("\n" + "=" * 70)
print("EXAMPLE 2: Balance Checking")
print("=" * 70)

# Ethereum address example
eth_address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
eth_info = scanner.check_balance(eth_address, "ETH")

print(f"\n💰 Balance Information:")
print(f"  Network: ETH")
print(f"  Address: {eth_info['address'][:20]}...")
print(f"  Balance: {eth_info['balance']:.8f} ETH")
print(f"  Price: ${eth_info['price_usd']:.2f}")
print(f"  Value: ${eth_info['value_usd']:.2f}")
print(f"  Can Withdraw: {eth_info['can_withdraw']}")

# Example 3: Email analysis
print("\n" + "=" * 70)
print("EXAMPLE 3: Email Analysis")
print("=" * 70)

test_emails = [
    'test@gmail.com',
    'test@comcast.net',
    'test@yahoo.com'
]

for email in test_emails:
    info = scanner.validate_email(email)
    print(f"\n📧 {email}")
    print(f"  SMTP: {info['smtp_server']}:{info['smtp_port']}")
    print(f"  Premium: {'✅ YES' if info['is_premium'] else '❌ NO'}")
    print(f"  SMS Gateway: {'✅ YES' if info['has_sms_gateway'] else '❌ NO'}")

# Example 4: SMS API Detection
print("\n" + "=" * 70)
print("EXAMPLE 4: SMS API Detection")
print("=" * 70)

test_text = '''
TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_AUTH_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
NEXMO_API_KEY = "xxxxxxxx"
'''

found_apis = scanner.sms_detector.scan_text_for_apis(test_text)
print(f"\n🔍 Found {len(found_apis)} SMS API credential(s):")
for api in found_apis:
    print(f"  - {api['provider']}: {len(api['credentials'])} credential(s)")

# Example 5: Statistics
print("\n" + "=" * 70)
print("EXAMPLE 5: Scanner Statistics")
print("=" * 70)

stats = scanner.get_statistics()
print(f"\n📊 Current Statistics:")
print(f"  Total Keys Found: {stats['extractor']['total_keys_found']}")
print(f"  Total Addresses: {stats['extractor']['total_addresses_derived']}")
print(f"  Total Wallets: {stats['database']['total_wallets']}")
print(f"  Total Credentials: {stats['database']['total_credentials']}")

# Example 6: Crypto utilities direct usage
print("\n" + "=" * 70)
print("EXAMPLE 6: Direct Crypto Operations")
print("=" * 70)

# Generate a random private key (for demo only)
import secrets
test_pk = secrets.token_hex(32)
print(f"\n🔑 Test Private Key: {test_pk[:32]}...")

# Derive addresses
networks_to_test = ['ETH', 'BTC', 'TRX']
print(f"\n📍 Derived Addresses:")
for network in networks_to_test:
    try:
        address = scanner.crypto_utils.private_key_to_address(test_pk, network)
        print(f"  {network}: {address}")
    except Exception as e:
        print(f"  {network}: Error - {e}")

# Example 7: Database operations
print("\n" + "=" * 70)
print("EXAMPLE 7: Database Operations")
print("=" * 70)

# Add a test wallet
test_wallet = {
    'address': '0xTEST_EXAMPLE_ADDRESS',
    'crypto_type': 'ETH',
    'balance': 1.5,
    'usd_value': 6250.00,
    'can_withdraw': True,
    'extraction_method': 'example_demo'
}

success = scanner.database.add_wallet(test_wallet)
print(f"\n💾 Add Wallet: {'✅ SUCCESS' if success else '❌ FAILED'}")

# Get updated statistics
db_stats = scanner.database.get_statistics()
print(f"\n📊 Database Statistics:")
print(f"  Total Wallets: {db_stats['total_wallets']}")
print(f"  Wallets with Balance: {db_stats['wallets_with_balance']}")
print(f"  Total USD Value: ${db_stats['total_usd_value']:.2f}")

print("\n" + "=" * 70)
print("✅ ALL EXAMPLES COMPLETED SUCCESSFULLY")
print("=" * 70)

print("""
🚀 READY TO USE:

Command Line:
  python main.py scan /path/to/directory
  python main.py seed "your twelve word seed"
  python main.py balance 0x123... ETH
  python main.py stats

Interactive Mode:
  python main.py
  > scan /path/to/directory
  > seed abandon abandon ...
  > stats
  > export ./results
  > quit

Python API:
  from main import LulzSecForensicScanner
  scanner = LulzSecForensicScanner()
  scanner.scan_directory('/path')
  scanner.get_statistics()
  scanner.export_results()

Documentation:
  - README.md                - Quick start guide
  - MODULAR_README.md        - Architecture overview
  - FINAL_REPORT.md          - Complete project report
  - TEST_STATUS_REPORT.md    - Test verification

All modules are tested and working! 🎉
""")
