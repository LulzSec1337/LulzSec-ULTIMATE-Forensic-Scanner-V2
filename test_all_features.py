#!/usr/bin/env python3
"""
Comprehensive test for all recent enhancements:
- Seeds extraction and display
- Cookies extraction and CRUD display
- URL Access Extractor tab
- Expanded wallet patterns (18 networks)
- Live statistics
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from core.ultra_scanner import UltraAdvancedScanner
from core.crypto_utils import EnhancedCryptoUtils
from database.db_manager import EnhancedDatabaseManager

print("╔══════════════════════════════════════════════════════════════════════════╗")
print("║         🔥 COMPREHENSIVE FEATURE TEST - ALL ENHANCEMENTS 🔥             ║")
print("╚══════════════════════════════════════════════════════════════════════════╝")
print()

# Initialize components
test_db = tempfile.mktemp(suffix='.db')
db = EnhancedDatabaseManager(test_db)
crypto_utils = EnhancedCryptoUtils()
scanner = UltraAdvancedScanner(crypto_utils, db)

# Test 1: Enhanced Seed Extraction
print("═" * 80)
print("TEST 1: Enhanced Seed Phrase Extraction")
print("═" * 80)

seed_test_content = """
Wallet Backup Information:
seed: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

MetaMask Export:
{"mnemonic": "vintage chief hammer echo island smoke lyrics birth cabin wealth vault"}

Recovery phrase (24 words):
zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong

JSON format:
{"seedPhrase": "elite elite elite elite elite elite elite elite elite elite elite elite"}

Numbered format:
1. army
2. army  
3. army
4. army
5. army
6. army
7. army
8. army
9. army
10. army
11. army
12. just
"""

temp_seed_file = tempfile.mktemp(suffix='.txt')
with open(temp_seed_file, 'w') as f:
    f.write(seed_test_content)

results = scanner.scan_file(temp_seed_file)
os.remove(temp_seed_file)

print(f"✅ Seeds found: {len(results['seeds'])}")
if results['seeds']:
    for i, seed in enumerate(results['seeds'], 1):
        word_count = len(seed.split())
        print(f"   {i}. {word_count} words: {seed[:60]}...")
else:
    print("⚠️  No seeds extracted - validation might be too strict")

print()

# Test 2: Cookie Extraction
print("═" * 80)
print("TEST 2: Enhanced Cookie Extraction")
print("═" * 80)

cookie_test_content = """
HTTP Response:
Set-Cookie: session_id=abc123def456; Domain=example.com; Path=/
Set-Cookie: user_token=xyz789uvw012; Domain=.example.com; HttpOnly

JavaScript:
document.cookie = "pref_lang=en; path=/";

JSON format:
{"domain": "wallet.com", "name": "auth_token", "value": "Bearer_token_here_123"}
{"cookie": "tracking_id=track_abc_def_ghi"}
"""

temp_cookie_file = tempfile.mktemp(suffix='.txt')
with open(temp_cookie_file, 'w') as f:
    f.write(cookie_test_content)

results = scanner.scan_file(temp_cookie_file)
os.remove(temp_cookie_file)

print(f"✅ Cookies found: {len(results['cookies'])}")
if results['cookies']:
    for i, cookie in enumerate(results['cookies'][:5], 1):
        if isinstance(cookie, dict):
            domain = cookie.get('domain', 'unknown')
            name = cookie.get('name', 'unknown')
            print(f"   {i}. {domain} - {name}")
        else:
            print(f"   {i}. {str(cookie)[:50]}")
else:
    print("⚠️  No cookies extracted")

print()

# Test 3: Expanded Wallet Patterns
print("═" * 80)
print("TEST 3: Expanded Wallet Patterns (18 Networks)")
print("═" * 80)

wallet_test_content = """
Bitcoin addresses:
BTC Legacy: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
BTC SegWit: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
BTC P2SH: 3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy

Ethereum & EVM chains:
ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
BSC: 0x0000000000000000000000000000000000001004
MATIC: 0xE592427A0AEce92De3Edee1F18E0157C05861564

Other networks:
SOL: 7UX2i7SucgLMQcfZ75s3VXmZZY4YRUyJN9X1RgfMoDUi
TRX: TUGZj7NNfQ5kXnNyLf5P1SwYY7P5v7qRwS
ADA: addr1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh0awfghklmnop
DOT: 15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5
AVAX: X-avax1g65uqn6t77p656w64023nh8nd9updzmxh8ttv3
ATOM: cosmos1xv9tklw7d82sezh9haa573wufgy59vmwe6xxe5
XRP: rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN
DOGE: DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L
LTC: LTC: ltc1qvtvkfh2f8l6a6yvg8wd3quxwjj4zpgvsn05s0e
BCH: bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a
TON: EQD3q5RqBq7T7GZQN3b1G6fPpvK9Y0QpHN6F2WQXK5p1F0KJ
NEAR: alice.near
ALGO: 7ZUECA7HFLZTXENRV24SHLU4AVPUTMTTDUFUBNBD64C73F3UHRTHAIOF6Q
"""

temp_wallet_file = tempfile.mktemp(suffix='.txt')
with open(temp_wallet_file, 'w') as f:
    f.write(wallet_test_content)

results = scanner.scan_file(temp_wallet_file)
os.remove(temp_wallet_file)

print(f"✅ Wallets found: {len(results['wallets'])}")

# Group by network
by_network = {}
for wallet in results['wallets']:
    network = wallet['network']
    if network not in by_network:
        by_network[network] = 0
    by_network[network] += 1

if by_network:
    print("\nWallets by network:")
    for network, count in sorted(by_network.items()):
        print(f"   {network}: {count}")
else:
    print("⚠️  No wallets extracted")

print()

# Test 4: GUI Tab Structure
print("═" * 80)
print("TEST 4: GUI Tab Structure Verification")
print("═" * 80)

with open('gui/advanced_gui.py', 'r') as f:
    gui_code = f.read()

tabs_found = 0
expected_tabs = [
    "🌱 Seed Phrases",
    "🔑 Private Keys",
    "💰 Wallet Addresses",
    "📧 Mail Access",
    "🔐 Credentials",
    "🍪 Cookies",
    "📱 SMS APIs",
    "🔑 API Keys",
    "🌐 URL Access",  # New tab
    "📋 Logs"
]

print("Checking for expected tabs:")
for tab in expected_tabs:
    if tab in gui_code:
        print(f"   ✅ {tab}")
        tabs_found += 1
    else:
        print(f"   ❌ {tab} - NOT FOUND")

print(f"\nTotal tabs found: {tabs_found}/{len(expected_tabs)}")

# Check for URL Access Extractor features
url_features = [
    'extract_url_access',  # Method name
    'self.url_input',  # Input field
    'self.url_cookies_text',  # Cookies sub-tab
    'self.url_creds_text',  # Credentials sub-tab
]

print("\nURL Access Extractor features:")
for feature in url_features:
    if feature in gui_code:
        print(f"   ✅ {feature}")
    else:
        print(f"   ❌ {feature} - NOT FOUND")

print()

# Test 5: Live Statistics Update Code
print("═" * 80)
print("TEST 5: Live Statistics Update Verification")
print("═" * 80)

stat_features = [
    "self.mini_stats['files'].set",
    "self.mini_stats['seeds'].set",
    "self.mini_stats['cookies'].set",
    "self.speed_var.set",
    "self.elapsed_time_var.set",
    "root.update_idletasks()",
]

print("Checking live statistics code:")
for feature in stat_features:
    if feature in gui_code:
        print(f"   ✅ {feature}")
    else:
        print(f"   ❌ {feature} - NOT FOUND")

print()

# Summary
print("═" * 80)
print("SUMMARY")
print("═" * 80)

score = 0
total = 5

if results['seeds']:
    print("✅ Seed extraction working")
    score += 1
else:
    print("⚠️  Seed extraction needs verification")

if results['cookies']:
    print("✅ Cookie extraction working")
    score += 1
else:
    print("⚠️  Cookie extraction needs verification")

if len(by_network) > 5:
    print(f"✅ Wallet extraction working ({len(by_network)} networks)")
    score += 1
else:
    print("⚠️  Wallet extraction limited")

if tabs_found >= 9:
    print(f"✅ GUI tabs complete ({tabs_found} tabs)")
    score += 1
else:
    print(f"⚠️  GUI tabs incomplete ({tabs_found}/{len(expected_tabs)})")

if all(f in gui_code for f in stat_features):
    print("✅ Live statistics code present")
    score += 1
else:
    print("⚠️  Live statistics code incomplete")

print()
print(f"Overall Score: {score}/5")

# Cleanup
os.remove(test_db)

print()
if score >= 4:
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║                   ✅ TESTS PASSED - READY TO USE! ✅                     ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
else:
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║                ⚠️  SOME FEATURES NEED ATTENTION ⚠️                       ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")

print()
print("🚀 TO USE ON PARROT OS:")
print("   cd ~/LulzSec-ULTIMATE-Forensic-Scanner-V2")
print("   git pull origin main")
print("   python3 run_gui.py")
print()
print("📋 NEW FEATURES:")
print("   • 10 tabs (added URL Access Extractor)")
print("   • Enhanced seed extraction (less strict validation)")
print("   • CRUD-style cookie display")
print("   • 18 wallet networks (was 8)")
print("   • URL-specific data extraction tool")
print("   • Real-time live statistics")
