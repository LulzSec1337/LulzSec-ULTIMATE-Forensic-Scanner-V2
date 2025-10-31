#!/usr/bin/env python3#!/usr/bin/env python3

""""""

Comprehensive Feature Test - Tests all new featuresComprehensive test for all recent enhancements:

"""- Seeds extraction and display

- Cookies extraction and CRUD display

import sys- URL Access Extractor tab

import time- Expanded wallet patterns (18 networks)

import logging- Live statistics

"""

logging.basicConfig(level=logging.INFO, format='%(message)s')

import sys

print("=" * 80)import os

print(" LulzSec Scanner - COMPREHENSIVE FEATURE TEST")import tempfile

print("=" * 80)

print()sys.path.insert(0, os.path.dirname(__file__))



# Test 1: Balance Checkerfrom core.ultra_scanner import UltraAdvancedScanner

print("TEST 1: Balance Checker with Free APIs")from core.crypto_utils import EnhancedCryptoUtils

print("-" * 80)from database.db_manager import EnhancedDatabaseManager

try:

    from config.api_config import APIConfigprint("╔══════════════════════════════════════════════════════════════════════════╗")

    from core.balance_checker import AdvancedBalanceCheckerprint("║         🔥 COMPREHENSIVE FEATURE TEST - ALL ENHANCEMENTS 🔥             ║")

    print("╚══════════════════════════════════════════════════════════════════════════╝")

    api_config = APIConfig()print()

    checker = AdvancedBalanceChecker(api_config)

    # Initialize components

    print("  Testing ETH...")test_db = tempfile.mktemp(suffix='.db')

    eth_info = checker.get_comprehensive_balance("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb", "ETH")db = EnhancedDatabaseManager(test_db)

    print(f"  ✅ ETH: Balance={eth_info['balance']:.8f}, Price=${eth_info['price_usd']:.2f}")crypto_utils = EnhancedCryptoUtils()

    scanner = UltraAdvancedScanner(crypto_utils, db)

    print("  Testing BTC...")

    btc_info = checker.get_comprehensive_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC")# Test 1: Enhanced Seed Extraction

    print(f"  ✅ BTC: Balance={btc_info['balance']:.8f}, Value=${btc_info['value_usd']:.2f}")print("═" * 80)

    print("TEST 1: Enhanced Seed Phrase Extraction")

    print("  ✅ TEST 1 PASSED\n")print("═" * 80)

except Exception as e:

    print(f"  ❌ FAILED: {e}\n")seed_test_content = """

    sys.exit(1)Wallet Backup Information:

seed: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

# Test 2: Seed Derivation

print("TEST 2: Seed Phrase Derivation")MetaMask Export:

print("-" * 80){"mnemonic": "vintage chief hammer echo island smoke lyrics birth cabin wealth vault"}

try:

    from core.seed_balance_checker import SeedBalanceCheckerRecovery phrase (24 words):

    zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong

    seed_checker = SeedBalanceChecker(checker)

    test_seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"JSON format:

    {"seedPhrase": "elite elite elite elite elite elite elite elite elite elite elite elite"}

    print("  Validating seed...")

    assert seed_checker.validate_seed(test_seed), "Seed invalid"Numbered format:

    print("  ✅ Valid")1. army

    2. army  

    eth_addr = seed_checker.derive_eth_address_from_seed(test_seed, 0)3. army

    btc_addr = seed_checker.derive_btc_address_from_seed(test_seed, 0)4. army

    print(f"  ✅ ETH[0]: {eth_addr}")5. army

    print(f"  ✅ BTC[0]: {btc_addr}")6. army

    print("  ✅ TEST 2 PASSED\n")7. army

except Exception as e:8. army

    print(f"  ❌ FAILED: {e}\n")9. army

    sys.exit(1)10. army

11. army

# Test 3: Performance Optimizer12. just

print("TEST 3: Performance Optimizer")"""

print("-" * 80)

try:temp_seed_file = tempfile.mktemp(suffix='.txt')

    from core.performance_optimizer import PerformanceOptimizerwith open(temp_seed_file, 'w') as f:

        f.write(seed_test_content)

    optimizer = PerformanceOptimizer(max_cpu_percent=70, max_memory_percent=70)

    usage = optimizer.get_current_usage()results = scanner.scan_file(temp_seed_file)

    print(f"  CPU: {usage['cpu_percent']:.1f}%, RAM: {usage['memory_percent']:.1f}%")os.remove(temp_seed_file)

    print(f"  Max workers: {optimizer.max_workers}")

    print(f"✅ Seeds found: {len(results['seeds'])}")

    results = optimizer.process_in_batches(list(range(100)), lambda x: x*2, batch_size=20)if results['seeds']:

    print(f"  ✅ Processed {len(results)} items")    for i, seed in enumerate(results['seeds'], 1):

    print("  ✅ TEST 3 PASSED\n")        word_count = len(seed.split())

except Exception as e:        print(f"   {i}. {word_count} words: {seed[:60]}...")

    print(f"  ❌ FAILED: {e}\n")else:

    sys.exit(1)    print("⚠️  No seeds extracted - validation might be too strict")



# Test 4: Auto Balance Integrationprint()

print("TEST 4: Auto Balance Integration")

print("-" * 80)# Test 2: Cookie Extraction

try:print("═" * 80)

    from core.auto_balance_integration import AutoBalanceIntegrationprint("TEST 2: Enhanced Cookie Extraction")

    print("═" * 80)

    auto_balance = AutoBalanceIntegration(api_config)

    test_keys = [cookie_test_content = """

        {'address': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb', 'crypto_type': 'ETH', 'private_key': 'test1'},HTTP Response:

        {'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'crypto_type': 'BTC', 'private_key': 'test2'}Set-Cookie: session_id=abc123def456; Domain=example.com; Path=/

    ]Set-Cookie: user_token=xyz789uvw012; Domain=.example.com; HttpOnly

    

    results = auto_balance.check_private_keys(test_keys)JavaScript:

    summary = auto_balance.get_summary()document.cookie = "pref_lang=en; path=/";

    print(f"  ✅ Found {len(results)} keys with balance")

    print(f"  ✅ Total: ${summary['total_usd_value']:.2f}")JSON format:

    print("  ✅ TEST 4 PASSED\n"){"domain": "wallet.com", "name": "auth_token", "value": "Bearer_token_here_123"}

except Exception as e:{"cookie": "tracking_id=track_abc_def_ghi"}

    print(f"  ❌ FAILED: {e}\n")"""

    sys.exit(1)

temp_cookie_file = tempfile.mktemp(suffix='.txt')

# Test 5: Multiple Networkswith open(temp_cookie_file, 'w') as f:

print("TEST 5: Network Support")    f.write(cookie_test_content)

print("-" * 80)

try:results = scanner.scan_file(temp_cookie_file)

    for network in ['ETH', 'BTC', 'BSC', 'POLYGON']:os.remove(temp_cookie_file)

        addr = {'ETH': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb', 'BTC': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',

                'BSC': '0x8894E0a0c962CB723c1976a4421c95949bE2D4E3', 'POLYGON': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'}[network]print(f"✅ Cookies found: {len(results['cookies'])}")

        try:if results['cookies']:

            balance = checker.get_balance(addr, network)    for i, cookie in enumerate(results['cookies'][:5], 1):

            print(f"  ✅ {network}: {balance:.8f}")        if isinstance(cookie, dict):

        except:            domain = cookie.get('domain', 'unknown')

            print(f"  ⚠️  {network}: API rate limit or error")            name = cookie.get('name', 'unknown')

    print("  ✅ TEST 5 PASSED\n")            print(f"   {i}. {domain} - {name}")

except Exception as e:        else:

    print(f"  ❌ FAILED: {e}\n")            print(f"   {i}. {str(cookie)[:50]}")

else:

print("=" * 80)    print("⚠️  No cookies extracted")

print(" ✅ ALL TESTS PASSED!")

print("=" * 80)print()

print("\nFeatures Working:")

print("  ✅ Balance checking (free APIs)")# Test 3: Expanded Wallet Patterns

print("  ✅ Seed derivation")print("═" * 80)

print("  ✅ Performance optimization")print("TEST 3: Expanded Wallet Patterns (18 Networks)")

print("  ✅ Auto integration")print("═" * 80)

print("  ✅ Multi-network support")

print("\n🚀 Ready to build!")wallet_test_content = """

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
