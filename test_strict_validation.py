#!/usr/bin/env python3
"""
Test strict seed validation
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from core.ultra_scanner import UltraAdvancedScanner
from core.crypto_utils import EnhancedCryptoUtils
from database.db_manager import EnhancedDatabaseManager

# Test cases
test_cases = [
    # Real BIP39 seeds (should PASS)
    {
        'text': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
        'should_pass': True,
        'name': 'Valid 12-word seed'
    },
    {
        'text': 'legal winner thank year wave sausage worth useful legal winner thank yellow',
        'should_pass': True,
        'name': 'Valid 12-word seed #2'
    },
    {
        'text': 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
        'should_pass': True,
        'name': 'Valid 12-word seed #3'
    },
    
    # Garbage data (should FAIL)
    {
        'text': 'account battle net login username kream raheem gmail com password browser logins',
        'should_pass': False,
        'name': 'Garbage from stealer log'
    },
    {
        'text': 'add users textbox value nje name value lil sis name value sister',
        'should_pass': False,
        'name': 'System data garbage'
    },
    {
        'text': 'bit graphics card nvidia geforce rtx computer name blizzeq domain name product',
        'should_pass': False,
        'name': 'Hardware info garbage'
    },
    {
        'text': 'exe pid cpu mem disk network user time status process service',
        'should_pass': False,
        'name': 'Process list garbage'
    },
]

print("╔═══════════════════════════════════════════════════════════════╗")
print("║        🔒 STRICT SEED VALIDATION TEST 🔒                      ║")
print("╚═══════════════════════════════════════════════════════════════╝\n")

# Initialize scanner
db = EnhancedDatabaseManager()
crypto = EnhancedCryptoUtils()
scanner = UltraAdvancedScanner(crypto, db)

passed = 0
failed = 0

for i, test in enumerate(test_cases, 1):
    print(f"Test {i}: {test['name']}")
    print(f"Text: {test['text'][:60]}...")
    
    result = scanner._validate_and_filter_seed(test['text'])
    expected = test['should_pass']
    
    if result == expected:
        print(f"✅ PASS - Validation returned {result} as expected\n")
        passed += 1
    else:
        print(f"❌ FAIL - Expected {expected} but got {result}\n")
        failed += 1

print("\n" + "="*65)
print(f"RESULTS: {passed}/{len(test_cases)} tests passed")
print("="*65)

if failed == 0:
    print("\n✅ ALL TESTS PASSED - Validation is working correctly!")
    print("   ✓ Real seeds are accepted")
    print("   ✓ Garbage data is rejected")
    sys.exit(0)
else:
    print(f"\n❌ {failed} TESTS FAILED - Validation needs adjustment")
    sys.exit(1)
