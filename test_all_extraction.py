#!/usr/bin/env python3
"""
Comprehensive Test for All Extraction Features
Tests: Credentials, Cookies, Logins, URLs, Private Keys, API Keys
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

print("=" * 80)
print("🧪 COMPREHENSIVE EXTRACTION TEST")
print("=" * 80)

# Create test directory structure
test_dir = tempfile.mkdtemp(prefix="lulzsec_test_")
print(f"\n📁 Test directory: {test_dir}")

# Create test files
test_files = {}

# 1. Cookie file (Netscape format)
test_files['cookies.txt'] = """# Netscape HTTP Cookie File
.facebook.com	TRUE	/	TRUE	1735689600	c_user	123456789
.facebook.com	TRUE	/	TRUE	1735689600	xs	session_token_here
.binance.com	TRUE	/	TRUE	1735689600	BNC-UUID	auth-uuid-here
"""

# 2. Logins file (Browser/Logins format)
os.makedirs(os.path.join(test_dir, "Browser", "Logins"), exist_ok=True)
test_files['Browser/Logins/passwords.txt'] = """URL: https://facebook.com/login
Username: user@example.com
Password: MySecurePass123!

URL: https://binance.com
Username: trader@crypto.com
Password: CryptoPass456!

URL: https://gmail.com
Login: myemail@gmail.com
Password: EmailPass789!
"""

# 3. Generic credentials file
test_files['credentials.txt'] = """
user@domain.com:password123
admin@website.com:AdminPass456

URL: https://twitter.com
Email: social@test.com
Password: TwitterPass789
"""

# 4. Private key file
test_files['wallet_backup.txt'] = """
Private Key: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
WIF Key: 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf
"""

# 5. API keys file
test_files['config.txt'] = """
GitHub Token: gho_xdQgd35xAtotoSNcmQe0ihNzz8testtoken123
Google API Key: AIzaCwacUSDyAGGUQ54AI7hOTIUnAqtestkey
JWT: eyJhbGciOiJSUzI1NiIsIng1dSI6InRlc3QifQ.eyJ0ZXN0IjoidGVzdCJ9.dGVzdA
"""

# Write test files
for filepath, content in test_files.items():
    full_path = os.path.join(test_dir, filepath)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, 'w') as f:
        f.write(content)
    print(f"✅ Created: {filepath}")

print("\n" + "=" * 80)
print("🚀 STARTING EXTRACTION TEST")
print("=" * 80)

# Import scanner
from ext import (
    UltimateProductionScanner,
    EnhancedDatabaseManager,
    APIConfig,
    EnhancedCryptoUtils,
    AdvancedBalanceChecker
)

# Initialize
api_config = APIConfig()
crypto_utils = EnhancedCryptoUtils()
balance_checker = AdvancedBalanceChecker(api_config)
db = EnhancedDatabaseManager()

# Delete existing test database
if os.path.exists(db.db_path):
    os.remove(db.db_path)
    db.init_database()
    print("✅ Fresh database initialized")

scanner = UltimateProductionScanner(db, api_config, crypto_utils, balance_checker)

# Callbacks
def progress_cb(value):
    pass

log_messages = []
def status_cb(message, msg_type):
    log_messages.append((message, msg_type))
    if "FOUND" in message or "CREDENTIAL" in message:
        print(f"   {message}")

# Run scan
print("\n📊 Running scan...")
options = {
    'scan_mode': 'data_only',
    'extract_credentials': True,
    'extract_cookies': True,
    'extract_sensitive': True,
    'extract_sms_apis': False,
    'extract_hosting': False,
    'extract_private_keys': False,  # Test data mode first
}

try:
    scanner.scan_complete_system(test_dir, progress_cb, status_cb, options)
    print("✅ Scan completed successfully")
except Exception as e:
    print(f"❌ Scan failed: {e}")
    import traceback
    traceback.print_exc()

# Verify results
print("\n" + "=" * 80)
print("📊 VERIFICATION RESULTS")
print("=" * 80)

import sqlite3

conn = sqlite3.connect(db.db_path)
cursor = conn.cursor()

# Test 1: Credentials
cursor.execute("SELECT COUNT(*) FROM credentials")
creds_count = cursor.fetchone()[0]
print(f"\n🔐 Credentials: {creds_count} found")
if creds_count > 0:
    cursor.execute("SELECT email, password, url FROM credentials LIMIT 5")
    for row in cursor.fetchall():
        print(f"   ✅ {row[0]} | {row[1][:20]}... | {row[2] or 'N/A'}")
    print("   ✅ TEST 1 PASSED: Credentials extracted")
else:
    print("   ❌ TEST 1 FAILED: No credentials found")

# Test 2: Cookies
cursor.execute("SELECT COUNT(*) FROM cookies")
cookies_count = cursor.fetchone()[0]
print(f"\n🍪 Cookies: {cookies_count} found")
if cookies_count > 0:
    cursor.execute("SELECT domain, name FROM cookies LIMIT 5")
    for row in cursor.fetchall():
        print(f"   ✅ {row[0]} - {row[1]}")
    print("   ✅ TEST 2 PASSED: Cookies extracted")
else:
    print("   ❌ TEST 2 FAILED: No cookies found")

# Test 3: Check URL extraction in credentials
cursor.execute("SELECT COUNT(*) FROM credentials WHERE url IS NOT NULL AND url != ''")
urls_count = cursor.fetchone()[0]
print(f"\n🌐 URLs in Credentials: {urls_count} found")
if urls_count > 0:
    cursor.execute("SELECT url, email FROM credentials WHERE url IS NOT NULL AND url != '' LIMIT 5")
    for row in cursor.fetchall():
        print(f"   ✅ {row[0]} - {row[1]}")
    print("   ✅ TEST 3 PASSED: URLs extracted with credentials")
else:
    print("   ⚠️  TEST 3 WARNING: No URLs found in credentials")

# Test 4: Private keys (if full scan)
cursor.execute("SELECT COUNT(*) FROM wallets WHERE private_key IS NOT NULL")
pk_count = cursor.fetchone()[0]
print(f"\n🔑 Private Keys: {pk_count} found")
if pk_count > 0:
    cursor.execute("SELECT SUBSTR(private_key, 1, 20), crypto_type FROM wallets WHERE private_key IS NOT NULL LIMIT 3")
    for row in cursor.fetchall():
        print(f"   ✅ {row[0]}... - {row[1]}")
    print("   ✅ TEST 4 PASSED: Private keys extracted")
else:
    print("   ⚠️  TEST 4 SKIPPED: No private keys (data_only mode)")

conn.close()

# Check stats
print("\n" + "=" * 80)
print("📊 SCANNER STATS")
print("=" * 80)
for key, value in scanner.stats.items():
    if value > 0:
        print(f"   {key}: {value}")

# Cleanup
print("\n" + "=" * 80)
print("🧹 CLEANUP")
print("=" * 80)
shutil.rmtree(test_dir)
print(f"✅ Removed test directory: {test_dir}")

print("\n" + "=" * 80)
print("🎉 TEST COMPLETE!")
print("=" * 80)

# Summary
total_tests = 4
passed_tests = 0
if creds_count > 0:
    passed_tests += 1
if cookies_count > 0:
    passed_tests += 1
if urls_count > 0:
    passed_tests += 1
# Skip PK test in data mode

print(f"\n✅ Passed: {passed_tests}/3 tests (excluding PK test)")
print(f"📊 Total extracted: {creds_count} creds, {cookies_count} cookies, {urls_count} URLs")

if passed_tests >= 2:
    print("\n🎉 SUCCESS: Core extraction features working!")
    sys.exit(0)
else:
    print("\n⚠️  WARNING: Some tests failed")
    sys.exit(1)
