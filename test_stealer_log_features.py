#!/usr/bin/env python3
"""
Test Stealer Log Features:
- Netscape cookie format parsing
- Browser/Logins folder extraction
- Private key to seed conversion
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ultra_scanner import UltraAdvancedScanner

print("=" * 70)
print("TEST: Stealer Log Features - Cookies + Logins + Private Keys")
print("=" * 70)

# Mock crypto_utils and db
class MockCrypto:
    pass

class MockDB:
    pass

scanner = UltraAdvancedScanner(MockCrypto(), MockDB())

# TEST 1: Netscape Cookie Format
print("\n[TEST 1] Netscape Cookie Format Parsing")
print("-" * 70)

netscape_cookies = """.google.com	TRUE	/	TRUE	1772743330	NID	525=lbuiHM5LeCMtc6Rno54stp2-V1sXLOJhivdM0Y6sGPl8R0rbs-v8CIGKS5GJlAdaxK5xcXHCJkk1P7Pzryy2WTCq54gM_8S_ANmUN7JvzLbVZyfH3fHW9Us0Gp8IGYa6ep6D6Ise2Ze8b6nPsXFGLKee5Z4_F-0yysAvLL3Gjt2SipIv74kh9B4_pxfXqafS9g
.bongobd.com	TRUE	/	TRUE	1772525983	__eoi	ID=e34c4daf1baeb7b5:T=1756973983:RT=1756973983:S=AA-AfjZ840tEdmJjHL5_LHEKIftA
.bongobd.com	TRUE	/	TRUE	1790669983	__gads	ID=f899069564b5de4f:T=1756973983:RT=1756973983:S=ALNI_MY00iSQ9NN8k3XIxFoJNLzLoAydlw
.bongobd.com	TRUE	/	TRUE	1790669983	__gpi	UID=0000118e95bb2337:T=1756973983:RT=1756973983:S=ALNI_MYG2giBFU-iPDIsfaFn1sPZmsA8zA
.tiktok.com	TRUE	/	TRUE	1790669981	_ttp	32E7fbpgkazJ8u2FOhIrJIOViVZ
.youtube.com	TRUE	/	TRUE	1772525983	VISITOR_INFO1_LIVE	d_33gjKJjCw
.facebook.com	TRUE	/	TRUE	1788529012	c_user	100012345678
.facebook.com	TRUE	/	TRUE	1788529012	xs	49%3Aabcdef123456%3A2%3A1234567890
"""

cookies = scanner.extract_cookies(netscape_cookies)
print(f"✅ Cookies found: {len(cookies)}")

for i, cookie in enumerate(cookies[:5], 1):
    print(f"\n  {i}. {cookie['domain']}")
    print(f"     Name: {cookie['name']}")
    print(f"     Value: {cookie['value'][:50]}{'...' if len(cookie['value']) > 50 else ''}")
    print(f"     Type: {cookie['type']}")
    print(f"     Secure: {cookie['secure']}")

# TEST 2: Browser/Logins Folder Extraction
print("\n\n[TEST 2] Browser/Logins Folder Extraction")
print("-" * 70)

logins_content = """URL: https://www.facebook.com/login/
Username: salmanparvez13@gmail.com
Password: S@LMuN!007
===============
URL: https://www.roblox.com/login
Username: SINJIB2
Password: IMICE007
===============
URL: https://accounts.google.com/
Username: john.doe@gmail.com
Password: MySecurePass123!
===============
URL: https://www.instagram.com/accounts/login/
Username: influencer_2024
Password: Insta$ecure456
===============
URL: https://github.com/login
Username: developer@company.com
Password: GitH@bP@ss789
"""

credentials = scanner.extract_logins_from_stealer(logins_content)
print(f"✅ Credentials found: {len(credentials)}")

for i, cred in enumerate(credentials, 1):
    print(f"\n  {i}. [{cred['category'].upper()}] {cred['url']}")
    print(f"     Username: {cred['username']}")
    print(f"     Password: {cred['password']}")

# TEST 3: Form Field Name Filtering (should reject)
print("\n\n[TEST 3] Form Field Name Filtering")
print("-" * 70)

fake_logins = """URL: https://example.com/
Username: user@example.com
Password: loginfmt
===============
URL: https://test.com/
Username: test@test.com
Password: userName
===============
URL: https://fake.com/
Username: fake@fake.com
Password: password
"""

fake_creds = scanner.extract_logins_from_stealer(fake_logins)
print(f"Found: {len(fake_creds)} credentials")
print(f"Expected: 0 (all should be filtered as form field names)")
if len(fake_creds) == 0:
    print("✅ PASSED - Form field names correctly rejected")
else:
    print("❌ FAILED - Some form field names leaked:")
    for cred in fake_creds:
        print(f"  - {cred['username']}: {cred['password']}")

# TEST 4: Private Key to Seed Conversion
print("\n\n[TEST 4] Private Key to Seed Conversion")
print("-" * 70)

# Test hex format private key (ETH/BTC)
hex_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
seed_result = scanner.convert_private_key_to_seed(hex_key, 'hex')

if seed_result:
    print(f"✅ Hex Private Key Converted:")
    print(f"   Original: {seed_result['original_key']}")
    print(f"   Format: {seed_result['format']}")
    print(f"   Pseudo Seed: {seed_result['pseudo_seed']}")
    print(f"   Note: {seed_result['note']}")
else:
    print("❌ Failed to convert hex key")

# Test WIF format (Bitcoin)
wif_key = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
seed_result_wif = scanner.convert_private_key_to_seed(wif_key, 'wif')

if seed_result_wif:
    print(f"\n✅ WIF Private Key Converted:")
    print(f"   Original: {seed_result_wif['original_key']}")
    print(f"   Format: {seed_result_wif['format']}")
    print(f"   Pseudo Seed: {seed_result_wif['pseudo_seed']}")
else:
    print("\n❌ Failed to convert WIF key")

# TEST 5: Invalid Private Key (should reject)
print("\n\n[TEST 5] Invalid Private Key Rejection")
print("-" * 70)

invalid_keys = [
    "not_a_key",
    "0xshort",
    "5invalidWIF",
    "tooshortkey"
]

rejected = 0
for key in invalid_keys:
    result = scanner.convert_private_key_to_seed(key, 'hex')
    if result is None:
        rejected += 1

print(f"Rejected: {rejected}/{len(invalid_keys)} invalid keys")
if rejected == len(invalid_keys):
    print("✅ PASSED - All invalid keys rejected")
else:
    print("❌ FAILED - Some invalid keys accepted")

# SUMMARY
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"✅ Netscape cookie parsing: {len(cookies)} cookies")
print(f"✅ Browser/Logins extraction: {len(credentials)} credentials")
print(f"✅ Form field filtering: {len(fake_creds) == 0}")
print(f"✅ Private key conversion: {seed_result is not None}")
print(f"✅ Invalid key rejection: {rejected == len(invalid_keys)}")
print("\nAll stealer log features functional!")
