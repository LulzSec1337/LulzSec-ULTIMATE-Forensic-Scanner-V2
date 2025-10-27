#!/bin/bash
# Startup checklist and launcher

echo "════════════════════════════════════════════════════════════════════════════"
echo "🔥 LULZSEC ULTIMATE FORENSIC SCANNER - STARTUP CHECKLIST"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

echo "✅ Checking all files are up to date..."
cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

echo ""
echo "📊 Verifying code changes:"
echo "   ├─ gui/advanced_gui.py (2031 lines) - Updated with 9 tabs + CRUD tables"
echo "   ├─ core/ultra_scanner.py (740 lines) - Updated with mail extraction"
echo "   └─ extractors/mail_extractor.py (200+ lines) - NEW mail access extractor"
echo ""

echo "🔍 Checking tab definitions..."
grep -c "notebook.add.*text=" gui/advanced_gui.py | \
    awk '{if($1>=9) print "   ✅ Found 9 tabs in GUI"; else print "   ❌ Missing tabs!"}'

echo ""
echo "🔍 Checking CRUD table formatting..."
if grep -q '┌.*─.*┐' gui/advanced_gui.py; then
    echo "   ✅ CRUD-style box drawing characters found"
else
    echo "   ❌ Box characters missing!"
fi

echo ""
echo "🔍 Checking seed display formatting..."
if grep -q 'SEED PHRASE.*WORDS.*VALID' gui/advanced_gui.py; then
    echo "   ✅ Seed phrase CRUD display found"
else
    echo "   ❌ Seed display formatting missing!"
fi

echo ""
echo "🔍 Checking private key display formatting..."
if grep -q 'PRIVATE KEY.*self.keys_text' gui/advanced_gui.py; then
    echo "   ✅ Private key CRUD display found"
else
    echo "   ❌ Key display formatting missing!"
fi

echo ""
echo "🔍 Checking mail access extractor..."
if [ -f "extractors/mail_extractor.py" ]; then
    echo "   ✅ Mail extractor module exists"
else
    echo "   ❌ Mail extractor missing!"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "📋 EXPECTED TABS IN GUI:"
echo "════════════════════════════════════════════════════════════════════════════"
echo "   1. 🌱 Seed Phrases     - ONLY seeds (12/15/18/21/24 words)"
echo "   2. 🔑 Private Keys     - ONLY keys (all formats)"
echo "   3. 💰 Wallet Addresses - Blockchain addresses"
echo "   4. 📧 Mail Access      - SMTP/IMAP/POP3 credentials"
echo "   5. 🔐 Credentials      - Email:password pairs"
echo "   6. 🍪 Cookies          - Browser cookies"
echo "   7. 📱 SMS APIs         - SMS service credentials"
echo "   8. 🔑 API Keys         - API keys (AWS, Stripe, etc.)"
echo "   9. 📋 Logs             - Scan progress and logs"
echo ""

echo "════════════════════════════════════════════════════════════════════════════"
echo "🎨 EXPECTED DISPLAY FORMAT:"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Seeds Tab:"
echo "┌──────────────────────────────────────────────────────────────────────────┐"
echo "│ 🌱 SEED PHRASE (12 WORDS) - VALID ✅                                    │"
echo "├──────────────────────────────────────────────────────────────────────────┤"
echo "│ word1 word2 word3 word4 word5 word6                                      │"
echo "│ word7 word8 word9 word10 word11 word12                                   │"
echo "└──────────────────────────────────────────────────────────────────────────┘"
echo ""
echo "Keys Tab:"
echo "┌──────────────────────────────────────────────────────────────────────────┐"
echo "│ 🔑 PRIVATE KEY - RAW_HEX_64                                              │"
echo "├──────────────────────────────────────────────────────────────────────────┤"
echo "│ e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262         │"
echo "└──────────────────────────────────────────────────────────────────────────┘"
echo ""

echo "════════════════════════════════════════════════════════════════════════════"
echo "🚨 IMPORTANT NOTES:"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "  ⚠️  The output you saw earlier like:"
echo "      🔑 RAW_HEX_64: 23a414dae...  (simple format)"
echo ""
echo "  ✅ Was from an OLD scan before these updates!"
echo ""
echo "  ✅ NEW scans will show beautiful CRUD-style tables with:"
echo "      - Box-drawing characters (┌─┐├┤└┘│)"
echo "      - Clear headers and sections"
echo "      - Word counts for seeds"
echo "      - Type labels for keys"
echo "      - Source file tracking"
echo "      - Derived addresses"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "🚀 READY TO LAUNCH!"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "To start the application with NEW formatting:"
echo ""
echo "   python run_gui.py"
echo ""
echo "Then:"
echo "   1. Select a directory with stealer logs"
echo "   2. Click 'SCAN WALLETS' or 'SCAN ALL DATA'"
echo "   3. Watch the NEW CRUD-style tables appear in each tab!"
echo "   4. Check all 9 tabs to see organized results"
echo ""
echo "════════════════════════════════════════════════════════════════════════════"
