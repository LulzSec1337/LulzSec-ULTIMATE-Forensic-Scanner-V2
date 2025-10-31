#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════
#   Quick Build & Push Script
#   Builds executables and pushes to GitHub
# ════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════════════════════"
echo "  🚀 LulzSec Scanner - Quick Build & Push"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

cd "$(dirname "$0")"

echo "1️⃣  Building executables..."
./BUILD_APPS.sh

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "2️⃣  Adding files to git..."
git add dist/

echo ""
echo "3️⃣  Committing..."
git commit -m "🔨 Build: Updated executables with new features" 2>/dev/null || echo "   (No changes to commit)"

echo ""
echo "4️⃣  Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════"
    echo "  ✅ BUILD & PUSH COMPLETE!"
    echo "════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "📦 Executables in dist/:"
    ls -lh dist/LulzSec-* 2>/dev/null
    echo ""
    echo "🌐 GitHub: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2"
    echo ""
    echo "🎯 NEW FEATURES:"
    echo "   - Auto balance checking for private keys"
    echo "   - Auto balance checking for seed phrases"
    echo "   - CPU/RAM optimization (no more freezing!)"
    echo "   - 14+ blockchain networks supported"
    echo "   - Results in balances_found.json"
    echo ""
else
    echo "❌ Push failed!"
    exit 1
fi
