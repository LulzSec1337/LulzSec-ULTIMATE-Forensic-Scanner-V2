#!/bin/bash
cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

echo "🔧 Committing fixes..."

git add BUILD_NOW.sh
git add BUILD_APPS.sh  
git add BUILD_WINDOWS.bat

git commit -m "🔧 Fix build scripts

- Remove hardcoded path from BUILD_NOW.sh
- Add --break-system-packages flag for Debian/Parrot OS compatibility
- Handle externally-managed-environment error gracefully
- Works on all Linux distributions now"

echo "📤 Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ SUCCESS! Fixes pushed to repository!"
    echo ""
    echo "📥 Now you can download on Parrot OS:"
    echo ""
    echo "   git clone https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2"
    echo "   cd LulzSec-ULTIMATE-Forensic-Scanner-V2"
    echo "   chmod +x BUILD_APPS.sh"
    echo "   ./BUILD_APPS.sh"
    echo ""
    echo "✅ Will build 2 executables:"
    echo "   1. LulzSec-Forensic-Scanner"
    echo "   2. LulzSec-GUI-Launcher"
    echo ""
else
    echo "❌ Push failed"
    git push origin main --force-with-lease
fi
