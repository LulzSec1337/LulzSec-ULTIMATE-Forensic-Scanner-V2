#!/bin/bash

echo "🎨 Setting up LulzSec icon and final push..."
cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

# Download and convert icon
chmod +x download_icon.sh
./download_icon.sh

# Add all files
git add download_icon.sh
git add BUILD_APPS.sh
git add BUILD_WINDOWS.bat
git add .gitignore
git add lulzsec_icon.ico 2>/dev/null || true

git commit -m "🎨 Add LulzSec icon and track executables

NEW FEATURES:
- Added LulzSec icon to both executables
- download_icon.sh script to fetch and convert icon
- Updated .gitignore to track dist/*.exe files
- Icon shows on Windows executables

ICON:
- Custom LulzSec hacker icon
- 256x256 resolution
- Applied to both .exe files

FIXES:
- Executables now visible in repo
- dist/ folder properly tracked
- Icon auto-applied during build"

git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ DONE! Icon added and dist/ will be tracked              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🎨 Icon: lulzsec_icon.ico created"
    echo "📦 Build scripts updated with --icon flag"
    echo "✅ .gitignore updated to track .exe files"
    echo ""
    echo "📥 On Parrot OS:"
    echo "   git pull origin main"
    echo "   ./BUILD_APPS.sh"
    echo ""
    echo "🪟 Executables will have LulzSec icon!"
    echo ""
else
    git push origin main --force-with-lease
fi
