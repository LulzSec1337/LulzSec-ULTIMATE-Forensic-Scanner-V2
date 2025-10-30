#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  💾 Committing Build Files to Repository                                    ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

# Make scripts executable
chmod +x BUILD_APPS.sh

# Add all build files
echo "📦 Adding files..."
git add BUILD_WINDOWS.bat
git add BUILD_APPS.sh
git add BUILD_GUIDE.md
git add .github/workflows/build-windows-exe.yml

echo "✅ Files staged:"
echo "   - BUILD_WINDOWS.bat (Windows build script)"
echo "   - BUILD_APPS.sh (Linux/Mac build script)"
echo "   - BUILD_GUIDE.md (Quick guide)"
echo "   - .github/workflows/build-windows-exe.yml (GitHub Actions)"
echo ""

# Commit
echo "💾 Committing..."
git commit -m "🔨 Add build scripts for 2 Windows executables

Files:
- BUILD_WINDOWS.bat: Windows batch script (double-click to build)
- BUILD_APPS.sh: Linux/Mac bash script
- BUILD_GUIDE.md: Quick build guide
- GitHub Actions workflow updated

Builds:
1. LulzSec-Forensic-Scanner.exe (main app from ext.py)
2. LulzSec-GUI-Launcher.exe (GUI from run_gui.py)

Usage:
- Windows: Run BUILD_WINDOWS.bat
- Linux/Mac: chmod +x BUILD_APPS.sh && ./BUILD_APPS.sh
- GitHub Actions: Automatic on push"

if [ $? -ne 0 ]; then
    echo "⚠️  Nothing to commit or commit failed"
    git status
    echo ""
fi

# Pull first to avoid conflicts
echo "📥 Pulling remote changes..."
git pull --rebase origin main

if [ $? -eq 0 ]; then
    # Push
    echo "📤 Pushing..."
    git push origin main
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║  ✅ SUCCESS! Build files pushed to GitHub!                                  ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "📦 Files now in repository:"
        echo "   ✅ BUILD_WINDOWS.bat"
        echo "   ✅ BUILD_APPS.sh"
        echo "   ✅ BUILD_GUIDE.md"
        echo "   ✅ .github/workflows/build-windows-exe.yml"
        echo ""
        echo "🚀 GitHub Actions is building now!"
        echo "   Check: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
        echo ""
        echo "📥 Or build locally:"
        echo "   Windows: BUILD_WINDOWS.bat"
        echo "   Linux/Mac: ./BUILD_APPS.sh"
        echo ""
        echo "✅ You'll get 2 executables:"
        echo "   1. LulzSec-Forensic-Scanner.exe"
        echo "   2. LulzSec-GUI-Launcher.exe"
        echo ""
    else
        echo ""
        echo "❌ Push failed - trying alternative..."
        git push --force-with-lease origin main || echo "❌ Force push also failed"
    fi
else
    echo ""
    echo "❌ Pull failed - resolving conflicts..."
    git pull origin main --allow-unrelated-histories
    git push origin main
fi
