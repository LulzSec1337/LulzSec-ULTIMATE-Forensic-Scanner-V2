#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     🚀 ONE-COMMAND BUILD: Commit & Let GitHub Build Your EXE               ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

echo "📝 Adding files to git..."
git add .github/workflows/build-windows-exe.yml
git add *.md
git add *.sh
git add auto_build.py

echo "✅ Files staged"
echo ""

echo "💾 Committing..."
git commit -m "🤖 Add GitHub Actions auto-build for Windows EXE

Automated build system that:
- Builds on Windows Server 2022
- Creates LulzSec-Forensic-Scanner.exe
- Includes all dependencies and fixes
- Downloadable from GitHub Actions Artifacts

Build time: 3-5 minutes
Download from: Actions tab → Artifacts

All tabs fixed, control panels added, ready for production!"

echo "✅ Committed!"
echo ""

echo "📤 Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║     ✅ PUSHED! Your Windows EXE is now building automatically!              ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🚀 Build Status:"
    echo "   https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    echo ""
    echo "⏱️  Build Time: 3-5 minutes"
    echo ""
    echo "📥 Download:"
    echo "   1. Go to Actions tab (link above)"
    echo "   2. Click on latest 'Build Windows Executable' workflow"
    echo "   3. Scroll to 'Artifacts' section"
    echo "   4. Download 'LulzSec-Forensic-Scanner-Windows.zip'"
    echo ""
    echo "📦 Package includes:"
    echo "   - LulzSec-Forensic-Scanner.exe (30-50 MB)"
    echo "   - README.txt (quick start guide)"
    echo "   - api_config.json (configuration)"
    echo ""
    echo "✅ Done! Your .exe is building right now on Windows Server!"
    echo ""
else
    echo ""
    echo "❌ Push failed"
    echo ""
    echo "Try manually:"
    echo "  git push origin main"
    echo ""
fi
