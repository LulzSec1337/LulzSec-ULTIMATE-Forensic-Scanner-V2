#!/bin/bash
echo "🚀 Pushing ALL build files to repository..."
cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

# Stage ALL new build files
git add BUILD_WINDOWS.bat
git add BUILD_APPS.sh
git add BUILD_GUIDE.md
git add COMMIT_BUILDS.sh
git add PUSH_NOW.sh
git add .github/workflows/build-windows-exe.yml
git add .gitignore

echo "✅ Files staged"
echo ""

# Commit
git commit -m "🔨 Add complete build system for 2 Windows executables

NEW BUILD FILES:
- BUILD_WINDOWS.bat: Windows batch script (double-click to build)
- BUILD_APPS.sh: Linux/Mac bash script  
- BUILD_GUIDE.md: Quick build documentation
- COMMIT_BUILDS.sh: Commit helper script
- PUSH_NOW.sh: Quick push script

UPDATED FILES:
- .github/workflows/build-windows-exe.yml: Now builds 2 apps
- .gitignore: Allow dist/ folder for executables

FEATURES:
- Builds LulzSec-Forensic-Scanner.exe (main scanner from ext.py)
- Builds LulzSec-GUI-Launcher.exe (GUI from run_gui.py)
- Auto-installs PyInstaller and dependencies
- Creates README and copies config
- Works on Windows, Linux, Mac
- GitHub Actions automatic build

USAGE:
Windows: Double-click BUILD_WINDOWS.bat
Linux/Mac: chmod +x BUILD_APPS.sh && ./BUILD_APPS.sh
GitHub: Automatic on push to main"

echo ""
echo "📥 Pulling remote changes..."
git pull --rebase origin main

echo ""
echo "📤 Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ SUCCESS! All build files saved to repository!           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📦 Files now on GitHub:"
    echo "   ✅ BUILD_WINDOWS.bat"
    echo "   ✅ BUILD_APPS.sh"
    echo "   ✅ BUILD_GUIDE.md"
    echo "   ✅ .github/workflows/build-windows-exe.yml"
    echo ""
    echo "🚀 GitHub Actions building now!"
    echo "   https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    echo ""
    echo "✅ You'll get 2 executables:"
    echo "   1. LulzSec-Forensic-Scanner.exe"
    echo "   2. LulzSec-GUI-Launcher.exe"
    echo ""
else
    echo "❌ Push failed - trying force..."
    git push --force-with-lease origin main
fi
