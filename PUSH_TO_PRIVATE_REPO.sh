#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  🔐 Saving Files to PRIVATE Repository                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

echo "📊 Checking git status..."
git status

echo ""
echo "📦 Adding all build files..."
git add BUILD_WINDOWS.bat
git add BUILD_APPS.sh
git add BUILD_GUIDE.md
git add COMMIT_BUILDS.sh
git add PUSH_NOW.sh
git add SAVE_ALL_NOW.sh
git add .github/workflows/build-windows-exe.yml
git add .gitignore

echo ""
echo "✅ Files staged for commit"
echo ""

echo "💾 Committing files..."
git commit -m "🔨 Add build system for 2 Windows executables

BUILD SCRIPTS:
- BUILD_WINDOWS.bat: Windows batch script (double-click to build)
- BUILD_APPS.sh: Linux/Mac bash script
- BUILD_GUIDE.md: Quick documentation

GITHUB ACTIONS:
- Updated workflow to build 2 executables
- LulzSec-Forensic-Scanner.exe (main scanner)
- LulzSec-GUI-Launcher.exe (GUI launcher)

FEATURES:
- Auto-installs PyInstaller and dependencies
- Builds standalone Windows executables
- No Python required on target machine
- All 9 tabs, control panels, export features included

USAGE:
Windows: Run BUILD_WINDOWS.bat
Linux/Mac: chmod +x BUILD_APPS.sh && ./BUILD_APPS.sh
GitHub Actions: Automatic on push"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Commit successful!"
    echo ""
else
    echo ""
    echo "⚠️  Nothing to commit (files may already be committed)"
    echo ""
fi

echo "📥 Pulling remote changes first..."
git pull origin main --no-rebase

echo ""
echo "📤 Attempting to push..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║  ✅ SUCCESS! All files saved to your PRIVATE repository!                    ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📦 Build files now available in repository:"
    echo "   ✅ BUILD_WINDOWS.bat"
    echo "   ✅ BUILD_APPS.sh"
    echo "   ✅ BUILD_GUIDE.md"
    echo "   ✅ .github/workflows/build-windows-exe.yml"
    echo ""
    echo "🚀 GitHub Actions will build automatically!"
    echo "   https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    echo ""
    echo "📥 Download executables from Actions > Artifacts (3-5 mins)"
    echo ""
    echo "✅ You'll get 2 Windows executables:"
    echo "   1. LulzSec-Forensic-Scanner.exe"
    echo "   2. LulzSec-GUI-Launcher.exe"
    echo ""
else
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║  ⚠️  AUTHENTICATION REQUIRED (Private Repo)                                  ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🔐 Your repository is PRIVATE - authentication needed"
    echo ""
    echo "📝 Option 1: Use GitHub CLI (Recommended)"
    echo "   gh auth login"
    echo "   git push origin main"
    echo ""
    echo "📝 Option 2: Use Personal Access Token"
    echo "   1. Go to: https://github.com/settings/tokens"
    echo "   2. Generate new token (classic)"
    echo "   3. Select: repo (full control)"
    echo "   4. Copy token"
    echo "   5. Run:"
    echo "      git remote set-url origin https://YOUR_TOKEN@github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2.git"
    echo "      git push origin main"
    echo ""
    echo "📝 Option 3: Use SSH"
    echo "   git remote set-url origin git@github.com:LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2.git"
    echo "   git push origin main"
    echo ""
    echo "🔍 Current remote URL:"
    git remote -v
    echo ""
fi
