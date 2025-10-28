#!/bin/bash

# 🚀 Commit GitHub Actions Workflow
# This script commits the auto-build workflow to your repository

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     🤖 Committing GitHub Actions Auto-Build Workflow                        ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Navigate to repository
cd ~/Desktop/logs\ crypto/LulzSec-ULTIMATE-Forensic-Scanner-V2 || {
    echo "❌ Failed to navigate to repository"
    exit 1
}

echo "📍 Current directory: $(pwd)"
echo ""

# Add files
echo "📦 Adding files to git..."
git add .github/workflows/build-windows-exe.yml
git add GITHUB_BUILD_SOLUTION.md
git add START_HERE.md
git add auto_build.py

echo "✅ Files staged"
echo ""

# Show what will be committed
echo "📝 Changes to be committed:"
git status --short
echo ""

# Commit
echo "💾 Committing..."
git commit -m "🤖 Add GitHub Actions auto-build workflow for Windows EXE

- Added .github/workflows/build-windows-exe.yml
- Builds on Windows Server automatically
- Creates LulzSec-Forensic-Scanner.exe
- Uploads as downloadable artifact
- Updated documentation (GITHUB_BUILD_SOLUTION.md, START_HERE.md)
- Fixed Linux build limitation (requires --enable-shared Python)

Workflow triggers:
- On push to main branch
- Manual trigger from Actions tab

Download from: GitHub Actions -> Artifacts
Build time: ~3-5 minutes"

echo "✅ Committed!"
echo ""

# Push
echo "📤 Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║     ✅ SUCCESS! Workflow pushed to GitHub                                    ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🚀 Your Windows executable is now building automatically!"
    echo ""
    echo "📊 Check build status:"
    echo "   https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    echo ""
    echo "📦 After build completes (3-5 minutes):"
    echo "   1. Click on the workflow run"
    echo "   2. Scroll to 'Artifacts' section"
    echo "   3. Download 'LulzSec-Forensic-Scanner-Windows.zip'"
    echo ""
    echo "✅ Done! Your .exe will be ready soon!"
else
    echo ""
    echo "❌ Push failed! Check your GitHub credentials."
    echo "   Run: git push origin main"
fi
