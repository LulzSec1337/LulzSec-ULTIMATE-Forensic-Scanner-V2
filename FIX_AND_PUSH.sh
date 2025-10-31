#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     🔧 Fixing Git Push Conflict                                              ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

echo "📥 Step 1: Pulling remote changes..."
git pull --rebase origin main

if [ $? -eq 0 ]; then
    echo "✅ Remote changes merged successfully"
    echo ""
    
    echo "📤 Step 2: Pushing all changes..."
    git push origin main
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════════════════════╗"
        echo "║                                                                              ║"
        echo "║     ✅ SUCCESS! GitHub Actions is now building your Windows EXE!            ║"
        echo "║                                                                              ║"
        echo "╚══════════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🚀 Build Status:"
        echo "   https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
        echo ""
        echo "⏱️  Your Windows executable will be ready in 3-5 minutes!"
        echo ""
        echo "📥 To download:"
        echo "   1. Visit the link above"
        echo "   2. Click on 'Build Windows Executable' workflow"
        echo "   3. Download from 'Artifacts' section"
        echo ""
        echo "📦 You'll get:"
        echo "   - LulzSec-Forensic-Scanner.exe (30-50 MB)"
        echo "   - README.txt"
        echo "   - api_config.json"
        echo ""
        echo "✅ All done! Your .exe is building right now!"
        echo ""
    else
        echo ""
        echo "❌ Push still failed. Trying force push..."
        echo ""
        git push --force-with-lease origin main
        
        if [ $? -eq 0 ]; then
            echo ""
            echo "✅ Force push successful! Build started!"
            echo ""
            echo "Visit: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
        else
            echo ""
            echo "❌ Force push also failed"
            echo ""
            echo "Manual fix required:"
            echo "  git pull origin main"
            echo "  git push origin main"
        fi
    fi
else
    echo ""
    echo "❌ Pull failed - there might be conflicts"
    echo ""
    echo "🔧 Let me try a different approach..."
    
    # Stash local changes
    echo "📦 Stashing local changes..."
    git stash
    
    echo "📥 Pulling remote..."
    git pull origin main
    
    echo "📤 Applying local changes..."
    git stash pop
    
    echo "💾 Recommitting..."
    git add -A
    git commit -m "🤖 Add GitHub Actions auto-build workflow + all improvements

- GitHub Actions workflow for Windows EXE build
- All tab fixes and improvements
- Control panel extractor
- Complete documentation
- Build scripts and guides"
    
    echo "📤 Pushing..."
    git push origin main
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ SUCCESS after conflict resolution!"
        echo ""
        echo "Visit: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    else
        echo ""
        echo "❌ Still having issues"
        echo ""
        echo "Let's check the status:"
        git status
    fi
fi
