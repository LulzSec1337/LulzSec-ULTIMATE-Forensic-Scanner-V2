#!/bin/bash

echo "════════════════════════════════════════════════════════════════"
echo "  🚀 Trigger GitHub Actions to Build Windows .exe"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Wine build failed on Parrot OS."
echo "Using GitHub Actions instead (easiest method)!"
echo ""
echo "GitHub will automatically build Windows .exe files with:"
echo "  ✅ LulzSec icon"
echo "  ✅ Both executables (Scanner + GUI)"
echo "  ✅ Ready to download"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📋 STEPS:"
echo ""
echo "1️⃣  Push to trigger auto-build:"
echo "   cd ~/build/LulzSec-ULTIMATE-Forensic-Scanner-V2"
echo "   git add ."
echo "   git commit -m 'Trigger build'"
echo "   git push origin main"
echo ""
echo "2️⃣  Wait 2-3 minutes for build to complete"
echo ""
echo "3️⃣  Download .exe files from:"
echo "   https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
echo ""
echo "4️⃣  Click latest workflow → Artifacts → Download ZIP"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "💡 OR manually trigger workflow:"
echo "   Go to: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
echo "   Click: 'Build Windows Executable'"
echo "   Click: 'Run workflow' button"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check if GitHub CLI is installed
if command -v gh &> /dev/null; then
    echo "🔧 GitHub CLI detected! Want to trigger build now? (y/n)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        cd ~/build/LulzSec-ULTIMATE-Forensic-Scanner-V2
        gh workflow run build-windows-exe.yml
        echo ""
        echo "✅ Workflow triggered!"
        echo "   Check status: gh run list"
        echo "   Or visit: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    fi
else
    echo "💡 Install GitHub CLI for easier workflow management:"
    echo "   sudo apt install gh"
fi

echo ""
