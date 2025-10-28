#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     🚀 FAST SOLUTION: Create Portable Python Bundle                        ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

set -e

cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

# Create a portable bundle that works on Windows
echo "📦 Creating portable bundle..."
echo "----------------------------------------"

# Install dependencies
pip3 install -q shiv pex zipapp

# Create dist directory
mkdir -p dist
rm -rf dist/*

# Create a self-contained Python archive
echo "🔨 Building portable archive..."
python3 -m zipapp . \
    --python="/usr/bin/env python3" \
    --output=dist/lulzsec-scanner.pyz \
    --main=ext:main

echo "✅ Created dist/lulzsec-scanner.pyz"
echo ""

# Alternative: Create executable with shiv
echo "🔨 Building executable with Shiv..."
shiv -c ext \
    -o dist/lulzsec-scanner \
    --python="/usr/bin/env python3" \
    --site-packages=/home/codespace/.local/lib/python3.12/site-packages \
    .

echo "✅ Created dist/lulzsec-scanner"
echo ""

# Make it executable
chmod +x dist/lulzsec-scanner

# Try one more approach - use pex
echo "🔨 Building executable with PEX..."
pex . -o dist/lulzsec-scanner.pex -c ext

echo "✅ Created dist/lulzsec-scanner.pex"
echo ""

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     ⚠️  LINUX LIMITATION ACKNOWLEDGED                                        ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "❌ Cannot create Windows .exe on Linux without:"
echo "   - Wine (requires sudo, very slow)"
echo "   - Docker with Windows container (not available)"
echo "   - Python compiled with --enable-shared"
echo ""
echo "✅ BEST SOLUTION: GitHub Actions (already set up!)"
echo ""
echo "📦 What I created instead:"
echo "   - dist/lulzsec-scanner.pyz  (Python zip app)"
echo "   - dist/lulzsec-scanner      (Linux executable)"
echo "   - dist/lulzsec-scanner.pex  (PEX executable)"
echo ""
echo "🚀 To get Windows .exe, use GitHub Actions:"
echo "   1. git add .github/workflows/build-windows-exe.yml"
echo "   2. git commit -m '🤖 Add auto-build workflow'"
echo "   3. git push origin main"
echo "   4. Visit: https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
echo "   5. Download .exe from Artifacts (ready in 3-5 minutes)"
echo ""

