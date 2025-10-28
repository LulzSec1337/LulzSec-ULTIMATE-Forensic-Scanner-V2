#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     🚀 Building Windows EXE using Nuitka (Cross-Compiler)                  ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

cd /workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2

# Install Nuitka (Python to C++ compiler that can cross-compile)
echo "📦 Installing Nuitka..."
pip3 install -q nuitka ordered-set zstandard

# Try to install MinGW for Windows cross-compilation
echo "📦 Installing MinGW (Windows compiler)..."
sudo apt-get update -qq
sudo apt-get install -y -qq mingw-w64 gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 || true

echo "✅ Compilers installed"
echo ""

# Create dist directory
mkdir -p dist
rm -rf dist/LulzSec-Forensic-Scanner.*

echo "🔨 Compiling to Windows executable with Nuitka..."
echo "This may take 5-10 minutes..."
echo ""

# Compile with Nuitka for Windows target
python3 -m nuitka \
    --onefile \
    --windows-disable-console \
    --output-dir=dist \
    --output-filename=LulzSec-Forensic-Scanner.exe \
    --include-data-files=api_config.json=api_config.json \
    --enable-plugin=tk-inter \
    --target-arch=x86_64 \
    --windows-icon-from-ico=icon.ico \
    --product-name="LulzSec Forensic Scanner" \
    --product-version="2.0.0.0" \
    --file-description="Ultimate Forensic Scanner for Crypto Wallets" \
    --copyright="LulzSec 2025" \
    --follow-imports \
    --assume-yes-for-downloads \
    ext.py 2>&1 | grep -v "Nuitka-Plugins:" | grep -v "Nuitka:INFO" || true

if [ -f "dist/LulzSec-Forensic-Scanner.exe" ]; then
    SIZE=$(du -h "dist/LulzSec-Forensic-Scanner.exe" | cut -f1)
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║     ✅ BUILD SUCCESSFUL!                                                     ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📦 File: dist/LulzSec-Forensic-Scanner.exe"
    echo "📊 Size: $SIZE"
    echo ""
    
    # Create README
    cat > dist/README.txt << 'EOF'
# LulzSec Forensic Scanner v2.0 - Windows Edition

## Quick Start:
1. Double-click LulzSec-Forensic-Scanner.exe
2. If Windows Defender blocks it, click "More info" then "Run anyway"
3. Select your stealer logs folder
4. Click "SCAN ALL DATA"

## Features:
- Extract crypto wallets and seed phrases
- Find credentials from browsers  
- Detect control panels (cPanel, Plesk, WHM)
- Export to Excel/CSV

Support: @Lulz1337
EOF
    
    cp api_config.json dist/
    
    echo "📦 Package ready in dist/ folder!"
    echo ""
    echo "🚀 Commit to repository:"
    echo "   git add dist/"
    echo "   git commit -m '🚀 Windows Executable v2.0'"
    echo "   git push origin main"
    
else
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║     ❌ CROSS-COMPILATION NOT AVAILABLE                                       ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "❌ Cannot cross-compile Windows .exe on this Linux system"
    echo ""
    echo "✅ SOLUTION: Use GitHub Actions (fastest and most reliable!)"
    echo ""
    echo "Run these commands:"
    echo ""
    echo "  chmod +x COMMIT_NOW.sh"
    echo "  ./COMMIT_NOW.sh"
    echo ""
    echo "Then visit:"
    echo "  https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2/actions"
    echo ""
    echo "Your Windows .exe will be ready in 3-5 minutes!"
    echo ""
fi
