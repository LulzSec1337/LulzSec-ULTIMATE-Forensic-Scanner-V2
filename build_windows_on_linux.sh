#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║     🚀 Building Windows EXE on Linux using Wine + PyInstaller              ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

set -e  # Exit on error

# Step 1: Install Wine (Windows emulator)
echo "📦 Step 1: Installing Wine..."
echo "----------------------------------------"
sudo apt-get update -qq
sudo dpkg --add-architecture i386
sudo apt-get install -y -qq wine wine32 wine64 winetricks
echo "✅ Wine installed"
echo ""

# Step 2: Setup Wine Python environment
echo "🐍 Step 2: Setting up Python in Wine..."
echo "----------------------------------------"
export WINEPREFIX=$HOME/.wine
export WINEARCH=win64

# Download Python for Windows
PYTHON_INSTALLER="python-3.11.9-amd64.exe"
if [ ! -f "$PYTHON_INSTALLER" ]; then
    echo "📥 Downloading Python 3.11 for Windows..."
    wget -q https://www.python.org/ftp/python/3.11.9/$PYTHON_INSTALLER
fi

# Install Python in Wine
echo "🔧 Installing Python in Wine..."
wine $PYTHON_INSTALLER /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

# Wait for installation
sleep 5

echo "✅ Python installed in Wine"
echo ""

# Step 3: Install PyInstaller and dependencies in Wine Python
echo "📦 Step 3: Installing dependencies in Wine Python..."
echo "----------------------------------------"
wine python -m pip install --upgrade pip
wine python -m pip install pyinstaller ecdsa mnemonic pycryptodome requests base58 colorama

echo "✅ Dependencies installed"
echo ""

# Step 4: Build the executable
echo "🔨 Step 4: Building Windows executable..."
echo "----------------------------------------"
wine python -m PyInstaller \
    --onefile \
    --windowed \
    --name=LulzSec-Forensic-Scanner \
    --add-data="api_config.json;." \
    --hidden-import=tkinter \
    --hidden-import=tkinter.ttk \
    --hidden-import=tkinter.messagebox \
    --hidden-import=tkinter.filedialog \
    --hidden-import=sqlite3 \
    --hidden-import=ecdsa \
    --hidden-import=mnemonic \
    --hidden-import=Crypto \
    --hidden-import=Crypto.Cipher \
    --hidden-import=Crypto.Cipher.AES \
    --hidden-import=requests \
    --hidden-import=base58 \
    --hidden-import=colorama \
    --collect-all=tkinter \
    --collect-all=mnemonic \
    --collect-all=ecdsa \
    ext.py

echo "✅ Build complete!"
echo ""

# Step 5: Verify executable
echo "📦 Step 5: Verifying executable..."
echo "----------------------------------------"
if [ -f "dist/LulzSec-Forensic-Scanner.exe" ]; then
    SIZE=$(du -h "dist/LulzSec-Forensic-Scanner.exe" | cut -f1)
    echo "✅ Executable created successfully!"
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
    
    # Copy config
    cp api_config.json dist/
    
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║     ✅ BUILD SUCCESSFUL!                                                     ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📦 Files ready:"
    echo "   - dist/LulzSec-Forensic-Scanner.exe ($SIZE)"
    echo "   - dist/README.txt"
    echo "   - dist/api_config.json"
    echo ""
    echo "🚀 Next steps:"
    echo "   git add dist/"
    echo "   git commit -m '🚀 Add Windows Executable'"
    echo "   git push origin main"
else
    echo "❌ Build failed - executable not found"
    exit 1
fi
