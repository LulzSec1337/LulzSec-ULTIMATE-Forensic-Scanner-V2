#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════
#   Build Windows .exe on Linux using Wine + PyInstaller
# ════════════════════════════════════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════════════"
echo "  🍷 Building Windows .exe on Linux (Wine + PyInstaller)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

cd "$(dirname "$0")"

# Check if Wine is installed
if ! command -v wine &> /dev/null; then
    echo "⚠️  Wine not installed. Installing..."
    echo ""
    sudo dpkg --add-architecture i386
    sudo apt update
    sudo apt install -y wine wine32 wine64 winetricks
    echo ""
fi

# Check if Python for Windows is installed in Wine
if [ ! -d "$HOME/.wine/drive_c/Python311" ]; then
    echo "📥 Installing Python 3.11 for Windows in Wine..."
    echo "   (This takes 3-5 minutes first time)"
    echo ""
    
    # Download Python installer
    wget -q https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe -O /tmp/python311.exe
    
    # Install Python silently
    wine /tmp/python311.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    
    rm /tmp/python311.exe
    echo "✅ Python for Windows installed"
    echo ""
fi

PYTHON_WIN="wine $HOME/.wine/drive_c/Python311/python.exe"
PIP_WIN="wine $HOME/.wine/drive_c/Python311/Scripts/pip.exe"

echo "📦 Installing PyInstaller + dependencies in Windows Python..."
$PIP_WIN install --upgrade pip --quiet 2>/dev/null
$PIP_WIN install pyinstaller ecdsa mnemonic pycryptodome requests base58 colorama --quiet 2>/dev/null
echo "✅ Installed"
echo ""

# Create api_config.json if missing
if [ ! -f "api_config.json" ]; then
    echo '{"etherscan_api_key":"","bscscan_api_key":"","blockcypher_token":"","blockchain_info_key":""}' > api_config.json
fi

echo "═══════════════════════════════════════════════════════════════"
echo "🔨 Building: LulzSec-Forensic-Scanner.exe"
echo "═══════════════════════════════════════════════════════════════"
echo "⏳ Building with Wine... (slower than native, 5-10 min)"
echo ""

# Clean old builds
rm -rf build dist *.spec

# Check if icon exists
ICON_FLAG=""
if [ -f "lulzsec_icon.ico" ]; then
    ICON_FLAG="--icon=lulzsec_icon.ico"
    echo "🎨 Using custom LulzSec icon"
fi

# Build with Wine
wine "$HOME/.wine/drive_c/Python311/Scripts/pyinstaller.exe" \
    --onefile \
    --windowed \
    $ICON_FLAG \
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

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ LulzSec-Forensic-Scanner.exe built!"
    echo ""
else
    echo ""
    echo "❌ Build failed"
    exit 1
fi

# Build GUI Launcher if run_gui.py exists
if [ -f "run_gui.py" ]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "🔨 Building: LulzSec-GUI-Launcher.exe"
    echo "═══════════════════════════════════════════════════════════════"
    
    wine "$HOME/.wine/drive_c/Python311/Scripts/pyinstaller.exe" \
        --onefile \
        --windowed \
        $ICON_FLAG \
        --name=LulzSec-GUI-Launcher \
        --add-data="api_config.json;." \
        --hidden-import=tkinter \
        --hidden-import=tkinter.ttk \
        --hidden-import=tkinter.messagebox \
        --hidden-import=tkinter.filedialog \
        --hidden-import=sqlite3 \
        --collect-all=tkinter \
        run_gui.py
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ LulzSec-GUI-Launcher.exe built!"
        echo ""
    fi
fi

# Create README
cat > dist/README.txt << 'EOF'
# LulzSec Forensic Scanner v2.0 - Windows Edition

## Quick Start:
1. Double-click LulzSec-Forensic-Scanner.exe
2. If Windows Defender blocks: Click "More info" then "Run anyway"
3. Select stealer logs folder
4. Click "SCAN ALL DATA"

## 2 Apps Included:
- LulzSec-Forensic-Scanner.exe (Main)
- LulzSec-GUI-Launcher.exe (Alternative GUI)

## Features: 9 tabs, Control panels, Export, Database
Support: @Lulz1337

Built on Linux with Wine - fully compatible with Windows
EOF

cp api_config.json dist/ 2>/dev/null

echo "═══════════════════════════════════════════════════════════════"
echo "            ✅ BUILD COMPLETE!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "📦 Windows executables in dist/ folder:"
ls -lh dist/*.exe 2>/dev/null
echo ""
echo "🪟 Transfer to Windows and test!"
echo "💾 Size: ~49MB (main), ~26MB (GUI)"
echo ""
