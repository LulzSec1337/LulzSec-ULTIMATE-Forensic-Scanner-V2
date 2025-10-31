#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════
#   LulzSec Forensic Scanner - Build Script (Linux/Mac/Windows)
#   Builds 2 executables
# ════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════════════════════"
echo "       🚀 LulzSec Forensic Scanner - Builder 🚀"
echo "              Building 2 Applications"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not installed!"
    exit 1
fi

echo "✅ Python: $(python3 --version)"
echo ""

echo "📦 Installing dependencies (with --break-system-packages for Parrot/Debian)..."
python3 -m pip install --upgrade pip --break-system-packages -q 2>/dev/null || pip3 install --upgrade pip -q
python3 -m pip install pyinstaller ecdsa mnemonic pycryptodome requests base58 colorama psutil --break-system-packages -q 2>/dev/null || pip3 install pyinstaller ecdsa mnemonic pycryptodome requests base58 colorama psutil -q
echo "✅ Installed"
echo ""

# Create api_config.json if missing
if [ ! -f "api_config.json" ]; then
    echo "📝 Creating api_config.json..."
    cat > api_config.json << 'EOF'
{
  "etherscan_api_key": "",
  "bscscan_api_key": "",
  "polygonscan_api_key": "",
  "ftmscan_api_key": "",
  "arbiscan_api_key": "",
  "optimism_api_key": "",
  "snowtrace_api_key": "",
  "hecoinfo_api_key": "",
  "moonscan_api_key": "",
  "cronoscan_api_key": ""
}
EOF
    echo "✅ Created api_config.json"
fi
echo ""

echo "🧹 Cleaning..."
rm -rf build dist *.spec
echo "✅ Cleaned"
echo ""

echo "🔨 Building Main Scanner..."

# Build with icon if available
if [ -f "lulzsec_icon.ico" ]; then
    ICON_ARG="--icon=lulzsec_icon.ico"
    echo "   ✅ Using LulzSec icon"
else
    ICON_ARG=""
    echo "   ⚠️  No icon found (run download_icon.sh)"
fi

python3 -m PyInstaller --onefile --windowed \
    --name=LulzSec-Forensic-Scanner \
    $ICON_ARG \
    --add-data="api_config.json:." \
    --hidden-import=tkinter --hidden-import=tkinter.ttk \
    --hidden-import=tkinter.messagebox --hidden-import=tkinter.filedialog \
    --hidden-import=sqlite3 --hidden-import=ecdsa --hidden-import=mnemonic \
    --hidden-import=Crypto --hidden-import=Crypto.Cipher \
    --hidden-import=Crypto.Cipher.AES --hidden-import=requests \
    --hidden-import=base58 --hidden-import=colorama \
    --collect-all=tkinter --collect-all=mnemonic --collect-all=ecdsa \
    ext.py

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi
echo "✅ Main Scanner built!"
echo ""

echo "🔨 Building GUI Launcher..."
if [ -f "run_gui.py" ]; then
    python3 -m PyInstaller --onefile --windowed \
        --name=LulzSec-GUI-Launcher \
        $ICON_ARG \
        --add-data="api_config.json:." \
        --hidden-import=tkinter --hidden-import=tkinter.ttk \
        --hidden-import=tkinter.messagebox --hidden-import=tkinter.filedialog \
        --hidden-import=sqlite3 --collect-all=tkinter \
        run_gui.py
    [ $? -eq 0 ] && echo "✅ GUI Launcher built!" || echo "⚠️  GUI build failed"
else
    echo "⚠️  run_gui.py not found"
fi
echo ""

echo "📝 Creating README..."
cat > dist/README.txt << 'EOF'
# LulzSec Forensic Scanner v2.0

## Quick Start:
1. Run LulzSec-Forensic-Scanner(.exe)
2. Select stealer logs folder
3. Click "SCAN ALL DATA"

## 2 Apps: Main Scanner + GUI Launcher
## Features: 9 tabs, Control panels, Export, Database
## Support: @Lulz1337
EOF

cp api_config.json dist/ 2>/dev/null
echo "✅ Package ready"
echo ""

echo "════════════════════════════════════════════════════════════════════════════"
echo "           ✅ BUILD COMPLETE!"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "📦 Files in dist/:"
ls -lh dist/ 2>/dev/null | grep -E "\.exe|README|json"
echo ""
