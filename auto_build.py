#!/usr/bin/env python3
"""
LulzSec Forensic Scanner - AUTO-BUILD SYSTEM
Automatically builds Windows executable with all dependencies
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"\n{'='*80}")
    print(f"🔧 {description}")
    print(f"{'='*80}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - SUCCESS")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - FAILED")
        if e.stderr:
            print(f"Error: {e.stderr}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║           🚀 LulzSec Forensic Scanner - AUTO-BUILD SYSTEM 🚀                ║
║                                                                              ║
║                    Building Windows Executable...                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    # Step 1: Install PyInstaller
    if not run_command(
        f"{sys.executable} -m pip install -q pyinstaller",
        "Installing PyInstaller"
    ):
        print("⚠️  PyInstaller may already be installed, continuing...")
    
    # Step 2: Install dependencies
    deps = ["ecdsa", "mnemonic", "pycryptodome", "requests", "base58", "colorama"]
    for dep in deps:
        run_command(
            f"{sys.executable} -m pip install -q {dep}",
            f"Installing {dep}"
        )
    
    # Step 3: Create dist directory
    os.makedirs("dist", exist_ok=True)
    print("\n✅ Directories prepared")
    
    # Step 4: Build executable
    print("\n" + "="*80)
    print("🔨 BUILDING EXECUTABLE - This will take 2-5 minutes...")
    print("="*80)
    
    separator = ";" if os.name == "nt" else ":"
    
    build_command = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name=LulzSec-Forensic-Scanner",
        f"--add-data=api_config.json{separator}.",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.filedialog",
        "--hidden-import=tkinter.messagebox",
        "--hidden-import=tkinter.scrolledtext",
        "--hidden-import=sqlite3",
        "--hidden-import=ecdsa",
        "--hidden-import=mnemonic",
        "--hidden-import=Crypto",
        "--hidden-import=Crypto.Hash",
        "--hidden-import=Crypto.Cipher",
        "--hidden-import=Crypto.Protocol.KDF",
        "--hidden-import=requests",
        "--hidden-import=base58",
        "--hidden-import=hashlib",
        "--hidden-import=json",
        "--collect-all=tkinter",
        "--collect-all=mnemonic",
        "--collect-all=ecdsa",
        "ext.py"
    ]
    
    try:
        print("⏳ Building... Please wait...")
        result = subprocess.run(build_command, check=True, capture_output=True, text=True)
        print("\n✅ BUILD SUCCESSFUL!")
    except subprocess.CalledProcessError as e:
        print("\n❌ BUILD FAILED")
        print(e.stderr)
        return False
    
    # Step 5: Verify the executable
    exe_path = Path("dist/LulzSec-Forensic-Scanner.exe")
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n{'='*80}")
        print("✅ EXECUTABLE CREATED SUCCESSFULLY!")
        print(f"{'='*80}")
        print(f"\n📦 File: {exe_path}")
        print(f"📊 Size: {size_mb:.2f} MB")
        
        # Create release package
        print(f"\n{'='*80}")
        print("📦 Creating Release Package...")
        print(f"{'='*80}")
        
        # Create README for the exe
        readme_content = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║           LulzSec ULTIMATE Forensic Scanner v2.0 - Windows Edition          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

🚀 QUICK START:

1. Double-click: LulzSec-Forensic-Scanner.exe

2. If Windows blocks it:
   - Click "More info"
   - Click "Run anyway"
   (This is normal for unsigned executables)

3. Select a directory with stealer logs

4. Click "SCAN ALL DATA"

5. View results in tabs:
   - Wallets
   - Seeds
   - Private Keys
   - Credentials
   - SMS APIs
   - Hosting
   - Control Panels
   - Cookies
   - Sensitive Data

📋 FEATURES:

✅ Complete standalone application (no Python needed)
✅ All 9 tabs with full functionality
✅ Control panel extractor (cPanel, Plesk, WHM, MySQL, etc.)
✅ Credential extraction with URLs
✅ Cookie extraction (Netscape format)
✅ Private key extraction (all formats)
✅ Real-time stats display
✅ Export to TXT/CSV/JSON
✅ SQLite database storage

💾 DATABASE:

The scanner creates: lulzsec_wallets_ultimate_v9.db
Location: Same folder as the .exe

📞 SUPPORT:

Telegram: @Lulz1337
GitHub: LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2

🔒 SECURITY NOTE:

This is a forensic analysis tool for legitimate security research.
Use responsibly and legally.

═══════════════════════════════════════════════════════════════════════════════
Generated: October 28, 2025
Version: 2.0 Federal Grade Edition
═══════════════════════════════════════════════════════════════════════════════
"""
        
        with open("dist/README.txt", "w") as f:
            f.write(readme_content)
        
        print("✅ README.txt created")
        
        # Copy api_config.json if it exists
        if Path("api_config.json").exists():
            shutil.copy("api_config.json", "dist/api_config.json")
            print("✅ api_config.json copied")
        
        print(f"\n{'='*80}")
        print("📦 RELEASE PACKAGE READY!")
        print(f"{'='*80}")
        print("\n📁 Contents of dist/ folder:")
        print("   - LulzSec-Forensic-Scanner.exe  (Main executable)")
        print("   - README.txt                    (User guide)")
        print("   - api_config.json               (Configuration)")
        
        print(f"\n{'='*80}")
        print("🎯 NEXT STEPS:")
        print(f"{'='*80}")
        print("\n1. Test the executable:")
        print("   - Copy dist/LulzSec-Forensic-Scanner.exe to Windows")
        print("   - Run it and test all features")
        print("\n2. Commit to repository:")
        print("   git add dist/")
        print("   git commit -m '🚀 Add Windows executable v2.0'")
        print("   git push origin main")
        print("\n3. Create GitHub Release:")
        print("   - Go to GitHub releases")
        print("   - Upload LulzSec-Forensic-Scanner.exe")
        print("   - Add release notes")
        
        print(f"\n{'='*80}")
        print("✅ BUILD COMPLETE!")
        print(f"{'='*80}\n")
        
        return True
    else:
        print("\n❌ ERROR: Executable not found after build")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
