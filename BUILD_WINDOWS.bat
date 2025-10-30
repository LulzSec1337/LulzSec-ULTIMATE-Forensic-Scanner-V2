@echo off
REM ════════════════════════════════════════════════════════════════════════════
REM   LulzSec Forensic Scanner - Windows EXE Builder
REM   Builds 2 Windows Executables
REM ════════════════════════════════════════════════════════════════════════════

echo.
echo ════════════════════════════════════════════════════════════════════════════
echo.
echo        🚀 LulzSec Forensic Scanner - Windows EXE Builder 🚀
echo.
echo                    Building 2 Applications
echo.
echo ════════════════════════════════════════════════════════════════════════════
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not installed! Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo ✅ Python found
echo.

echo ════════════════════════════════════════════════════════════════════════════
echo 📦 Installing PyInstaller and dependencies
echo ════════════════════════════════════════════════════════════════════════════
echo.
python -m pip install --upgrade pip --quiet
python -m pip install pyinstaller ecdsa mnemonic pycryptodome requests base58 colorama --quiet
echo ✅ Installed
echo.

echo ════════════════════════════════════════════════════════════════════════════
echo 🧹 Cleaning old builds
echo ════════════════════════════════════════════════════════════════════════════
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec
echo ✅ Cleaned
echo.

echo ════════════════════════════════════════════════════════════════════════════
echo 🔨 Building Main Scanner: LulzSec-Forensic-Scanner.exe
echo ════════════════════════════════════════════════════════════════════════════
echo ⏳ Building... (3-5 minutes)
echo.

if exist lulzsec_icon.ico (
    echo    ✅ Using LulzSec icon
    pyinstaller --onefile --windowed --icon=lulzsec_icon.ico --name=LulzSec-Forensic-Scanner --add-data="api_config.json;." --hidden-import=tkinter --hidden-import=tkinter.ttk --hidden-import=tkinter.messagebox --hidden-import=tkinter.filedialog --hidden-import=sqlite3 --hidden-import=ecdsa --hidden-import=mnemonic --hidden-import=Crypto --hidden-import=Crypto.Cipher --hidden-import=Crypto.Cipher.AES --hidden-import=requests --hidden-import=base58 --hidden-import=colorama --collect-all=tkinter --collect-all=mnemonic --collect-all=ecdsa ext.py
) else (
    echo    ⚠️  No icon found
    pyinstaller --onefile --windowed --name=LulzSec-Forensic-Scanner --add-data="api_config.json;." --hidden-import=tkinter --hidden-import=tkinter.ttk --hidden-import=tkinter.messagebox --hidden-import=tkinter.filedialog --hidden-import=sqlite3 --hidden-import=ecdsa --hidden-import=mnemonic --hidden-import=Crypto --hidden-import=Crypto.Cipher --hidden-import=Crypto.Cipher.AES --hidden-import=requests --hidden-import=base58 --hidden-import=colorama --collect-all=tkinter --collect-all=mnemonic --collect-all=ecdsa ext.py
)

if errorlevel 1 (
    echo ❌ Main Scanner build failed
    pause
    exit /b 1
)
echo ✅ Main Scanner built!
echo.

echo ════════════════════════════════════════════════════════════════════════════
echo 🔨 Building GUI Launcher: LulzSec-GUI-Launcher.exe
echo ════════════════════════════════════════════════════════════════════════════
if exist run_gui.py (
    if exist lulzsec_icon.ico (
        pyinstaller --onefile --windowed --icon=lulzsec_icon.ico --name=LulzSec-GUI-Launcher --add-data="api_config.json;." --hidden-import=tkinter --hidden-import=tkinter.ttk --hidden-import=tkinter.messagebox --hidden-import=tkinter.filedialog --hidden-import=sqlite3 --collect-all=tkinter run_gui.py
    ) else (
        pyinstaller --onefile --windowed --name=LulzSec-GUI-Launcher --add-data="api_config.json;." --hidden-import=tkinter --hidden-import=tkinter.ttk --hidden-import=tkinter.messagebox --hidden-import=tkinter.filedialog --hidden-import=sqlite3 --collect-all=tkinter run_gui.py
    )
    if errorlevel 1 (
        echo ⚠️  GUI Launcher failed, but Main Scanner ready
    ) else (
        echo ✅ GUI Launcher built!
    )
) else (
    echo ⚠️  run_gui.py not found
)
echo.

echo 📝 Creating README...
(
echo # LulzSec Forensic Scanner v2.0 - Windows Edition
echo.
echo ## Quick Start:
echo 1. Double-click LulzSec-Forensic-Scanner.exe
echo 2. If Windows Defender blocks: Click "More info" then "Run anyway"
echo 3. Select stealer logs folder
echo 4. Click "SCAN ALL DATA"
echo.
echo ## 2 Apps Included:
echo - LulzSec-Forensic-Scanner.exe (Main)
echo - LulzSec-GUI-Launcher.exe (Alternative GUI)
echo.
echo ## Features: 9 tabs, Control panels, Export, Database
echo Support: @Lulz1337
) > dist\README.txt

copy api_config.json dist\ >nul 2>&1
echo ✅ Package ready
echo.

echo ════════════════════════════════════════════════════════════════════════════
echo            ✅ BUILD COMPLETE!
echo ════════════════════════════════════════════════════════════════════════════
echo.
echo 📦 Executables in dist\ folder:
dir /B dist\*.exe 2>nul
echo.
echo 🎯 Test: Double-click dist\LulzSec-Forensic-Scanner.exe
echo.
pause
