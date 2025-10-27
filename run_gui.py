#!/usr/bin/env python3
"""
🚀 LulzSec Forensic Scanner - GUI Launcher
Launch the advanced federal-grade forensic interface
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Check for required packages
try:
    import tkinter
except ImportError:
    print("❌ Error: tkinter is not installed")
    print("📦 Install with: sudo apt-get install python3-tk")
    sys.exit(1)

# Import and run GUI
from gui.advanced_gui import LulzSecAdvancedGUI

if __name__ == "__main__":
    print("🚀 Launching LulzSec Forensic Scanner GUI...")
    print("💻 Initializing federal-grade interface...")
    
    try:
        app = LulzSecAdvancedGUI()
        app.run()
    except KeyboardInterrupt:
        print("\n⚠️ GUI closed by user")
    except Exception as e:
        print(f"\n❌ Error launching GUI: {e}")
        import traceback
        traceback.print_exc()
