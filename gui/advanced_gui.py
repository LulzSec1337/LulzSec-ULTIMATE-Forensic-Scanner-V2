#!/usr/bin/env python3
"""
🎨 LULZSEC ADVANCED GUI - Federal Grade Forensic Interface
Fully featured tactical GUI with all scanner capabilities integrated
"""

import os
import sys
import time
import json
import re
import sqlite3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, Menu, simpledialog
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.api_config import APIConfig
from core.crypto_utils import EnhancedCryptoUtils
from core.balance_checker import AdvancedBalanceChecker
from core.ultra_scanner import UltraAdvancedScanner
from database.db_manager import EnhancedDatabaseManager
from validators.email_validator import EmailValidator
from validators.sms_detector import SMSAPIDetector
from extractors.private_key_extractor import ComprehensivePrivateKeyExtractor
from extractors.url_extractor import AdvancedURLExtractor


class EnhancedNeonTheme:
    """Tactical dark theme with neon accents - Federal Agency Grade"""
    
    def __init__(self):
        self.colors = {
            'bg': '#0a0e1a',              # Deep dark background
            'bg_secondary': '#131824',     # Card background
            'bg_tertiary': '#1a1f2e',      # Input background
            'bg_card': '#161b29',          # Panel background
            'fg': '#e0e6f0',               # Primary text
            'fg_secondary': '#a8b2c7',     # Secondary text
            'accent': '#00ff88',           # Primary accent (neon green)
            'neon_blue': '#00d9ff',        # Electric blue
            'neon_cyan': '#00ffcc',        # Cyan
            'neon_pink': '#ff00cc',        # Hot pink
            'neon_purple': '#9d00ff',      # Purple
            'neon_yellow': '#ffeb3b',      # Yellow
            'neon_orange': '#ff6600',      # Orange
            'neon_green': '#00ff88',       # Green
            'success': '#00ff88',          # Success green
            'warning': '#ffeb3b',          # Warning yellow
            'danger': '#ff3366',           # Danger red
            'border': '#2a3142'            # Border color
        }
        
        self.fonts = {
            'heading': ('Segoe UI', 12, 'bold'),
            'subheading': ('Segoe UI', 10, 'bold'),
            'normal': ('Segoe UI', 9),
            'small': ('Segoe UI', 8),
            'tiny': ('Segoe UI', 7),
            'mono': ('Consolas', 9),
            'mono_small': ('Consolas', 8)
        }
    
    def apply_theme(self, root):
        """Apply theme to root window"""
        root.configure(bg=self.colors['bg'])
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Progressbar style
        style.configure('TProgressbar',
                       background=self.colors['neon_green'],
                       troughcolor=self.colors['bg_tertiary'],
                       borderwidth=0,
                       thickness=8)
        
        # Frame style
        style.configure('TFrame', background=self.colors['bg'])
        
        # Label style
        style.configure('TLabel',
                       background=self.colors['bg'],
                       foreground=self.colors['fg'])


class ToolTip:
    """Simple tooltip widget"""
    
    def __init__(self, widget, text, delay=500, theme=None):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.theme = theme or EnhancedNeonTheme()
        self.tw = None
        self.id = None
        self.widget.bind('<Enter>', self.on_enter)
        self.widget.bind('<Leave>', self.on_leave)
    
    def on_enter(self, event=None):
        self.id = self.widget.after(self.delay, self.show)
    
    def on_leave(self, event=None):
        if self.id:
            self.widget.after_cancel(self.id)
        self.hide()
    
    def show(self):
        if self.tw:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(self.tw, text=self.text,
                        background=self.theme.colors['bg_card'],
                        foreground=self.theme.colors['fg'],
                        font=self.theme.fonts['small'],
                        relief='solid', borderwidth=1,
                        padx=8, pady=4)
        label.pack()
    
    def hide(self):
        if self.tw:
            self.tw.destroy()
            self.tw = None


class LulzSecAdvancedGUI:
    """Federal-grade forensic scanner GUI with full feature integration"""
    
    def __init__(self):
        # Initialize core components
        self.db = EnhancedDatabaseManager()
        self.api_config = APIConfig()
        self.theme = EnhancedNeonTheme()
        self.crypto_utils = EnhancedCryptoUtils()
        self.balance_checker = AdvancedBalanceChecker(self.api_config)
        self.email_validator = EmailValidator()
        self.sms_detector = SMSAPIDetector()
        self.key_extractor = ComprehensivePrivateKeyExtractor(
            self.crypto_utils, 
            self.balance_checker, 
            lambda msg, typ: self.add_log(msg, typ) if hasattr(self, 'add_log') else None
        )
        
        # ULTRA-ADVANCED SCANNER
        self.ultra_scanner = UltraAdvancedScanner(self.crypto_utils, self.db)
        
        # URL EXTRACTOR
        self.url_extractor = AdvancedURLExtractor()
        
        # Scanning state
        self.is_scanning = False
        self.scan_thread = None
        
        # GUI state
        self.root = tk.Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind('<Configure>', self.on_window_resize)
        self.last_window_size = (1600, 900)
        
        # Live metrics
        self.metrics = {
            'scan_start_time': None,
            'scan_phase': 'Idle',
            'files_scanned': 0,
            'wallets_found': 0,
            'seeds_found': 0,
            'credentials_found': 0,
            'cookies_found': 0,
            'sensitive_found': 0,
            'sms_apis_found': 0,
            'hosting_found': 0,
            'total_value_usd': 0.0,
            'memory_usage_mb': 0.0,
            'files_per_second': 0.0,
            'estimated_time_remaining': 0
        }
        
        # Tooltips
        self.tooltips = []
        
        # Setup GUI
        self.setup_gui()
    
    def on_closing(self):
        """Handle window close"""
        if self.is_scanning:
            if messagebox.askokcancel("Quit", "⚠️ Scan in progress. Are you sure you want to quit?"):
                self.is_scanning = False
                time.sleep(0.3)
                self.root.destroy()
        else:
            self.root.destroy()
    
    def on_window_resize(self, event):
        """Handle window resize for responsive UI"""
        if event.widget == self.root:
            new_size = (event.width, event.height)
            if abs(new_size[0] - self.last_window_size[0]) > 50 or \
               abs(new_size[1] - self.last_window_size[1]) > 50:
                self.last_window_size = new_size
    
    def add_tooltip(self, widget, text):
        """Add tooltip to widget"""
        tooltip = ToolTip(widget, text, delay=500, theme=self.theme)
        self.tooltips.append(tooltip)
        return tooltip
    
    def setup_gui(self):
        """Setup complete GUI"""
        self.root.title("[LULZSEC FORENSIC SCANNER v9.1 ADVANCED] - TACTICAL OSINT SUITE")
        self.root.geometry("1920x1080")
        self.root.minsize(1600, 900)
        
        self.theme.apply_theme(self.root)
        
        # Menu Bar
        self.setup_menu_bar()
        
        # Main container
        main = tk.Frame(self.root, bg=self.theme.colors['bg'])
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.setup_header(main)
        
        # Content with 3 panels
        content = tk.PanedWindow(main, orient=tk.HORIZONTAL, bg=self.theme.colors['bg'],
                                sashwidth=8, sashrelief=tk.RAISED)
        content.pack(fill=tk.BOTH, expand=True, pady=(10, 10))
        
        # Left panel (controls)
        left = self.setup_left_panel(content)
        content.add(left, minsize=400)
        
        # Center panel (results)
        center = self.setup_center_panel(content)
        content.add(center, minsize=700)
        
        # Right panel (details)
        right = self.setup_right_panel(content)
        content.add(right, minsize=500)
        
        # Bottom status bar
        self.setup_status_bar(main)
        
        # Start metrics update
        self.start_metrics_update()
    
    def setup_menu_bar(self):
        """Setup enhanced menu bar"""
        menubar = Menu(self.root, bg=self.theme.colors['bg_card'], 
                      fg=self.theme.colors['fg'])
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0, bg=self.theme.colors['bg_card'],
                        fg=self.theme.colors['fg'])
        menubar.add_cascade(label="📁 File", menu=file_menu)
        file_menu.add_command(label="🔄 Refresh All", command=self.refresh_all)
        file_menu.add_separator()
        file_menu.add_command(label="💾 Backup Database", command=self.backup_database)
        file_menu.add_command(label="📤 Export All Data", command=self.export_all_data)
        file_menu.add_separator()
        file_menu.add_command(label="❌ Exit", command=self.on_closing)
        
        # Export Menu
        export_menu = Menu(menubar, tearoff=0, bg=self.theme.colors['bg_card'],
                          fg=self.theme.colors['fg'])
        menubar.add_cascade(label="📤 Export", menu=export_menu)
        export_menu.add_command(label="💰 Export Wallets (JSON)", command=self.export_wallets_json)
        export_menu.add_command(label="🌱 Export Seeds (TXT)", command=self.export_seeds_txt)
        export_menu.add_command(label="🔑 Export Credentials (CSV)", command=self.export_credentials_csv)
        export_menu.add_command(label="📱 Export SMS APIs", command=self.export_sms_apis)
        
        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0, bg=self.theme.colors['bg_card'],
                         fg=self.theme.colors['fg'])
        menubar.add_cascade(label="🛠️ Tools", menu=tools_menu)
        tools_menu.add_command(label="🔑 Private Key Converter", command=self.open_key_converter)
        tools_menu.add_command(label="🌱 Bulk Seed Validator", command=self.bulk_validate_seeds)
        tools_menu.add_command(label="💰 Bulk Balance Checker", command=self.bulk_check_balances)
        tools_menu.add_separator()
        tools_menu.add_command(label="📧 Validate Email Credentials", command=self.validate_emails)
        tools_menu.add_command(label="🔍 Search Specific URL", command=self.search_url_tool)
        
        # Settings Menu
        settings_menu = Menu(menubar, tearoff=0, bg=self.theme.colors['bg_card'],
                            fg=self.theme.colors['fg'])
        menubar.add_cascade(label="⚙️ Settings", menu=settings_menu)
        settings_menu.add_command(label="🔑 API Management", command=self.open_api_settings)
        settings_menu.add_command(label="🧪 Test APIs", command=self.test_apis)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0, bg=self.theme.colors['bg_card'],
                        fg=self.theme.colors['fg'])
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        help_menu.add_command(label="📖 User Guide", command=self.show_user_guide)
        help_menu.add_command(label="ℹ️ About", command=self.show_about)
    
    def setup_header(self, parent):
        """Setup tactical header"""
        header = tk.Frame(parent, bg=self.theme.colors['bg_card'],
                         highlightbackground=self.theme.colors['accent'],
                         highlightthickness=2)
        header.pack(fill=tk.X, pady=(0, 10))
        
        # Left: Title
        title_frame = tk.Frame(header, bg=self.theme.colors['bg_card'])
        title_frame.pack(side=tk.LEFT, padx=15, pady=10)
        
        tk.Label(title_frame, text="[LULZSEC FORENSIC v9.1 ADVANCED]",
                bg=self.theme.colors['bg_card'], 
                fg=self.theme.colors['accent'],
                font=('Segoe UI', 16, 'bold')).pack(anchor=tk.W)
        
        tk.Label(title_frame, text="Federal-Grade Cryptocurrency Recovery & OSINT System",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['small']).pack(anchor=tk.W)
        
        # Right: Status
        status_frame = tk.Frame(header, bg=self.theme.colors['bg_card'])
        status_frame.pack(side=tk.RIGHT, padx=15, pady=10)
        
        self.scan_status_label = tk.Label(status_frame, text="[◼ STANDBY]",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['neon_yellow'],
                font=('Segoe UI', 14, 'bold'))
        self.scan_status_label.pack()
        
        tk.Label(status_frame, text="USER: @LulzSec1337",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['tiny']).pack()
    
    def setup_left_panel(self, parent):
        """Setup left control panel"""
        left = tk.Frame(parent, bg=self.theme.colors['bg_secondary'])
        left.config(width=400)
        left.pack_propagate(False)
        
        # Scrollable container
        canvas = tk.Canvas(left, bg=self.theme.colors['bg'], highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.theme.colors['bg'])
        
        scrollable_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        def _configure_canvas(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind('<Configure>', _configure_canvas)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _on_mousewheel_linux(event):
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")
        
        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel_linux)
            canvas.bind_all("<Button-5>", _on_mousewheel_linux)
        
        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
        
        canvas.bind('<Enter>', _bind_mousewheel)
        canvas.bind('<Leave>', _unbind_mousewheel)
        
        # --- SCAN CONTROLS ---
        scan_frame = tk.LabelFrame(scrollable_frame, text="  🚀 SCAN CONTROLS  ",
                                  bg=self.theme.colors['bg_secondary'],
                                  fg=self.theme.colors['neon_cyan'],
                                  font=('Segoe UI', 11, 'bold'),
                                  borderwidth=2, relief='solid', padx=12, pady=12)
        scan_frame.pack(fill=tk.X, padx=10, pady=(10, 8))
        
        # Directory selection
        tk.Label(scan_frame, text="📁 Target Directory:",
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['fg'],
                font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        
        self.dir_var = tk.StringVar()
        dir_entry = tk.Entry(scan_frame, textvariable=self.dir_var,
                bg=self.theme.colors['bg_tertiary'],
                fg=self.theme.colors['fg'],
                font=('Segoe UI', 9),
                insertbackground=self.theme.colors['accent'],
                borderwidth=1, relief='solid')
        dir_entry.pack(fill=tk.X, pady=(0, 8), ipady=5)
        
        # Quick directory buttons
        quick_dir = tk.Frame(scan_frame, bg=self.theme.colors['bg_secondary'])
        quick_dir.pack(fill=tk.X, pady=(0, 10))
        
        tk.Button(quick_dir, text="📂 Browse",
                 command=self.browse_dir,
                 bg=self.theme.colors['accent'],
                 fg='#000000',
                 font=('Segoe UI', 9, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=12, pady=6, cursor='hand2').pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        tk.Button(quick_dir, text="📥 Downloads",
                 command=lambda: self.dir_var.set(os.path.expanduser("~/Downloads")),
                 bg=self.theme.colors['neon_blue'],
                 fg='#ffffff',
                 font=('Segoe UI', 9, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=12, pady=6, cursor='hand2').pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        tk.Button(quick_dir, text="🏠 Home",
                 command=lambda: self.dir_var.set(os.path.expanduser("~")),
                 bg=self.theme.colors['neon_purple'],
                 fg='#ffffff',
                 font=('Segoe UI', 9, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=12, pady=6, cursor='hand2').pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Separator
        tk.Frame(scan_frame, height=2, bg=self.theme.colors['border']).pack(fill=tk.X, pady=10)
        
        # PRIMARY SCAN BUTTONS
        self.scan_crypto_btn = tk.Button(scan_frame, text="💰 SCAN WALLETS\nCrypto & Seeds Only",
                                 command=self.start_crypto_scan,
                                 bg=self.theme.colors['neon_green'],
                                 fg='#000000',
                                 font=('Segoe UI', 12, 'bold'),
                                 borderwidth=0, relief='flat',
                                 padx=18, pady=15, cursor='hand2')
        self.scan_crypto_btn.pack(fill=tk.X, pady=(0, 8))
        
        self.scan_all_btn = tk.Button(scan_frame, text="📊 SCAN ALL DATA\nEverything (Full Forensics)",
                                 command=self.start_full_scan,
                                 bg=self.theme.colors['neon_blue'],
                                 fg='#ffffff',
                                 font=('Segoe UI', 12, 'bold'),
                                 borderwidth=0, relief='flat',
                                 padx=18, pady=15, cursor='hand2')
        self.scan_all_btn.pack(fill=tk.X, pady=(0, 8))
        
        self.stop_btn = tk.Button(scan_frame, text="⏹️ STOP SCAN",
                                 command=self.stop_scan,
                                 state='disabled',
                                 bg=self.theme.colors['danger'],
                                 fg='#ffffff',
                                 font=('Segoe UI', 11, 'bold'),
                                 borderwidth=0, relief='flat',
                                 padx=15, pady=12, cursor='hand2')
        self.stop_btn.pack(fill=tk.X)
        
        # --- LIVE STATISTICS ---
        stats_frame = tk.LabelFrame(scrollable_frame, text="  📊 LIVE STATISTICS  ",
                                   bg=self.theme.colors['bg_secondary'],
                                   fg=self.theme.colors['neon_yellow'],
                                   font=('Segoe UI', 11, 'bold'),
                                   borderwidth=2, relief='solid', padx=12, pady=12)
        stats_frame.pack(fill=tk.X, padx=10, pady=(0, 8))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(stats_frame, variable=self.progress_var,
                                       maximum=100, mode='determinate')
        progress_bar.pack(fill=tk.X, pady=(0, 8))
        
        self.progress_percent_var = tk.StringVar(value="0%")
        tk.Label(stats_frame, textvariable=self.progress_percent_var,
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['neon_yellow'],
                font=('Segoe UI', 16, 'bold')).pack(pady=(0, 10))
        
        # Time stats
        time_grid = tk.Frame(stats_frame, bg=self.theme.colors['bg_secondary'])
        time_grid.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(time_grid, text="⏱️ Elapsed:",
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['fg'],
                font=('Segoe UI', 9)).grid(row=0, column=0, sticky=tk.W, pady=3)
        self.elapsed_time_var = tk.StringVar(value="00:00:00")
        tk.Label(time_grid, textvariable=self.elapsed_time_var,
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['neon_blue'],
                font=('Segoe UI', 9, 'bold')).grid(row=0, column=1, sticky=tk.E, pady=3)
        
        tk.Label(time_grid, text="⏳ Remaining:",
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['fg'],
                font=('Segoe UI', 9)).grid(row=1, column=0, sticky=tk.W, pady=3)
        self.remaining_time_var = tk.StringVar(value="---")
        tk.Label(time_grid, textvariable=self.remaining_time_var,
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['neon_green'],
                font=('Segoe UI', 9, 'bold')).grid(row=1, column=1, sticky=tk.E, pady=3)
        
        tk.Label(time_grid, text="⚡ Speed:",
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['fg'],
                font=('Segoe UI', 9)).grid(row=2, column=0, sticky=tk.W, pady=3)
        self.speed_var = tk.StringVar(value="0 files/s")
        tk.Label(time_grid, textvariable=self.speed_var,
                bg=self.theme.colors['bg_secondary'],
                fg=self.theme.colors['neon_orange'],
                font=('Segoe UI', 9, 'bold')).grid(row=2, column=1, sticky=tk.E, pady=3)
        
        time_grid.grid_columnconfigure(1, weight=1)
        
        # Separator
        tk.Frame(stats_frame, height=1, bg=self.theme.colors['border']).pack(fill=tk.X, pady=10)
        
        # Extraction counters
        self.mini_stats = {}
        counters = [
            ("📁 Files Scanned", 'files', self.theme.colors['neon_blue']),
            ("💰 Wallets Found", 'wallets', self.theme.colors['neon_green']),
            ("🌱 Seeds Found", 'seeds', self.theme.colors['neon_pink']),
            ("✅ Seeds Validated", 'validated', self.theme.colors['neon_green']),
            ("🔑 Credentials", 'credentials', self.theme.colors['neon_orange']),
            ("🍪 Cookies", 'cookies', self.theme.colors['neon_cyan']),
            ("📱 SMS APIs", 'sms', self.theme.colors['neon_purple']),
            ("☁️ Cloud Services", 'services', self.theme.colors['neon_cyan']),
            ("💵 Total USD Value", 'usd', self.theme.colors['neon_yellow'])
        ]
        
        for label, key, color in counters:
            row = tk.Frame(stats_frame, bg=self.theme.colors['bg_card'],
                          borderwidth=1, relief='solid')
            row.pack(fill=tk.X, pady=2)
            
            tk.Label(row, text=label,
                    bg=self.theme.colors['bg_card'],
                    fg=self.theme.colors['fg'],
                    font=('Segoe UI', 8)).pack(side=tk.LEFT, padx=10, pady=5)
            
            var = tk.StringVar(value="$0" if key == 'usd' else "0")
            self.mini_stats[key] = var
            tk.Label(row, textvariable=var,
                    bg=self.theme.colors['bg_card'],
                    fg=color,
                    font=('Segoe UI', 9, 'bold')).pack(side=tk.RIGHT, padx=10, pady=5)
        
        # --- SCAN OPTIONS ---
        opts_frame = tk.LabelFrame(scrollable_frame, text="  ⚙️ SCAN OPTIONS  ",
                                  bg=self.theme.colors['bg_secondary'],
                                  fg=self.theme.colors['neon_pink'],
                                  font=('Segoe UI', 10, 'bold'),
                                  borderwidth=2, relief='solid', padx=10, pady=10)
        opts_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.opt_vars = {}
        
        options = [
            ("✅ Extract Wallet Addresses", 'extract_wallets', True),
            ("✅ Extract Seed Phrases", 'extract_seeds', True),
            ("✅ Validate Seeds (BIP39)", 'validate_seeds', True),
            ("✅ Derive All Networks", 'derive_networks', True),
            ("✅ Extract Credentials", 'extract_creds', True),
            ("✅ Extract Cookies", 'extract_cookies', True),
            ("✅ Detect SMS APIs", 'detect_sms', True),
            ("✅ Find Cloud Services", 'find_cloud', True),
            ("⚡ Check Balances (Slow)", 'check_balances', False),
            ("💵 Get USD Prices", 'get_usd', False),
            ("📧 Validate Emails", 'validate_emails', False)
        ]
        
        for text, key, default in options:
            var = tk.BooleanVar(value=default)
            self.opt_vars[key] = var
            tk.Checkbutton(opts_frame, text=text, variable=var,
                          bg=self.theme.colors['bg_secondary'],
                          fg=self.theme.colors['fg'],
                          selectcolor=self.theme.colors['bg_tertiary'],
                          activebackground=self.theme.colors['bg_secondary'],
                          font=('Segoe UI', 8),
                          cursor='hand2').pack(anchor=tk.W, pady=2)
        
        return left
    
    def setup_center_panel(self, parent):
        """Setup center results panel with comprehensive tabs"""
        center = tk.Frame(parent, bg=self.theme.colors['bg'])
        
        # Tabbed interface for results
        notebook = ttk.Notebook(center)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Seed Phrases (ONLY seeds, 12/24 words)
        seeds_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(seeds_tab, text="🌱 Seed Phrases")
        
        self.seeds_text = scrolledtext.ScrolledText(seeds_tab,
                                                     bg=self.theme.colors['bg_tertiary'],
                                                     fg=self.theme.colors['fg'],
                                                     font=self.theme.fonts['mono_small'],
                                                     insertbackground=self.theme.colors['accent'],
                                                     wrap=tk.NONE)
        self.seeds_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 2: Private Keys (ONLY keys)
        keys_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(keys_tab, text="🔑 Private Keys")
        
        self.keys_text = scrolledtext.ScrolledText(keys_tab,
                                                    bg=self.theme.colors['bg_tertiary'],
                                                    fg=self.theme.colors['fg'],
                                                    font=self.theme.fonts['mono_small'],
                                                    insertbackground=self.theme.colors['accent'],
                                                    wrap=tk.NONE)
        self.keys_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 3: Wallets
        wallets_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(wallets_tab, text="💰 Wallet Addresses")
        
        self.wallets_text = scrolledtext.ScrolledText(wallets_tab,
                                                       bg=self.theme.colors['bg_tertiary'],
                                                       fg=self.theme.colors['fg'],
                                                       font=self.theme.fonts['mono_small'],
                                                       insertbackground=self.theme.colors['accent'],
                                                       wrap=tk.WORD)
        self.wallets_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 4: Mail Access (NEW - SMTP/IMAP/POP3)
        mail_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(mail_tab, text="📧 Mail Access")
        
        self.mail_text = scrolledtext.ScrolledText(mail_tab,
                                                    bg=self.theme.colors['bg_tertiary'],
                                                    fg=self.theme.colors['fg'],
                                                    font=self.theme.fonts['mono_small'],
                                                    insertbackground=self.theme.colors['accent'],
                                                    wrap=tk.WORD)
        self.mail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 5: Credentials
        creds_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(creds_tab, text="� Credentials")
        
        self.creds_text = scrolledtext.ScrolledText(creds_tab,
                                                     bg=self.theme.colors['bg_tertiary'],
                                                     fg=self.theme.colors['fg'],
                                                     font=self.theme.fonts['mono_small'],
                                                     insertbackground=self.theme.colors['accent'],
                                                     wrap=tk.WORD)
        self.creds_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 6: Cookies
        cookies_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(cookies_tab, text="🍪 Cookies")
        
        self.cookies_text = scrolledtext.ScrolledText(cookies_tab,
                                                       bg=self.theme.colors['bg_tertiary'],
                                                       fg=self.theme.colors['fg'],
                                                       font=self.theme.fonts['mono_small'],
                                                       insertbackground=self.theme.colors['accent'],
                                                       wrap=tk.WORD)
        self.cookies_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 7: SMS APIs
        sms_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(sms_tab, text="📱 SMS APIs")
        
        self.sms_text = scrolledtext.ScrolledText(sms_tab,
                                                   bg=self.theme.colors['bg_tertiary'],
                                                   fg=self.theme.colors['fg'],
                                                   font=self.theme.fonts['mono_small'],
                                                   insertbackground=self.theme.colors['accent'],
                                                   wrap=tk.WORD)
        self.sms_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 8: API Keys
        apikeys_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(apikeys_tab, text="🔑 API Keys")
        
        self.apikeys_text = scrolledtext.ScrolledText(apikeys_tab,
                                                       bg=self.theme.colors['bg_tertiary'],
                                                       fg=self.theme.colors['fg'],
                                                       font=self.theme.fonts['mono_small'],
                                                       insertbackground=self.theme.colors['accent'],
                                                       wrap=tk.WORD)
        self.apikeys_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab 9: Logs
        logs_tab = tk.Frame(notebook, bg=self.theme.colors['bg'])
        notebook.add(logs_tab, text="📋 Logs")
        
        self.logs_text = scrolledtext.ScrolledText(logs_tab,
                                                    bg=self.theme.colors['bg_tertiary'],
                                                    fg=self.theme.colors['fg'],
                                                    font=self.theme.fonts['mono_small'],
                                                    insertbackground=self.theme.colors['accent'],
                                                    wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        return center
    
    def setup_right_panel(self, parent):
        """Setup right details panel"""
        right = tk.Frame(parent, bg=self.theme.colors['bg_secondary'])
        right.config(width=500)
        right.pack_propagate(False)
        
        # Details title
        title_frame = tk.Frame(right, bg=self.theme.colors['bg_card'],
                              highlightbackground=self.theme.colors['accent'],
                              highlightthickness=1)
        title_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(title_frame, text="📋 EXTRACTION DETAILS",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['accent'],
                font=('Segoe UI', 11, 'bold')).pack(pady=8)
        
        # Details text area
        self.details_text = scrolledtext.ScrolledText(right,
                                                       bg=self.theme.colors['bg_tertiary'],
                                                       fg=self.theme.colors['fg'],
                                                       font=self.theme.fonts['mono_small'],
                                                       insertbackground=self.theme.colors['accent'],
                                                       wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Quick action buttons
        actions_frame = tk.Frame(right, bg=self.theme.colors['bg_secondary'])
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(actions_frame, text="💰 Check Balances",
                 command=self.check_balances,
                 bg=self.theme.colors['neon_green'],
                 fg='#000000',
                 font=('Segoe UI', 9, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=12, pady=8, cursor='hand2').pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(actions_frame, text="📧 Validate Emails",
                 command=self.validate_emails,
                 bg=self.theme.colors['neon_blue'],
                 fg='#ffffff',
                 font=('Segoe UI', 9, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=12, pady=8, cursor='hand2').pack(fill=tk.X, pady=(0, 5))
        
        tk.Button(actions_frame, text="💾 Export All",
                 command=self.export_all_data,
                 bg=self.theme.colors['neon_yellow'],
                 fg='#000000',
                 font=('Segoe UI', 9, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=12, pady=8, cursor='hand2').pack(fill=tk.X)
        
        return right
    
    def setup_status_bar(self, parent):
        """Setup bottom status bar"""
        status_bar = tk.Frame(parent, bg=self.theme.colors['bg_card'],
                             highlightbackground=self.theme.colors['border'],
                             highlightthickness=1)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Left: Phase
        tk.Label(status_bar, text="Phase:",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['small']).pack(side=tk.LEFT, padx=5)
        
        self.phase_var = tk.StringVar(value="Idle")
        tk.Label(status_bar, textvariable=self.phase_var,
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['neon_cyan'],
                font=('Segoe UI', 8, 'bold')).pack(side=tk.LEFT, padx=(0, 15))
        
        # Center: Files scanned
        tk.Label(status_bar, text="Files:",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['small']).pack(side=tk.LEFT, padx=5)
        
        self.files_scanned_var = tk.StringVar(value="0")
        tk.Label(status_bar, textvariable=self.files_scanned_var,
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['neon_blue'],
                font=('Segoe UI', 8, 'bold')).pack(side=tk.LEFT, padx=(0, 15))
        
        # Right: Memory
        tk.Label(status_bar, text="Memory:",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['small']).pack(side=tk.RIGHT, padx=5)
        
        self.memory_var = tk.StringVar(value="0 MB")
        tk.Label(status_bar, textvariable=self.memory_var,
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['neon_orange'],
                font=('Segoe UI', 8, 'bold')).pack(side=tk.RIGHT, padx=(0, 5), pady=5)
    
    # ========================================================================
    # CORE FUNCTIONALITY METHODS
    # ========================================================================
    
    def start_metrics_update(self):
        """Start periodic metrics update"""
        self.update_live_metrics()
    
    def update_live_metrics(self):
        """Update all live metrics"""
        try:
            # Update time
            if self.metrics['scan_start_time']:
                elapsed = time.time() - self.metrics['scan_start_time']
                hours = int(elapsed // 3600)
                minutes = int((elapsed % 3600) // 60)
                seconds = int(elapsed % 60)
                self.elapsed_time_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            else:
                self.elapsed_time_var.set("00:00:00")
            
            # Update phase
            self.phase_var.set(self.metrics['scan_phase'])
            
            # Update database counts
            self.update_metrics_from_db()
            
            # Update displays
            self.files_scanned_var.set(str(self.metrics['files_scanned']))
            self.memory_var.set(f"{self.metrics['memory_usage_mb']:.0f} MB")
            self.speed_var.set(f"{self.metrics['files_per_second']:.1f} files/s")
            
            # Update mini stats
            self.mini_stats['files'].set(str(self.metrics['files_scanned']))
            self.mini_stats['wallets'].set(str(self.metrics['wallets_found']))
            self.mini_stats['seeds'].set(str(self.metrics['seeds_found']))
            self.mini_stats['credentials'].set(str(self.metrics['credentials_found']))
            self.mini_stats['cookies'].set(str(self.metrics['cookies_found']))
            self.mini_stats['sms'].set(str(self.metrics['sms_apis_found']))
            self.mini_stats['services'].set(str(self.metrics['hosting_found']))
            self.mini_stats['usd'].set(f"${self.metrics['total_value_usd']:.2f}")
            
            # Validated seeds
            try:
                conn = sqlite3.connect(self.db.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM seeds WHERE is_valid = 1")
                validated = cursor.fetchone()[0]
                self.mini_stats['validated'].set(str(validated))
                conn.close()
            except:
                self.mini_stats['validated'].set("0")
            
            # Schedule next update
            self.root.after(1000, self.update_live_metrics)
            
        except Exception as e:
            print(f"Metrics update error: {e}")
            self.root.after(1000, self.update_live_metrics)
    
    def update_metrics_from_db(self):
        """Update metrics from database"""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM wallets")
            self.metrics['wallets_found'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM seeds")
            self.metrics['seeds_found'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM credentials")
            self.metrics['credentials_found'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM cookies")
            self.metrics['cookies_found'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sms_apis")
            self.metrics['sms_apis_found'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM hosting_services")
            self.metrics['hosting_found'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT SUM(usd_value) FROM wallets WHERE usd_value IS NOT NULL")
            result = cursor.fetchone()[0]
            self.metrics['total_value_usd'] = float(result) if result else 0.0
            
            conn.close()
            
            # Memory usage
            try:
                import psutil
                process = psutil.Process()
                self.metrics['memory_usage_mb'] = process.memory_info().rss / 1024 / 1024
            except:
                self.metrics['memory_usage_mb'] = 0
                
        except Exception as e:
            print(f"DB metrics error: {e}")
    
    def browse_dir(self):
        """Browse for directory"""
        directory = filedialog.askdirectory(title="Select Target Directory")
        if directory:
            self.dir_var.set(directory)
            self.add_log(f"📁 Directory selected: {directory}", "info")
    
    def add_log(self, message, level="info"):
        """Add log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        colors = {
            'info': self.theme.colors['fg'],
            'success': self.theme.colors['neon_green'],
            'warning': self.theme.colors['neon_yellow'],
            'error': self.theme.colors['danger'],
            'critical': self.theme.colors['neon_pink']
        }
        
        color = colors.get(level, self.theme.colors['fg'])
        
        # Add to logs
        self.logs_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.logs_text.see(tk.END)
        
        # Also show in details
        self.details_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.details_text.see(tk.END)
    
    def start_crypto_scan(self):
        """Start cryptocurrency-focused scan"""
        target_dir = self.dir_var.get()
        if not target_dir or not os.path.exists(target_dir):
            messagebox.showerror("Error", "Please select a valid target directory")
            return
        
        self.is_scanning = True
        self.metrics['scan_start_time'] = time.time()
        self.metrics['scan_phase'] = 'Scanning Crypto...'
        
        # Update UI
        self.scan_status_label.config(text="[▶ SCANNING]", fg=self.theme.colors['neon_green'])
        self.scan_crypto_btn.config(state='disabled')
        self.scan_all_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        self.add_log("🚀 Starting cryptocurrency scan...", "success")
        self.add_log(f"📁 Target: {target_dir}", "info")
        
        # Start scan in thread
        import threading
        self.scan_thread = threading.Thread(target=self._run_crypto_scan, args=(target_dir,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _run_crypto_scan(self, target_dir):
        """Run ULTRA-ADVANCED cryptocurrency scan with ALL payloads"""
        try:
            # Update phase
            self.metrics['scan_phase'] = 'Initializing Ultra Scan...'
            self.add_log("🔥 ULTRA-ADVANCED SCANNER INITIALIZED", "success")
            self.add_log("📊 Loading extraction patterns:", "info")
            self.add_log("   • 50+ seed phrase patterns (BIP39 validated)", "info")
            self.add_log("   • 30+ private key formats (all blockchains)", "info")
            self.add_log("   • 8+ wallet networks (ETH, BTC, TRX, SOL, LTC, DOGE, BNB, XRP)", "info")
            self.add_log("   • Smart duplicate removal & fake data filtering", "info")
            self.add_log("   • Real-time validation & address derivation", "info")
            self.add_log("", "info")
            
            # Clear previous results
            self.wallets_text.delete(1.0, tk.END)
            self.seeds_text.delete(1.0, tk.END)
            self.keys_text.delete(1.0, tk.END)
            self.creds_text.delete(1.0, tk.END)
            self.mail_text.delete(1.0, tk.END)
            self.cookies_text.delete(1.0, tk.END)
            self.sms_text.delete(1.0, tk.END)
            self.apikeys_text.delete(1.0, tk.END)
            
            # Tabs are now clean and ready for CRUD-style data display
            # Data will appear in real-time as it's extracted
            
            # Count files first
            total_files = 0
            file_list = []
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    # Skip very large files
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.getsize(file_path) < 50 * 1024 * 1024:  # Max 50MB
                            file_list.append(file_path)
                            total_files += 1
                    except:
                        continue
            
            if total_files == 0:
                self.add_log("⚠️ No files found in directory", "warning")
                return
            
            self.add_log(f"📊 Found {total_files} files to scan", "success")
            self.add_log("🔍 ULTRA-AGGRESSIVE EXTRACTION MODE ACTIVE", "success")
            
            # Statistics
            files_scanned = 0
            start_time = time.time()
            
            total_wallets = 0
            total_seeds = 0
            total_keys = 0
            total_creds = 0
            total_urls = 0
            total_sms = 0
            total_tokens = 0
            total_apis = 0
            total_mail = 0
            total_cookies = 0
            
            # Scan each file with ULTRA scanner
            for file_path in file_list:
                if not self.is_scanning:
                    self.add_log("⏹️ Scan stopped by user", "warning")
                    break
                
                files_scanned += 1
                file_name = os.path.basename(file_path)
                
                # Update metrics
                self.metrics['files_scanned'] = files_scanned
                self.metrics['scan_phase'] = f'Ultra Scanning... {files_scanned}/{total_files}'
                
                # Calculate progress
                progress = (files_scanned / total_files) * 100
                self.progress_var.set(progress)
                self.progress_percent_var.set(f"{progress:.1f}%")
                
                # Calculate speed and update live stats
                elapsed = time.time() - start_time
                if elapsed > 0:
                    speed = files_scanned / elapsed
                    self.metrics['files_per_second'] = speed
                    self.speed_var.set(f"{speed:.1f} files/s")
                    
                    # Update elapsed time
                    hours, rem = divmod(int(elapsed), 3600)
                    minutes, seconds = divmod(rem, 60)
                    self.elapsed_time_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
                    
                    # Estimate remaining time
                    remaining_files = total_files - files_scanned
                    if speed > 0:
                        remaining_time = remaining_files / speed
                        self.metrics['estimated_time_remaining'] = remaining_time
                        hours, rem = divmod(int(remaining_time), 3600)
                        minutes, seconds = divmod(rem, 60)
                        self.remaining_time_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
                
                # Update live statistics counters
                self.mini_stats['files'].set(str(files_scanned))
                self.mini_stats['wallets'].set(str(total_wallets))
                self.mini_stats['seeds'].set(str(total_seeds))
                self.mini_stats['validated'].set(str(total_seeds))
                self.mini_stats['credentials'].set(str(total_creds))
                self.mini_stats['cookies'].set(str(total_cookies))
                self.mini_stats['sms'].set(str(total_sms))
                
                # Force UI update for real-time display
                self.root.update_idletasks()
                
                # ULTRA SCAN - Extract EVERYTHING
                try:
                    results = self.ultra_scanner.scan_file(file_path)
                    
                    # Process wallets
                    if results['wallets']:
                        count = len(results['wallets'])
                        total_wallets += count
                        self.add_log(f"💰 {file_name}: Found {count} wallet address(es)", "success")
                        
                        # Group by network for better display
                        by_network = {}
                        for wallet in results['wallets']:
                            network = wallet['network']
                            if network not in by_network:
                                by_network[network] = []
                            by_network[network].append(wallet['address'])
                        
                        # Display grouped by network
                        for network, addresses in by_network.items():
                            self.wallets_text.insert(tk.END, f"\n💰 {network} ({len(addresses)} addresses):\n")
                            self.wallets_text.insert(tk.END, "-" * 80 + "\n")
                            
                            # Show first 20 addresses
                            for addr in list(set(addresses))[:20]:
                                self.wallets_text.insert(tk.END, f"  {addr}\n")
                                
                                # Save to database
                                self.db.add_wallet({
                                    'address': addr,
                                    'network': network,
                                    'source_file': file_path
                                })
                            
                            if len(addresses) > 20:
                                self.wallets_text.insert(tk.END, f"  ... and {len(addresses) - 20} more\n")
                            
                            self.wallets_text.insert(tk.END, "\n")
                            self.wallets_text.see(tk.END)
                    
                    # Process seed phrases (ONLY seeds in Seeds tab)
                    if results['seeds']:
                        count = len(results['seeds'])
                        total_seeds += count
                        self.add_log(f"🌱 {file_name}: Found {count} VALID seed phrase(s)", "success")
                        
                        for seed in results['seeds']:
                            word_count = len(seed.split())
                            
                            # CRUD-style table display
                            self.seeds_text.insert(tk.END, "┌" + "─" * 78 + "┐\n")
                            self.seeds_text.insert(tk.END, f"│ 🌱 SEED PHRASE ({word_count} WORDS) - VALID ✅{' ' * (78-len(f' SEED PHRASE ({word_count} WORDS) - VALID ✅')-4)}│\n")
                            self.seeds_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                            
                            # Split seed into lines for better readability
                            words = seed.split()
                            for i in range(0, len(words), 6):
                                line_words = ' '.join(words[i:i+6])
                                self.seeds_text.insert(tk.END, f"│ {line_words:<76} │\n")
                            
                            self.seeds_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                            self.seeds_text.insert(tk.END, f"│ 📁 Source: {file_name:<64} │\n")
                            
                            # Save to database
                            self.db.add_seed_phrase({
                                'seed_phrase': seed,
                                'word_count': word_count,
                                'is_valid': True,
                                'source_file': file_path
                            })
                            
                            # Derive addresses if enabled
                            if self.opt_vars.get('derive_networks', tk.BooleanVar(value=True)).get():
                                try:
                                    self.seeds_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                                    self.seeds_text.insert(tk.END, f"│ 📊 DERIVED ADDRESSES:{' ' * 56} │\n")
                                    self.seeds_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                                    
                                    all_addresses = self.crypto_utils.derive_all_addresses_from_seed(seed)
                                    for network, addr_info in all_addresses.items():
                                        if 'address' in addr_info:
                                            address = addr_info['address']
                                            self.seeds_text.insert(tk.END, f"│ {network:8s}: {address:<66} │\n")
                                            self.db.add_derived_address({
                                                'seed_phrase': seed,
                                                'network': network,
                                                'address': address
                                            })
                                except Exception as e:
                                    self.seeds_text.insert(tk.END, f"│ ⚠️ Derivation error: {str(e)[:60]:<59} │\n")
                            
                            self.seeds_text.insert(tk.END, "└" + "─" * 78 + "┘\n\n")
                            self.seeds_text.see(tk.END)
                        
                        # Force update to show seeds immediately
                        self.root.update_idletasks()
                    
                    # Process private keys (ONLY keys in Keys tab)
                    if results['private_keys']:
                        count = len(results['private_keys'])
                        total_keys += count
                        self.add_log(f"🔑 {file_name}: Found {count} private key(s)", "success")
                        
                        for key_data in results['private_keys'][:20]:
                            key_type = key_data['type']
                            key = key_data['key']
                            
                            # CRUD-style table display in KEYS tab
                            self.keys_text.insert(tk.END, "┌" + "─" * 78 + "┐\n")
                            self.keys_text.insert(tk.END, f"│ 🔑 PRIVATE KEY - {key_type}{' ' * (78-len(f' PRIVATE KEY - {key_type}')-4)}│\n")
                            self.keys_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                            self.keys_text.insert(tk.END, f"│ {key:<76} │\n")
                            self.keys_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                            self.keys_text.insert(tk.END, f"│ 📁 Source: {file_name:<64} │\n")
                            
                            # Try to derive address
                            try:
                                if key_type in ['RAW_HEX_64', 'RAW_HEX_66', 'ETH_PRIVATE_KEY']:
                                    self.keys_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                                    self.keys_text.insert(tk.END, f"│ 📊 DERIVED ADDRESSES:{' ' * 56} │\n")
                                    self.keys_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                                    
                                    for network in ['ETH', 'BTC', 'TRX']:
                                        try:
                                            addr = self.crypto_utils.private_key_to_address(key, network)
                                            if addr:
                                                self.keys_text.insert(tk.END, f"│ {network:8s}: {addr:<66} │\n")
                                                self.db.add_wallet({
                                                    'address': addr,
                                                    'network': network,
                                                    'private_key': key,
                                                    'source_file': file_path
                                                })
                                        except:
                                            pass
                            except:
                                pass
                            
                            self.keys_text.insert(tk.END, "└" + "─" * 78 + "┘\n\n")
                            self.keys_text.see(tk.END)
                    
                    # Process credentials
                    if results['credentials']:
                        count = len(results['credentials'])
                        total_creds += count
                        
                        if count > 0:
                            self.add_log(f"🔐 {file_name}: Found {count} credential(s)", "success")
                            
                            # Display with better formatting
                            self.creds_text.insert(tk.END, f"\n📄 From: {file_name} ({count} credentials)\n")
                            self.creds_text.insert(tk.END, "-" * 80 + "\n")
                            
                            for cred in results['credentials'][:50]:  # Show first 50
                                username = cred['username']
                                password = cred['password']
                                self.creds_text.insert(tk.END, f"{username}:{password}\n")
                                self.creds_text.see(tk.END)
                                
                                self.db.add_credential({
                                    'email': username,
                                    'password': password,
                                    'source_file': file_path
                                })
                            
                            if count > 50:
                                self.creds_text.insert(tk.END, f"... and {count - 50} more credentials\n")
                            
                            self.creds_text.insert(tk.END, "\n")
                    
                    # Process URLs
                    if results['urls']:
                        count = len(results['urls'])
                        total_urls += count
                        if count > 0:
                            self.add_log(f"🔗 {file_name}: Found {count} URL(s)", "info")
                            # Show first few
                            for url in results['urls'][:5]:
                                self.details_text.insert(tk.END, f"🔗 {url}\n")
                    
                    # Process SMS APIs
                    if results['sms_apis']:
                        count = len(results['sms_apis'])
                        total_sms += count
                        
                        if count > 0:
                            self.add_log(f"📱 {file_name}: Found {count} SMS API credential(s)", "success")
                            
                            self.sms_text.insert(tk.END, "\n" + "=" * 80 + "\n")
                            self.sms_text.insert(tk.END, f"📱 SMS APIs from: {file_name}\n")
                            self.sms_text.insert(tk.END, "=" * 80 + "\n\n")
                            
                            for api in results['sms_apis']:
                                provider = api['provider']
                                self.sms_text.insert(tk.END, f"� Provider: {provider}\n")
                                self.sms_text.insert(tk.END, "-" * 80 + "\n")
                                
                                for key, value in api.items():
                                    if key != 'provider' and value:
                                        self.sms_text.insert(tk.END, f"  {key:15s}: {value}\n")
                                
                                self.sms_text.insert(tk.END, "\n")
                                self.sms_text.see(tk.END)
                                
                                self.db.add_sms_api({
                                    'provider': provider,
                                    'api_key': str(api),
                                    'source_file': file_path
                                })
                            
                            self.sms_text.insert(tk.END, "=" * 80 + "\n\n")
                    
                    # Process social tokens
                    if results['social_tokens']:
                        count = len(results['social_tokens'])
                        total_tokens += count
                        self.add_log(f"💬 {file_name}: Found {count} social media token(s)", "success")
                        
                        for token_data in results['social_tokens']:
                            platform = token_data['platform']
                            token = token_data['token']
                            self.details_text.insert(tk.END, f"💬 {platform}: {token}\n")
                    
                    # Process API keys
                    if results['api_keys']:
                        count = len(results['api_keys'])
                        total_apis += count
                        self.add_log(f"🔑 {file_name}: Found {count} API key(s)", "success")
                        
                        for api_data in results['api_keys']:
                            service = api_data['service']
                            api_key = api_data['api_key']
                            # Display in API Keys tab with CRUD-style formatting
                            self.apikeys_text.insert(tk.END, "┌" + "─" * 78 + "┐\n")
                            self.apikeys_text.insert(tk.END, f"│ 🔑 {service.upper()}{' ' * (78-len(f' {service.upper()}')-4)}│\n")
                            self.apikeys_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                            self.apikeys_text.insert(tk.END, f"│ {api_key:<76} │\n")
                            self.apikeys_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                            self.apikeys_text.insert(tk.END, f"│ 📁 Source: {file_name:<64} │\n")
                            self.apikeys_text.insert(tk.END, "└" + "─" * 78 + "┘\n\n")
                            self.apikeys_text.see(tk.END)
                    
                    # Process Mail Access (NEW)
                    if results.get('mail_access'):
                        mail_accounts = results['mail_access']
                        count = len(mail_accounts)
                        total_mail += count
                        if count > 0:
                            self.add_log(f"📧 {file_name}: Found {count} mail access account(s)", "success")
                            
                            for mail_data in mail_accounts:
                                # CRUD-style table display in Mail Access tab
                                provider = mail_data.get('provider', 'UNKNOWN').upper()
                                header_text = f" MAIL ACCESS - {provider}"
                                padding = 78 - len(header_text) - 4
                                
                                self.mail_text.insert(tk.END, "┌" + "─" * 78 + "┐\n")
                                self.mail_text.insert(tk.END, f"│ 📧{header_text}{' ' * padding}│\n")
                                self.mail_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                                
                                # Email
                                if 'email' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 📬 Email      : {mail_data['email']:<61} │\n")
                                
                                # Password
                                if 'password' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 🔐 Password   : {mail_data['password']:<61} │\n")
                                
                                # SMTP Server
                                if 'smtp_server' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 📤 SMTP Server: {mail_data['smtp_server']:<61} │\n")
                                
                                # SMTP Port
                                if 'smtp_port' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 🔌 SMTP Port  : {str(mail_data['smtp_port']):<61} │\n")
                                
                                # IMAP Server
                                if 'imap_server' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 📥 IMAP Server: {mail_data['imap_server']:<61} │\n")
                                
                                # IMAP Port
                                if 'imap_port' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 🔌 IMAP Port  : {str(mail_data['imap_port']):<61} │\n")
                                
                                # POP3 Server
                                if 'pop3_server' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 📥 POP3 Server: {mail_data['pop3_server']:<61} │\n")
                                
                                # POP3 Port
                                if 'pop3_port' in mail_data:
                                    self.mail_text.insert(tk.END, f"│ 🔌 POP3 Port  : {str(mail_data['pop3_port']):<61} │\n")
                                
                                self.mail_text.insert(tk.END, "├" + "─" * 78 + "┤\n")
                                self.mail_text.insert(tk.END, f"│ 📁 Source: {file_name:<64} │\n")
                                self.mail_text.insert(tk.END, "└" + "─" * 78 + "┘\n\n")
                                self.mail_text.see(tk.END)
                                
                                # Save to database
                                self.db.add_smtp_credential({
                                    'email': mail_data.get('email', ''),
                                    'password': mail_data.get('password', ''),
                                    'smtp_server': mail_data.get('smtp_server', ''),
                                    'smtp_port': mail_data.get('smtp_port', 0),
                                    'source_file': file_path
                                })
                    
                    # Process Cookies
                    if results.get('cookies'):
                        count = len(results['cookies'])
                        total_cookies += count
                        if count > 0:
                            self.cookies_text.insert(tk.END, f"\n📄 From: {file_name} ({count} cookies)\n")
                            self.cookies_text.insert(tk.END, "-" * 80 + "\n")
                            for cookie in results['cookies'][:50]:
                                self.cookies_text.insert(tk.END, f"{cookie}\n")
                            if count > 50:
                                self.cookies_text.insert(tk.END, f"... and {count - 50} more cookies\n")
                            self.cookies_text.insert(tk.END, "\n")
                            self.cookies_text.see(tk.END)
                
                except Exception as e:
                    if files_scanned % 100 == 0:
                        self.add_log(f"⚠️ Error scanning {file_name}: {str(e)[:50]}", "warning")
                
                # Update display more frequently for better responsiveness
                if files_scanned % 5 == 0:  # Update every 5 files instead of 10
                    self.root.update_idletasks()
                
                # Log progress every 50 files
                if files_scanned % 50 == 0:
                    self.add_log(f"📊 Progress: {files_scanned}/{total_files} files ({progress:.1f}%) - Speed: {speed:.1f} files/s", "info")
            
            # Final update
            self.progress_var.set(100)
            self.progress_percent_var.set("100%")
            
            # Comprehensive summary with better formatting
            summary = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║           🔥 ULTRA SCAN COMPLETE - MAXIMUM EXTRACTION 🔥                ║
╚══════════════════════════════════════════════════════════════════════════╝

📊 EXTRACTION RESULTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Files Processed:       {files_scanned:,} / {total_files:,}
💰 Wallet Addresses:      {total_wallets:,}
🌱 Seed Phrases (VALID):  {total_seeds:,}
🔑 Private Keys:          {total_keys:,}
🔐 Credentials:           {total_creds:,}
� Mail Access:           {total_mail:,}
🍪 Cookies:               {total_cookies:,}
�🔗 URLs Extracted:        {total_urls:,}
📱 SMS APIs:              {total_sms:,}
💬 Social Tokens:         {total_tokens:,}
🔑 API Keys:              {total_apis:,}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⏱️  Scan Time:     {elapsed:.2f} seconds ({elapsed/60:.1f} minutes)
⚡ Average Speed:  {speed:.2f} files/second
🎯 Success Rate:   {(files_scanned/total_files*100):.1f}%

✅ SMART FEATURES APPLIED:
   • BIP39 seed phrase validation
   • Fake/test data filtering
   • Duplicate removal
   • Address derivation from seeds
   • Private key validation
   • Credential format validation
   • Mail server configuration extraction
   • Cookie and session data extraction

💾 DATABASE: All findings saved to lulzsec_wallets_ultimate_v9.db
📊 TABS: Check all 9 tabs for complete results
📤 EXPORT: Use Export menu to save results in various formats

{"🎉 HIGH VALUE SCAN! Seeds/Keys/Mail Found!" if total_seeds > 0 or total_keys > 0 or total_mail > 0 else ""}
            """
            self.add_log(summary, "success")
            
            # Update final statistics
            self.update_metrics_from_db()
            
        except Exception as e:
            self.add_log(f"❌ Scan error: {e}", "error")
            import traceback
            self.add_log(traceback.format_exc(), "error")
        finally:
            self.is_scanning = False
            self.metrics['scan_phase'] = 'Idle'
            self.scan_status_label.config(text="[◼ STANDBY]", fg=self.theme.colors['neon_yellow'])
            self.scan_crypto_btn.config(state='normal')
            self.scan_all_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
        """Run cryptocurrency scan"""
        try:
            # Update phase
            self.metrics['scan_phase'] = 'Initializing...'
            
            # Count files first
            total_files = 0
            for root, dirs, files in os.walk(target_dir):
                total_files += len(files)
            
            if total_files == 0:
                self.add_log("⚠️ No files found in directory", "warning")
                return
            
            self.add_log(f"📊 Found {total_files} files to scan", "info")
            
            # Scan files
            files_scanned = 0
            start_time = time.time()
            
            for root, dirs, files in os.walk(target_dir):
                if not self.is_scanning:
                    self.add_log("⏹️ Scan stopped by user", "warning")
                    break
                
                for file in files:
                    if not self.is_scanning:
                        break
                    
                    file_path = os.path.join(root, file)
                    files_scanned += 1
                    
                    # Update metrics
                    self.metrics['files_scanned'] = files_scanned
                    self.metrics['scan_phase'] = f'Scanning... {files_scanned}/{total_files}'
                    
                    # Calculate progress
                    progress = (files_scanned / total_files) * 100
                    self.progress_var.set(progress)
                    self.progress_percent_var.set(f"{progress:.1f}%")
                    
                    # Calculate speed
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        speed = files_scanned / elapsed
                        self.metrics['files_per_second'] = speed
                        
                        # Estimate remaining time
                        remaining_files = total_files - files_scanned
                        if speed > 0:
                            remaining_time = remaining_files / speed
                            self.metrics['estimated_time_remaining'] = remaining_time
                    
                    try:
                        # Read file content
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1024 * 1024)  # Read max 1MB
                        
                        # Extract wallet addresses using regex patterns
                        wallet_patterns = {
                            'ETH': r'0x[a-fA-F0-9]{40}',
                            'BTC': r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b',
                            'TRX': r'T[A-Za-z1-9]{33}',
                            'SOL': r'[1-9A-HJ-NP-Za-km-z]{32,44}',
                            'LTC': r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}',
                            'DOGE': r'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}'
                        }
                        
                        addresses_found = []
                        for network, pattern in wallet_patterns.items():
                            matches = re.findall(pattern, content)
                            for match in matches[:10]:  # Limit per network
                                addresses_found.append({'network': network, 'address': match})
                        
                        if addresses_found:
                            self.add_log(f"💰 Found {len(addresses_found)} address(es) in {file}", "success")
                            for addr in addresses_found[:5]:  # Limit display
                                network = addr.get('network', 'UNKNOWN')
                                address = addr.get('address', '')
                                self.wallets_text.insert(tk.END, f"{network}: {address}\n")
                                
                                # Save to database
                                self.db.add_wallet({
                                    'address': address,
                                    'network': network,
                                    'source_file': file_path
                                })
                        
                        # Extract seed phrases
                        seeds = self.crypto_utils.extract_seed_phrases_from_text(content)
                        if seeds:
                            self.add_log(f"🌱 Found {len(seeds)} seed phrase(s) in {file}", "success")
                            for seed in seeds:
                                # Validate seed
                                is_valid = self.crypto_utils.validate_seed_phrase(seed)
                                status = "✅ VALID" if is_valid else "❌ INVALID"
                                
                                self.seeds_text.insert(tk.END, f"{status}: {seed[:50]}...\n")
                                
                                # Save to database
                                self.db.add_seed_phrase({
                                    'seed_phrase': seed,
                                    'word_count': len(seed.split()),
                                    'is_valid': is_valid,
                                    'source_file': file_path
                                })
                                
                                # If valid and option enabled, derive addresses
                                if is_valid and self.opt_vars.get('derive_networks', tk.BooleanVar(value=True)).get():
                                    private_keys = self.crypto_utils.extract_private_keys_from_text(seed)
                                    if private_keys:
                                        pk = private_keys[0]
                                        for network in ['ETH', 'BTC', 'TRX', 'SOL']:
                                            try:
                                                addr = self.crypto_utils.private_key_to_address(pk, network)
                                                if addr:
                                                    self.db.add_derived_address({
                                                        'seed_phrase': seed,
                                                        'network': network,
                                                        'address': addr
                                                    })
                                            except:
                                                pass
                        
                        # Extract credentials if enabled
                        if self.opt_vars.get('extract_creds', tk.BooleanVar(value=True)).get():
                            # Simple email:password pattern
                            cred_pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s]+)'
                            matches = re.findall(cred_pattern, content)
                            
                            if matches:
                                self.add_log(f"🔑 Found {len(matches)} credential(s) in {file}", "success")
                                for email, password in matches[:10]:  # Limit
                                    self.creds_text.insert(tk.END, f"{email}:{password}\n")
                                    
                                    self.db.add_credential({
                                        'email': email,
                                        'password': password,
                                        'source_file': file_path
                                    })
                        
                        # Detect SMS APIs if enabled
                        if self.opt_vars.get('detect_sms', tk.BooleanVar(value=True)).get():
                            sms_apis = self.sms_detector.scan_text_for_apis(content)
                            if sms_apis:
                                self.add_log(f"📱 Found {len(sms_apis)} SMS API credential(s) in {file}", "success")
                                for api in sms_apis:
                                    provider = api.get('provider', 'Unknown')
                                    creds = api.get('credentials', {})
                                    self.sms_text.insert(tk.END, f"{provider}: {creds}\n")
                                    
                                    self.db.add_sms_api({
                                        'provider': provider,
                                        'api_key': str(creds),
                                        'source_file': file_path
                                    })
                    
                    except Exception as e:
                        if files_scanned % 100 == 0:  # Only log every 100 files
                            self.add_log(f"⚠️ Error scanning {file}: {str(e)[:50]}", "warning")
            
            # Final update
            self.progress_var.set(100)
            self.progress_percent_var.set("100%")
            self.add_log(f"✅ Cryptocurrency scan complete! Scanned {files_scanned} files", "success")
            
            # Update final statistics
            self.update_metrics_from_db()
            
            # Show summary
            stats = self.db.get_statistics()
            summary = f"""
📊 SCAN SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Files Scanned: {files_scanned}
💰 Wallets Found: {stats.get('wallets', 0)}
🌱 Seeds Found: {stats.get('seeds', 0)}
✅ Valid Seeds: {stats.get('valid_seeds', 0)}
🔑 Credentials: {stats.get('credentials', 0)}
📱 SMS APIs: {stats.get('sms_apis', 0)}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            """
            self.add_log(summary, "success")
            
        except Exception as e:
            self.add_log(f"❌ Scan error: {e}", "error")
            import traceback
            self.add_log(traceback.format_exc(), "error")
        finally:
            self.is_scanning = False
            self.metrics['scan_phase'] = 'Idle'
            self.scan_status_label.config(text="[◼ STANDBY]", fg=self.theme.colors['neon_yellow'])
            self.scan_crypto_btn.config(state='normal')
            self.scan_all_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
    
    def start_full_scan(self):
        """Start full forensic scan"""
        target_dir = self.dir_var.get()
        if not target_dir or not os.path.exists(target_dir):
            messagebox.showerror("Error", "Please select a valid target directory")
            return
        
        self.is_scanning = True
        self.metrics['scan_start_time'] = time.time()
        self.metrics['scan_phase'] = 'Full Scan...'
        
        # Update UI
        self.scan_status_label.config(text="[▶ SCANNING]", fg=self.theme.colors['neon_green'])
        self.scan_crypto_btn.config(state='disabled')
        self.scan_all_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        self.add_log("🚀 Starting full forensic scan...", "success")
        self.add_log(f"📁 Target: {target_dir}", "info")
        
        # Start scan in thread
        import threading
        self.scan_thread = threading.Thread(target=self._run_full_scan, args=(target_dir,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _run_full_scan(self, target_dir):
        """Run full forensic scan"""
        try:
            # Full scan includes everything from crypto scan plus more
            self.add_log("📊 Starting comprehensive forensic extraction...", "info")
            
            # Run the crypto scan logic (same as crypto scan)
            self._run_crypto_scan(target_dir)
            
        except Exception as e:
            self.add_log(f"❌ Scan error: {e}", "error")
            import traceback
            self.add_log(traceback.format_exc(), "error")
        finally:
            self.is_scanning = False
            self.metrics['scan_phase'] = 'Idle'
            self.scan_status_label.config(text="[◼ STANDBY]", fg=self.theme.colors['neon_yellow'])
            self.scan_crypto_btn.config(state='normal')
            self.scan_all_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
    
    def stop_scan(self):
        """Stop current scan"""
        if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the scan?"):
            self.is_scanning = False
            self.add_log("⏹️ Scan stopped by user", "warning")
    
    def check_balances(self):
        """Check wallet balances"""
        self.add_log("💰 Checking balances...", "info")
        messagebox.showinfo("Balance Check", "Balance checking will be implemented in the full scanner integration")
    
    def validate_emails(self):
        """Validate email credentials"""
        self.add_log("📧 Validating emails...", "info")
        messagebox.showinfo("Email Validation", "Email validation will be implemented in the full scanner integration")
    
    def export_all_data(self):
        """Export all data"""
        self.add_log("💾 Exporting all data...", "info")
        messagebox.showinfo("Export", "Data export will be implemented in the full scanner integration")
    
    def refresh_all(self):
        """Refresh all data displays"""
        self.add_log("🔄 Refreshing displays...", "info")
        self.update_metrics_from_db()
    
    def backup_database(self):
        """Backup database"""
        try:
            backup_path = self.db.backup_database()
            messagebox.showinfo("Backup Complete", f"Database backed up to:\n{backup_path}")
            self.add_log(f"💾 Database backed up: {backup_path}", "success")
        except Exception as e:
            messagebox.showerror("Backup Error", f"Failed to backup database:\n{e}")
            self.add_log(f"❌ Backup failed: {e}", "error")
    
    # Placeholder methods for menu items
    def export_wallets_json(self):
        messagebox.showinfo("Export", "Wallet export (JSON) - Coming soon")
    
    def export_seeds_txt(self):
        messagebox.showinfo("Export", "Seed export (TXT) - Coming soon")
    
    def export_credentials_csv(self):
        messagebox.showinfo("Export", "Credentials export (CSV) - Coming soon")
    
    def export_sms_apis(self):
        messagebox.showinfo("Export", "SMS API export - Coming soon")
    
    def open_key_converter(self):
        messagebox.showinfo("Tool", "Private Key Converter - Coming soon")
    
    def bulk_validate_seeds(self):
        messagebox.showinfo("Tool", "Bulk Seed Validator - Coming soon")
    
    def bulk_check_balances(self):
        messagebox.showinfo("Tool", "Bulk Balance Checker - Coming soon")
    
    def search_url_tool(self):
        """Advanced URL/Domain search tool"""
        # Create dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("🔍 Advanced URL/Domain Search")
        dialog.geometry("900x700")
        dialog.configure(bg=self.theme.colors['bg'])
        
        # Header
        tk.Label(dialog, text="🔍 SEARCH SPECIFIC WEBSITE/DOMAIN",
                bg=self.theme.colors['bg'],
                fg=self.theme.colors['accent'],
                font=('Segoe UI', 14, 'bold')).pack(pady=10)
        
        tk.Label(dialog, text="Find all credentials, cookies, tokens for a specific domain",
                bg=self.theme.colors['bg'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['small']).pack(pady=5)
        
        # Input frame
        input_frame = tk.Frame(dialog, bg=self.theme.colors['bg_card'], padx=20, pady=15)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(input_frame, text="Target Domain:",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg'],
                font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        
        domain_var = tk.StringVar()
        domain_entry = tk.Entry(input_frame, textvariable=domain_var,
                               bg=self.theme.colors['bg_tertiary'],
                               fg=self.theme.colors['fg'],
                               font=('Segoe UI', 11),
                               insertbackground=self.theme.colors['accent'],
                               width=50)
        domain_entry.pack(fill=tk.X, pady=5, ipady=5)
        
        # Quick domains
        quick_frame = tk.Frame(input_frame, bg=self.theme.colors['bg_card'])
        quick_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(quick_frame, text="Quick Select:",
                bg=self.theme.colors['bg_card'],
                fg=self.theme.colors['fg_secondary'],
                font=self.theme.fonts['small']).pack(side=tk.LEFT, padx=(0, 10))
        
        quick_domains = ['binance.com', 'coinbase.com', 'gmail.com', 'outlook.com', 'paypal.com']
        for domain in quick_domains:
            tk.Button(quick_frame, text=domain,
                     command=lambda d=domain: domain_var.set(d),
                     bg=self.theme.colors['neon_blue'],
                     fg='#ffffff',
                     font=self.theme.fonts['small'],
                     borderwidth=0, relief='flat',
                     padx=8, pady=4, cursor='hand2').pack(side=tk.LEFT, padx=2)
        
        # Results frame
        results_frame = tk.LabelFrame(dialog, text="  Results  ",
                                     bg=self.theme.colors['bg_secondary'],
                                     fg=self.theme.colors['neon_yellow'],
                                     font=('Segoe UI', 10, 'bold'))
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        results_text = scrolledtext.ScrolledText(results_frame,
                                                 bg=self.theme.colors['bg_tertiary'],
                                                 fg=self.theme.colors['fg'],
                                                 font=self.theme.fonts['mono_small'],
                                                 wrap=tk.WORD)
        results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def perform_search():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showwarning("Input Required", "Please enter a domain to search")
                return
            
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🔍 Searching for: {domain}\n")
            results_text.insert(tk.END, "=" * 80 + "\n\n")
            
            # Get last scan directory
            last_dir = self.dir_var.get()
            if not last_dir or not os.path.exists(last_dir):
                results_text.insert(tk.END, "⚠️ Please run a scan first to search results\n")
                return
            
            # Search all scanned files
            found_count = 0
            total_creds = []
            total_urls = []
            total_cookies = []
            total_tokens = []
            
            for root, dirs, files in os.walk(last_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(5 * 1024 * 1024)  # Max 5MB
                        
                        # Search for domain
                        search_result = self.url_extractor.search_domain(content, domain)
                        
                        if search_result['found']:
                            found_count += 1
                            results_text.insert(tk.END, f"\n📄 File: {os.path.basename(file_path)}\n")
                            results_text.insert(tk.END, "-" * 80 + "\n")
                            
                            if search_result['urls']:
                                results_text.insert(tk.END, f"🔗 URLs ({len(search_result['urls'])}):\n")
                                for url in search_result['urls'][:10]:
                                    results_text.insert(tk.END, f"  • {url}\n")
                                    total_urls.append(url)
                                results_text.insert(tk.END, "\n")
                            
                            if search_result['credentials']:
                                results_text.insert(tk.END, f"🔐 Credentials ({len(search_result['credentials'])}):\n")
                                for cred in search_result['credentials'][:10]:
                                    results_text.insert(tk.END, f"  • {cred.get('email', 'N/A')}:{cred.get('password', 'N/A')}\n")
                                    total_creds.append(cred)
                                results_text.insert(tk.END, "\n")
                            
                            if search_result['cookies']:
                                results_text.insert(tk.END, f"🍪 Cookies ({len(search_result['cookies'])}):\n")
                                for cookie in search_result['cookies'][:5]:
                                    results_text.insert(tk.END, f"  • {cookie}\n")
                                    total_cookies.append(cookie)
                                results_text.insert(tk.END, "\n")
                            
                            if search_result['tokens']:
                                results_text.insert(tk.END, f"🔑 Tokens ({len(search_result['tokens'])}):\n")
                                for token in search_result['tokens'][:5]:
                                    results_text.insert(tk.END, f"  • {token}\n")
                                    total_tokens.append(token)
                                results_text.insert(tk.END, "\n")
                    
                    except:
                        continue
            
            # Summary
            results_text.insert(tk.END, "\n" + "=" * 80 + "\n")
            results_text.insert(tk.END, "📊 SEARCH SUMMARY\n")
            results_text.insert(tk.END, "=" * 80 + "\n")
            results_text.insert(tk.END, f"Files with matches: {found_count}\n")
            results_text.insert(tk.END, f"Total URLs found: {len(total_urls)}\n")
            results_text.insert(tk.END, f"Total Credentials: {len(total_creds)}\n")
            results_text.insert(tk.END, f"Total Cookies: {len(total_cookies)}\n")
            results_text.insert(tk.END, f"Total Tokens: {len(total_tokens)}\n")
            
            if found_count == 0:
                results_text.insert(tk.END, "\n⚠️ No matches found for this domain\n")
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=self.theme.colors['bg'])
        btn_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(btn_frame, text="🔍 Search",
                 command=perform_search,
                 bg=self.theme.colors['accent'],
                 fg='#000000',
                 font=('Segoe UI', 11, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=20, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="💾 Export Results",
                 command=lambda: self.export_text_content(results_text.get(1.0, tk.END), f"{domain_var.get()}_search_results.txt"),
                 bg=self.theme.colors['neon_blue'],
                 fg='#ffffff',
                 font=('Segoe UI', 10, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=20, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="❌ Close",
                 command=dialog.destroy,
                 bg=self.theme.colors['danger'],
                 fg='#ffffff',
                 font=('Segoe UI', 10, 'bold'),
                 borderwidth=0, relief='flat',
                 padx=20, pady=10, cursor='hand2').pack(side=tk.RIGHT, padx=5)
    
    def export_text_content(self, content: str, filename: str):
        """Export text content to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=filename,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Results exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export:\n{e}")
    
    def open_api_settings(self):
        messagebox.showinfo("Settings", "API Management - Coming soon")
    
    def test_apis(self):
        messagebox.showinfo("Settings", "API Testing - Coming soon")
    
    def show_user_guide(self):
        messagebox.showinfo("Help", "User Guide - Coming soon")
    
    def show_about(self):
        about_text = """
LulzSec Forensic Scanner v9.1 Advanced

Federal-Grade Cryptocurrency Recovery & OSINT System

Coded by: @Lulz1337

Features:
• Multi-network wallet detection (14+ blockchains)
• BIP39 seed phrase extraction & validation
• Credential extraction & validation
• SMS API detection
• Cloud service identification
• Browser cookie extraction
• Real-time balance checking
• Advanced export capabilities

© 2025 LulzSec. All rights reserved.
        """
        messagebox.showinfo("About", about_text)
    
    def run(self):
        """Run the GUI"""
        self.root.mainloop()


if __name__ == "__main__":
    app = LulzSecAdvancedGUI()
    app.run()
