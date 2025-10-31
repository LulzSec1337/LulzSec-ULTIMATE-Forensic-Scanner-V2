#!/usr/bin/env python3
"""
API Settings GUI - Configure API keys and test connections
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import os
import sys
import threading

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.api_config import APIConfig
from core.balance_checker import AdvancedBalanceChecker
from core.seed_balance_checker import SeedBalanceChecker


class APISettingsGUI:
    """
    API Settings & Testing GUI
    - Configure API keys
    - Test connections
    - Check balance examples
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔧 API Settings & Testing")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e1e')
        
        # Load config
        self.api_config = APIConfig()
        self.balance_checker = None
        
        # Style
        self.setup_styles()
        
        # Build UI
        self.create_widgets()
        
        # Load current settings
        self.load_settings()
    
    def setup_styles(self):
        """Setup dark theme styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff', font=('Segoe UI', 10))
        style.configure('TButton', background='#0d7377', foreground='#ffffff', font=('Segoe UI', 10, 'bold'))
        style.map('TButton', background=[('active', '#14a085')])
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'), foreground='#00d4ff')
        style.configure('Success.TLabel', foreground='#00ff00')
        style.configure('Error.TLabel', foreground='#ff0000')
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Header
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(
            header_frame,
            text="🔧 API Configuration & Testing",
            style='Header.TLabel'
        ).pack(side='left')
        
        ttk.Button(
            header_frame,
            text="💾 Save Settings",
            command=self.save_settings
        ).pack(side='right', padx=5)
        
        ttk.Button(
            header_frame,
            text="♻️  Reset to Free APIs",
            command=self.reset_to_free_apis
        ).pack(side='right', padx=5)
        
        # Create notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: API Keys
        api_tab = ttk.Frame(notebook)
        notebook.add(api_tab, text="🔑 API Keys")
        self.create_api_keys_tab(api_tab)
        
        # Tab 2: Testing
        test_tab = ttk.Frame(notebook)
        notebook.add(test_tab, text="🧪 Test Connections")
        self.create_test_tab(test_tab)
        
        # Tab 3: Examples
        examples_tab = ttk.Frame(notebook)
        notebook.add(examples_tab, text="📋 Examples")
        self.create_examples_tab(examples_tab)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief='sunken'
        )
        status_label.pack(fill='x', side='bottom', padx=10, pady=5)
    
    def create_api_keys_tab(self, parent):
        """Create API keys configuration tab"""
        
        # Scrollable frame
        canvas = tk.Canvas(parent, bg='#1e1e1e', highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # API Key fields
        self.api_entries = {}
        
        apis = [
            ("Etherscan (ETH)", "etherscan_key", "Get free API: https://etherscan.io/apis"),
            ("BSCScan (BSC)", "bscscan_key", "Get free API: https://bscscan.com/apis"),
            ("PolygonScan (POLYGON)", "polygonscan_key", "Get free API: https://polygonscan.com/apis"),
            ("SnowTrace (AVAX)", "snowtrace_key", "Get free API: https://snowtrace.io/apis"),
            ("FTMScan (Fantom)", "ftmscan_key", "Get free API: https://ftmscan.com/apis"),
            ("Arbiscan (Arbitrum)", "arbiscan_key", "Get free API: https://arbiscan.io/apis"),
            ("Optimism Etherscan", "optimism_key", "Get free API: https://optimistic.etherscan.io/apis"),
        ]
        
        for i, (name, key, hint) in enumerate(apis):
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill='x', padx=20, pady=10)
            
            ttk.Label(frame, text=name, font=('Segoe UI', 11, 'bold')).pack(anchor='w')
            ttk.Label(frame, text=hint, foreground='#888888').pack(anchor='w')
            
            entry = ttk.Entry(frame, width=60, font=('Consolas', 9))
            entry.pack(fill='x', pady=5)
            self.api_entries[key] = entry
        
        # Info box
        info_frame = ttk.Frame(scrollable_frame)
        info_frame.pack(fill='x', padx=20, pady=20)
        
        info_text = """
ℹ️  API Key Information:

• FREE APIs: No key required! Scanner works without API keys using free endpoints
• Optional Keys: Add keys for higher rate limits (5 requests/sec vs 1 request/sec)
• Get Keys: Visit the links above to register for free API keys
• Privacy: Keys stored locally in api_config.json (never sent to external servers)

💡 Tip: Leave empty to use free public endpoints!
        """
        
        info_label = tk.Label(
            info_frame,
            text=info_text,
            bg='#2a2a2a',
            fg='#00d4ff',
            font=('Segoe UI', 9),
            justify='left',
            padx=10,
            pady=10
        )
        info_label.pack(fill='both')
    
    def create_test_tab(self, parent):
        """Create connection testing tab"""
        
        # Test buttons frame
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=20, pady=20)
        
        ttk.Label(btn_frame, text="Test Connections:", font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=5)
        
        buttons = [
            ("🌐 Test All Networks", self.test_all_networks),
            ("💰 Test Balance Check (ETH)", lambda: self.test_balance("ETH")),
            ("₿  Test Balance Check (BTC)", lambda: self.test_balance("BTC")),
            ("🔗 Test BSC", lambda: self.test_balance("BSC")),
            ("🌈 Test POLYGON", lambda: self.test_balance("POLYGON")),
            ("💵 Test Price API", self.test_price_api),
            ("🌱 Test Seed Derivation", self.test_seed_derivation),
        ]
        
        for text, command in buttons:
            ttk.Button(btn_frame, text=text, command=command, width=30).pack(pady=5)
        
        # Results area
        ttk.Label(parent, text="Test Results:", font=('Segoe UI', 12, 'bold')).pack(anchor='w', padx=20, pady=(20, 5))
        
        self.test_output = scrolledtext.ScrolledText(
            parent,
            height=20,
            bg='#0a0a0a',
            fg='#00ff00',
            font=('Consolas', 9),
            insertbackground='white'
        )
        self.test_output.pack(fill='both', expand=True, padx=20, pady=(0, 20))
    
    def create_examples_tab(self, parent):
        """Create examples tab"""
        
        example_text = """
═══════════════════════════════════════════════════════════════════════════
                        📋 USAGE EXAMPLES
═══════════════════════════════════════════════════════════════════════════

1. CHECK BALANCE FOR ADDRESS
───────────────────────────────────────────────────────────────────────────
    from core.balance_checker import AdvancedBalanceChecker
    from config.api_config import APIConfig
    
    api_config = APIConfig()
    checker = AdvancedBalanceChecker(api_config)
    
    # Check ETH balance
    balance = checker.get_balance("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb", "ETH")
    print(f"Balance: {balance} ETH")
    
    # Get USD value
    usd_value = checker.get_balance_in_usd("0x742d...", "ETH")
    print(f"Value: ${usd_value:.2f}")

2. CHECK SEED PHRASE BALANCE
───────────────────────────────────────────────────────────────────────────
    from core.seed_balance_checker import SeedBalanceChecker
    
    seed_checker = SeedBalanceChecker(balance_checker)
    
    seed = "word1 word2 word3 ... word12"
    results = seed_checker.check_seed_balances(seed, check_indices=5)
    
    print(f"Total: ${results['total_usd']:.2f}")
    for network, info in results['networks'].items():
        print(f"{network}: {info['total_balance']} coins")

3. SUPPORTED NETWORKS
───────────────────────────────────────────────────────────────────────────
    • Ethereum (ETH)           • Binance Smart Chain (BSC)
    • Bitcoin (BTC)            • Polygon (MATIC)
    • Solana (SOL)             • Avalanche (AVAX)
    • Tron (TRX)               • Fantom (FTM)
    • Litecoin (LTC)           • Arbitrum (ARB)
    • Dogecoin (DOGE)          • Optimism (OP)

4. FREE API ENDPOINTS (NO KEY REQUIRED)
───────────────────────────────────────────────────────────────────────────
    ETH:     https://api.etherscan.io/api
    BTC:     https://blockstream.info/api
    BSC:     https://api.bscscan.com/api
    POLYGON: https://api.polygonscan.com/api
    
    ⚠️  Rate Limit: 1 request/sec (free)
    ✅ With API Key: 5 requests/sec

5. PERFORMANCE OPTIMIZATION
───────────────────────────────────────────────────────────────────────────
    from core.performance_optimizer import PerformanceOptimizer
    
    optimizer = PerformanceOptimizer(
        max_cpu_percent=70,
        max_memory_percent=70
    )
    
    # Process in batches
    results = optimizer.process_in_batches(
        items_list,
        process_function,
        batch_size=100
    )
    
    ✅ CPU usage kept under 70%
    ✅ RAM usage kept under 70%
    ✅ No system freezing!

═══════════════════════════════════════════════════════════════════════════
        """
        
        text_widget = scrolledtext.ScrolledText(
            parent,
            bg='#0a0a0a',
            fg='#00d4ff',
            font=('Consolas', 9),
            wrap='word'
        )
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', example_text)
        text_widget.config(state='disabled')
    
    def load_settings(self):
        """Load current API settings"""
        try:
            if os.path.exists('api_config.json'):
                with open('api_config.json', 'r') as f:
                    config = json.load(f)
                
                # Load etherscan key
                if 'etherscan' in config and 'key' in config['etherscan']:
                    self.api_entries['etherscan_key'].insert(0, config['etherscan']['key'])
                
                self.log_output("✅ Settings loaded")
        except Exception as e:
            self.log_output(f"⚠️  Error loading settings: {e}")
    
    def save_settings(self):
        """Save API settings"""
        try:
            config = {
                "etherscan": {"key": self.api_entries['etherscan_key'].get().strip(), "free": True},
                "bscscan": {"key": self.api_entries['bscscan_key'].get().strip(), "free": True},
                "polygonscan": {"key": self.api_entries['polygonscan_key'].get().strip(), "free": True},
                "snowtrace": {"key": self.api_entries['snowtrace_key'].get().strip(), "free": True},
                "ftmscan": {"key": self.api_entries['ftmscan_key'].get().strip(), "free": True},
                "arbiscan": {"key": self.api_entries['arbiscan_key'].get().strip(), "free": True},
                "optimism": {"key": self.api_entries['optimism_key'].get().strip(), "free": True}
            }
            
            with open('api_config.json.template', 'w') as f:
                json.dump(config, f, indent=2)
            
            messagebox.showinfo("Success", "✅ API settings saved to api_config.json.template")
            self.status_var.set("Settings saved successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings:\n{e}")
            self.status_var.set(f"Error: {e}")
    
    def reset_to_free_apis(self):
        """Reset to free API endpoints"""
        if messagebox.askyesno("Reset", "Reset all API keys to use free endpoints?"):
            for entry in self.api_entries.values():
                entry.delete(0, 'end')
            self.status_var.set("Reset to free APIs")
            messagebox.showinfo("Reset", "✅ Resetted to free API endpoints")
    
    def log_output(self, message):
        """Log message to test output"""
        if hasattr(self, 'test_output'):
            self.test_output.insert('end', f"{message}\n")
            self.test_output.see('end')
        self.status_var.set(message)
    
    def test_all_networks(self):
        """Test all network connections"""
        self.log_output("\n" + "="*70)
        self.log_output("🌐 TESTING ALL NETWORKS")
        self.log_output("="*70)
        
        def run_test():
            try:
                # Reinitialize with current settings
                self.api_config = APIConfig()
                self.balance_checker = AdvancedBalanceChecker(self.api_config)
                
                test_addresses = {
                    'ETH': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
                    'BTC': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                    'BSC': '0x8894E0a0c962CB723c1976a4421c95949bE2D4E3',
                }
                
                for network, address in test_addresses.items():
                    self.log_output(f"\n📡 Testing {network}...")
                    try:
                        info = self.balance_checker.get_comprehensive_balance(address, network)
                        self.log_output(f"  ✅ {network}: Connected")
                        self.log_output(f"     Balance: {info['balance']:.8f}")
                        self.log_output(f"     Price: ${info['price_usd']:.2f}")
                        self.log_output(f"     Value: ${info['value_usd']:.2f}")
                    except Exception as e:
                        self.log_output(f"  ❌ {network}: {str(e)[:100]}")
                
                self.log_output("\n" + "="*70)
                self.log_output("✅ All tests complete!")
                self.log_output("="*70 + "\n")
                
            except Exception as e:
                self.log_output(f"❌ Test failed: {e}")
        
        threading.Thread(target=run_test, daemon=True).start()
    
    def test_balance(self, network):
        """Test balance check for specific network"""
        self.log_output(f"\n🧪 Testing {network} balance check...")
        
        def run_test():
            try:
                self.api_config = APIConfig()
                self.balance_checker = AdvancedBalanceChecker(self.api_config)
                
                test_addr = {
                    'ETH': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
                    'BTC': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                    'BSC': '0x8894E0a0c962CB723c1976a4421c95949bE2D4E3',
                    'POLYGON': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'
                }.get(network, '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb')
                
                info = self.balance_checker.get_comprehensive_balance(test_addr, network)
                
                self.log_output(f"  Address: {test_addr}")
                self.log_output(f"  Balance: {info['balance']:.8f} {network}")
                self.log_output(f"  Price: ${info['price_usd']:.2f}")
                self.log_output(f"  USD Value: ${info['value_usd']:.2f}")
                self.log_output(f"  Can Withdraw: {info['can_withdraw']}")
                self.log_output(f"  ✅ Test passed!\n")
                
            except Exception as e:
                self.log_output(f"  ❌ Test failed: {e}\n")
        
        threading.Thread(target=run_test, daemon=True).start()
    
    def test_price_api(self):
        """Test price API"""
        self.log_output("\n💵 Testing Price API (CoinGecko)...")
        
        def run_test():
            try:
                self.api_config = APIConfig()
                self.balance_checker = AdvancedBalanceChecker(self.api_config)
                
                cryptos = ['ETH', 'BTC', 'SOL', 'DOGE', 'BNB']
                
                for crypto in cryptos:
                    price = self.balance_checker.get_usd_price(crypto)
                    self.log_output(f"  {crypto}: ${price:,.2f}")
                
                self.log_output("  ✅ Price API working!\n")
                
            except Exception as e:
                self.log_output(f"  ❌ Test failed: {e}\n")
        
        threading.Thread(target=run_test, daemon=True).start()
    
    def test_seed_derivation(self):
        """Test seed phrase address derivation"""
        self.log_output("\n🌱 Testing Seed Phrase Derivation...")
        
        def run_test():
            try:
                self.api_config = APIConfig()
                self.balance_checker = AdvancedBalanceChecker(self.api_config)
                seed_checker = SeedBalanceChecker(self.balance_checker)
                
                # Test seed (public example)
                test_seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                
                self.log_output(f"  Seed: {test_seed[:40]}...")
                self.log_output(f"  Valid: {seed_checker.validate_seed(test_seed)}")
                
                eth_addr = seed_checker.derive_eth_address_from_seed(test_seed, 0)
                btc_addr = seed_checker.derive_btc_address_from_seed(test_seed, 0)
                
                self.log_output(f"  ETH[0]: {eth_addr}")
                self.log_output(f"  BTC[0]: {btc_addr}")
                self.log_output("  ✅ Derivation working!\n")
                
            except Exception as e:
                self.log_output(f"  ❌ Test failed: {e}\n")
        
        threading.Thread(target=run_test, daemon=True).start()


def main():
    """Launch GUI"""
    root = tk.Tk()
    app = APISettingsGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
