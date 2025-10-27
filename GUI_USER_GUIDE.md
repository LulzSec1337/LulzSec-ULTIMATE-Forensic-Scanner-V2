# 🎨 LulzSec Advanced GUI - User Guide

## Federal-Grade Forensic Interface

### Quick Start

```bash
# Launch the GUI
python run_gui.py

# Or launch directly
python -m gui.advanced_gui
```

---

## 🖥️ Interface Overview

The GUI is divided into 4 main sections:

### 1. **Top Header**
- **Title**: Shows version and system name
- **Status Indicator**: Current scan state (STANDBY/SCANNING/COMPLETE)
- **User Badge**: Authenticated user information

### 2. **Left Panel - Control Center** (400px)
Contains all scan controls and live statistics:

#### 🚀 SCAN CONTROLS
- **Target Directory Selection**
  - Manual entry field
  - 📂 Browse button - File dialog
  - 📥 Downloads - Quick select ~/Downloads
  - 🏠 Home - Quick select home directory

- **Primary Scan Buttons**
  - **💰 SCAN WALLETS** - Crypto-only scan
    - Extracts wallet addresses
    - Finds seed phrases
    - Validates BIP39 seeds
    - Derives addresses for all networks
  
  - **📊 SCAN ALL DATA** - Full forensic scan
    - Everything from crypto scan PLUS:
    - Credential extraction
    - Cookie extraction
    - SMS API detection
    - Cloud service identification
    - Email validation
    - Balance checking (if enabled)

  - **⏹️ STOP SCAN** - Emergency stop button

#### 📊 LIVE STATISTICS
Real-time metrics updated every second:

- **Progress Bar** - Visual scan completion %
- **Percentage Display** - Numeric progress (0-100%)
- **Time Statistics**
  - ⏱️ Elapsed: Running time (HH:MM:SS)
  - ⏳ Remaining: Estimated time left
  - ⚡ Speed: Files processed per second

- **Extraction Counters**
  - 📁 Files Scanned
  - 💰 Wallets Found
  - 🌱 Seeds Found
  - ✅ Seeds Validated (BIP39)
  - 🔑 Credentials (email/password)
  - 🍪 Cookies
  - 📱 SMS APIs
  - ☁️ Cloud Services
  - 💵 Total USD Value

#### ⚙️ SCAN OPTIONS
Fine-tune what gets extracted:

**Essential Options (Always On)**
- ✅ Extract Wallet Addresses
- ✅ Extract Seed Phrases
- ✅ Validate Seeds (BIP39)
- ✅ Derive All Networks
- ✅ Extract Credentials
- ✅ Extract Cookies
- ✅ Detect SMS APIs
- ✅ Find Cloud Services

**Advanced Options (Optional - Slower)**
- ⚡ Check Balances - Query blockchain APIs
- 💵 Get USD Prices - Real-time pricing
- 📧 Validate Emails - SMTP/IMAP validation

### 3. **Center Panel - Results Tabs**
Tabbed interface showing extracted data:

#### Tab 1: 💰 Wallets
- All discovered wallet addresses
- Network type (ETH, BTC, TRX, etc.)
- Balance (if checked)
- USD value (if enabled)
- Source file path

#### Tab 2: 🌱 Seeds
- BIP39 seed phrases (12/24 word)
- Validation status
- Derived addresses for all networks:
  - Ethereum (ETH)
  - Bitcoin (BTC, Segwit, Legacy, Bech32)
  - Binance Smart Chain (BSC)
  - Polygon (MATIC)
  - Avalanche (AVAX)
  - Fantom (FTM)
  - Arbitrum (ARB)
  - Optimism (OP)
  - Tron (TRX)
  - Solana (SOL)
  - Litecoin (LTC)
  - Dogecoin (DOGE)
  - BNB Chain

#### Tab 3: 🔑 Credentials
- Email addresses
- Passwords
- Username/password pairs
- API keys
- Authentication tokens
- Source location

#### Tab 4: 📱 SMS APIs
- Twilio credentials
  - Account SID
  - Auth Token
  - API Key/Secret
- Nexmo/Vonage
- Plivo
- MessageBird
- Sinch
- ClickSend
- Textlocal

#### Tab 5: 📋 Logs
- Real-time activity log
- Timestamped entries
- Color-coded by severity:
  - 🔵 Info (white)
  - 🟢 Success (green)
  - 🟡 Warning (yellow)
  - 🔴 Error (red)

### 4. **Right Panel - Details & Actions** (500px)

#### 📋 EXTRACTION DETAILS
- Detailed information about selected items
- Derived addresses for seeds
- Network-specific details
- Balance information
- Metadata

#### Quick Action Buttons
- **💰 Check Balances** - Query blockchain APIs for wallet balances
- **📧 Validate Emails** - Test SMTP/IMAP credentials
- **💾 Export All** - Export all data to files

### 5. **Bottom Status Bar**
- **Phase**: Current scan phase (Idle/Scanning/Processing)
- **Files**: Total files scanned
- **Memory**: Current memory usage (MB)

---

## 📁 Menu Bar Features

### 📁 File Menu
- **🔄 Refresh All** - Reload all data from database
- **💾 Backup Database** - Create timestamped backup
- **📤 Export All Data** - Export everything to JSON
- **❌ Exit** - Close application

### 📤 Export Menu
- **💰 Export Wallets (JSON)** - Structured wallet data
- **🌱 Export Seeds (TXT)** - Plain text seed phrases
  - One seed per line
  - Includes all derived addresses
  - Network labels included
- **🔑 Export Credentials (CSV)** - Spreadsheet format
  - Columns: Email, Password, Source, Type
- **📱 Export SMS APIs** - JSON format with all API credentials

### 🛠️ Tools Menu

#### 🔑 Private Key Converter
Convert between key formats:
- Raw Hex ↔ WIF (Bitcoin)
- Raw Hex ↔ Address (any network)
- WIF ↔ Address
- Private Key → Public Key → Address

Input:
```
Private Key: 0x1234567890abcdef...
Network: Ethereum
```

Output:
```
Public Key: 0x04...
Address: 0xABCD...
```

#### 🌱 Bulk Seed Validator
Validate multiple seeds at once:

Input:
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong
...
```

Output:
```
✅ Valid: 45 seeds
❌ Invalid: 3 seeds
📊 Success Rate: 93.75%
```

#### 💰 Bulk Balance Checker
Check balances for multiple addresses:

Input:
```
0x1234... (ETH)
bc1q5678... (BTC)
T9yD... (TRX)
...
```

Output:
```
0x1234... → 0.5 ETH ($1,250.00)
bc1q5678... → 0.01 BTC ($580.00)
T9yD... → 1000 TRX ($90.00)
Total: $1,920.00
```

#### 🔍 Search Specific URL
Search for credentials/wallets on specific website:

Input:
```
URL/Domain: coinbase.com
```

Output:
```
Found 5 credentials for coinbase.com:
- user@email.com:password123
- trader@mail.com:securepass456
...
```

### ⚙️ Settings Menu

#### 🔑 API Management
Configure blockchain API keys:

- **Etherscan** (Ethereum, BSC, Polygon, etc.)
  - Free tier: 5 requests/second
  - API Key: Your_Etherscan_Key_Here
  
- **BlockCypher** (Bitcoin)
  - Free tier: 200 requests/hour
  - Token: Your_BlockCypher_Token
  
- **Blockstream** (Bitcoin)
  - No API key required
  - Rate limit: Default
  
- **TronGrid** (Tron)
  - API Key: Your_TronGrid_Key
  
- **Solana RPC**
  - Endpoint: https://api.mainnet-beta.solana.com
  
- **CoinGecko** (Prices)
  - Free tier: 50 calls/minute
  - API Key: Optional (demo mode available)

#### 🧪 Test APIs
Verify all configured APIs:

```
Testing Etherscan (Ethereum)...
✅ Connected - Rate limit: 5 req/sec

Testing BlockCypher (Bitcoin)...
✅ Connected - Rate limit: 200 req/hour

Testing TronGrid (Tron)...
✅ Connected - API key valid

Testing CoinGecko (Prices)...
✅ Connected - Prices available

Testing Solana RPC...
✅ Connected - Mainnet online
```

### ❓ Help Menu
- **📖 User Guide** - This document
- **ℹ️ About** - Version info and credits

---

## 🎯 Usage Workflows

### Workflow 1: Quick Crypto Scan

1. Click **📂 Browse** or **📥 Downloads**
2. Select target directory
3. Leave all options checked (defaults)
4. Click **💰 SCAN WALLETS**
5. Watch real-time statistics
6. View results in **💰 Wallets** and **🌱 Seeds** tabs
7. Click **💾 Export All** when complete

**Best for**: Fast extraction of wallets and seeds

---

### Workflow 2: Full Forensic Analysis

1. Select target directory
2. Enable ALL scan options:
   - ✅ All essential options
   - ✅ Check Balances
   - ✅ Get USD Prices
   - ✅ Validate Emails
3. Click **📊 SCAN ALL DATA**
4. Monitor progress in left panel
5. Review all tabs:
   - 💰 Wallets (with balances and USD values)
   - 🌱 Seeds (validated and derived)
   - 🔑 Credentials (tested emails)
   - 📱 SMS APIs
6. Use right panel for detailed analysis
7. Export specific categories from Export menu

**Best for**: Comprehensive intelligence gathering

---

### Workflow 3: Seed Phrase Recovery

1. Select directory containing potential seed phrases
2. Enable:
   - ✅ Extract Seed Phrases
   - ✅ Validate Seeds
   - ✅ Derive All Networks
   - ✅ Check Balances (if you want to find funded wallets)
3. Click **💰 SCAN WALLETS**
4. Go to **🌱 Seeds** tab
5. Look for validated seeds (✅ mark)
6. Check right panel for derived addresses
7. Export validated seeds: **Export → 🌱 Export Seeds (TXT)**

**Best for**: Recovering access to crypto wallets

---

### Workflow 4: Credential Harvesting

1. Select stealer logs or database dumps
2. Enable:
   - ✅ Extract Credentials
   - ✅ Extract Cookies
   - ✅ Detect SMS APIs
   - ✅ Validate Emails (optional but recommended)
3. Click **📊 SCAN ALL DATA**
4. Review:
   - **🔑 Credentials** tab - Email/password combos
   - **📱 SMS APIs** tab - Twilio/Nexmo accounts
5. Click **📧 Validate Emails** in right panel
6. Export: **Export → 🔑 Export Credentials (CSV)**

**Best for**: OSINT and credential analysis

---

## 🎨 Theme & Customization

### Color Scheme (Tactical Dark)
- Background: Deep navy (#0a0e1a)
- Cards: Dark blue (#131824)
- Accent: Neon green (#00ff88)
- Secondary accents:
  - Electric blue (#00d9ff)
  - Hot pink (#ff00cc)
  - Purple (#9d00ff)
  - Yellow (#ffeb3b)
  - Orange (#ff6600)

### Responsive Layout
- Minimum window: 1600x900
- Recommended: 1920x1080 or larger
- Panels resize dynamically
- Text auto-scales based on window size

---

## 💡 Pro Tips

### 1. **Use Fast Mode for Large Directories**
When scanning 10,000+ files:
- Disable "Check Balances" initially
- Disable "Validate Emails" initially
- Run crypto scan first
- Then use bulk tools on found items

### 2. **Network-Specific Searches**
To find only Bitcoin wallets:
- Scan directory
- Open database with SQL browser
- Filter: `SELECT * FROM wallets WHERE network = 'BTC'`

### 3. **Finding Funded Wallets**
- Enable "Check Balances"
- Enable "Get USD Prices"
- After scan, sort by USD value
- Focus on wallets with balance > $0

### 4. **API Rate Limits**
If you hit rate limits:
- Use free Etherscan key (5 req/sec)
- Spread checks over time
- Use bulk balance checker with delays

### 5. **Seed Validation Speed**
- BIP39 validation is fast (CPU-bound)
- Address derivation is slower (crypto operations)
- If scanning 1000+ seeds, disable "Derive All Networks" first
- Manually derive for validated seeds only

---

## 🐛 Troubleshooting

### GUI Won't Launch
```bash
# Check tkinter installation
python3 -c "import tkinter"

# If error, install:
sudo apt-get install python3-tk  # Ubuntu/Debian
sudo yum install python3-tkinter  # CentOS/RHEL
brew install python-tk@3.9        # macOS
```

### Slow Performance
- Disable balance checking for initial scan
- Disable email validation for large datasets
- Close other applications
- Increase available RAM

### No Results Found
- Check target directory permissions
- Verify files are readable
- Check scan options are enabled
- Review logs tab for errors

### API Errors
- Verify API keys in Settings
- Test APIs using "Test APIs" button
- Check internet connection
- Verify rate limits not exceeded

---

## 📊 Database Schema

Data is stored in SQLite: `lulzsec_wallets_ultimate_v9.db`

### Tables:
- **wallets** - Wallet addresses and balances
- **seeds** - Seed phrases and validation status
- **derived_addresses** - Addresses derived from seeds
- **credentials** - Email/password pairs
- **cookies** - Browser cookies
- **sms_apis** - SMS service credentials
- **hosting_services** - Cloud/hosting identifications
- **private_keys** - Private keys found
- **smtp_credentials** - Email server credentials

---

## 🔒 Security Notes

⚠️ **Important**: This tool is for authorized forensic analysis only.

- Extracted credentials are stored locally
- Database is NOT encrypted by default
- API keys are stored in plaintext (`api_config.json`)
- Always work on isolated/secured systems
- Delete sensitive data after analysis
- Backup database before modifications

---

## 📞 Support

**Telegram**: @Lulz1337  
**Version**: v9.1 Advanced  
**Last Updated**: October 2025

---

## 🎯 Keyboard Shortcuts

*Coming soon in future update*

- `Ctrl+S` - Start scan
- `Ctrl+Q` - Stop scan
- `Ctrl+E` - Export all
- `Ctrl+R` - Refresh
- `Ctrl+B` - Backup database
- `F5` - Refresh displays
- `Esc` - Close dialogs

---

Made with 💀 by LulzSec
