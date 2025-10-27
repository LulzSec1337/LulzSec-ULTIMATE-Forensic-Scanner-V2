# 🚀 Quick Start - GUI Edition

## Launch the Advanced GUI in 30 Seconds

```bash
# 1. Clone the repository
git clone https://github.com/LulzSec1337/LulzSec-ULTIMATE-Forensic-Scanner-V2
cd LulzSec-ULTIMATE-Forensic-Scanner-V2

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the GUI
python run_gui.py
```

That's it! The federal-grade forensic interface will open.

---

## 🎯 Your First Scan

1. **Select Target**
   - Click "📂 Browse" or "📥 Downloads"
   - Choose directory to scan

2. **Choose Scan Type**
   - **💰 SCAN WALLETS** - Fast crypto scan (wallets + seeds)
   - **📊 SCAN ALL DATA** - Full forensic analysis

3. **Watch Live Stats**
   - Progress bar updates in real-time
   - See extracted items as they're found
   - Monitor speed and time remaining

4. **Export Results**
   - Click "💾 Export All" when complete
   - Or use Export menu for specific formats

---

## 🖼️ GUI Features

### Left Panel - Controls
- **Scan Controls**: Start/stop, directory selection
- **Live Statistics**: Real-time counters and progress
- **Scan Options**: Fine-tune what gets extracted

### Center Panel - Results
- **💰 Wallets Tab**: All cryptocurrency addresses
- **🌱 Seeds Tab**: BIP39 seed phrases with validation
- **🔑 Credentials Tab**: Email/password combos
- **📱 SMS APIs Tab**: Twilio/Nexmo credentials
- **📋 Logs Tab**: Real-time activity log

### Right Panel - Details
- **Extraction Details**: Deep dive into selected items
- **Quick Actions**: Balance check, email validation, export

### Menu Bar
- **📁 File**: Refresh, backup, export, exit
- **📤 Export**: Multiple format options
- **🛠️ Tools**: Key converter, bulk validator, URL search
- **⚙️ Settings**: API management, testing
- **❓ Help**: User guide, about

---

## 💡 Quick Tips

### Fastest Scan (10,000+ files)
```
✅ Extract Wallets
✅ Extract Seeds
✅ Validate Seeds
✅ Derive Networks
❌ Check Balances (disable for speed)
❌ Get USD Prices (disable for speed)
❌ Validate Emails (disable for speed)
```

### Most Thorough Scan (Complete Analysis)
```
✅ Enable ALL options
   (slower but finds everything)
```

### Credential Harvesting
```
✅ Extract Credentials
✅ Extract Cookies
✅ Detect SMS APIs
✅ Validate Emails
```

---

## 🎨 Interface Preview

```
┌─────────────────────────────────────────────────────────────────────┐
│ [LULZSEC FORENSIC v9.1 ADVANCED]           [◼ STANDBY] @LulzSec1337 │
├──────────┬───────────────────────────────────────────────┬───────────┤
│  SCAN    │                  RESULTS                      │  DETAILS  │
│ CONTROLS │                                               │           │
│          │  ┌─Wallets─┬─Seeds─┬─Credentials─┬─SMS─┐    │  Address  │
│ 📂 Dir:  │  │                                      │    │  Info:    │
│ [Browse] │  │  0x1234...  ETH  0.5 ETH $1,250    │    │           │
│          │  │  bc1q567...  BTC  0.01 BTC  $580    │    │  Network: │
│ 💰 SCAN  │  │  T9yD...    TRX  1000 TRX   $90     │    │  ETH      │
│ WALLETS  │  │                                      │    │           │
│          │  │                                      │    │  Balance: │
│ 📊 SCAN  │  │                                      │    │  0.5 ETH  │
│ ALL DATA │  │                                      │    │           │
│          │  └──────────────────────────────────────┘    │  USD:     │
│ ⏹️ STOP  │                                               │  $1,250   │
│          │                                               │           │
│ 📊 STATS │                                               │ [Check    │
│          │                                               │  Balance] │
│ 42%      │                                               │           │
│ ━━━━━━━  │                                               │ [Validate │
│          │                                               │  Email]   │
│ Files:   │                                               │           │
│ 1,234    │                                               │ [Export   │
│ Wallets: │                                               │  All]     │
│ 56       │                                               │           │
│ Seeds:   │                                               │           │
│ 12       │                                               │           │
└──────────┴───────────────────────────────────────────────┴───────────┘
│ Phase: Scanning... | Files: 1234 | Memory: 128 MB                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📱 CLI Alternative

Prefer command line? Use the main scanner:

```bash
# Quick wallet scan
python main.py scan ~/Downloads

# Check balances
python main.py balance

# Get statistics
python main.py stats

# Interactive mode
python main.py interactive
```

---

## 📖 Full Documentation

- **GUI User Guide**: `GUI_USER_GUIDE.md` - Complete interface documentation
- **README**: `README.md` - Project overview
- **Module Documentation**: `MODULAR_README.md` - Code architecture
- **Quick Start**: `QUICKSTART.md` - CLI usage guide

---

## 🔧 Troubleshooting

### "tkinter not found"
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS
brew install python-tk@3.9

# Already installed? Reinstall Python with tkinter
```

### GUI crashes on launch
```bash
# Check Python version (need 3.7+)
python3 --version

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Try running with verbose output
python -v run_gui.py
```

### Scan finds nothing
- Check directory has read permissions
- Verify scan options are enabled
- Review logs tab for errors
- Try smaller test directory first

---

## 🎯 Next Steps

1. ✅ Launch GUI successfully
2. ✅ Run first scan
3. ✅ Export results
4. 📖 Read full user guide (`GUI_USER_GUIDE.md`)
5. ⚙️ Configure APIs in Settings menu
6. 🔍 Try advanced tools (bulk validator, key converter)
7. 💰 Enable balance checking with API keys

---

## 🌟 Pro Mode

Want maximum extraction power?

1. Get free API keys:
   - **Etherscan**: https://etherscan.io/apis
   - **BlockCypher**: https://www.blockcypher.com/dev/
   - **CoinGecko**: https://www.coingecko.com/en/api

2. Add keys: Settings → API Management

3. Enable all scan options

4. Run full scan on large dataset

5. Use bulk tools for found items

6. Export everything in your preferred format

---

Made with 💀 by **@Lulz1337**

For support: Telegram @Lulz1337
