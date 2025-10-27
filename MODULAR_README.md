# 🚀 LulzSec ULTIMATE Forensic Scanner v9.0 - Modular Architecture

## 📁 Project Structure

```
LulzSec-ULTIMATE-Forensic-Scanner-V2/
├── main.py                     # Main entry point (NEW - clean & organized)
├── ext.py                      # Original monolithic file (LEGACY - kept for reference)
├── requirements.txt            # Python dependencies
│
├── config/                     # Configuration management
│   ├── __init__.py
│   └── api_config.py          # API keys & endpoints
│
├── core/                       # Core functionality
│   ├── __init__.py
│   ├── crypto_utils.py        # Cryptocurrency utilities (keys, addresses, derivation)
│   ├── balance_checker.py     # Balance checking across multiple blockchains
│   └── scanner.py             # Main scanning engine
│
├── database/                   # Database operations
│   ├── __init__.py
│   └── db_manager.py          # SQLite database management
│
├── validators/                 # Data validation modules
│   ├── __init__.py
│   ├── email_validator.py     # SMTP/IMAP email validation
│   └── sms_detector.py        # SMS API detection & validation
│
├── extractors/                 # Data extraction modules
│   ├── __init__.py
│   ├── private_key_extractor.py    # Extract private keys (all formats)
│   ├── seed_extractor.py          # Extract BIP39 seed phrases
│   ├── sensitive_data.py          # Extract API keys, tokens, SSH keys
│   ├── hosting_detector.py        # Hosting/Cloud service credentials
│   ├── social_media.py            # Social media account extraction
│   ├── website_access.py          # Website credential extraction
│   ├── browser_cookies.py         # Cookie extraction & validation
│   └── blockchain_wallets.py      # Blockchain wallet file extraction
│
├── utils/                      # Utility modules
│   ├── __init__.py
│   ├── export_manager.py      # Data export functionality
│   ├── live_feed.py           # Live action feed for status updates
│   └── helpers.py             # Helper functions
│
└── gui/                        # GUI components
    ├── __init__.py
    ├── main_window.py         # Main application window
    ├── tabs.py                # Tab components (wallets, seeds, credentials, etc.)
    ├── theme.py               # Modern neon theme
    └── widgets.py             # Custom widgets & dialogs
```

## 🎯 Why Modular?

### Problems with Monolithic ext.py (14,404 lines):
- ❌ **Impossible to maintain** - All code in one massive file
- ❌ **Hard to debug** - Can't isolate issues
- ❌ **Slow to load** - Python must parse 14k+ lines
- ❌ **Not reusable** - Can't import specific functionality
- ❌ **Poor performance** - Everything loads at once
- ❌ **Team collaboration difficult** - Merge conflicts guaranteed

### Benefits of Modular Structure:
- ✅ **Easy to maintain** - Each module has single responsibility
- ✅ **Fast debugging** - Issues isolated to specific modules
- ✅ **Better performance** - Only load what you need
- ✅ **Reusable code** - Import any module independently
- ✅ **Team-friendly** - Multiple people can work on different modules
- ✅ **Testable** - Each module can be tested separately

## 🔧 Module Descriptions

### config/ - Configuration Management
- `api_config.py`: Manages API keys, endpoints for blockchain services

### core/ - Core Functionality
- `crypto_utils.py`: BIP39 seed validation, key derivation, address generation
- `balance_checker.py`: Check balances on ETH, BTC, TRX, SOL, etc.
- `scanner.py`: Main scanning engine that coordinates all extractors

### database/ - Database Layer
- `db_manager.py`: SQLite operations for wallets, seeds, credentials

### validators/ - Data Validators
- `email_validator.py`: SMTP/IMAP validation, premium email detection
- `sms_detector.py`: SMS API (Twilio, Nexmo, etc.) detection & validation

### extractors/ - Data Extractors
- `private_key_extractor.py`: Extract private keys (hex, WIF, keystore, etc.)
- `seed_extractor.py`: Extract 12/15/18/24 word seed phrases
- `sensitive_data.py`: Extract AWS keys, Stripe keys, SSH keys, JWT tokens
- `hosting_detector.py`: Extract cPanel, WHM, Plesk, FTP credentials
- `social_media.py`: Extract social media accounts
- `website_access.py`: Extract website credentials by category
- `browser_cookies.py`: Extract & validate cookies
- `blockchain_wallets.py`: Extract from wallet.dat, keystore files

### utils/ - Utilities
- `export_manager.py`: Export data to TXT, CSV, JSON formats
- `live_feed.py`: Real-time status updates during scanning
- `helpers.py`: Common helper functions

### gui/ - Graphical Interface
- `main_window.py`: Main application window
- `tabs.py`: All tab implementations (wallets, seeds, private keys, credentials, etc.)
- `theme.py`: Modern dark theme with neon accents
- `widgets.py`: Custom tooltips, dialogs, settings windows

## 🚀 How to Run

### Option 1: Run New Modular Version (Recommended)
```bash
python main.py
```

### Option 2: Run Original Monolithic Version (Legacy)
```bash
python ext.py
```

## 📦 Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## 🔄 Migration Status

### ✅ Completed:
- [x] Project structure created
- [x] requirements.txt extracted
- [x] API configuration module
- [x] Documentation created

### 🔄 In Progress:
- [ ] Core crypto utilities (IN PROGRESS)
- [ ] Balance checker
- [ ] Database manager
- [ ] All extractors
- [ ] GUI components
- [ ] Main entry point

### 📝 To Do:
- [ ] Extract all 20+ classes from ext.py
- [ ] Create comprehensive unit tests
- [ ] Add type hints throughout
- [ ] Performance optimizations
- [ ] Async/await for better responsiveness

## 💡 Usage Example

```python
# Before (Monolithic):
# Had to run entire ext.py file

# After (Modular):
from core.crypto_utils import EnhancedCryptoUtils
from core.balance_checker import AdvancedBalanceChecker
from extractors.seed_extractor import SeedExtractor

# Use only what you need!
crypto = EnhancedCryptoUtils()
seeds = crypto.extract_seed_phrases_from_text(my_text)
```

## 🎨 Modern Features

- **Live Action Feed**: Real-time updates during scanning
- **Multi-Network Support**: BTC, ETH, BSC, POLYGON, TRX, SOL, LTC, DOGE, AVAX, FTM, ARB, OP
- **Comprehensive Extraction**: Seeds, private keys, cookies, credentials, API keys
- **Email Validation**: SMTP/IMAP testing with premium provider detection
- **SMS API Detection**: Twilio, Nexmo, Plivo, MessageBird support
- **Hosting Services**: cPanel, WHM, Plesk, AWS, GCP, Azure credentials
- **Social Media Hunter**: Extract accounts from 20+ platforms
- **Cookie Validation**: Test if sessions are still valid
- **Advanced GUI**: Modern dark theme with real-time metrics

## ⚠️ Security Warning

This tool is for educational and authorized forensic analysis only. Always:
- Encrypt extracted data immediately
- Never share or upload sensitive information
- Follow local laws and regulations
- Get proper authorization before scanning

## 👨‍💻 Credits

**Coded by**: @LulzSec1337 (Telegram)
**Version**: 9.0 Ultimate Edition
**Year**: 2024-2025

---

**Note**: The original `ext.py` is kept for reference but should not be used in production. Always use the modular `main.py` entry point for better performance and maintainability.
