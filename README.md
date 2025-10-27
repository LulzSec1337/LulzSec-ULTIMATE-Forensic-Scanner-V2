# 🚀 LulzSec ULTIMATE Forensic Scanner v9.1 Advanced

## ⚡ Quick Start

### 🎨 NEW: Launch Advanced GUI (Recommended)
```bash
python run_gui.py
```

**Federal-grade forensic interface with:**
- Real-time scanning & live metrics
- 5 tabbed result views (Wallets/Seeds/Credentials/SMS/Logs)
- 3-panel responsive layout
- Advanced export options
- Built-in balance checker & email validator
- Bulk tools & key converter

📖 **Full GUI Guide**: [GUI_USER_GUIDE.md](GUI_USER_GUIDE.md)  
🚀 **Quick GUI Tutorial**: [QUICKSTART_GUI.md](QUICKSTART_GUI.md)

---

### 💻 Command Line Interface
```bash
# Modular CLI (Recommended)
python main.py scan ~/Downloads
python main.py stats
python main.py interactive

# Original Version (Fallback)
python ext.py
```

## 📚 Documentation

### Quick Start Guides
- **[QUICKSTART_GUI.md](QUICKSTART_GUI.md)** ⭐ - Launch GUI in 30 seconds
- **[GUI_USER_GUIDE.md](GUI_USER_GUIDE.md)** 🎨 - Complete GUI documentation
- **[QUICKSTART.md](QUICKSTART.md)** - CLI usage guide

### Technical Documentation
- **[MODULAR_README.md](MODULAR_README.md)** - Complete architecture overview
- **[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)** - Step-by-step extraction guide
- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Current status & next steps
- **[TEST_STATUS_REPORT.md](TEST_STATUS_REPORT.md)** - Test results (100% pass rate)

## 🏗️ Architecture Status

**Current**: Fully Modular ✅ (100%) + Advanced GUI ✅

The project has been successfully migrated from monolithic to modular architecture with a federal-grade GUI.

### Structure:
```
├── run_gui.py           ← 🎨 GUI Launcher (NEW!)
├── main.py              ← Modular CLI entry point
├── ext.py               ← Original monolithic version
│
├── gui/                 ← 🎨 GUI Components (✅ Complete)
│   ├── advanced_gui.py  ← Federal-grade interface
│   └── __init__.py
│
├── config/              ← Configuration (✅ Complete)
│   ├── api_config.py    ← API key management
│   └── __init__.py
│
├── core/                ← Core modules (✅ Complete)
│   ├── crypto_utils.py  ← BIP39, key derivation, 14+ networks
│   ├── balance_checker.py ← Multi-network balance checking
│   └── __init__.py
│
├── database/            ← Database layer (✅ Complete)
│   ├── db_manager.py    ← SQLite with 9 tables
│   └── __init__.py
│
├── validators/          ← Validators (✅ Complete)
│   ├── email_validator.py ← SMTP/IMAP validation
│   ├── sms_detector.py  ← SMS API detection (7 providers)
│   └── __init__.py
│
├── extractors/          ← Data extractors (✅ Complete)
│   ├── private_key_extractor.py ← 15+ wallet formats
│   └── __init__.py
│
├── utils/               ← Utilities
│   └── __init__.py
│
└── modules/             ← Legacy modules
    └── __init__.py
```

## 🎯 For Developers

### Continue the Migration:
```bash
# Interactive module extraction
python extract_module.py
```

See **[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)** for detailed instructions.

## 📦 Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python main.py
```

## ✨ Features

- **Multi-Network Support**: BTC, ETH, BSC, POLYGON, TRX, SOL, LTC, DOGE, AVAX, FTM, ARB, OP
- **Comprehensive Extraction**: Seeds, private keys, cookies, credentials, API keys
- **Email Validation**: SMTP/IMAP testing with premium provider detection
- **SMS API Detection**: Twilio, Nexmo, Plivo, MessageBird support
- **Hosting Services**: cPanel, WHM, Plesk, AWS, GCP, Azure credentials
- **Social Media Hunter**: Extract accounts from 20+ platforms
- **Advanced GUI**: Modern dark theme with real-time metrics

## ⚠️ Security Warning

This tool is for educational and authorized forensic analysis only.

## 👨‍💻 Credits

**Coded by**: @LulzSec1337 (Telegram)
**Version**: 9.0 Ultimate Edition
**Architecture**: Transitioning to Modular

---

**Status**: 20% Complete - Infrastructure Ready
**Next**: Extract core modules (crypto, balance, database)
