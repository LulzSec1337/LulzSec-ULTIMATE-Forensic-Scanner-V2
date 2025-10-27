# 🚀 LulzSec ULTIMATE Forensic Scanner v9.0

## ⚡ Quick Start

### Run the Application (Original Version)
```bash
python ext.py
```

### Run the Application (New Modular Version)
```bash
python main.py
```

## 📚 Documentation

- **[MODULAR_README.md](MODULAR_README.md)** - Complete architecture overview
- **[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)** - Step-by-step extraction guide
- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Current status & next steps

## 🏗️ Architecture Status

**Current**: Infrastructure Complete ✅ (20%)

The project is being migrated from a single 14,404-line monolithic file to a clean modular architecture.

### Structure:
```
├── main.py              ← New modular entry point
├── ext.py               ← Original file (fully functional)
│
├── config/              ← Configuration (✅ Complete)
├── core/                ← Core modules (🔄 Next)
├── database/            ← Database layer (📝 Todo)
├── validators/          ← Validators (📝 Todo)
├── extractors/          ← Data extractors (📝 Todo)
├── utils/               ← Utilities (📝 Todo)
└── gui/                 ← GUI components (📝 Todo)
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
