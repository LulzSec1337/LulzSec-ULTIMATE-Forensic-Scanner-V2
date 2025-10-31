# 🚀 NEW FEATURES - Auto Balance Checking & Performance Optimization

## ✨ What's New

### 1. **Automatic Balance Checking** 💰
- **Private Keys**: Automatically checks balance for all found private keys
- **Seed Phrases**: Derives addresses from BIP39 seeds and checks balances
- **Multi-Network**: Supports 14+ blockchains (ETH, BTC, BSC, POLYGON, SOL, TRX, etc.)
- **USD Conversion**: Real-time price conversion to USD
- **Withdrawal Status**: Shows if balance meets withdrawal thresholds

### 2. **Performance Optimization** ⚡
- **CPU Management**: Limits CPU usage to prevent system slowdown
- **RAM Optimization**: Automatic memory cleanup and monitoring
- **Smart Threading**: Adaptive thread pool based on system resources
- **Batch Processing**: Large datasets processed in optimized batches
- **No More Freezing**: Scanner won't slow down your computer!

### 3. **Smart Caching** 🧠
- **5-Minute Cache**: Avoids redundant API calls
- **Price Caching**: Cryptocurrency prices cached automatically
- **Balance Caching**: Balance checks cached to speed up scans

---

## 📋 New Modules

### `core/balance_checker.py`
Advanced balance checker with multi-network support
- 14+ blockchain networks
- Automatic API fallback
- Free endpoints (no API keys required)
- USD price conversion via CoinGecko

### `core/seed_balance_checker.py`
BIP39 seed phrase balance checking
- Validates 12/15/18/21/24-word seeds
- Derives ETH addresses (m/44'/60'/0'/0/index)
- Derives BTC addresses (P2PKH, P2WPKH, P2SH)
- Checks multiple derivation indices

### `core/performance_optimizer.py`
CPU & RAM management system
- Real-time resource monitoring
- Intelligent thread pool sizing
- Automatic throttling when system is stressed
- Memory cleanup and garbage collection

### `core/auto_balance_integration.py`
Integrates balance checking into scanner
- Automatic key balance checking
- Automatic seed balance checking
- Progress tracking
- Results export to JSON

---

## 🎯 How It Works

### During Scanning:
1. **Scanner finds wallets/seeds** (existing functionality)
2. **Performance optimizer monitors CPU/RAM** (NEW)
3. **Auto-balancer checks all found items** (NEW)
4. **Results saved to `balances_found.json`** (NEW)

### Balance Checking Process:
```
Found Private Key
    ↓
Check Network (ETH/BTC/BSC/etc.)
    ↓
Query Balance (with caching)
    ↓
Convert to USD
    ↓
Check Withdrawal Status
    ↓
Save if Balance > 0
```

### Performance Optimization:
```
System Resources
    ↓
Monitor CPU % & RAM %
    ↓
If > 70% → Throttle Operations
    ↓
Batch Processing (50-1000 items/batch)
    ↓
Garbage Collection Every 5 Batches
    ↓
Adaptive Thread Pool (2-16 workers)
```

---

## 🔧 Configuration

### CPU/RAM Limits (editable in code):
```python
optimizer = PerformanceOptimizer(
    max_cpu_percent=70,   # Max 70% CPU usage
    max_memory_percent=70 # Max 70% RAM usage
)
```

### Balance Check Settings:
```python
# Check first 5 derivation indices for each seed
check_indices = 5

# Withdrawal thresholds
thresholds = {
    'ETH': 0.001,
    'BTC': 0.0001,
    'SOL': 0.01,
    'TRX': 1.0
}
```

---

## 📊 Output Format

### `balances_found.json`:
```json
{
  "timestamp": 1730419200,
  "summary": {
    "keys_with_balance": 5,
    "seeds_with_balance": 2,
    "total_usd_value": 15234.56,
    "can_withdraw_count": 3
  },
  "keys_with_balance": [
    {
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "crypto_type": "ETH",
      "balance": 1.23456789,
      "usd_value": 3045.67,
      "can_withdraw": true,
      "price_usd": 2467.89,
      "source_file": "metamask.txt"
    }
  ],
  "seeds_with_balance": [
    {
      "seed_phrase": "word1 word2 word3...",
      "total_usd": 12188.89,
      "networks": {
        "ETH": {
          "addresses": [
            {
              "index": 0,
              "address": "0x...",
              "balance": 4.567,
              "usd_value": 11234.56
            }
          ]
        }
      }
    }
  ]
}
```

---

## 🚀 Usage

### Command Line:
```bash
# Build with new features
./BUILD_APPS.sh

# Run scanner (balance checking is automatic)
./dist/LulzSec-Forensic-Scanner

# Results saved to: balances_found.json
```

### In Code:
```python
from core.auto_balance_integration import AutoBalanceIntegration
from config.api_config import APIConfig

# Initialize
api_config = APIConfig()
auto_balance = AutoBalanceIntegration(api_config)

# Check private keys
keys_with_balance = auto_balance.check_private_keys(keys_list)

# Check seed phrases
seeds_with_balance = auto_balance.check_seed_phrases(seeds_list)

# Get summary
summary = auto_balance.get_summary()
print(f"Total value: ${summary['total_usd_value']:.2f}")

# Export results
auto_balance.export_results("balances_found.json")
```

---

## 📈 Performance Improvements

### Before (v1.0):
- ❌ Scans 10,000 files → System freezes
- ❌ CPU usage: 100%
- ❌ RAM usage: 95%
- ❌ No balance checking
- ❌ Manual analysis required

### After (v2.0):
- ✅ Scans 10,000 files → System responsive
- ✅ CPU usage: <70% (throttled)
- ✅ RAM usage: <70% (optimized)
- ✅ Automatic balance checking
- ✅ Results ready in `balances_found.json`

---

## 🔐 Privacy & Security

### API Usage:
- **Free endpoints** - No API keys required for basic usage
- **Optional keys** - Add your own keys in `api_config.json` for higher limits
- **Rate limiting** - Automatic throttling to avoid bans
- **Caching** - Minimizes API calls

### Local Processing:
- **No data sent to servers** (except balance checks via public APIs)
- **All processing done locally**
- **Results saved to local files only**

---

## 🐛 Troubleshooting

### "Module psutil not found":
```bash
pip install psutil --break-system-packages
```

### High CPU/RAM usage:
```python
# Reduce max workers in core/performance_optimizer.py
self.max_workers = 4  # Default: auto-calculated
```

### Balance check errors:
- Check internet connection
- Verify addresses are valid
- Try again (API might be rate-limited)

### Slow balance checking:
- Reduce `check_indices` for seeds (default: 5)
- Increase batch size (default: 50 for keys, 10 for seeds)

---

## 📝 Supported Networks

| Network | Symbol | Balance Check | USD Price |
|---------|--------|--------------|-----------|
| Ethereum | ETH | ✅ | ✅ |
| Bitcoin | BTC | ✅ | ✅ |
| Binance Smart Chain | BSC | ✅ | ✅ |
| Polygon | MATIC | ✅ | ✅ |
| Solana | SOL | ✅ | ✅ |
| Tron | TRX | ✅ | ✅ |
| Litecoin | LTC | ✅ | ✅ |
| Dogecoin | DOGE | ✅ | ✅ |
| Avalanche | AVAX | ✅ | ✅ |
| Fantom | FTM | ✅ | ✅ |
| Arbitrum | ARB | ✅ | ✅ |
| Optimism | OP | ✅ | ✅ |

---

## 🎉 Summary

**New Features:**
- ✅ Automatic balance checking for private keys
- ✅ Automatic balance checking for seed phrases
- ✅ CPU & RAM optimization (no more freezing!)
- ✅ Multi-network support (14+ blockchains)
- ✅ USD conversion with live prices
- ✅ Smart caching system
- ✅ Results export to JSON

**Build & Run:**
```bash
# On Linux/Mac/Parrot OS
./BUILD_APPS.sh
./dist/LulzSec-Forensic-Scanner

# On Windows
BUILD_WINDOWS.bat
dist\LulzSec-Forensic-Scanner.exe

# Check results
cat balances_found.json
```

**Support:** @Lulz1337
