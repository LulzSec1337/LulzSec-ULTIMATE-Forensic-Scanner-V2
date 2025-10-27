"""
🔧 MIGRATION GUIDE: From Monolithic to Modular Architecture
================================================================

This document tracks the migration from ext.py (14,404 lines) to modular structure.

## 📊 Migration Progress

### Phase 1: Infrastructure (COMPLETED ✅)
- [x] Create directory structure
- [x] Create __init__.py files  
- [x] Create requirements.txt
- [x] Create MODULAR_README.md
- [x] Create main.py entry point
- [x] Extract APIConfig class → config/api_config.py

### Phase 2: Core Modules (IN PROGRESS 🔄)
- [ ] Extract EnhancedCryptoUtils → core/crypto_utils.py (LINES: ~600)
- [ ] Extract AdvancedBalanceChecker → core/balance_checker.py (LINES: ~300)
- [ ] Extract UltimateProductionScanner → core/scanner.py (LINES: ~2000)

### Phase 3: Database (TODO 📝)
- [ ] Extract EnhancedDatabaseManager → database/db_manager.py (LINES: ~500)

### Phase 4: Validators (TODO 📝)
- [ ] Extract EmailValidator → validators/email_validator.py (LINES: ~200)
- [ ] Extract RealTimeEmailValidator → validators/email_validator.py
- [ ] Extract SMSAPIDetector → validators/sms_detector.py (LINES: ~300)
- [ ] Extract CookieSessionValidator → validators/cookie_validator.py (LINES: ~150)

### Phase 5: Extractors (TODO 📝)
- [ ] Extract ComprehensivePrivateKeyExtractor → extractors/private_key_extractor.py (LINES: ~800)
- [ ] Extract RealTimeSeedProcessor → extractors/seed_extractor.py (LINES: ~200)
- [ ] Extract SensitiveDataDetector → extractors/sensitive_data.py (LINES: ~400)
- [ ] Extract HostingServiceDetector → extractors/hosting_detector.py (LINES: ~600)
- [ ] Extract SocialMediaAccountHunter → extractors/social_media.py (LINES: ~200)
- [ ] Extract WebsiteAccessExtractor → extractors/website_access.py (LINES: ~300)
- [ ] Extract BrowserCookieExtractor → extractors/browser_cookies.py (LINES: ~200)
- [ ] Extract BlockchainWalletFileExtractor → extractors/blockchain_wallets.py (LINES: ~300)
- [ ] Extract CreditCardExtractor → extractors/credit_cards.py (LINES: ~150)

### Phase 6: Utilities (TODO 📝)
- [ ] Extract EnhancedExportManager → utils/export_manager.py (LINES: ~500)
- [ ] Extract LiveActionFeed → utils/live_feed.py (LINES: ~100)
- [ ] Extract StealerLogParser → utils/stealer_parser.py (LINES: ~100)
- [ ] Extract CookieSessionManager → utils/cookie_manager.py (LINES: ~100)

### Phase 7: GUI Components (TODO 📝)
- [ ] Extract LulzSecEnhancedGUI (main window) → gui/main_window.py (LINES: ~3000)
- [ ] Extract Tab creation methods → gui/tabs.py (LINES: ~2000)
- [ ] Extract EnhancedNeonTheme → gui/theme.py (LINES: ~200)
- [ ] Extract ToolTip, SelectiveExportDialog, EnhancedSettingsDialog → gui/widgets.py (LINES: ~1000)

## 📝 Class Extraction Reference

### ext.py Line Numbers (Approximate)
```
APIConfig: 101-200
EmailValidator: 203-337
RealTimeEmailValidator: 356-424
RealTimePrivateKeyFinder: 433-500
ComprehensivePrivateKeyExtractor: 509-990
RealTimeSeedProcessor: 997-1052
LiveActionFeed: 1060-1105
SMSAPIDetector: 1110-1265
HostingServiceDetector: 1272-1595
EnhancedCryptoUtils: 1626-1962
AdvancedBalanceChecker: 2060-2375
EnhancedDatabaseManager: 2389-2884
SensitiveDataDetector: 2884-3147
StealerLogParser: 3149-3195
WebsiteAccessExtractor: 3200-3371
SocialMediaAccountHunter: 3375-3471
CookieSessionValidator: 3510-3621
CookieSessionManager: 3637-3705
UltimateProductionScanner: 3712-5875
EnhancedExportManager: 5976-6658
EnhancedSettingsDialog: 6660-7296
ToolTip: 7322-7387
EnhancedNeonTheme: 7394-7578
SelectiveExportDialog: 7581-7848
BrowserCookieExtractor: 7953-8109
CreditCardExtractor: 8110-8216
AdvancedSocialMediaExtractor: 8218-8307
BlockchainWalletFileExtractor: 8312-8455
LulzSecEnhancedGUI: 8458-14285
main() function: 14318-14363
```

## 🛠️ How to Extract a Module

### Step 1: Identify the class
- Find line numbers in ext.py
- Note dependencies (what other classes it uses)

### Step 2: Create new module file
```python
# Example: core/crypto_utils.py
"""
Cryptocurrency Utilities
Handles BIP39 seeds, key derivation, address generation
"""

import hashlib
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Paste class code here
class EnhancedCryptoUtils:
    # ... class implementation
```

### Step 3: Update imports in new module
- Change relative imports to absolute
- Import dependencies from other modules

### Step 4: Update main.py or dependent modules
```python
# Instead of:
from ext import EnhancedCryptoUtils

# Use:
from core.crypto_utils import EnhancedCryptoUtils
```

### Step 5: Test the extracted module
```bash
python -c "from core.crypto_utils import EnhancedCryptoUtils; print('OK')"
```

## 🔍 Quick Extraction Commands

```bash
# Extract lines 101-200 (APIConfig) - DONE ✅
# Already extracted to config/api_config.py

# Extract lines 1626-1962 (EnhancedCryptoUtils) - TODO
# Will extract to core/crypto_utils.py

# Extract lines 2060-2375 (AdvancedBalanceChecker) - TODO  
# Will extract to core/balance_checker.py
```

## 🚀 Testing Strategy

1. Extract one class at a time
2. Test import: `python -c "from module import Class"`
3. Test instantiation: Create object and call methods
4. Run full application with new module
5. Compare behavior with original ext.py

## 📈 Benefits Tracking

### Original ext.py:
- Size: 14,404 lines
- Load time: ~2-3 seconds
- Memory: ~50MB on startup

### Target Modular Version:
- Largest module: <1000 lines
- Load time: ~0.5 seconds (lazy loading)
- Memory: ~20MB on startup (load what you need)

## 💡 Pro Tips

1. **Extract smallest dependencies first** - Start with utility classes that don't depend on others
2. **Keep ext.py as reference** - Don't delete until all modules work
3. **Use type hints** - Add them during extraction
4. **Add docstrings** - Document while extracting
5. **Test incrementally** - Don't extract everything at once

## 🐛 Common Issues

### Issue: Import errors
**Solution**: Check if dependent modules are extracted first

### Issue: Circular imports
**Solution**: Move shared code to separate utils module

### Issue: Missing dependencies
**Solution**: Add to requirements.txt and run pip install

## 📞 Support

For questions about migration:
- Check MODULAR_README.md
- Review this migration guide
- Test with original ext.py first

---

**Last Updated**: 2025-01-27
**Status**: Phase 1 Complete, Phase 2 In Progress
**Maintainer**: @LulzSec1337
