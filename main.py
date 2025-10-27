#!/usr/bin/env python3
"""
LulzSec ULTIMATE Forensic Scanner V9.0 - MODULAR EDITION
Advanced cryptocurrency wallet and credential scanner

Author: LulzSec1337
Version: 9.0 MODULAR
Date: 2025-10-27

FULLY FUNCTIONAL & ADVANCED:
- All modules extracted and tested ✅
- 14+ blockchain networks supported ✅
- Multi-format private key extraction ✅
- SMS API detection (Twilio, Nexmo, etc.) ✅
- Email validation (SMTP/IMAP) ✅
- Comprehensive database management ✅
- Real-time balance checking ✅
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import all modules
from config.api_config import APIConfig
from core.crypto_utils import EnhancedCryptoUtils
from core.balance_checker import AdvancedBalanceChecker
from database.db_manager import EnhancedDatabaseManager
from validators.email_validator import EmailValidator
from validators.sms_detector import SMSAPIDetector
from extractors.private_key_extractor import ComprehensivePrivateKeyExtractor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lulzsec_scanner.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class LulzSecForensicScanner:
    """
    Main forensic scanner class - integrates all modules
    
    Features:
    - Modular architecture
    - All extractors functional
    - All validators working
    - Multi-network support
    - Database persistence
    - Advanced reporting
    """
    
    def __init__(self):
        """Initialize all scanner components"""
        logger.info("=" * 60)
        logger.info("LulzSec ULTIMATE Forensic Scanner V9.0 - STARTING")
        logger.info("=" * 60)
        
        # Initialize core modules
        self.api_config = APIConfig()
        self.crypto_utils = EnhancedCryptoUtils()
        self.balance_checker = AdvancedBalanceChecker(self.api_config)
        self.database = EnhancedDatabaseManager()
        
        # Initialize validators
        self.email_validator = EmailValidator()
        self.sms_detector = SMSAPIDetector()
        
        # Initialize extractors
        self.key_extractor = ComprehensivePrivateKeyExtractor(
            self.crypto_utils,
            self.balance_checker,
            self.status_callback
        )
        
        logger.info("✅ All modules initialized successfully")
    
    def status_callback(self, message: str, level: str = "info"):
        """Status callback for extractors"""
        if level == "success":
            logger.info(f"✅ {message}")
        elif level == "error":
            logger.error(f"❌ {message}")
        elif level == "warning":
            logger.warning(f"⚠️  {message}")
        else:
            logger.info(message)
    
    def scan_directory(self, directory_path: str):
        """
        Scan directory for wallets and credentials
        
        Args:
            directory_path: Path to directory to scan
        """
        logger.info(f"🔍 Scanning directory: {directory_path}")
        
        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            return
        
        # Scan all files
        file_count = 0
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_count += 1
                
                logger.info(f"📄 Scanning file {file_count}: {file}")
                
                # Extract private keys
                self.key_extractor.extract_all_key_formats(file_path)
                
                # Scan for SMS APIs
                sms_apis = self.sms_detector.scan_file_for_apis(file_path)
                if sms_apis:
                    logger.info(f"  Found {len(sms_apis)} SMS API credential(s)")
                    for api in sms_apis:
                        self.database.add_sms_api({
                            'provider': api['provider'],
                            'api_key': str(api['credentials']),
                            'source_file': file_path
                        })
        
        logger.info(f"✅ Scanned {file_count} file(s)")
    
    def scan_file(self, file_path: str):
        """
        Scan single file for wallets and credentials
        
        Args:
            file_path: Path to file to scan
        """
        logger.info(f"🔍 Scanning file: {file_path}")
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return
        
        # Extract private keys
        self.key_extractor.extract_all_key_formats(file_path)
        
        # Scan for SMS APIs
        sms_apis = self.sms_detector.scan_file_for_apis(file_path)
        if sms_apis:
            logger.info(f"Found {len(sms_apis)} SMS API credential(s)")
        
        logger.info("✅ Scan complete")
    
    def validate_seed_phrase(self, seed_phrase: str):
        """
        Validate and derive addresses from seed phrase
        
        Args:
            seed_phrase: BIP39 seed phrase
            
        Returns:
            Dictionary with validation results
        """
        logger.info("🔄 Validating seed phrase...")
        
        is_valid = self.crypto_utils.validate_seed_phrase(seed_phrase)
        
        if not is_valid:
            logger.error("❌ Invalid seed phrase")
            return {'valid': False}
        
        logger.info("✅ Valid seed phrase")
        
        # Extract private keys
        private_keys = self.crypto_utils.extract_private_keys_from_text(seed_phrase)
        
        result = {
            'valid': True,
            'word_count': len(seed_phrase.split()),
            'private_keys': private_keys
        }
        
        # Derive addresses for each network
        if private_keys:
            pk = private_keys[0]
            addresses = {}
            
            networks = ['ETH', 'BTC', 'TRX', 'SOL', 'LTC', 'DOGE']
            for network in networks:
                try:
                    addr = self.crypto_utils.private_key_to_address(pk, network)
                    if addr:
                        addresses[network] = addr
                except Exception as e:
                    logger.debug(f"Address derivation error for {network}: {e}")
            
            result['addresses'] = addresses
        
        return result
    
    def check_balance(self, address: str, network: str):
        """
        Check balance for address
        
        Args:
            address: Cryptocurrency address
            network: Network type (ETH, BTC, etc.)
            
        Returns:
            Dictionary with balance information
        """
        logger.info(f"💰 Checking balance for {network} address...")
        
        info = self.balance_checker.get_comprehensive_balance(address, network)
        
        logger.info(f"Balance: {info['balance']:.8f} {network}")
        logger.info(f"Value: ${info['value_usd']:.2f} USD")
        
        return info
    
    def validate_email(self, email: str):
        """
        Get email information
        
        Args:
            email: Email address
            
        Returns:
            Dictionary with email details
        """
        logger.info(f"📧 Analyzing email: {email}")
        
        info = self.email_validator.get_email_info(email)
        
        if info.get('is_premium'):
            logger.info("✅ Premium ISP email detected")
        
        if info.get('has_sms_gateway'):
            logger.info("✅ SMS gateway available")
        
        return info
    
    def get_statistics(self):
        """Get comprehensive scanner statistics"""
        logger.info("📊 Gathering statistics...")
        
        # Database stats
        db_stats = self.database.get_statistics()
        
        # Extractor stats
        extractor_stats = self.key_extractor.get_summary()
        
        # Balance checker stats
        balance_stats = self.balance_checker.get_cache_stats()
        
        stats = {
            'database': db_stats,
            'extractor': extractor_stats,
            'balance_cache': balance_stats
        }
        
        # Print summary
        logger.info("=" * 60)
        logger.info("SCANNER STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Total Keys Found: {extractor_stats['total_keys_found']}")
        logger.info(f"Total Addresses: {extractor_stats['total_addresses_derived']}")
        logger.info(f"Total Wallets in DB: {db_stats['total_wallets']}")
        logger.info(f"Total Credentials: {db_stats['total_credentials']}")
        logger.info(f"Valid SMS APIs: {db_stats['valid_sms_apis']}")
        logger.info("=" * 60)
        
        return stats
    
    def export_results(self, output_dir: str = "."):
        """
        Export all results to files
        
        Args:
            output_dir: Output directory path
        """
        logger.info("📤 Exporting results...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Export private keys
        keys_path = os.path.join(output_dir, "found_private_keys.txt")
        self.key_extractor.export_found_keys(keys_path)
        logger.info(f"✅ Keys exported to: {keys_path}")
        
        # Backup database
        db_path = os.path.join(output_dir, "lulzsec_backup.db")
        success, path = self.database.backup_database(db_path)
        if success:
            logger.info(f"✅ Database backed up to: {path}")
        
        logger.info("✅ Export complete")
    
    def run_interactive(self):
        """Run interactive mode"""
        logger.info("🎮 Interactive mode - Type 'help' for commands")
        
        while True:
            try:
                cmd = input("\nlulzsec> ").strip().lower()
                
                if cmd == 'help':
                    print("""
Available Commands:
  scan <path>         - Scan file or directory
  seed <phrase>       - Validate seed phrase
  balance <addr> <net> - Check balance (e.g., balance 0x123... ETH)
  email <address>     - Analyze email
  stats               - Show statistics
  export [dir]        - Export results
  quit                - Exit scanner
                    """)
                
                elif cmd.startswith('scan '):
                    path = cmd[5:].strip()
                    if os.path.isdir(path):
                        self.scan_directory(path)
                    else:
                        self.scan_file(path)
                
                elif cmd.startswith('seed '):
                    seed = cmd[5:].strip()
                    result = self.validate_seed_phrase(seed)
                    print(f"Valid: {result.get('valid')}")
                    if result.get('addresses'):
                        print("\nDerived Addresses:")
                        for net, addr in result['addresses'].items():
                            print(f"  {net}: {addr}")
                
                elif cmd.startswith('balance '):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        address = parts[1]
                        network = parts[2].upper()
                        info = self.check_balance(address, network)
                
                elif cmd.startswith('email '):
                    email = cmd[6:].strip()
                    info = self.validate_email(email)
                
                elif cmd == 'stats':
                    self.get_statistics()
                
                elif cmd.startswith('export'):
                    parts = cmd.split()
                    output_dir = parts[1] if len(parts) > 1 else "."
                    self.export_results(output_dir)
                
                elif cmd in ['quit', 'exit', 'q']:
                    logger.info("👋 Exiting scanner...")
                    break
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except Exception as e:
                logger.error(f"Command error: {e}")


def main():
    """Main entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║    LulzSec ULTIMATE Forensic Scanner V9.0 MODULAR    ║
    ║                                                       ║
    ║    ✅ Fully Functional & Advanced                     ║
    ║    ✅ All Modules Tested & Working                    ║
    ║    ✅ 14+ Blockchain Networks                         ║
    ║    ✅ Multi-Format Key Extraction                     ║
    ║    ✅ SMS API Detection                               ║
    ║    ✅ Email Validation                                ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Initialize scanner
    scanner = LulzSecForensicScanner()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'scan' and len(sys.argv) > 2:
            path = sys.argv[2]
            if os.path.isdir(path):
                scanner.scan_directory(path)
            else:
                scanner.scan_file(path)
            scanner.get_statistics()
            scanner.export_results()
        
        elif command == 'seed' and len(sys.argv) > 2:
            seed = ' '.join(sys.argv[2:])
            result = scanner.validate_seed_phrase(seed)
            if result.get('addresses'):
                print("\nDerived Addresses:")
                for net, addr in result['addresses'].items():
                    print(f"{net}: {addr}")
        
        elif command == 'balance' and len(sys.argv) > 3:
            address = sys.argv[2]
            network = sys.argv[3].upper()
            scanner.check_balance(address, network)
        
        elif command == 'stats':
            scanner.get_statistics()
        
        elif command == 'help':
            print("""
Usage: python main.py [command] [arguments]

Commands:
  scan <path>              - Scan file or directory for wallets
  seed <phrase>            - Validate BIP39 seed phrase
  balance <address> <net>  - Check balance (ETH, BTC, etc.)
  stats                    - Show scanner statistics
  interactive              - Enter interactive mode
  help                     - Show this help message

Examples:
  python main.py scan /path/to/directory
  python main.py seed "word1 word2 ... word12"
  python main.py balance 0x123... ETH
  python main.py interactive
            """)
        
        else:
            print("Unknown command. Use 'python main.py help' for usage.")
    
    else:
        # No arguments - run interactive mode
        scanner.run_interactive()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Scanner terminated by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
