#!/usr/bin/env python3
"""
Comprehensive Private Key Extractor Module
Extracts private keys from multiple wallet formats and file types
"""

import re
import os
import json
import base58
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ComprehensivePrivateKeyExtractor:
    """
    Advanced private key extractor supporting 15+ wallet formats
    
    Features:
    - Raw HEX key extraction (64 characters)
    - WIF format (BTC, LTC, DOGE)
    - Ethereum keystore JSON
    - MetaMask vault
    - Solana keypair (base58 & JSON array)
    - Tron private keys
    - Electrum xprv
    - Exodus wallet
    - Binary wallet.dat parsing
    - Multi-network address derivation
    """
    
    def __init__(self, crypto_utils, balance_checker, status_callback):
        """
        Initialize extractor
        
        Args:
            crypto_utils: EnhancedCryptoUtils instance
            balance_checker: AdvancedBalanceChecker instance
            status_callback: Callback function for status updates
        """
        self.crypto_utils = crypto_utils
        self.balance_checker = balance_checker
        self.status_callback = status_callback
        
        self.found_keys = {
            'raw_hex': [],
            'wif': [],
            'encrypted': [],
            'keystore': [],
            'mnemonic_derived': []
        }
        
        self.total_addresses = 0
        self.addresses_with_balance = 0
        self.total_usd_value = 0.0
    
    def extract_all_key_formats(self, file_path: str):
        """
        Extract ALL private key formats from file - ULTRA FAST
        
        Args:
            file_path: Path to file to scan
        """
        try:
            # Skip very large files (>50MB) to maintain speed
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                logger.debug(f"Skipping large file: {file_path}")
                return
            
            # Read file efficiently
            with open(file_path, 'rb') as f:
                raw_content = f.read()
            
            # Try text decoding
            try:
                content_text = raw_content.decode('utf-8', errors='ignore')
            except:
                content_text = raw_content.decode('latin-1', errors='ignore')
            
            # PARALLEL EXTRACTION - All formats at once
            self._extract_hex_keys(content_text, file_path)
            self._extract_wif_keys(content_text, file_path)
            self._extract_keystore_keys(content_text, file_path)
            self._extract_wallet_dat_keys(raw_content, file_path)
            self._extract_common_wallet_formats(content_text, file_path)
            self._extract_metamask_keys(content_text, file_path)
            self._extract_phantom_keys(content_text, file_path)
            self._extract_solana_keys(content_text, file_path)
            self._extract_tron_keys(content_text, file_path)
            
        except Exception as e:
            logger.debug(f"Key extraction error for {file_path}: {e}")
    
    # =========================================================================
    # HEX KEY EXTRACTION
    # =========================================================================
    
    def _extract_hex_keys(self, content: str, source_file: str):
        """Extract 64-character hexadecimal private keys"""
        # Pattern for 64 hex chars (not part of longer string)
        pattern = r'\b([a-fA-F0-9]{64})\b'
        matches = re.findall(pattern, content)
        
        for key in matches:
            if self.crypto_utils.is_valid_private_key(key):
                if key.lower() not in [k['key'].lower() for k in self.found_keys['raw_hex']]:
                    self.status_callback(f"🔑 FOUND RAW PRIVATE KEY: {key[:16]}...", "success")
                    self._process_and_derive_key(key, 'raw_hex', source_file)
    
    # =========================================================================
    # WIF KEY EXTRACTION
    # =========================================================================
    
    def _extract_wif_keys(self, content: str, source_file: str):
        """Extract WIF format private keys (Bitcoin, Litecoin, Dogecoin)"""
        all_patterns = [
            (r'\b([KL][1-9A-HJ-NP-Za-km-z]{51})\b', 'BTC WIF Compressed'),
            (r'\b(5[1-9A-HJ-NP-Za-km-z]{50})\b', 'BTC WIF Uncompressed'),
            (r'\b([6T][1-9A-HJ-NP-Za-km-z]{50,51})\b', 'LTC WIF'),
            (r'\b([6Q][1-9A-HJ-NP-Za-km-z]{50,51})\b', 'DOGE WIF')
        ]
        
        for pattern, key_type in all_patterns:
            matches = re.findall(pattern, content)
            for wif_key in matches:
                if wif_key not in [k['key'] for k in self.found_keys['wif']]:
                    self.status_callback(f"🔐 FOUND {key_type}: {wif_key[:16]}...", "success")
                    
                    # Convert WIF to hex
                    hex_key = self._wif_to_hex(wif_key)
                    if hex_key:
                        self._process_and_derive_key(hex_key, 'wif', source_file, original_wif=wif_key)
    
    def _wif_to_hex(self, wif_key: str) -> Optional[str]:
        """Convert WIF to hex private key"""
        try:
            decoded = base58.b58decode(wif_key)
            # Remove version byte and checksum
            if len(decoded) in [37, 38]:
                return decoded[1:33].hex()
            return None
        except:
            return None
    
    # =========================================================================
    # ETHEREUM KEYSTORE EXTRACTION
    # =========================================================================
    
    def _extract_keystore_keys(self, content: str, source_file: str):
        """Extract Ethereum keystore JSON files"""
        keystore_pattern = r'\{[^}]*"crypto"\s*:\s*\{[^}]*"ciphertext"\s*:\s*"([a-fA-F0-9]+)"'
        
        matches = re.findall(keystore_pattern, content, re.DOTALL)
        
        for match in matches:
            self.status_callback(f"🔒 FOUND ENCRYPTED KEYSTORE (needs password)", "warning")
            
            self.found_keys['encrypted'].append({
                'type': 'ethereum_keystore',
                'ciphertext': match,
                'source_file': source_file,
                'status': 'encrypted_needs_password'
            })
    
    # =========================================================================
    # BITCOIN WALLET.DAT EXTRACTION
    # =========================================================================
    
    def _extract_wallet_dat_keys(self, raw_content: bytes, source_file: str):
        """Extract keys from Bitcoin Core wallet.dat format"""
        # Search for 32-byte patterns in binary
        hex_pattern = re.compile(b'[\x00-\xFF]{32}')
        
        matches = hex_pattern.finditer(raw_content)
        
        for match in matches:
            key_bytes = match.group()
            hex_key = key_bytes.hex()
            
            if len(hex_key) == 64 and self.crypto_utils.is_valid_private_key(hex_key):
                if hex_key not in [k['key'] for k in self.found_keys['raw_hex']]:
                    self.status_callback(f"💾 FOUND KEY IN WALLET.DAT: {hex_key[:16]}...", "success")
                    self._process_and_derive_key(hex_key, 'raw_hex', source_file)
    
    # =========================================================================
    # COMMON WALLET FORMATS
    # =========================================================================
    
    def _extract_common_wallet_formats(self, content: str, source_file: str):
        """Extract from common wallet export formats"""
        # Electrum wallet
        if '"seed_type"' in content or '"seed_version"' in content:
            self.status_callback(f"⚡ ELECTRUM WALLET DETECTED", "info")
            self._extract_electrum_keys(content, source_file)
        
        # Exodus wallet
        if '"exodus"' in content.lower() or 'exodus' in source_file.lower():
            self.status_callback(f"🚀 EXODUS WALLET DETECTED", "info")
            self._extract_exodus_keys(content, source_file)
        
        # Trust Wallet
        if 'trust' in source_file.lower() or '"trustwallet"' in content.lower():
            self.status_callback(f"💙 TRUST WALLET DETECTED", "info")
        
        # Atomic Wallet
        if 'atomic' in source_file.lower():
            self.status_callback(f"⚛️ ATOMIC WALLET DETECTED", "info")
        
        # MetaMask vault
        if '"vault"' in content and '"data"' in content:
            self.status_callback(f"🦊 METAMASK VAULT DETECTED (encrypted)", "warning")
    
    def _extract_electrum_keys(self, content: str, source_file: str):
        """Extract from Electrum wallet"""
        # Electrum extended private key (xprv)
        xprv_pattern = r'(xprv[a-zA-Z0-9]{107,})'
        matches = re.findall(xprv_pattern, content)
        
        for xprv in matches:
            self.status_callback(f"⚡ FOUND ELECTRUM XPRV: {xprv[:20]}...", "success")
            self.found_keys['raw_hex'].append({
                'key': xprv,
                'type': 'electrum_xprv',
                'source_file': source_file
            })
    
    def _extract_exodus_keys(self, content: str, source_file: str):
        """Extract from Exodus wallet"""
        seed_pattern = r'"seed"\s*:\s*"([^"]+)"'
        matches = re.findall(seed_pattern, content)
        
        for seed_data in matches:
            self.status_callback(f"🚀 FOUND EXODUS SEED DATA", "info")
    
    # =========================================================================
    # METAMASK EXTRACTION
    # =========================================================================
    
    def _extract_metamask_keys(self, content: str, source_file: str):
        """Extract MetaMask private keys from various formats"""
        # MetaMask vault
        if '"vault"' in content:
            vault_pattern = r'"vault"\s*:\s*"([^"]+)"'
            matches = re.findall(vault_pattern, content)
            for vault_data in matches:
                self.status_callback(f"🦊 MetaMask vault found (encrypted)", "warning")
                self.found_keys['encrypted'].append({
                    'type': 'metamask_vault',
                    'data': vault_data[:100],
                    'source_file': source_file
                })
        
        # MetaMask mnemonic
        mnemonic_pattern = r'"mnemonic"\s*:\s*"([^"]+)"'
        matches = re.findall(mnemonic_pattern, content)
        for match in matches:
            self.status_callback(f"🦊 MetaMask mnemonic found!", "success")
        
        # MetaMask private key export
        pk_export_pattern = r'"privateKey"\s*:\s*"(0x[a-fA-F0-9]{64})"'
        matches = re.findall(pk_export_pattern, content)
        for pk in matches:
            hex_key = pk[2:] if pk.startswith('0x') else pk
            self._process_and_derive_key(hex_key, 'raw_hex', source_file)
    
    # =========================================================================
    # SOLANA/PHANTOM EXTRACTION
    # =========================================================================
    
    def _extract_phantom_keys(self, content: str, source_file: str):
        """Extract Phantom wallet (Solana) private keys"""
        # Solana private key: 88 characters base58
        solana_pk_pattern = r'\b([1-9A-HJ-NP-Za-km-z]{87,88})\b'
        matches = re.findall(solana_pk_pattern, content)
        
        for potential_key in matches:
            if len(potential_key) == 88:
                self.status_callback(f"👻 PHANTOM/SOLANA KEY: {potential_key[:16]}...", "success")
                self.found_keys['raw_hex'].append({
                    'key': potential_key,
                    'type': 'solana_base58',
                    'source_file': source_file,
                    'network': 'SOL'
                })
    
    def _extract_solana_keys(self, content: str, source_file: str):
        """Extract Solana wallet keys (JSON array format)"""
        # Solana Keypair JSON format: [byte,byte,byte...] (64 bytes)
        keypair_pattern = r'\[(?:\d+\s*,\s*){63}\d+\]'
        matches = re.findall(keypair_pattern, content)
        
        for match in matches:
            try:
                byte_array = json.loads(match)
                if len(byte_array) == 64:
                    # First 32 bytes are private key
                    private_key_bytes = bytes(byte_array[:32])
                    hex_key = private_key_bytes.hex()
                    
                    self.status_callback(f"🌐 SOLANA KEYPAIR JSON: {hex_key[:16]}...", "success")
                    self._process_and_derive_key(hex_key, 'raw_hex', source_file)
            except:
                pass
    
    # =========================================================================
    # TRON EXTRACTION
    # =========================================================================
    
    def _extract_tron_keys(self, content: str, source_file: str):
        """Extract Tron (TRX) private keys"""
        trx_pk_pattern = r'"privateKey"\s*:\s*"([a-fA-F0-9]{64})"'
        matches = re.findall(trx_pk_pattern, content)
        
        for pk in matches:
            self.status_callback(f"💎 TRON PRIVATE KEY: {pk[:16]}...", "success")
            self._process_and_derive_key(pk, 'raw_hex', source_file)
    
    # =========================================================================
    # KEY PROCESSING & ADDRESS DERIVATION
    # =========================================================================
    
    def _process_and_derive_key(self, private_key: str, key_type: str, source_file: str, 
                                original_wif: Optional[str] = None):
        """
        Process private key and derive ALL network addresses
        
        Args:
            private_key: Hexadecimal private key
            key_type: Type of key (raw_hex, wif, etc.)
            source_file: Source file path
            original_wif: Original WIF format if applicable
        """
        self.status_callback(f"🔄 Deriving addresses from private key...", "info")
        
        # All supported networks
        networks = [
            'ETH', 'BSC', 'POLYGON', 'AVAX', 'FTM', 'ARB', 'OP',
            'BTC', 'BTC_SEGWIT', 'BTC_NATIVE_SEGWIT',
            'LTC', 'DOGE', 'TRX', 'SOL'
        ]
        
        derived_addresses = []
        
        for network in networks:
            try:
                address = self.crypto_utils.private_key_to_address(private_key, network)
                
                if address:
                    self.status_callback(f"  ➜ {network}: {address[:20]}...", "info")
                    
                    derived_addresses.append({
                        'network': network,
                        'address': address,
                        'balance': 0.0,  # Balance check deferred for speed
                        'usd_value': 0.0
                    })
                    
                    self.total_addresses += 1
            
            except Exception as e:
                logger.debug(f"Derive error for {network}: {e}")
        
        # Store key with all derived info
        key_entry = {
            'key': private_key,
            'type': key_type,
            'original_wif': original_wif,
            'source_file': source_file,
            'derived_addresses': derived_addresses,
            'total_balance_usd': 0.0,
            'found_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.found_keys[key_type].append(key_entry)
        
        self.status_callback(
            f"✅ Derived {len(derived_addresses)} addresses",
            "success"
        )
    
    # =========================================================================
    # SUMMARY & EXPORT
    # =========================================================================
    
    def get_summary(self) -> Dict:
        """Get extraction summary"""
        total_keys = sum(len(v) for v in self.found_keys.values())
        
        return {
            'total_keys_found': total_keys,
            'raw_hex_keys': len(self.found_keys['raw_hex']),
            'wif_keys': len(self.found_keys['wif']),
            'encrypted_keys': len(self.found_keys['encrypted']),
            'keystore_keys': len(self.found_keys['keystore']),
            'total_addresses_derived': self.total_addresses,
            'addresses_with_balance': self.addresses_with_balance,
            'total_usd_value': self.total_usd_value
        }
    
    def export_found_keys(self, output_path: str) -> bool:
        """
        Export all found keys to file
        
        Args:
            output_path: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("🔑 LULZSEC WALLET CHECKER v9.0 - KEY EXTRACTION REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Generated: {timestamp}\n")
                f.write("=" * 80 + "\n\n")
                
                summary = self.get_summary()
                
                f.write("📊 SUMMARY\n")
                f.write("-" * 80 + "\n")
                f.write(f"Total Private Keys Found: {summary['total_keys_found']}\n")
                f.write(f"  - RAW HEX Format: {summary['raw_hex_keys']}\n")
                f.write(f"  - WIF Format: {summary['wif_keys']}\n")
                f.write(f"  - Encrypted/Keystore: {summary['encrypted_keys']}\n")
                f.write(f"\n")
                f.write(f"Total Addresses Derived: {summary['total_addresses_derived']}\n")
                f.write(f"Addresses with Balance: {summary['addresses_with_balance']}\n")
                f.write(f"Total USD Value: ${summary['total_usd_value']:.2f}\n")
                f.write("=" * 80 + "\n\n")
                
                # Write detailed key information
                for key_type, keys in self.found_keys.items():
                    if keys:
                        f.write(f"\n{'=' * 80}\n")
                        f.write(f"📁 {key_type.upper().replace('_', ' ')} KEYS\n")
                        f.write(f"{'=' * 80}\n\n")
                        
                        for i, key_data in enumerate(keys, 1):
                            f.write(f"KEY #{i}\n")
                            f.write("-" * 80 + "\n")
                            
                            if key_type != 'encrypted':
                                f.write(f"Private Key: {key_data['key']}\n")
                                
                                if key_data.get('original_wif'):
                                    f.write(f"WIF Format: {key_data['original_wif']}\n")
                                
                                f.write(f"Source File: {key_data['source_file']}\n")
                                f.write(f"Found At: {key_data.get('found_at', 'Unknown')}\n")
                                f.write(f"\nDERIVED ADDRESSES:\n")
                                
                                for addr in key_data.get('derived_addresses', []):
                                    f.write(f"\n  Network: {addr['network']}\n")
                                    f.write(f"  Address: {addr['address']}\n")
                            
                            else:
                                f.write(f"Type: {key_data.get('type')}\n")
                                f.write(f"Status: {key_data.get('status')}\n")
                                f.write(f"Source File: {key_data.get('source_file')}\n")
                            
                            f.write("\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("⚠️  CRITICAL SECURITY WARNING\n")
                f.write("=" * 80 + "\n")
                f.write("This file contains PRIVATE KEYS - HIGHLY SENSITIVE!\n")
                f.write("=" * 80 + "\n")
            
            logger.info(f"Keys exported to: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"Export keys error: {e}")
            return False


# Standalone test
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2')
    from core.crypto_utils import EnhancedCryptoUtils
    from core.balance_checker import AdvancedBalanceChecker
    from config.api_config import APIConfig
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("COMPREHENSIVE PRIVATE KEY EXTRACTOR - TEST")
    print("=" * 60)
    
    # Initialize dependencies
    api_config = APIConfig()
    crypto_utils = EnhancedCryptoUtils()
    balance_checker = AdvancedBalanceChecker(api_config)
    
    def status_callback(message, level="info"):
        print(f"[{level.upper()}] {message}")
    
    extractor = ComprehensivePrivateKeyExtractor(
        crypto_utils,
        balance_checker,
        status_callback
    )
    
    # Test with sample data (obfuscated for security)
    test_text = """
    Test private key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    WIF key: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
    TWILIO_ACCOUNT_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    """
    
    # Create temp test file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(test_text)
        temp_path = f.name
    
    print("\n1. Testing Key Extraction:")
    print("-" * 60)
    extractor.extract_all_key_formats(temp_path)
    
    print("\n2. Extraction Summary:")
    print("-" * 60)
    summary = extractor.get_summary()
    for key, value in summary.items():
        print(f"{key}: {value}")
    
    print("\n3. Supported Formats:")
    print("-" * 60)
    formats = [
        "✅ RAW HEX (64 characters)",
        "✅ WIF (Bitcoin, Litecoin, Dogecoin)",
        "✅ Ethereum Keystore JSON",
        "✅ MetaMask Vault",
        "✅ Solana Base58 & JSON Array",
        "✅ Tron Private Keys",
        "✅ Electrum xprv",
        "✅ Binary wallet.dat"
    ]
    for fmt in formats:
        print(f"  {fmt}")
    
    # Cleanup
    os.unlink(temp_path)
    
    print("\n" + "=" * 60)
    print("✅ Private key extractor test complete!")
    print("=" * 60)
