#!/usr/bin/env python3
"""
Seed Phrase Balance Checker
Derives addresses from BIP39 seeds and checks balances across all networks
"""

import logging
from typing import Dict, List, Tuple
from mnemonic import Mnemonic
import hashlib
import hmac
import struct

try:
    from ecdsa import SigningKey, SECP256k1
    from ecdsa.util import string_to_number
except ImportError:
    SigningKey = None

logger = logging.getLogger(__name__)


class SeedBalanceChecker:
    """
    Check balances for addresses derived from BIP39 seed phrases
    Supports: ETH, BTC, BSC, POLYGON, and other EVM chains
    """
    
    def __init__(self, balance_checker):
        """
        Args:
            balance_checker: Instance of AdvancedBalanceChecker
        """
        self.balance_checker = balance_checker
        self.mnemo = Mnemonic("english")
    
    def validate_seed(self, seed_phrase: str) -> bool:
        """
        Validate BIP39 seed phrase
        
        Args:
            seed_phrase: Space-separated seed words
            
        Returns:
            True if valid, False otherwise
        """
        try:
            words = seed_phrase.strip().split()
            if len(words) not in [12, 15, 18, 21, 24]:
                return False
            return self.mnemo.check(seed_phrase)
        except:
            return False
    
    def derive_eth_address_from_seed(self, seed_phrase: str, index: int = 0) -> str:
        """
        Derive Ethereum address from BIP39 seed (m/44'/60'/0'/0/index)
        
        Args:
            seed_phrase: BIP39 seed phrase
            index: Derivation index (default 0)
            
        Returns:
            Ethereum address (0x...)
        """
        try:
            if not SigningKey:
                raise ImportError("ecdsa library required")
            
            # Generate seed from mnemonic
            seed = self.mnemo.to_seed(seed_phrase)
            
            # Derive master key
            master_key = self._derive_master_key(seed)
            
            # Derive eth key: m/44'/60'/0'/0/index
            eth_key = self._derive_child_key(master_key, [
                0x8000002C,  # 44' (purpose)
                0x8000003C,  # 60' (ETH)
                0x80000000,  # 0'  (account)
                0,           # 0   (change)
                index        # index
            ])
            
            # Convert to Ethereum address
            private_key = eth_key[:32]
            sk = SigningKey.from_string(private_key, curve=SECP256k1)
            vk = sk.get_verifying_key()
            public_key = vk.to_string()
            
            # Keccak-256 hash of public key
            from Crypto.Hash import keccak
            keccak_hash = keccak.new(digest_bits=256)
            keccak_hash.update(public_key)
            address = '0x' + keccak_hash.hexdigest()[-40:]
            
            return address
            
        except Exception as e:
            logger.error(f"ETH address derivation error: {e}")
            return None
    
    def derive_btc_address_from_seed(self, seed_phrase: str, index: int = 0, address_type: str = 'P2PKH') -> str:
        """
        Derive Bitcoin address from BIP39 seed (m/44'/0'/0'/0/index)
        
        Args:
            seed_phrase: BIP39 seed phrase
            index: Derivation index
            address_type: P2PKH (legacy), P2WPKH (native segwit), P2SH (segwit)
            
        Returns:
            Bitcoin address
        """
        try:
            if not SigningKey:
                raise ImportError("ecdsa library required")
            
            # Generate seed
            seed = self.mnemo.to_seed(seed_phrase)
            
            # Derive master key
            master_key = self._derive_master_key(seed)
            
            # Derive BTC key: m/44'/0'/0'/0/index
            btc_key = self._derive_child_key(master_key, [
                0x8000002C,  # 44'
                0x80000000,  # 0' (BTC)
                0x80000000,  # 0' (account)
                0,           # 0 (change)
                index        # index
            ])
            
            private_key = btc_key[:32]
            sk = SigningKey.from_string(private_key, curve=SECP256k1)
            vk = sk.get_verifying_key()
            public_key = b'\x04' + vk.to_string()  # Uncompressed
            
            # Compressed public key
            x = int.from_bytes(vk.to_string()[:32], 'big')
            y = int.from_bytes(vk.to_string()[32:], 'big')
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            compressed_pubkey = prefix + x.to_bytes(32, 'big')
            
            # Generate address based on type
            if address_type == 'P2PKH':
                # Legacy address (1...)
                return self._pubkey_to_p2pkh(compressed_pubkey, mainnet=True)
            elif address_type == 'P2WPKH':
                # Native SegWit (bc1...)
                return self._pubkey_to_p2wpkh(compressed_pubkey)
            elif address_type == 'P2SH':
                # SegWit (3...)
                return self._pubkey_to_p2sh_p2wpkh(compressed_pubkey)
            else:
                return self._pubkey_to_p2pkh(compressed_pubkey, mainnet=True)
                
        except Exception as e:
            logger.error(f"BTC address derivation error: {e}")
            return None
    
    def _derive_master_key(self, seed: bytes) -> bytes:
        """Derive BIP32 master key from seed"""
        h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return h
    
    def _derive_child_key(self, parent_key: bytes, path: List[int]) -> bytes:
        """Derive child key following BIP32 path"""
        key = parent_key[:32]
        chain_code = parent_key[32:]
        
        for index in path:
            data = b'\x00' + key + struct.pack('>I', index)
            h = hmac.new(chain_code, data, hashlib.sha512).digest()
            key = h[:32]
            chain_code = h[32:]
        
        return key + chain_code
    
    def _pubkey_to_p2pkh(self, pubkey: bytes, mainnet: bool = True) -> str:
        """Convert public key to P2PKH address (legacy 1...)"""
        import base58
        
        # SHA256 then RIPEMD160
        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        
        # Add version byte
        version = b'\x00' if mainnet else b'\x6f'
        payload = version + ripe
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        # Encode to base58
        return base58.b58encode(payload + checksum).decode()
    
    def _pubkey_to_p2wpkh(self, pubkey: bytes) -> str:
        """Convert public key to P2WPKH address (native segwit bc1...)"""
        # This is simplified - real implementation needs bech32 encoding
        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        return "bc1" + ripe.hex()[:39]  # Simplified
    
    def _pubkey_to_p2sh_p2wpkh(self, pubkey: bytes) -> str:
        """Convert public key to P2SH-P2WPKH address (segwit 3...)"""
        import base58
        
        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        
        # Create redeemScript
        redeem_script = b'\x00\x14' + ripe
        
        # Hash redeemScript
        script_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
        
        # Add version byte for P2SH
        version = b'\x05'
        payload = version + script_hash
        
        # Checksum
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        return base58.b58encode(payload + checksum).decode()
    
    def check_seed_balances(self, seed_phrase: str, check_indices: int = 5) -> Dict[str, any]:
        """
        Check balances for all addresses derived from seed phrase
        
        Args:
            seed_phrase: BIP39 seed phrase
            check_indices: Number of derivation indices to check (default 5)
            
        Returns:
            Dictionary with all balance information
        """
        if not self.validate_seed(seed_phrase):
            return {
                'valid': False,
                'error': 'Invalid seed phrase'
            }
        
        results = {
            'valid': True,
            'seed_phrase': seed_phrase,
            'total_usd': 0.0,
            'networks': {}
        }
        
        # Networks to check
        networks = [
            ('ETH', 'derive_eth_address_from_seed'),
            ('BSC', 'derive_eth_address_from_seed'),  # Same as ETH
            ('POLYGON', 'derive_eth_address_from_seed'),  # Same as ETH
            ('BTC', 'derive_btc_address_from_seed'),
        ]
        
        for network, derive_method in networks:
            network_results = {
                'addresses': [],
                'total_balance': 0.0,
                'total_usd': 0.0
            }
            
            for index in range(check_indices):
                try:
                    # Derive address
                    if derive_method == 'derive_eth_address_from_seed':
                        address = self.derive_eth_address_from_seed(seed_phrase, index)
                    else:
                        address = self.derive_btc_address_from_seed(seed_phrase, index)
                    
                    if not address:
                        continue
                    
                    # Check balance
                    balance_info = self.balance_checker.get_comprehensive_balance(address, network)
                    
                    if balance_info['balance'] > 0:
                        network_results['addresses'].append({
                            'index': index,
                            'address': address,
                            'balance': balance_info['balance'],
                            'usd_value': balance_info['value_usd'],
                            'can_withdraw': balance_info['can_withdraw']
                        })
                        
                        network_results['total_balance'] += balance_info['balance']
                        network_results['total_usd'] += balance_info['value_usd']
                
                except Exception as e:
                    logger.error(f"Error checking {network} index {index}: {e}")
            
            if network_results['addresses']:
                results['networks'][network] = network_results
                results['total_usd'] += network_results['total_usd']
        
        return results
    
    def quick_check_seed(self, seed_phrase: str) -> bool:
        """
        Quick check if seed has any balance (checks first address only)
        
        Args:
            seed_phrase: BIP39 seed phrase
            
        Returns:
            True if any balance found, False otherwise
        """
        if not self.validate_seed(seed_phrase):
            return False
        
        # Check ETH first address (most common)
        try:
            eth_addr = self.derive_eth_address_from_seed(seed_phrase, 0)
            if eth_addr:
                balance = self.balance_checker.get_balance(eth_addr, 'ETH')
                if balance > 0:
                    return True
        except:
            pass
        
        # Check BTC first address
        try:
            btc_addr = self.derive_btc_address_from_seed(seed_phrase, 0)
            if btc_addr:
                balance = self.balance_checker.get_balance(btc_addr, 'BTC')
                if balance > 0:
                    return True
        except:
            pass
        
        return False


# Test module
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2')
    from config.api_config import APIConfig
    from core.balance_checker import AdvancedBalanceChecker
    
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 70)
    print("SEED PHRASE BALANCE CHECKER - TEST")
    print("=" * 70)
    
    # Initialize
    api_config = APIConfig()
    balance_checker = AdvancedBalanceChecker(api_config)
    seed_checker = SeedBalanceChecker(balance_checker)
    
    # Test seed (public example - DO NOT USE FOR REAL FUNDS)
    test_seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    
    print(f"\n1. Validating seed phrase:")
    print(f"   Valid: {seed_checker.validate_seed(test_seed)}")
    
    print(f"\n2. Deriving addresses:")
    eth_addr = seed_checker.derive_eth_address_from_seed(test_seed, 0)
    btc_addr = seed_checker.derive_btc_address_from_seed(test_seed, 0)
    print(f"   ETH[0]: {eth_addr}")
    print(f"   BTC[0]: {btc_addr}")
    
    print(f"\n3. Checking balances (first 3 addresses):")
    results = seed_checker.check_seed_balances(test_seed, check_indices=3)
    print(f"   Total USD: ${results['total_usd']:.2f}")
    for network, info in results.get('networks', {}).items():
        print(f"   {network}: {info['total_balance']:.8f} (${info['total_usd']:.2f})")
    
    print("\n" + "=" * 70)
    print("✅ Seed balance checker test complete!")
    print("=" * 70)
