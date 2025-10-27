#!/usr/bin/env python3
"""
Advanced Balance Checker Module
Multi-network cryptocurrency balance checking with caching and USD conversion
"""

import requests
import time
import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class AdvancedBalanceChecker:
    """
    Advanced multi-network balance checker with intelligent caching
    
    Features:
    - 14+ blockchain network support
    - Automatic API fallback
    - 5-minute balance cache
    - Real-time USD price conversion
    - Free API endpoints (no keys required)
    - Withdrawal status checking
    """
    
    def __init__(self, api_config):
        self.api_config = api_config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        # Price cache (5 minute TTL)
        self.price_cache = {}
        self.price_cache_time = {}
        
        # Balance cache (5 minute TTL)
        self.balance_cache = {}
        self.balance_cache_time = {}
        self.cache_ttl = 300  # 5 minutes
        
        # FREE APIs (no API key needed)
        self.free_apis = {
            'ETH': [
                'https://api.etherscan.io/api',
                'https://eth.blockscout.com/api',
                'https://api.ethplorer.io'
            ],
            'BTC': [
                'https://blockstream.info/api',
                'https://blockchain.info',
                'https://blockchair.com/bitcoin/api'
            ],
            'BSC': [
                'https://api.bscscan.com/api',
                'https://bsc.blockscout.com/api'
            ],
            'POLYGON': [
                'https://api.polygonscan.com/api',
                'https://polygon.blockscout.com/api'
            ]
        }
        
        # Withdrawal thresholds
        self.thresholds = {
            'ETH': 0.001, 'BTC': 0.0001, 'TRX': 1.0, 'SOL': 0.01,
            'BNB': 0.01, 'BSC': 0.001, 'POLYGON': 0.1, 'AVAX': 0.1,
            'FTM': 1.0, 'LTC': 0.01, 'DOGE': 10.0, 'ARB': 0.001, 'OP': 0.001
        }
    
    def get_balance(self, address: str, crypto_type: str) -> float:
        """
        Get balance with intelligent caching
        
        Args:
            address: Cryptocurrency address
            crypto_type: Network type (ETH, BTC, etc.)
            
        Returns:
            Balance as float
        """
        # Check cache first
        cache_key = f"{crypto_type}:{address}"
        if cache_key in self.balance_cache:
            if time.time() - self.balance_cache_time.get(cache_key, 0) < self.cache_ttl:
                logger.debug(f"Cache hit for {cache_key}")
                return self.balance_cache[cache_key]
        
        # Fetch balance
        try:
            t = crypto_type.upper()
            
            balance = self._route_balance_check(t, address)
            
            # Cache result
            self.balance_cache[cache_key] = balance
            self.balance_cache_time[cache_key] = time.time()
            
            return balance
        
        except Exception as e:
            logger.debug(f"Balance check error for {crypto_type} {address}: {e}")
            return 0.0
    
    def _route_balance_check(self, crypto_type: str, address: str) -> float:
        """Route balance check to appropriate network handler"""
        handlers = {
            'ETH': self.get_eth_balance,
            'ETHEREUM': self.get_eth_balance,
            'BSC': self.get_bsc_balance,
            'BNB': self.get_bsc_balance,
            'POLYGON': self.get_polygon_balance,
            'BTC': self.get_btc_balance,
            'BITCOIN': self.get_btc_balance,
            'BTC_LEGACY': self.get_btc_balance,
            'BTC_SEGWIT': self.get_btc_balance,
            'BTC_NATIVE_SEGWIT': self.get_btc_balance,
            'LTC': self.get_ltc_balance,
            'LITECOIN': self.get_ltc_balance,
            'DOGE': self.get_doge_balance,
            'DOGECOIN': self.get_doge_balance,
            'TRX': self.get_trx_balance,
            'TRON': self.get_trx_balance,
            'SOL': self.get_sol_balance,
            'SOLANA': self.get_sol_balance,
            'AVAX': self.get_avax_balance,
            'FTM': self.get_ftm_balance,
            'ARB': self.get_arb_balance,
            'OP': self.get_op_balance
        }
        
        handler = handlers.get(crypto_type)
        if handler:
            return handler(address)
        
        logger.warning(f"Unknown crypto type: {crypto_type}")
        return 0.0
    
    # EVM-Compatible Network Handlers
    
    def get_eth_balance(self, address: str) -> float:
        """Get Ethereum balance"""
        try:
            endpoint = self.api_config.get_endpoint('ETH')
            api_key = self.api_config.apis.get('etherscan', {}).get('key', '')
            
            params = {
                'module': 'account',
                'action': 'balance',
                'address': address,
                'tag': 'latest'
            }
            if api_key:
                params['apikey'] = api_key
            
            response = self.session.get(endpoint, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"ETH balance error: {e}")
        return 0.0
    
    def get_bsc_balance(self, address: str) -> float:
        """Get Binance Smart Chain balance"""
        try:
            endpoint = self.api_config.get_endpoint('BSC')
            api_key = self.api_config.apis.get('bscscan', {}).get('key', '')
            
            params = {
                'module': 'account',
                'action': 'balance',
                'address': address,
                'tag': 'latest'
            }
            if api_key:
                params['apikey'] = api_key
            
            response = self.session.get(endpoint, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"BSC balance error: {e}")
        return 0.0
    
    def get_polygon_balance(self, address: str) -> float:
        """Get Polygon balance"""
        try:
            endpoint = self.api_config.get_endpoint('POLYGON')
            api_key = self.api_config.apis.get('polygonscan', {}).get('key', '')
            
            params = {
                'module': 'account',
                'action': 'balance',
                'address': address,
                'tag': 'latest'
            }
            if api_key:
                params['apikey'] = api_key
            
            response = self.session.get(endpoint, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"Polygon balance error: {e}")
        return 0.0
    
    def get_avax_balance(self, address: str) -> float:
        """Get Avalanche balance"""
        try:
            endpoint = self.api_config.get_endpoint('AVAX')
            response = self.session.get(
                f"{endpoint}?module=account&action=balance&address={address}", 
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"AVAX balance error: {e}")
        return 0.0
    
    def get_ftm_balance(self, address: str) -> float:
        """Get Fantom balance"""
        try:
            endpoint = self.api_config.get_endpoint('FTM')
            response = self.session.get(
                f"{endpoint}?module=account&action=balance&address={address}", 
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"FTM balance error: {e}")
        return 0.0
    
    def get_arb_balance(self, address: str) -> float:
        """Get Arbitrum balance"""
        try:
            endpoint = self.api_config.get_endpoint('ARB')
            response = self.session.get(
                f"{endpoint}?module=account&action=balance&address={address}", 
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"ARB balance error: {e}")
        return 0.0
    
    def get_op_balance(self, address: str) -> float:
        """Get Optimism balance"""
        try:
            endpoint = self.api_config.get_endpoint('OP')
            response = self.session.get(
                f"{endpoint}?module=account&action=balance&address={address}", 
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if str(data.get('status')) == '1':
                    return int(data['result']) / 10**18
        except Exception as e:
            logger.debug(f"OP balance error: {e}")
        return 0.0
    
    # Bitcoin & Forks
    
    def get_btc_balance(self, address: str) -> float:
        """Get Bitcoin balance with fallback APIs"""
        # Try Blockstream API first (most reliable)
        try:
            url = f"https://blockstream.info/api/address/{address}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                funded = data.get('chain_stats', {}).get('funded_txo_sum', 0)
                spent = data.get('chain_stats', {}).get('spent_txo_sum', 0)
                return (funded - spent) / 10**8
        except Exception as e:
            logger.debug(f"Blockstream BTC API error: {e}")
        
        # Fallback to BlockCypher
        try:
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('balance', 0) / 10**8
        except Exception as e:
            logger.debug(f"BlockCypher BTC API error: {e}")
        
        return 0.0
    
    def get_ltc_balance(self, address: str) -> float:
        """Get Litecoin balance"""
        try:
            url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('balance', 0) / 10**8
        except Exception as e:
            logger.debug(f"LTC balance error: {e}")
        return 0.0
    
    def get_doge_balance(self, address: str) -> float:
        """Get Dogecoin balance"""
        try:
            url = f"https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('balance', 0) / 10**8
        except Exception as e:
            logger.debug(f"DOGE balance error: {e}")
        return 0.0
    
    # Other Networks
    
    def get_trx_balance(self, address: str) -> float:
        """Get Tron balance"""
        try:
            url = f"https://api.trongrid.io/v1/accounts/{address}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    return data['data'][0].get('balance', 0) / 10**6
        except Exception as e:
            logger.debug(f"TRX balance error: {e}")
        return 0.0
    
    def get_sol_balance(self, address: str) -> float:
        """Get Solana balance"""
        try:
            url = "https://api.mainnet-beta.solana.com"
            payload = {
                "jsonrpc": "2.0", 
                "id": 1, 
                "method": "getBalance", 
                "params": [address]
            }
            response = self.session.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'result' in data:
                    return data['result']['value'] / 10**9
        except Exception as e:
            logger.debug(f"SOL balance error: {e}")
        return 0.0
    
    # Price & USD Conversion
    
    def get_usd_price(self, crypto_type: str) -> float:
        """
        Get USD price from CoinGecko with caching
        
        Args:
            crypto_type: Cryptocurrency symbol
            
        Returns:
            USD price as float
        """
        crypto_type = crypto_type.upper()
        
        # Check cache
        if crypto_type in self.price_cache:
            if time.time() - self.price_cache_time.get(crypto_type, 0) < 300:
                return self.price_cache[crypto_type]
        
        # CoinGecko ID mapping
        coin_ids = {
            'ETH': 'ethereum', 'BTC': 'bitcoin', 'BSC': 'binancecoin', 'BNB': 'binancecoin',
            'POLYGON': 'matic-network', 'AVAX': 'avalanche-2', 'FTM': 'fantom',
            'ARB': 'arbitrum', 'OP': 'optimism', 'LTC': 'litecoin', 'DOGE': 'dogecoin',
            'TRX': 'tron', 'SOL': 'solana', 'ADA': 'cardano', 'XRP': 'ripple'
        }
        
        coin_id = coin_ids.get(crypto_type, crypto_type.lower())
        
        try:
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin_id}&vs_currencies=usd"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                price = data.get(coin_id, {}).get('usd', 0)
                
                # Cache price
                self.price_cache[crypto_type] = price
                self.price_cache_time[crypto_type] = time.time()
                
                return price
        except Exception as e:
            logger.debug(f"Price fetch error for {crypto_type}: {e}")
        
        return 0.0
    
    def get_balance_in_usd(self, address: str, crypto_type: str) -> float:
        """
        Get balance in USD
        
        Args:
            address: Cryptocurrency address
            crypto_type: Network type
            
        Returns:
            Balance in USD as float
        """
        balance = self.get_balance(address, crypto_type)
        if balance > 0:
            price = self.get_usd_price(crypto_type)
            return balance * price
        return 0.0
    
    def check_withdrawal_status(self, address: str, crypto_type: str, balance: float) -> bool:
        """
        Check if balance meets withdrawal threshold
        
        Args:
            address: Cryptocurrency address
            crypto_type: Network type
            balance: Current balance
            
        Returns:
            True if can withdraw, False otherwise
        """
        if balance <= 0:
            return False
        
        threshold = self.thresholds.get(crypto_type.upper(), 0.0)
        return balance >= threshold
    
    def get_comprehensive_balance(self, address: str, crypto_type: str) -> Dict[str, any]:
        """
        Get comprehensive balance information
        
        Args:
            address: Cryptocurrency address
            crypto_type: Network type
            
        Returns:
            Dictionary with balance details
        """
        balance = self.get_balance(address, crypto_type)
        price = self.get_usd_price(crypto_type)
        usd_value = balance * price
        can_withdraw = self.check_withdrawal_status(address, crypto_type, balance)
        
        return {
            'address': address,
            'network': crypto_type.upper(),
            'balance': balance,
            'price_usd': price,
            'value_usd': usd_value,
            'can_withdraw': can_withdraw,
            'threshold': self.thresholds.get(crypto_type.upper(), 0.0),
            'cached': f"{crypto_type}:{address}" in self.balance_cache
        }
    
    def clear_cache(self):
        """Clear all caches"""
        self.balance_cache.clear()
        self.balance_cache_time.clear()
        self.price_cache.clear()
        self.price_cache_time.clear()
        logger.info("Cleared all caches")
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        return {
            'balance_cache_size': len(self.balance_cache),
            'price_cache_size': len(self.price_cache),
            'cache_ttl_seconds': self.cache_ttl
        }


# Standalone test
if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2')
    from config.api_config import APIConfig
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("ADVANCED BALANCE CHECKER - STANDALONE TEST")
    print("=" * 60)
    
    # Initialize
    api_config = APIConfig()
    checker = AdvancedBalanceChecker(api_config)
    
    # Test addresses (public examples)
    test_addresses = {
        'ETH': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        'BTC': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',  # Satoshi's address
    }
    
    print("\n1. Testing Balance Checks:")
    print("-" * 60)
    for network, address in test_addresses.items():
        try:
            info = checker.get_comprehensive_balance(address, network)
            print(f"\n{network}:")
            print(f"  Address: {info['address'][:20]}...")
            print(f"  Balance: {info['balance']:.8f}")
            print(f"  Price: ${info['price_usd']:.2f}")
            print(f"  Value: ${info['value_usd']:.2f}")
            print(f"  Can Withdraw: {info['can_withdraw']}")
            print(f"  Cached: {info['cached']}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n2. Testing Price Fetching:")
    print("-" * 60)
    for crypto in ['ETH', 'BTC', 'SOL', 'DOGE']:
        price = checker.get_usd_price(crypto)
        print(f"{crypto}: ${price:.2f}")
    
    print("\n3. Cache Statistics:")
    print("-" * 60)
    stats = checker.get_cache_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\n4. Testing Cache Hit:")
    print("-" * 60)
    # Second call should hit cache
    eth_addr = test_addresses['ETH']
    balance1 = checker.get_balance(eth_addr, 'ETH')
    balance2 = checker.get_balance(eth_addr, 'ETH')
    print(f"First call: {balance1:.8f}")
    print(f"Second call (cached): {balance2:.8f}")
    print(f"Cache hit: {balance1 == balance2}")
    
    print("\n" + "=" * 60)
    print("✅ Balance checker module test complete!")
    print("=" * 60)
