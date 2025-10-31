#!/usr/bin/env python3
"""
Auto Balance Checker Integration
Automatically checks balances for all found private keys and seed phrases
"""

import logging
from typing import Dict, List
from core.balance_checker import AdvancedBalanceChecker
from core.seed_balance_checker import SeedBalanceChecker
from core.performance_optimizer import PerformanceOptimizer

logger = logging.getLogger(__name__)


class AutoBalanceIntegration:
    """
    Integrates automatic balance checking into the scanner
    - Checks all found private keys
    - Checks all found seed phrases
    - Uses performance optimization
    - Caches results to avoid redundant API calls
    """
    
    def __init__(self, api_config):
        """
        Args:
            api_config: APIConfig instance
        """
        self.balance_checker = AdvancedBalanceChecker(api_config)
        self.seed_checker = SeedBalanceChecker(self.balance_checker)
        self.optimizer = PerformanceOptimizer(max_cpu_percent=70, max_memory_percent=70)
        
        # Results storage
        self.key_balances = []
        self.seed_balances = []
        
        logger.info("Auto Balance Integration initialized")
    
    def check_private_keys(self, keys_data: List[Dict], 
                          progress_callback=None) -> List[Dict]:
        """
        Check balances for all private keys
        
        Args:
            keys_data: List of dicts with 'address', 'crypto_type', 'private_key'
            progress_callback: Optional callback(current, total, message)
            
        Returns:
            List of keys with balance > 0
        """
        if not keys_data:
            return []
        
        logger.info(f"Checking balances for {len(keys_data)} private keys...")
        
        def check_key(key_data):
            try:
                address = key_data.get('address')
                crypto_type = key_data.get('crypto_type', 'ETH')
                
                if not address:
                    return None
                
                # Get comprehensive balance
                balance_info = self.balance_checker.get_comprehensive_balance(
                    address, crypto_type
                )
                
                if balance_info['balance'] > 0:
                    result = {
                        **key_data,
                        'balance': balance_info['balance'],
                        'usd_value': balance_info['value_usd'],
                        'can_withdraw': balance_info['can_withdraw'],
                        'price_usd': balance_info['price_usd']
                    }
                    logger.info(f"💰 Found balance: {address[:20]}... = ${balance_info['value_usd']:.2f}")
                    return result
                
            except Exception as e:
                logger.debug(f"Error checking key {key_data.get('address', 'unknown')}: {e}")
            
            return None
        
        # Process with optimization
        results = self.optimizer.process_in_batches(
            keys_data,
            check_key,
            batch_size=50,
            progress_callback=progress_callback
        )
        
        self.key_balances.extend(results)
        
        logger.info(f"✅ Found {len(results)} keys with balance!")
        return results
    
    def check_seed_phrases(self, seeds: List[str], 
                          progress_callback=None,
                          check_indices: int = 5) -> List[Dict]:
        """
        Check balances for all seed phrases
        
        Args:
            seeds: List of seed phrases
            progress_callback: Optional callback(current, total, message)
            check_indices: Number of derivation indices to check per seed
            
        Returns:
            List of seeds with balance > 0
        """
        if not seeds:
            return []
        
        logger.info(f"Checking balances for {len(seeds)} seed phrases...")
        
        def check_seed(seed_phrase):
            try:
                # Validate first
                if not self.seed_checker.validate_seed(seed_phrase):
                    return None
                
                # Check balances
                results = self.seed_checker.check_seed_balances(
                    seed_phrase, 
                    check_indices=check_indices
                )
                
                if results['total_usd'] > 0:
                    logger.info(f"💰 Found seed with balance: ${results['total_usd']:.2f}")
                    return results
                
            except Exception as e:
                logger.debug(f"Error checking seed: {e}")
            
            return None
        
        # Process with optimization
        results = self.optimizer.process_in_batches(
            seeds,
            check_seed,
            batch_size=10,  # Smaller batches for seeds (more intensive)
            progress_callback=progress_callback
        )
        
        self.seed_balances.extend(results)
        
        logger.info(f"✅ Found {len(results)} seeds with balance!")
        return results
    
    def get_total_value(self) -> float:
        """Get total USD value across all found balances"""
        total = 0.0
        
        # Sum key balances
        for key_balance in self.key_balances:
            total += key_balance.get('usd_value', 0.0)
        
        # Sum seed balances
        for seed_balance in self.seed_balances:
            total += seed_balance.get('total_usd', 0.0)
        
        return total
    
    def get_summary(self) -> Dict:
        """Get summary of all balance checks"""
        return {
            'keys_with_balance': len(self.key_balances),
            'seeds_with_balance': len(self.seed_balances),
            'total_usd_value': self.get_total_value(),
            'can_withdraw_count': sum(
                1 for k in self.key_balances if k.get('can_withdraw', False)
            ),
            'cache_stats': self.balance_checker.get_cache_stats()
        }
    
    def export_results(self, output_file: str = "balances_found.json"):
        """Export results to JSON file"""
        import json
        
        data = {
            'timestamp': time.time(),
            'summary': self.get_summary(),
            'keys_with_balance': self.key_balances,
            'seeds_with_balance': self.seed_balances
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Results exported to {output_file}")
        return output_file
    
    def clear_results(self):
        """Clear all stored results"""
        self.key_balances.clear()
        self.seed_balances.clear()
        self.balance_checker.clear_cache()
        logger.info("Results cleared")


# Integration helper for ext.py
def integrate_balance_checking(scanner_instance, api_config):
    """
    Helper function to integrate balance checking into existing scanner
    
    Usage in ext.py:
        from core.auto_balance_integration import integrate_balance_checking
        
        # After scanning completes
        balance_results = integrate_balance_checking(self, self.api_config)
    """
    auto_balance = AutoBalanceIntegration(api_config)
    
    # Get all found keys from scanner
    keys_to_check = []
    
    # Extract from wallet data
    if hasattr(scanner_instance, 'wallet_data'):
        for wallet in scanner_instance.wallet_data:
            if wallet.get('address') and wallet.get('private_key'):
                keys_to_check.append({
                    'address': wallet['address'],
                    'private_key': wallet['private_key'],
                    'crypto_type': wallet.get('crypto_type', 'ETH'),
                    'source_file': wallet.get('source_file', 'unknown')
                })
    
    # Check balances
    if keys_to_check:
        logger.info(f"🔍 Checking balances for {len(keys_to_check)} wallets...")
        keys_with_balance = auto_balance.check_private_keys(keys_to_check)
        
        if keys_with_balance:
            logger.info(f"💰 FOUND {len(keys_with_balance)} WALLETS WITH BALANCE!")
            logger.info(f"💵 Total value: ${auto_balance.get_total_value():.2f} USD")
    
    # Get all found seeds
    seeds_to_check = []
    if hasattr(scanner_instance, 'seed_data'):
        for seed in scanner_instance.seed_data:
            if seed.get('seed_phrase'):
                seeds_to_check.append(seed['seed_phrase'])
    
    # Check seed balances
    if seeds_to_check:
        logger.info(f"🔍 Checking balances for {len(seeds_to_check)} seed phrases...")
        seeds_with_balance = auto_balance.check_seed_phrases(seeds_to_check, check_indices=5)
        
        if seeds_with_balance:
            logger.info(f"💰 FOUND {len(seeds_with_balance)} SEEDS WITH BALANCE!")
            logger.info(f"💵 Total seed value: ${sum(s['total_usd'] for s in seeds_with_balance):.2f} USD")
    
    # Export results
    if keys_with_balance or seeds_with_balance:
        output_file = auto_balance.export_results()
        logger.info(f"📄 Results saved to: {output_file}")
    
    return auto_balance


# Test module
if __name__ == "__main__":
    import sys
    import time
    sys.path.insert(0, '/workspaces/LulzSec-ULTIMATE-Forensic-Scanner-V2')
    from config.api_config import APIConfig
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("AUTO BALANCE INTEGRATION - TEST")
    print("=" * 70)
    
    # Initialize
    api_config = APIConfig()
    auto_balance = AutoBalanceIntegration(api_config)
    
    # Test keys (public examples)
    test_keys = [
        {
            'address': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
            'crypto_type': 'ETH',
            'private_key': 'test_key_1'
        },
        {
            'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'crypto_type': 'BTC',
            'private_key': 'test_key_2'
        }
    ]
    
    print("\n1. Checking private keys:")
    print("-" * 70)
    results = auto_balance.check_private_keys(test_keys)
    print(f"   Found {len(results)} keys with balance")
    
    print("\n2. Summary:")
    print("-" * 70)
    summary = auto_balance.get_summary()
    for key, value in summary.items():
        print(f"   {key}: {value}")
    
    print("\n" + "=" * 70)
    print("✅ Auto balance integration test complete!")
    print("=" * 70)
