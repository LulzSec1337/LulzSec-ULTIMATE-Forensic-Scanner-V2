"""
API Configuration Manager
Handles API keys and endpoints for various blockchain services
"""

import os
import json
import logging

logger = logging.getLogger(__name__)


class APIConfig:
    def __init__(self):
        self.apis = {
            'etherscan': {
                'key': '5CHARYC76NDVNSBI2FT18CEXAE82BZMMYN',
                'free': True,
                'endpoints': {
                    'ETH': 'https://api.etherscan.io/api',
                    'BSC': 'https://api.bscscan.com/api',
                    'POLYGON': 'https://api.polygonscan.com/api',
                    'AVAX': 'https://api.snowtrace.io/api',
                    'FTM': 'https://api.ftmscan.com/api',
                    'ARB': 'https://api.arbiscan.io/api',
                    'OP': 'https://api-optimistic.etherscan.io/api'
                }
            },
            'blockcypher': {
                'key': '',
                'free': True,
                'endpoints': {
                    'BTC': 'https://api.blockcypher.com/v1/btc/main',
                    'LTC': 'https://api.blockcypher.com/v1/ltc/main',
                    'DOGE': 'https://api.blockcypher.com/v1/doge/main'
                }
            },
            'blockchain_info': {
                'key': '',
                'free': True,
                'endpoint': 'https://blockchain.info'
            },
            'blockstream': {
                'free': True,
                'endpoint': 'https://blockstream.info/api'
            },
            'trongrid': {
                'key': '',
                'free': True,
                'endpoint': 'https://api.trongrid.io'
            },
            'solana': {
                'free': True,
                'endpoints': [
                    'https://api.mainnet-beta.solana.com',
                    'https://solana-api.projectserum.com'
                ]
            },
            'sms_apis': {
                'twilio': {'key': '', 'sid': ''},
                'nexmo': {'key': '', 'secret': ''},
                'plivo': {'key': '', 'secret': ''},
                'messagebird': {'key': ''}
            },
            'email_validation': {
                'hunter_io': {'key': ''},
                'zerobounce': {'key': ''},
                'neverbounce': {'key': ''}
            }
        }
        
        self.price_apis = [
            'https://api.coingecko.com/api/v3',
            'https://api.coinbase.com/v2',
            'https://api.binance.com/api/v3'
        ]
        
        self.load()
    
    def load(self):
        """Load API configuration from file"""
        if os.path.exists('api_config.json'):
            try:
                with open('api_config.json', 'r') as f:
                    loaded = json.load(f)
                    for provider, data in loaded.items():
                        if provider in self.apis:
                            self.apis[provider].update(data)
            except Exception as e:
                logger.error(f"API config load error: {e}")
    
    def save(self):
        """Save API configuration to file"""
        try:
            with open('api_config.json', 'w') as f:
                json.dump(self.apis, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"API config save error: {e}")
            return False
    
    def get_endpoint(self, network):
        """Get API endpoint for a specific network"""
        for provider, config in self.apis.items():
            if 'endpoints' in config:
                if network in config['endpoints']:
                    return config['endpoints'][network]
            elif 'endpoint' in config and provider.upper() == network:
                return config['endpoint']
        return None
