#!/usr/bin/env python3
"""
Email Validator Module
SMTP/IMAP authentication and premium email detection
"""

import smtplib
import imaplib
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class EmailValidator:
    """
    Advanced email validation with SMTP/IMAP authentication
    
    Features:
    - SMTP authentication testing
    - IMAP authentication testing
    - Premium ISP email detection
    - SMS gateway capability detection
    - Multi-provider support (Gmail, Outlook, Yahoo, etc.)
    """
    
    def __init__(self):
        # SMTP servers configuration
        self.smtp_ports = {
            'gmail.com': ('smtp.gmail.com', 587),
            'outlook.com': ('smtp.office365.com', 587),
            'hotmail.com': ('smtp.office365.com', 587),
            'yahoo.com': ('smtp.mail.yahoo.com', 587),
            'icloud.com': ('smtp.mail.me.com', 587),
            'comcast.net': ('smtp.comcast.net', 587),
            'aol.com': ('smtp.aol.com', 587),
            'mail.com': ('smtp.mail.com', 587),
            'zoho.com': ('smtp.zoho.com', 587),
            'protonmail.com': ('smtp.protonmail.com', 587),
        }
        
        # IMAP servers configuration
        self.imap_servers = {
            'gmail.com': ('imap.gmail.com', 993),
            'outlook.com': ('imap.office365.com', 993),
            'hotmail.com': ('imap.office365.com', 993),
            'yahoo.com': ('imap.mail.yahoo.com', 993),
            'icloud.com': ('imap.mail.me.com', 993),
            'comcast.net': ('imap.comcast.net', 993),
            'aol.com': ('imap.aol.com', 993),
            'mail.com': ('imap.mail.com', 993),
            'zoho.com': ('imap.zoho.com', 993),
        }
        
        # Premium ISP email providers
        self.premium_providers = [
            'comcast.net', 'att.net', 'verizon.net', 'charter.net',
            'cox.net', 'bellsouth.net', 'earthlink.net', 'sbcglobal.net',
            'rr.com', 'centurylink.net', 'windstream.net'
        ]
        
        # SMS email gateway capable providers
        self.sms_email_gateways = {
            'comcast.net': True,
            'att.net': True,
            'verizon.net': True,
            'tmobile.com': True,
            'sprint.com': True
        }
    
    def get_smtp_server(self, email: str) -> Optional[Tuple[str, int]]:
        """
        Get SMTP server configuration for email
        
        Args:
            email: Email address
            
        Returns:
            Tuple of (server, port) or None
        """
        try:
            domain = email.split('@')[1].lower()
            if domain in self.smtp_ports:
                return self.smtp_ports[domain]
            else:
                # Try common pattern
                return (f'smtp.{domain}', 587)
        except:
            return None
    
    def get_imap_server(self, email: str) -> Optional[Tuple[str, int]]:
        """
        Get IMAP server configuration for email
        
        Args:
            email: Email address
            
        Returns:
            Tuple of (server, port) or None
        """
        try:
            domain = email.split('@')[1].lower()
            if domain in self.imap_servers:
                return self.imap_servers[domain]
            else:
                # Try common pattern
                return (f'imap.{domain}', 993)
        except:
            return None
    
    def validate_smtp(self, email: str, password: str, timeout: int = 10) -> Tuple[bool, str]:
        """
        Validate email/password using SMTP authentication
        
        Args:
            email: Email address
            password: Email password
            timeout: Connection timeout in seconds
            
        Returns:
            Tuple of (success, message)
        """
        try:
            smtp_info = self.get_smtp_server(email)
            if not smtp_info:
                return False, "Unknown SMTP server"
            
            server, port = smtp_info
            
            smtp = smtplib.SMTP(server, port, timeout=timeout)
            smtp.starttls()
            smtp.login(email, password)
            smtp.quit()
            
            logger.info(f"SMTP validation successful: {email}")
            return True, "SMTP authentication successful"
        
        except smtplib.SMTPAuthenticationError:
            return False, "Invalid credentials"
        except smtplib.SMTPException as e:
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            logger.debug(f"SMTP connection error for {email}: {e}")
            return False, f"Connection error: {str(e)}"
    
    def validate_imap(self, email: str, password: str, timeout: int = 10) -> Tuple[bool, str]:
        """
        Validate email/password using IMAP authentication
        
        Args:
            email: Email address
            password: Email password
            timeout: Connection timeout in seconds
            
        Returns:
            Tuple of (success, message)
        """
        try:
            imap_info = self.get_imap_server(email)
            if not imap_info:
                return False, "Unknown IMAP server"
            
            server, port = imap_info
            
            imap = imaplib.IMAP4_SSL(server, port)
            imap.login(email, password)
            imap.logout()
            
            logger.info(f"IMAP validation successful: {email}")
            return True, "IMAP authentication successful"
        
        except imaplib.IMAP4.error:
            return False, "Invalid credentials"
        except Exception as e:
            logger.debug(f"IMAP connection error for {email}: {e}")
            return False, f"Connection error: {str(e)}"
    
    def validate_both(self, email: str, password: str) -> Dict[str, any]:
        """
        Validate using both SMTP and IMAP
        
        Args:
            email: Email address
            password: Email password
            
        Returns:
            Dictionary with validation results
        """
        smtp_result, smtp_msg = self.validate_smtp(email, password)
        imap_result, imap_msg = self.validate_imap(email, password)
        
        return {
            'smtp': {'valid': smtp_result, 'message': smtp_msg},
            'imap': {'valid': imap_result, 'message': imap_msg},
            'overall': smtp_result or imap_result
        }
    
    def is_premium_email(self, email: str) -> bool:
        """
        Check if email is from premium ISP provider
        
        Args:
            email: Email address
            
        Returns:
            True if premium ISP email, False otherwise
        """
        try:
            domain = email.split('@')[1].lower()
            return domain in self.premium_providers
        except:
            return False
    
    def has_sms_gateway(self, email: str) -> bool:
        """
        Check if email provider has SMS gateway capability
        
        Args:
            email: Email address
            
        Returns:
            True if SMS gateway available, False otherwise
        """
        try:
            domain = email.split('@')[1].lower()
            return self.sms_email_gateways.get(domain, False)
        except:
            return False
    
    def get_sms_gateway_address(self, phone_number: str, carrier: str) -> Optional[str]:
        """
        Get SMS gateway email address for phone number
        
        Args:
            phone_number: Phone number (10 digits)
            carrier: Carrier name (att, verizon, tmobile, sprint)
            
        Returns:
            SMS gateway email address or None
        """
        gateways = {
            'att': f'{phone_number}@txt.att.net',
            'verizon': f'{phone_number}@vtext.com',
            'tmobile': f'{phone_number}@tmomail.net',
            'sprint': f'{phone_number}@messaging.sprintpcs.com',
            'comcast': f'{phone_number}@comcastpcs.textmsg.com',
        }
        
        return gateways.get(carrier.lower())
    
    def get_email_info(self, email: str) -> Dict[str, any]:
        """
        Get comprehensive email information
        
        Args:
            email: Email address
            
        Returns:
            Dictionary with email details
        """
        try:
            domain = email.split('@')[1].lower()
            smtp = self.get_smtp_server(email)
            imap = self.get_imap_server(email)
            
            return {
                'email': email,
                'domain': domain,
                'smtp_server': smtp[0] if smtp else None,
                'smtp_port': smtp[1] if smtp else None,
                'imap_server': imap[0] if imap else None,
                'imap_port': imap[1] if imap else None,
                'is_premium': self.is_premium_email(email),
                'has_sms_gateway': self.has_sms_gateway(email),
                'known_provider': domain in self.smtp_ports
            }
        except Exception as e:
            logger.error(f"Get email info error: {e}")
            return {'email': email, 'error': str(e)}


# Standalone test
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("EMAIL VALIDATOR - STANDALONE TEST")
    print("=" * 60)
    
    validator = EmailValidator()
    
    print("\n1. Testing SMTP Server Detection:")
    print("-" * 60)
    test_emails = [
        'test@gmail.com',
        'test@outlook.com',
        'test@yahoo.com',
        'test@comcast.net'
    ]
    
    for email in test_emails:
        smtp = validator.get_smtp_server(email)
        print(f"{email}: {smtp}")
    
    print("\n2. Testing Premium Email Detection:")
    print("-" * 60)
    for email in test_emails:
        is_premium = validator.is_premium_email(email)
        print(f"{email}: {'✅ PREMIUM' if is_premium else '❌ Standard'}")
    
    print("\n3. Testing SMS Gateway Detection:")
    print("-" * 60)
    for email in test_emails:
        has_sms = validator.has_sms_gateway(email)
        print(f"{email}: {'✅ HAS SMS' if has_sms else '❌ No SMS'}")
    
    print("\n4. Testing SMS Gateway Address Generation:")
    print("-" * 60)
    phone = "5551234567"
    for carrier in ['att', 'verizon', 'tmobile', 'sprint']:
        gateway = validator.get_sms_gateway_address(phone, carrier)
        print(f"{carrier}: {gateway}")
    
    print("\n5. Testing Email Info Extraction:")
    print("-" * 60)
    info = validator.get_email_info('test@comcast.net')
    for key, value in info.items():
        print(f"{key}: {value}")
    
    print("\n" + "=" * 60)
    print("✅ Email validator test complete!")
    print("=" * 60)
    print("\nNote: SMTP/IMAP validation requires real credentials")
    print("Use validate_smtp() or validate_both() with actual accounts")
