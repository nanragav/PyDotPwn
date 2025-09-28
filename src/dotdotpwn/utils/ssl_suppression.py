"""
SSL Warning Suppression for PyDotPwn
This module suppresses urllib3 SSL warnings for security testing
"""

import urllib3
import warnings

def suppress_ssl_warnings():
    """Suppress all SSL-related warnings"""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
    
# Auto-suppress when module is imported
suppress_ssl_warnings()