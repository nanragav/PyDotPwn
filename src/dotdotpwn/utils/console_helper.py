"""
Console helper utilities for handling cross-platform output and encoding issues.
"""

import sys
import locale
from typing import Optional
from rich.console import Console as RichConsole

def get_safe_char(unicode_char: str, fallback: str = "") -> str:
    """
    Get a safe character for console output, falling back to ASCII if needed.
    
    Args:
        unicode_char: The Unicode character to try
        fallback: Fallback ASCII character if Unicode fails
        
    Returns:
        Safe character for console output
    """
    try:
        # Try to encode the character with the current system encoding
        if sys.stdout.encoding:
            unicode_char.encode(sys.stdout.encoding)
            return unicode_char
        else:
            return fallback
    except (UnicodeEncodeError, AttributeError):
        return fallback

def get_console_encoding() -> str:
    """Get the current console encoding."""
    try:
        return sys.stdout.encoding or locale.getpreferredencoding() or 'utf-8'
    except:
        return 'utf-8'

def safe_print(text: str, encoding: Optional[str] = None) -> None:
    """
    Safely print text to console, handling encoding issues.
    
    Args:
        text: Text to print
        encoding: Optional encoding to use
    """
    if encoding is None:
        encoding = get_console_encoding()
    
    try:
        print(text)
    except UnicodeEncodeError:
        # Replace problematic characters with safe alternatives
        safe_text = text.encode(encoding, errors='replace').decode(encoding)
        print(safe_text)

# Define safe emoji mappings
SAFE_EMOJIS = {
    '✅': '[+]',
    '🎯': '[*]', 
    '📊': '[>]',
    '🖥️': '[OS]',
    '⚡': '[!]',
    '🔢': '[#]',
    '🌐': '[WWW]',
    '🔍': '[SCAN]',
    '📝': '[LOG]',
    '🚀': '[RUN]',
    '💻': '[CLI]',
    '🔧': '[TOOL]',
    '📋': '[INFO]',
    '⚠️': '[WARNING]',
    '❌': '[ERROR]',
    '🎨': '[UI]',
    '📈': '[STATS]',
    '🔒': '[SEC]',
    '⏱️': '[TIME]',
    '🎪': '[TEST]',
    '🚨': '[ALERT]',
    '💡': '[TIP]',
    '💥': '[ERROR]',
    '🔗': '[LINK]',
    '📁': '[DIR]',
    '📡': '[NET]',
    '📄': '[FILE]',
    '📚': '[DOCS]',
    '🔎': '[SEARCH]',
    '→': '->',
    '🗂️': '[FOLDER]',
    '🔐': '[SECURE]'
}

def safe_emoji(emoji: str) -> str:
    """
    Get a safe emoji replacement for console output.
    
    Args:
        emoji: Unicode emoji character
        
    Returns:
        Safe ASCII replacement
    """
    return get_safe_char(emoji, SAFE_EMOJIS.get(emoji, ''))

def make_text_safe(text: str) -> str:
    """
    Make text safe for console output by replacing problematic Unicode characters.
    
    Args:
        text: Text that may contain Unicode characters
        
    Returns:
        Safe text for console output
    """
    safe_text = text
    for emoji, replacement in SAFE_EMOJIS.items():
        if get_safe_char(emoji, '') == '':
            safe_text = safe_text.replace(emoji, replacement)
    
    return safe_text

def is_unicode_supported() -> bool:
    """
    Check if the current console supports Unicode output.
    
    Returns:
        True if Unicode is supported, False otherwise
    """
    try:
        test_char = '✅'
        if sys.stdout.encoding:
            test_char.encode(sys.stdout.encoding)
            return True
        return False
    except (UnicodeEncodeError, AttributeError):
        return False

class SafeConsole:
    """Safe console wrapper that handles Unicode encoding issues."""
    
    def __init__(self):
        self._console = RichConsole()
        self.unicode_supported = is_unicode_supported()
    
    def print(self, *args, **kwargs):
        """Print with automatic Unicode safety."""
        if args:
            # Process the first argument (main text)
            text = str(args[0])
            if not self.unicode_supported:
                text = make_text_safe(text)
            
            # Create new args tuple with safe text
            new_args = (text,) + args[1:]
            self._console.print(*new_args, **kwargs)
        else:
            self._console.print(**kwargs)

# Console detection
UNICODE_SUPPORTED = is_unicode_supported()
CONSOLE_ENCODING = get_console_encoding()

# Create a safe console instance
console = SafeConsole()