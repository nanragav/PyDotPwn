"""
Bisection Algorithm Module

Implementation of the bisection method to detect the exact depth of directory 
traversal vulnerabilities once they have been found.

The bisection method in mathematics is a root-finding method which repeatedly 
bisects an interval then selects a subinterval in which a root must lie for 
further processing.

Python implementation of the original DotDotPwn BisectionAlgorithm.pm
Original by nitr0us (nitrousenador@gmail.com)
"""

from typing import Protocol, Any, Optional
from .traversal_engine import TraversalEngine, OSType
import time


class VulnerabilityTester(Protocol):
    """Protocol for vulnerability testing functions"""
    
    def test_vulnerability(self, traversal: str) -> bool:
        """Test if a traversal string triggers a vulnerability"""
        ...


class BisectionAlgorithm:
    """
    Bisection Algorithm implementation to find exact traversal depth
    
    This algorithm helps detect the exact depth of a directory traversal
    vulnerability once it has been found by using binary search approach.
    """

    def __init__(self, quiet: bool = False):
        """Initialize the Bisection Algorithm"""
        self.quiet = quiet

    def find_exact_depth(
        self,
        tester: VulnerabilityTester,
        min_depth: int = 1,
        max_depth: int = 16,
        os_type: OSType = OSType.GENERIC,
        specific_file: Optional[str] = None,
        extension: Optional[str] = None,
        time_delay: float = 0.3
    ) -> Optional[int]:
        """
        Find the exact depth of vulnerability using bisection method
        
        Args:
            tester: Object that implements VulnerabilityTester protocol
            min_depth: Minimum depth to test (inclusive)
            max_depth: Maximum depth to test (inclusive)  
            os_type: Operating system type for file selection
            specific_file: Specific file to target
            extension: File extension to append
            time_delay: Delay between tests in seconds
            
        Returns:
            Exact depth where vulnerability exists, or None if not found
        """
        if not self.quiet:
            print("\\n[========= BISECTION ALGORITHM =========]\\n")
            print(f"[+] Searching for exact depth between {min_depth} and {max_depth}")

        # Initialize the traversal engine for generating test payloads
        engine = TraversalEngine(quiet=True)
        
        left = min_depth
        right = max_depth
        exact_depth = None

        while left <= right:
            # Calculate middle point
            mid = (left + right) // 2
            
            if not self.quiet:
                print(f"[*] Testing depth: {mid}")

            # Generate traversal for this specific depth
            traversals = engine.generate_traversals(
                os_type=os_type,
                depth=mid,
                specific_file=specific_file,
                extension=extension,
                bisection_depth=mid  # Use exact depth, not range
            )

            # Test vulnerability at this depth
            vulnerable = False
            for traversal in traversals:
                if tester.test_vulnerability(traversal):
                    vulnerable = True
                    exact_depth = mid
                    break
                
                # Add delay between requests
                if time_delay > 0:
                    time.sleep(time_delay)

            if vulnerable:
                if not self.quiet:
                    print(f"[+] Vulnerability found at depth {mid}")
                
                # Vulnerability found - try to find smaller depth
                right = mid - 1
            else:
                if not self.quiet:
                    print(f"[-] No vulnerability at depth {mid}")
                    
                # No vulnerability - try larger depth
                left = mid + 1

        # Final result
        if exact_depth is not None:
            if not self.quiet:
                print(f"\\n[+] BISECTION RESULT: Exact vulnerability depth is {exact_depth}")
                print(f"[+] This means {exact_depth} '../' sequences are needed to reach the root directory")
            return exact_depth
        else:
            if not self.quiet:
                print("\\n[-] BISECTION RESULT: No vulnerability found in the specified depth range")
            return None

    def analyze_traversal_pattern(
        self, 
        vulnerable_traversal: str
    ) -> dict:
        """
        Analyze a vulnerable traversal pattern to extract useful information
        
        Args:
            vulnerable_traversal: The traversal string that triggered vulnerability
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'traversal': vulnerable_traversal,
            'estimated_depth': 0,
            'pattern_type': 'unknown',
            'encoding_used': [],
            'special_chars': []
        }

        # Count depth indicators
        dotdot_count = vulnerable_traversal.count('../')
        dotdot_win_count = vulnerable_traversal.count('..\\\\')
        
        analysis['estimated_depth'] = max(dotdot_count, dotdot_win_count)

        # Detect pattern type
        if '../' in vulnerable_traversal:
            analysis['pattern_type'] = 'unix_style'
        elif '..\\\\'in vulnerable_traversal:
            analysis['pattern_type'] = 'windows_style'
        elif '%2f' in vulnerable_traversal.lower():
            analysis['pattern_type'] = 'url_encoded'
        elif '%5c' in vulnerable_traversal.lower():
            analysis['pattern_type'] = 'url_encoded_windows'

        # Detect encoding
        encodings = {
            '%2f': 'URL encoded forward slash',
            '%5c': 'URL encoded backslash', 
            '%2e': 'URL encoded dot',
            '%00': 'Null byte',
            '0x2f': 'Hex encoded forward slash',
            '0x5c': 'Hex encoded backslash',
            '%c0%af': 'UTF-8 overlong encoding',
            '%252f': 'Double URL encoded forward slash'
        }

        for encoding, description in encodings.items():
            if encoding in vulnerable_traversal.lower():
                analysis['encoding_used'].append(description)

        # Detect special characters
        special_chars = ['?', '*', '<', '>', '|', ':', '"']
        for char in special_chars:
            if char in vulnerable_traversal:
                analysis['special_chars'].append(char)

        return analysis

    def generate_depth_variants(
        self,
        base_traversal: str,
        min_depth: int = 1,
        max_depth: int = 10
    ) -> list:
        """
        Generate variants of a traversal pattern with different depths
        
        Args:
            base_traversal: Base traversal pattern (e.g., "../")
            min_depth: Minimum repetition count
            max_depth: Maximum repetition count
            
        Returns:
            List of traversal variants with different depths
        """
        variants = []
        
        for depth in range(min_depth, max_depth + 1):
            variant = base_traversal * depth
            variants.append({
                'depth': depth,
                'traversal': variant,
                'length': len(variant)
            })
            
        return variants

    def optimize_traversal_set(
        self,
        traversal_list: list,
        max_patterns: int = 100
    ) -> list:
        """
        Optimize a large set of traversal patterns for bisection testing
        
        Args:
            traversal_list: List of traversal strings
            max_patterns: Maximum number of patterns to return
            
        Returns:
            Optimized list of traversal patterns
        """
        if len(traversal_list) <= max_patterns:
            return traversal_list

        # Sort by length and uniqueness to get diverse patterns
        unique_patterns = list(set(traversal_list))
        
        # Sort by length to get good depth distribution
        unique_patterns.sort(key=len)
        
        # Select evenly distributed patterns
        step = len(unique_patterns) // max_patterns
        if step == 0:
            step = 1
            
        optimized = []
        for i in range(0, len(unique_patterns), step):
            optimized.append(unique_patterns[i])
            if len(optimized) >= max_patterns:
                break
                
        return optimized


class HTTPBisectionTester:
    """HTTP-specific implementation of VulnerabilityTester for bisection algorithm"""
    
    def __init__(self, host: str, port: int, ssl: bool = False, pattern: Optional[str] = None):
        """
        Initialize HTTP tester for bisection
        
        Args:
            host: Target hostname
            port: Target port
            ssl: Use HTTPS if True
            pattern: Pattern to match in response for vulnerability detection
        """
        self.host = host
        self.port = port
        self.ssl = ssl
        self.pattern = pattern

    def test_vulnerability(self, traversal: str) -> bool:
        """
        Test if traversal triggers vulnerability via HTTP
        
        Args:
            traversal: Traversal string to test
            
        Returns:
            True if vulnerability detected, False otherwise
        """
        try:
            import requests
            
            scheme = "https" if self.ssl else "http"
            url = f"{scheme}://{self.host}:{self.port}/{traversal}"
            
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            # Check if response indicates vulnerability
            if response.status_code == 200:
                if self.pattern:
                    return self.pattern in response.text
                else:
                    # If no pattern specified, assume 200 status indicates vulnerability
                    return True
                    
        except Exception:
            # Network errors or other issues - treat as not vulnerable
            pass
            
        return False


class FTPBisectionTester:
    """FTP-specific implementation of VulnerabilityTester for bisection algorithm"""
    
    def __init__(self, host: str, port: int = 21, username: str = "anonymous", password: str = "dot@dot.pwn"):
        """Initialize FTP tester for bisection"""
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def test_vulnerability(self, traversal: str) -> bool:
        """Test if traversal triggers vulnerability via FTP"""
        try:
            import ftplib
            
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=10)
            ftp.login(self.username, self.password)
            
            # Try to retrieve file using traversal
            try:
                ftp.retrbinary(f"RETR {traversal}", lambda x: None)
                ftp.quit()
                return True
            except ftplib.error_perm:
                ftp.quit()
                return False
                
        except Exception:
            return False