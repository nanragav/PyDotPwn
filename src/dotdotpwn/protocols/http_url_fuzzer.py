"""
HTTP URL Fuzzer Module

Fuzzer for testing directory traversal via URL parameters where the TRAVERSAL
placeholder is embedded in the URL.

Python implementation of the original DotDotPwn HTTP_Url.pm
Original by chr1x & nitr0us
"""

import asyncio
import aiohttp
import time
import random
from typing import List, Optional, Dict, Any, Callable
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pathlib import Path
from ..core.traversal_engine import TraversalEngine, OSType
from ..core.bisection_algorithm import BisectionAlgorithm


class HTTPURLFuzzer:
    """
    HTTP URL Directory Traversal Fuzzer
    
    Tests for directory traversal vulnerabilities by replacing TRAVERSAL placeholder
    in URLs with traversal patterns
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        user_agent_file: Optional[str] = None,
        quiet: bool = False
    ):
        """
        Initialize HTTP URL Fuzzer
        
        Args:
            base_url: Base URL with TRAVERSAL placeholder
            timeout: Request timeout in seconds
            user_agent_file: Path to user agent strings file
            quiet: Quiet mode for minimal output
        """
        self.base_url = base_url
        self.timeout = timeout
        self.quiet = quiet
        self.user_agents = self._load_user_agents(user_agent_file)
        self.vulnerabilities_found = 0
        self.false_positives = 0
        
        # Validate URL contains TRAVERSAL placeholder
        if "TRAVERSAL" not in base_url:
            raise ValueError("Base URL must contain 'TRAVERSAL' placeholder")
        
        # Parse URL to extract host information
        parsed = urlparse(base_url)
        self.host = parsed.hostname
        self.port = parsed.port
        self.scheme = parsed.scheme
        
        # Set default ports
        if not self.port:
            self.port = 443 if self.scheme == 'https' else 80

    def _load_user_agents(self, user_agent_file: Optional[str] = None) -> List[str]:
        """Load user agent strings from file or use defaults"""
        default_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101",
            "DotDotPwn-Python/3.0.2"
        ]

        if user_agent_file and Path(user_agent_file).exists():
            try:
                with open(user_agent_file, 'r', encoding='utf-8') as f:
                    agents = [line.strip() for line in f if line.strip()]
                return agents if agents else default_agents
            except Exception:
                pass
                
        return default_agents

    def _get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        return random.choice(self.user_agents).strip()

    async def fuzz_async(
        self,
        traversals: List[str],
        pattern: str,
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        Asynchronous HTTP URL fuzzing
        
        Args:
            traversals: List of traversal strings to test
            pattern: Pattern to match in response for vulnerability detection (required)
            time_delay: Delay between requests in seconds
            break_on_first: Stop after first vulnerability found
            continue_on_error: Continue testing if connection errors occur
            progress_callback: Callback function for progress updates
            bisection: Enable bisection algorithm when vulnerability found
            
        Returns:
            Dictionary with fuzzing results
        """
        if not pattern:
            raise ValueError("Pattern is required for HTTP URL fuzzing")

        results = {
            'vulnerabilities': [],
            'false_positives': [],
            'errors': [],
            'total_tests': len(traversals),
            'vulnerabilities_found': 0,
            'false_positives_count': 0
        }

        connector = aiohttp.TCPConnector(
            ssl=False if self.scheme == 'https' else None,
            limit=10,
            limit_per_host=5
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as session:
            
            for i, traversal in enumerate(traversals):
                try:
                    # Add delay between requests
                    if time_delay > 0 and i > 0:
                        await asyncio.sleep(time_delay)

                    # Test the traversal
                    result = await self._test_traversal(session, traversal, pattern)
                    
                    if result['vulnerable']:
                        results['vulnerabilities'].append(result)
                        results['vulnerabilities_found'] += 1
                        self.vulnerabilities_found += 1
                        
                        if not self.quiet:
                            print(f"\\n[*] VULNERABLE: {result['url']}")
                            if result.get('matched_content'):
                                print(f"    Pattern matched: {result['matched_content'][:100]}...")

                        # Run bisection algorithm if enabled
                        if bisection:
                            await self._run_bisection(traversal, pattern)
                            
                        if break_on_first:
                            break
                            
                    elif result['false_positive']:
                        results['false_positives'].append(result)
                        results['false_positives_count'] += 1
                        self.false_positives += 1
                        
                        if not self.quiet:
                            print(f"\\n[*] FALSE POSITIVE: {result['url']}")
                    
                    elif result['error']:
                        results['errors'].append(result)
                        
                        if not continue_on_error and 'connection' in result['error'].lower():
                            print(f"\\n[-] Connection error: {result['error']}")
                            break
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(i + 1, len(traversals), traversal)
                    
                    # Quiet mode progress indicator
                    elif self.quiet and (i + 1) % 10 == 0:
                        print(".", end="", flush=True)

                except asyncio.CancelledError:
                    print("\\n[-] Fuzzing cancelled")
                    break
                except Exception as e:
                    error_result = {
                        'traversal': traversal,
                        'url': self.base_url.replace('TRAVERSAL', traversal),
                        'error': str(e),
                        'vulnerable': False,
                        'false_positive': False
                    }
                    results['errors'].append(error_result)

        return results

    async def _test_traversal(
        self, 
        session: aiohttp.ClientSession, 
        traversal: str, 
        pattern: str
    ) -> Dict[str, Any]:
        """
        Test a single traversal string
        
        Args:
            session: aiohttp session
            traversal: Traversal string to test
            pattern: Pattern to match in response
            
        Returns:
            Dictionary with test results
        """
        # Replace TRAVERSAL placeholder in URL
        url = self.base_url.replace('TRAVERSAL', traversal)
        
        headers = {
            'User-Agent': self._get_random_user_agent(),
            'Accept': '*/*',
            'Connection': 'close'
        }

        result = {
            'traversal': traversal,
            'url': url,
            'vulnerable': False,
            'false_positive': False,
            'error': None,
            'status_code': None,
            'content_length': None,
            'response_time': None,
            'matched_content': None
        }

        try:
            start_time = time.time()
            
            async with session.get(url, headers=headers, allow_redirects=False) as response:
                
                result['status_code'] = response.status
                result['response_time'] = time.time() - start_time
                
                # Read response content
                content = await response.text(errors='ignore')
                result['content_length'] = len(content)

                # Check for vulnerability pattern
                if pattern in content:
                    result['vulnerable'] = True
                    # Store matched content snippet
                    pattern_index = content.find(pattern)
                    start_idx = max(0, pattern_index - 50)
                    end_idx = min(len(content), pattern_index + len(pattern) + 50)
                    result['matched_content'] = content[start_idx:end_idx]
                else:
                    # Response received but pattern not found
                    result['false_positive'] = True

        except aiohttp.ClientError as e:
            result['error'] = f"Client error: {str(e)}"
        except asyncio.TimeoutError:
            result['error'] = "Request timeout"
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"

        return result

    async def _run_bisection(self, vulnerable_traversal: str, pattern: str):
        """Run bisection algorithm to find exact depth"""
        if not self.quiet:
            print("\\n[========= BISECTION ALGORITHM =========]\\n")
            
        tester = HTTPURLBisectionTester(
            base_url=self.base_url,
            pattern=pattern,
            timeout=self.timeout
        )
        
        bisection = BisectionAlgorithm(quiet=self.quiet)
        exact_depth = bisection.find_exact_depth(tester)
        
        if exact_depth:
            if not self.quiet:
                print(f"[+] Exact vulnerability depth found: {exact_depth}")
        else:
            if not self.quiet:
                print("[-] Could not determine exact depth")

    def fuzz_sync(
        self,
        traversals: List[str],
        pattern: str,
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        Synchronous HTTP URL fuzzing (wrapper for async method)
        """
        return asyncio.run(self.fuzz_async(
            traversals=traversals,
            pattern=pattern,
            time_delay=time_delay,
            break_on_first=break_on_first,
            continue_on_error=continue_on_error,
            bisection=bisection
        ))

    def test_single_traversal(self, traversal: str, pattern: str) -> Dict[str, Any]:
        """
        Test a single traversal string (convenience method)
        
        Args:
            traversal: Traversal string to test
            pattern: Pattern to match in response
            
        Returns:
            Test result dictionary
        """
        return self.fuzz_sync([traversal], pattern=pattern)

    def analyze_url(self) -> Dict[str, Any]:
        """
        Analyze the base URL structure
        
        Returns:
            Dictionary with URL analysis
        """
        parsed = urlparse(self.base_url)
        
        analysis = {
            'scheme': parsed.scheme,
            'hostname': parsed.hostname,
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'traversal_locations': [],
            'parameter_count': 0
        }

        # Find TRAVERSAL locations
        if 'TRAVERSAL' in parsed.path:
            analysis['traversal_locations'].append('path')
        
        if parsed.query:
            # Parse query parameters
            params = parse_qs(parsed.query, keep_blank_values=True)
            analysis['parameter_count'] = len(params)
            
            for param_name, param_values in params.items():
                for value in param_values:
                    if 'TRAVERSAL' in value:
                        analysis['traversal_locations'].append(f'query_param_{param_name}')

        if 'TRAVERSAL' in parsed.fragment:
            analysis['traversal_locations'].append('fragment')

        return analysis

    def generate_url_variants(self, traversal: str) -> List[str]:
        """
        Generate URL variants with different encoding schemes
        
        Args:
            traversal: Base traversal string
            
        Returns:
            List of URL variants with different encodings
        """
        variants = []
        
        # Original traversal
        variants.append(self.base_url.replace('TRAVERSAL', traversal))
        
        # URL encoded
        import urllib.parse
        url_encoded = urllib.parse.quote(traversal)
        variants.append(self.base_url.replace('TRAVERSAL', url_encoded))
        
        # Double URL encoded
        double_encoded = urllib.parse.quote(url_encoded)
        variants.append(self.base_url.replace('TRAVERSAL', double_encoded))
        
        # HTML entity encoded dots
        html_encoded = traversal.replace('.', '&#46;')
        variants.append(self.base_url.replace('TRAVERSAL', html_encoded))
        
        # Unicode encoded
        unicode_encoded = traversal.replace('../', '%u002E%u002E%u002F')
        variants.append(self.base_url.replace('TRAVERSAL', unicode_encoded))

        return variants

    def generate_and_fuzz(
        self,
        pattern: str,
        os_type: OSType = OSType.GENERIC,
        depth: int = 6,
        specific_file: Optional[str] = None,
        extra_files: bool = False,
        extension: Optional[str] = None,
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        Generate traversals and fuzz in one operation
        
        Args:
            pattern: Pattern to match in response (required)
            os_type: Operating system type
            depth: Traversal depth
            specific_file: Specific file to target
            extra_files: Include extra files
            extension: File extension to append
            time_delay: Delay between requests
            break_on_first: Stop after first vulnerability
            continue_on_error: Continue on connection errors
            bisection: Enable bisection algorithm
            
        Returns:
            Fuzzing results dictionary
        """
        # Generate traversals
        engine = TraversalEngine(quiet=self.quiet)
        traversals = engine.generate_traversals(
            os_type=os_type,
            depth=depth,
            specific_file=specific_file,
            extra_files=extra_files,
            extension=extension
        )

        # Perform fuzzing
        return self.fuzz_sync(
            traversals=traversals,
            pattern=pattern,
            time_delay=time_delay,
            break_on_first=break_on_first,
            continue_on_error=continue_on_error,
            bisection=bisection
        )


class HTTPURLBisectionTester:
    """HTTP URL-specific implementation of VulnerabilityTester for bisection algorithm"""
    
    def __init__(self, base_url: str, pattern: str, timeout: int = 10):
        """Initialize HTTP URL tester for bisection"""
        self.base_url = base_url
        self.pattern = pattern
        self.timeout = timeout

    def test_vulnerability(self, traversal: str) -> bool:
        """Test if traversal triggers vulnerability via HTTP URL"""
        try:
            import requests
            
            url = self.base_url.replace('TRAVERSAL', traversal)
            
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            return self.pattern in response.text
            
        except Exception:
            return False