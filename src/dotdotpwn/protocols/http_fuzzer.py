"""
HTTP Fuzzer Module

Package to craft and send HTTP requests for directory traversal fuzzing.

Python implementation of the original DotDotPwn HTTP.pm
Original by chr1x & nitr0us
"""

import asyncio
import aiohttp
import time
import random
from typing import List, Optional, Dict, Any, Callable
from pathlib import Path
from ..core.traversal_engine import TraversalEngine, OSType
from ..core.bisection_algorithm import BisectionAlgorithm, HTTPBisectionTester


class HTTPFuzzer:
    """
    HTTP Directory Traversal Fuzzer
    
    Crafts and sends HTTP requests to test for directory traversal vulnerabilities
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        ssl: bool = False,
        method: str = "GET",
        timeout: int = 10,
        user_agent_file: Optional[str] = None,
        quiet: bool = False
    ):
        """
        Initialize HTTP Fuzzer
        
        Args:
            host: Target hostname or IP
            port: Target port (default: 80)
            ssl: Use HTTPS if True (default: False)
            method: HTTP method (GET, POST, HEAD, etc.)
            timeout: Request timeout in seconds
            user_agent_file: Path to user agent strings file
            quiet: Quiet mode for minimal output
        """
        self.host = host
        self.port = port
        self.ssl = ssl
        self.method = method.upper()
        self.timeout = timeout
        self.quiet = quiet
        self.user_agents = self._load_user_agents(user_agent_file)
        self.vulnerabilities_found = 0
        self.false_positives = 0
        
        # Build base URL
        scheme = "https" if ssl else "http"
        port_str = f":{port}" if port not in (80, 443) else ""
        self.base_url = f"{scheme}://{host}{port_str}"

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
        pattern: Optional[str] = None,
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        Asynchronous HTTP fuzzing
        
        Args:
            traversals: List of traversal strings to test
            pattern: Pattern to match in response for vulnerability detection
            time_delay: Delay between requests in seconds
            break_on_first: Stop after first vulnerability found
            continue_on_error: Continue testing if connection errors occur
            progress_callback: Callback function for progress updates
            bisection: Enable bisection algorithm when vulnerability found
            
        Returns:
            Dictionary with fuzzing results
        """
        results = {
            'vulnerabilities': [],
            'false_positives': [],
            'errors': [],
            'total_tests': len(traversals),
            'vulnerabilities_found': 0,
            'false_positives_count': 0
        }

        connector = aiohttp.TCPConnector(
            ssl=False if self.ssl else None,
            limit=10,  # Connection pool limit
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
                            if pattern and result.get('matched_content'):
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
                        'url': f"{self.base_url}/{traversal}",
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
        pattern: Optional[str] = None
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
        url = f"{self.base_url}/{traversal}"
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
            
            async with session.request(
                self.method, 
                url, 
                headers=headers,
                allow_redirects=False
            ) as response:
                
                result['status_code'] = response.status
                result['response_time'] = time.time() - start_time
                
                # Read response content
                content = await response.text(errors='ignore')
                result['content_length'] = len(content)

                # Check for vulnerability
                if response.status == 200:
                    if pattern:
                        if pattern in content:
                            result['vulnerable'] = True
                            # Store matched content snippet
                            pattern_index = content.find(pattern)
                            start_idx = max(0, pattern_index - 50)
                            end_idx = min(len(content), pattern_index + len(pattern) + 50)
                            result['matched_content'] = content[start_idx:end_idx]
                        else:
                            result['false_positive'] = True
                    else:
                        # No pattern specified - treat 200 as vulnerable
                        result['vulnerable'] = True

        except aiohttp.ClientError as e:
            result['error'] = f"Client error: {str(e)}"
        except asyncio.TimeoutError:
            result['error'] = "Request timeout"
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"

        return result

    async def _run_bisection(self, vulnerable_traversal: str, pattern: Optional[str] = None):
        """Run bisection algorithm to find exact depth"""
        if not self.quiet:
            print("\\n[========= BISECTION ALGORITHM =========]\\n")
            
        tester = HTTPBisectionTester(
            host=self.host,
            port=self.port,
            ssl=self.ssl,
            pattern=pattern
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
        pattern: Optional[str] = None,
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        Synchronous HTTP fuzzing (wrapper for async method)
        """
        return asyncio.run(self.fuzz_async(
            traversals=traversals,
            pattern=pattern,
            time_delay=time_delay,
            break_on_first=break_on_first,
            continue_on_error=continue_on_error,
            bisection=bisection
        ))

    def test_single_traversal(
        self,
        traversal: str,
        pattern: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test a single traversal string (convenience method)
        
        Args:
            traversal: Traversal string to test
            pattern: Pattern to match in response
            
        Returns:
            Test result dictionary
        """
        return self.fuzz_sync([traversal], pattern=pattern)

    def generate_and_fuzz(
        self,
        os_type: OSType = OSType.GENERIC,
        depth: int = 6,
        specific_file: Optional[str] = None,
        extra_files: bool = False,
        extension: Optional[str] = None,
        pattern: Optional[str] = None,
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        Generate traversals and fuzz in one operation
        
        Args:
            os_type: Operating system type
            depth: Traversal depth
            specific_file: Specific file to target
            extra_files: Include extra files
            extension: File extension to append
            pattern: Pattern to match in response
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