"""
Payload Fuzzer Module

Protocol-independent payload fuzzer that sends custom payloads with traversal patterns
to any host and port.

Python implementation of the original DotDotPwn Payload.pm
Original by chr1x & nitr0us
"""

import socket
import ssl
import time
import asyncio
from typing import List, Optional, Dict, Any, Callable
from ..core.traversal_engine import TraversalEngine, OSType, DetectionMethod
from ..core.bisection_algorithm import BisectionAlgorithm


class PayloadFuzzer:
    """
    Protocol-Independent Payload Fuzzer
    
    Sends custom payloads with traversal patterns to test for directory traversal 
    vulnerabilities in any protocol
    """

    def __init__(
        self,
        host: str,
        port: int,
        payload_template: str,
        ssl_enabled: bool = False,
        timeout: int = 10,
        quiet: bool = False
    ):
        """
        Initialize Payload Fuzzer
        
        Args:
            host: Target hostname or IP
            port: Target port
            payload_template: Payload template with TRAVERSAL placeholder
            ssl_enabled: Use SSL/TLS for connection
            timeout: Connection timeout in seconds
            quiet: Quiet mode for minimal output
        """
        self.host = host
        self.port = port
        self.payload_template = payload_template
        self.ssl_enabled = ssl_enabled
        self.timeout = timeout
        self.quiet = quiet
        self.vulnerabilities_found = 0
        
        # Validate payload template
        if "TRAVERSAL" not in payload_template:
            raise ValueError("Payload template must contain 'TRAVERSAL' placeholder")

    def fuzz(
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
        Payload fuzzing
        
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

        if not self.quiet:
            print(f"[+] Testing payload against {self.host}:{self.port}")
            if self.ssl_enabled:
                print("[+] SSL/TLS enabled")
            if pattern:
                print(f"[+] Looking for pattern: {pattern}")

        for i, traversal in enumerate(traversals):
            try:
                # Add delay between requests
                if time_delay > 0 and i > 0:
                    time.sleep(time_delay)

                # Test the traversal
                result = self._test_traversal(traversal, pattern)
                
                if result['vulnerable']:
                    results['vulnerabilities'].append(result)
                    results['vulnerabilities_found'] += 1
                    self.vulnerabilities_found += 1
                    
                    if not self.quiet:
                        print(f"\\n[*] VULNERABLE: {result['payload'][:100]}...")
                        if pattern and result.get('matched_content'):
                            print(f"    Pattern matched: {result['matched_content'][:100]}...")

                    # Run bisection algorithm if enabled
                    if bisection:
                        self._run_bisection(traversal, pattern)
                        
                    if break_on_first:
                        break
                        
                elif result['false_positive']:
                    results['false_positives'].append(result)
                    results['false_positives_count'] += 1
                    
                    if not self.quiet:
                        print(f"\\n[*] FALSE POSITIVE: {result['payload'][:100]}...")
                
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

            except KeyboardInterrupt:
                print("\\n[-] Fuzzing cancelled by user")
                break
            except Exception as e:
                error_result = {
                    'traversal': traversal,
                    'payload': self.payload_template.replace('TRAVERSAL', traversal),
                    'error': str(e),
                    'vulnerable': False,
                    'false_positive': False
                }
                results['errors'].append(error_result)

        return results

    def _test_traversal(self, traversal: str, pattern: Optional[str] = None) -> Dict[str, Any]:
        """
        Test a single traversal string with payload
        
        Args:
            traversal: Traversal string to test
            pattern: Pattern to match in response
            
        Returns:
            Dictionary with test results
        """
        # Create payload by replacing TRAVERSAL placeholder
        payload = self.payload_template.replace('TRAVERSAL', traversal)
        
        result = {
            'traversal': traversal,
            'payload': payload,
            'vulnerable': False,
            'false_positive': False,
            'error': None,
            'response': None,
            'response_length': None,
            'response_time': None,
            'matched_content': None
        }

        sock = None
        try:
            start_time = time.time()
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Wrap with SSL if enabled
            if self.ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            # Connect
            sock.connect((self.host, self.port))
            
            # Send payload
            sock.sendall(payload.encode('utf-8'))
            
            # Receive response
            response_data = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    # Limit response size to prevent memory issues
                    if len(response_data) > 1024 * 1024:  # 1MB limit
                        break
            except socket.timeout:
                # Timeout reading response is okay
                pass
            
            result['response_time'] = time.time() - start_time
            result['response_length'] = len(response_data)
            
            # Decode response
            try:
                response_text = response_data.decode('utf-8', errors='ignore')
                result['response'] = response_text[:4096]  # Store first 4KB
            except:
                result['response'] = response_data.hex()[:4096]
            
            # Check for vulnerability
            if pattern and response_data:
                if pattern.encode('utf-8') in response_data or pattern in response_text:
                    result['vulnerable'] = True
                    # Store matched content snippet
                    if pattern in response_text:
                        pattern_index = response_text.find(pattern)
                        start_idx = max(0, pattern_index - 50)
                        end_idx = min(len(response_text), pattern_index + len(pattern) + 50)
                        result['matched_content'] = response_text[start_idx:end_idx]
                else:
                    # Response received but pattern not found
                    result['false_positive'] = True
            elif response_data:
                # No pattern specified but got response - assume vulnerable
                result['vulnerable'] = True

        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except socket.timeout:
            result['error'] = "Connection timeout"
        except ssl.SSLError as e:
            result['error'] = f"SSL error: {str(e)}"
        except Exception as e:
            result['error'] = f"Connection error: {str(e)}"
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result

    def _run_bisection(self, vulnerable_traversal: str, pattern: Optional[str] = None):
        """Run bisection algorithm to find exact depth"""
        if not self.quiet:
            print("\\n[========= BISECTION ALGORITHM =========]\\n")
            
        tester = PayloadBisectionTester(
            host=self.host,
            port=self.port,
            payload_template=self.payload_template,
            ssl_enabled=self.ssl_enabled,
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
        return self._test_traversal(traversal, pattern)

    def test_connection(self) -> Dict[str, Any]:
        """
        Test basic connection to target
        
        Returns:
            Dictionary with connection test results
        """
        result = {
            'connected': False,
            'ssl_handshake': False,
            'error': None
        }

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if self.ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
                
            sock.connect((self.host, self.port))
            result['connected'] = True
            
            if self.ssl_enabled:
                result['ssl_handshake'] = True
                
            sock.close()

        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except socket.timeout:
            result['error'] = "Connection timeout"
        except ssl.SSLError as e:
            result['error'] = f"SSL handshake failed: {str(e)}"
        except Exception as e:
            result['error'] = f"Connection error: {str(e)}"
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result

    def validate_payload(self) -> Dict[str, Any]:
        """
        Validate payload template
        
        Returns:
            Dictionary with validation results
        """
        result = {
            'valid': True,
            'warnings': [],
            'errors': []
        }

        # Check for TRAVERSAL placeholder
        if "TRAVERSAL" not in self.payload_template:
            result['valid'] = False
            result['errors'].append("Payload template must contain 'TRAVERSAL' placeholder")

        # Check payload length
        if len(self.payload_template) > 65535:
            result['warnings'].append("Payload template is very large (>64KB)")

        # Check for binary data
        try:
            self.payload_template.encode('utf-8')
        except UnicodeEncodeError:
            result['warnings'].append("Payload contains non-UTF-8 characters")

        # Count TRAVERSAL occurrences
        traversal_count = self.payload_template.count('TRAVERSAL')
        if traversal_count > 1:
            result['warnings'].append(f"Multiple TRAVERSAL placeholders found ({traversal_count})")
        elif traversal_count == 0:
            result['valid'] = False
            result['errors'].append("No TRAVERSAL placeholder found in payload")

        return result

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
        bisection: bool = False,
        detection_method: DetectionMethod = DetectionMethod.ANY
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
        # Validate payload first
        validation = self.validate_payload()
        if not validation['valid']:
            return {
                'error': 'Invalid payload template',
                'validation_errors': validation['errors'],
                'vulnerabilities_found': 0
            }

        # Generate traversals
        engine = TraversalEngine(quiet=self.quiet)
        traversals = engine.generate_traversals(
            os_type=os_type,
            depth=depth,
            specific_file=specific_file,
            extra_files=extra_files,
            extension=extension,
            detection_method=detection_method
        )

        # Perform fuzzing
        return self.fuzz(
            traversals=traversals,
            pattern=pattern,
            time_delay=time_delay,
            break_on_first=break_on_first,
            continue_on_error=continue_on_error,
            bisection=bisection
        )


class PayloadBisectionTester:
    """Payload-specific implementation of VulnerabilityTester for bisection algorithm"""
    
    def __init__(
        self, 
        host: str, 
        port: int, 
        payload_template: str,
        ssl_enabled: bool = False,
        pattern: Optional[str] = None,
        timeout: int = 10
    ):
        """Initialize Payload tester for bisection"""
        self.host = host
        self.port = port
        self.payload_template = payload_template
        self.ssl_enabled = ssl_enabled
        self.pattern = pattern
        self.timeout = timeout

    def test_vulnerability(self, traversal: str) -> bool:
        """Test if traversal triggers vulnerability via custom payload"""
        try:
            fuzzer = PayloadFuzzer(
                host=self.host,
                port=self.port,
                payload_template=self.payload_template,
                ssl_enabled=self.ssl_enabled,
                timeout=self.timeout,
                quiet=True
            )
            
            result = fuzzer.test_single_traversal(traversal, self.pattern)
            return result.get('vulnerable', False)
            
        except Exception:
            return False