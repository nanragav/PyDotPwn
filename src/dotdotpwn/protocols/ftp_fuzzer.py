"""
FTP Fuzzer Module

Package to craft and send FTP requests for directory traversal fuzzing.

Python implementation of the original DotDotPwn FTP.pm
Original by chr1x & nitr0us
"""

import ftplib
import time
import asyncio
from typing import List, Optional, Dict, Any, Callable
from ..core.traversal_engine import TraversalEngine, OSType
from ..core.bisection_algorithm import BisectionAlgorithm, FTPBisectionTester


class FTPFuzzer:
    """
    FTP Directory Traversal Fuzzer
    
    Crafts and sends FTP requests to test for directory traversal vulnerabilities
    """

    def __init__(
        self,
        host: str,
        port: int = 21,
        username: str = "anonymous",
        password: str = "dot@dot.pwn",
        timeout: int = 30,
        quiet: bool = False
    ):
        """
        Initialize FTP Fuzzer
        
        Args:
            host: Target hostname or IP
            port: Target port (default: 21)
            username: FTP username (default: anonymous)
            password: FTP password (default: dot@dot.pwn)
            timeout: Connection timeout in seconds
            quiet: Quiet mode for minimal output
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.quiet = quiet
        self.vulnerabilities_found = 0

    def fuzz(
        self,
        traversals: List[str],
        time_delay: float = 0.3,
        break_on_first: bool = False,
        continue_on_error: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        bisection: bool = False
    ) -> Dict[str, Any]:
        """
        FTP fuzzing
        
        Args:
            traversals: List of traversal strings to test
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
            'errors': [],
            'total_tests': len(traversals),
            'vulnerabilities_found': 0
        }

        if not self.quiet:
            print(f"[+] Testing FTP server at {self.host}:{self.port}")
            print(f"[+] Using credentials: {self.username}:{self.password}")

        for i, traversal in enumerate(traversals):
            try:
                # Add delay between requests
                if time_delay > 0 and i > 0:
                    time.sleep(time_delay)

                # Test the traversal
                result = self._test_traversal(traversal)
                
                if result['vulnerable']:
                    results['vulnerabilities'].append(result)
                    results['vulnerabilities_found'] += 1
                    self.vulnerabilities_found += 1
                    
                    if not self.quiet:
                        print(f"\\n[*] VULNERABLE: {result['command']}")
                        if result.get('file_content'):
                            print(f"    File content preview: {result['file_content'][:100]}...")

                    # Run bisection algorithm if enabled
                    if bisection:
                        self._run_bisection(traversal)
                        
                    if break_on_first:
                        break
                
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
                    'command': f"RETR {traversal}",
                    'error': str(e),
                    'vulnerable': False
                }
                results['errors'].append(error_result)

        return results

    def _test_traversal(self, traversal: str) -> Dict[str, Any]:
        """
        Test a single traversal string via FTP
        
        Args:
            traversal: Traversal string to test
            
        Returns:
            Dictionary with test results
        """
        result = {
            'traversal': traversal,
            'command': f"RETR {traversal}",
            'vulnerable': False,
            'error': None,
            'file_content': None,
            'file_size': None,
            'response_time': None
        }

        ftp = None
        try:
            start_time = time.time()
            
            # Connect to FTP server
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            
            # Login
            ftp.login(self.username, self.password)
            
            # Try to retrieve file using traversal
            file_data = []
            
            def collect_data(data):
                file_data.append(data)
            
            try:
                ftp.retrbinary(f"RETR {traversal}", collect_data)
                
                # If we reach here, file was successfully retrieved
                result['vulnerable'] = True
                result['response_time'] = time.time() - start_time
                
                # Combine file data
                if file_data:
                    full_data = b''.join(file_data)
                    result['file_size'] = len(full_data)
                    # Store first 1KB as preview
                    result['file_content'] = full_data[:1024].decode('utf-8', errors='ignore')
                
            except ftplib.error_perm as e:
                # File not found or permission denied - not vulnerable
                error_msg = str(e)
                if "550" in error_msg:  # File not found
                    pass  # Normal behavior, not an error
                else:
                    result['error'] = f"FTP permission error: {error_msg}"
            
            ftp.quit()

        except ftplib.error_temp as e:
            result['error'] = f"FTP temporary error: {str(e)}"
        except ftplib.error_perm as e:
            result['error'] = f"FTP permission error: {str(e)}"
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except TimeoutError:
            result['error'] = "Connection timeout"
        except Exception as e:
            result['error'] = f"FTP error: {str(e)}"
        finally:
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass

        return result

    def _run_bisection(self, vulnerable_traversal: str):
        """Run bisection algorithm to find exact depth"""
        if not self.quiet:
            print("\\n[========= BISECTION ALGORITHM =========]\\n")
            
        tester = FTPBisectionTester(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password
        )
        
        bisection = BisectionAlgorithm(quiet=self.quiet)
        exact_depth = bisection.find_exact_depth(tester)
        
        if exact_depth:
            if not self.quiet:
                print(f"[+] Exact vulnerability depth found: {exact_depth}")
        else:
            if not self.quiet:
                print("[-] Could not determine exact depth")

    def test_single_traversal(self, traversal: str) -> Dict[str, Any]:
        """
        Test a single traversal string (convenience method)
        
        Args:
            traversal: Traversal string to test
            
        Returns:
            Test result dictionary
        """
        return self._test_traversal(traversal)

    def test_connection(self) -> Dict[str, Any]:
        """
        Test basic FTP connection
        
        Returns:
            Dictionary with connection test results
        """
        result = {
            'connected': False,
            'login_successful': False,
            'server_info': None,
            'error': None
        }

        ftp = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            result['connected'] = True
            
            # Get server welcome message
            result['server_info'] = ftp.getwelcome()
            
            # Try to login
            ftp.login(self.username, self.password)
            result['login_successful'] = True
            
            ftp.quit()

        except ftplib.error_perm as e:
            result['error'] = f"Login failed: {str(e)}"
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except TimeoutError:
            result['error'] = "Connection timeout"
        except Exception as e:
            result['error'] = f"Connection error: {str(e)}"
        finally:
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass

        return result

    def list_directory(self, path: str = "/") -> Dict[str, Any]:
        """
        List directory contents (for reconnaissance)
        
        Args:
            path: Directory path to list
            
        Returns:
            Dictionary with directory listing results
        """
        result = {
            'success': False,
            'files': [],
            'directories': [],
            'error': None
        }

        ftp = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            ftp.login(self.username, self.password)
            
            # Change to specified directory
            if path != "/":
                ftp.cwd(path)
            
            # Get directory listing
            items = []
            ftp.retrlines('LIST', items.append)
            
            # Parse listing
            for item in items:
                parts = item.split()
                if len(parts) >= 9:
                    permissions = parts[0]
                    name = ' '.join(parts[8:])
                    
                    if permissions.startswith('d'):
                        result['directories'].append(name)
                    else:
                        result['files'].append(name)
            
            result['success'] = True
            ftp.quit()

        except ftplib.error_perm as e:
            result['error'] = f"Permission error: {str(e)}"
        except Exception as e:
            result['error'] = f"Directory listing error: {str(e)}"
        finally:
            if ftp:
                try:
                    ftp.quit()
                except:
                    pass

        return result

    def generate_and_fuzz(
        self,
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
        return self.fuzz(
            traversals=traversals,
            time_delay=time_delay,
            break_on_first=break_on_first,
            continue_on_error=continue_on_error,
            bisection=bisection
        )