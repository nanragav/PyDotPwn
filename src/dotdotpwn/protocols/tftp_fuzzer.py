"""
TFTP Fuzzer Module

Package to craft and send TFTP requests for directory traversal fuzzing.

Python implementation of the original DotDotPwn TFTP.pm
Original by chr1x & nitr0us
"""

import socket
import struct
import time
from typing import List, Optional, Dict, Any, Callable
from ..core.traversal_engine import TraversalEngine, OSType, DetectionMethod
from ..core.bisection_algorithm import BisectionAlgorithm


class TFTPFuzzer:
    """
    TFTP Directory Traversal Fuzzer
    
    Crafts and sends TFTP requests to test for directory traversal vulnerabilities
    """

    # TFTP Opcodes
    TFTP_RRQ = 1    # Read Request
    TFTP_WRQ = 2    # Write Request  
    TFTP_DATA = 3   # Data
    TFTP_ACK = 4    # Acknowledgment
    TFTP_ERROR = 5  # Error

    def __init__(
        self,
        host: str,
        port: int = 69,
        timeout: int = 10,
        quiet: bool = False
    ):
        """
        Initialize TFTP Fuzzer
        
        Args:
            host: Target hostname or IP
            port: Target port (default: 69)
            timeout: Request timeout in seconds
            quiet: Quiet mode for minimal output
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.quiet = quiet
        self.vulnerabilities_found = 0

    def _create_tftp_request(self, filename: str, mode: str = "octet") -> bytes:
        """
        Create TFTP Read Request packet
        
        Args:
            filename: Filename to request
            mode: Transfer mode (default: octet)
            
        Returns:
            TFTP request packet as bytes
        """
        # TFTP RRQ packet format:
        # 2 bytes: Opcode (1 for RRQ)
        # string: Filename (null-terminated)
        # string: Mode (null-terminated)
        
        packet = struct.pack('!H', self.TFTP_RRQ)  # Opcode
        packet += filename.encode('utf-8') + b'\\0'  # Filename
        packet += mode.encode('utf-8') + b'\\0'      # Mode
        
        return packet

    def _parse_tftp_response(self, data: bytes) -> Dict[str, Any]:
        """
        Parse TFTP response packet
        
        Args:
            data: Response packet data
            
        Returns:
            Dictionary with parsed response information
        """
        if len(data) < 2:
            return {'opcode': 0, 'error': 'Invalid packet size'}
        
        opcode = struct.unpack('!H', data[:2])[0]
        
        response = {'opcode': opcode}
        
        if opcode == self.TFTP_DATA:
            # Data packet: 2 bytes opcode + 2 bytes block number + data
            if len(data) >= 4:
                block_num = struct.unpack('!H', data[2:4])[0]
                file_data = data[4:]
                response.update({
                    'block_number': block_num,
                    'data': file_data,
                    'data_size': len(file_data)
                })
        
        elif opcode == self.TFTP_ERROR:
            # Error packet: 2 bytes opcode + 2 bytes error code + error message
            if len(data) >= 4:
                error_code = struct.unpack('!H', data[2:4])[0]
                error_msg = data[4:].rstrip(b'\\0').decode('utf-8', errors='ignore')
                response.update({
                    'error_code': error_code,
                    'error_message': error_msg
                })
        
        return response

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
        TFTP fuzzing
        
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
            print(f"[+] Testing TFTP server at {self.host}:{self.port}")

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
                        print(f"\\n[*] VULNERABLE: TFTP GET {result['filename']}")
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
                    'filename': traversal,
                    'error': str(e),
                    'vulnerable': False
                }
                results['errors'].append(error_result)

        return results

    def _test_traversal(self, traversal: str) -> Dict[str, Any]:
        """
        Test a single traversal string via TFTP
        
        Args:
            traversal: Traversal string to test
            
        Returns:
            Dictionary with test results
        """
        result = {
            'traversal': traversal,
            'filename': traversal,
            'vulnerable': False,
            'error': None,
            'file_content': None,
            'file_size': None,
            'response_time': None,
            'tftp_error_code': None,
            'tftp_error_message': None
        }

        sock = None
        try:
            start_time = time.time()
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Create TFTP Read Request
            request_packet = self._create_tftp_request(traversal)
            
            # Send request
            sock.sendto(request_packet, (self.host, self.port))
            
            # Receive response
            try:
                response_data, server_addr = sock.recvfrom(4096)
                result['response_time'] = time.time() - start_time
                
                # Parse TFTP response
                parsed_response = self._parse_tftp_response(response_data)
                
                if parsed_response['opcode'] == self.TFTP_DATA:
                    # Received data - file exists and was retrieved
                    result['vulnerable'] = True
                    result['file_size'] = parsed_response.get('data_size', 0)
                    
                    if 'data' in parsed_response:
                        # Store file content preview
                        file_data = parsed_response['data']
                        result['file_content'] = file_data.decode('utf-8', errors='ignore')
                        
                        # For large files, try to receive more blocks
                        if len(file_data) == 512:  # TFTP block size
                            additional_data = self._receive_remaining_blocks(
                                sock, server_addr, parsed_response.get('block_number', 1)
                            )
                            if additional_data:
                                result['file_content'] += additional_data.decode('utf-8', errors='ignore')
                                result['file_size'] += len(additional_data)
                
                elif parsed_response['opcode'] == self.TFTP_ERROR:
                    # Received error - file not found or access denied
                    result['tftp_error_code'] = parsed_response.get('error_code')
                    result['tftp_error_message'] = parsed_response.get('error_message', '')
                    
                    # Error code 1 = File not found (normal)
                    # Error code 2 = Access violation (could indicate file exists but no permission)
                    if result['tftp_error_code'] == 2:
                        # Access violation might indicate file exists
                        result['vulnerable'] = True
                        result['error'] = f"Access violation (file may exist): {result['tftp_error_message']}"
                
                else:
                    result['error'] = f"Unexpected TFTP opcode: {parsed_response['opcode']}"
                    
            except socket.timeout:
                result['error'] = "Request timeout - no response from TFTP server"
            except ConnectionRefusedError:
                result['error'] = "Connection refused"

        except Exception as e:
            result['error'] = f"TFTP error: {str(e)}"
        finally:
            if sock:
                sock.close()

        return result

    def _receive_remaining_blocks(
        self, 
        sock: socket.socket, 
        server_addr: tuple, 
        start_block: int
    ) -> bytes:
        """
        Receive remaining TFTP data blocks for large files
        
        Args:
            sock: UDP socket
            server_addr: Server address tuple
            start_block: Starting block number
            
        Returns:
            Additional file data as bytes
        """
        additional_data = b''
        current_block = start_block
        max_blocks = 10  # Limit to prevent infinite loops
        
        try:
            for _ in range(max_blocks):
                # Send ACK for current block
                ack_packet = struct.pack('!HH', self.TFTP_ACK, current_block)
                sock.sendto(ack_packet, server_addr)
                
                # Receive next block
                try:
                    response_data, _ = sock.recvfrom(4096)
                    parsed_response = self._parse_tftp_response(response_data)
                    
                    if parsed_response['opcode'] == self.TFTP_DATA:
                        block_data = parsed_response.get('data', b'')
                        additional_data += block_data
                        current_block += 1
                        
                        # If block is less than 512 bytes, it's the last block
                        if len(block_data) < 512:
                            break
                    else:
                        break
                        
                except socket.timeout:
                    break
                    
        except Exception:
            pass
            
        return additional_data

    def _run_bisection(self, vulnerable_traversal: str):
        """Run bisection algorithm to find exact depth"""
        if not self.quiet:
            print("\\n[========= BISECTION ALGORITHM =========]\\n")
            
        # Create a TFTP-specific bisection tester
        tester = TFTPBisectionTester(
            host=self.host,
            port=self.port,
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
        Test basic TFTP connection
        
        Returns:
            Dictionary with connection test results
        """
        result = {
            'connected': False,
            'server_responsive': False,
            'error': None
        }

        try:
            # Try to request a non-existent file to test if server responds
            test_result = self._test_traversal("nonexistent_test_file_12345.txt")
            
            if test_result.get('tftp_error_code') is not None:
                # Server responded with error - it's alive
                result['connected'] = True
                result['server_responsive'] = True
            elif test_result.get('error') and 'timeout' not in test_result['error'].lower():
                # Server responded but with unexpected response
                result['connected'] = True
                result['server_responsive'] = True
            elif 'timeout' in test_result.get('error', '').lower():
                result['error'] = "TFTP server not responding (timeout)"
            else:
                result['error'] = test_result.get('error', 'Unknown connection error')

        except Exception as e:
            result['error'] = f"Connection test error: {str(e)}"

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
            extension=extension,
            detection_method=detection_method
        )

        # Perform fuzzing
        return self.fuzz(
            traversals=traversals,
            time_delay=time_delay,
            break_on_first=break_on_first,
            continue_on_error=continue_on_error,
            bisection=bisection
        )


class TFTPBisectionTester:
    """TFTP-specific implementation of VulnerabilityTester for bisection algorithm"""
    
    def __init__(self, host: str, port: int = 69, timeout: int = 10):
        """Initialize TFTP tester for bisection"""
        self.host = host
        self.port = port
        self.timeout = timeout

    def test_vulnerability(self, traversal: str) -> bool:
        """Test if traversal triggers vulnerability via TFTP"""
        try:
            fuzzer = TFTPFuzzer(
                host=self.host,
                port=self.port,
                timeout=self.timeout,
                quiet=True
            )
            
            result = fuzzer.test_single_traversal(traversal)
            return result.get('vulnerable', False)
            
        except Exception:
            return False