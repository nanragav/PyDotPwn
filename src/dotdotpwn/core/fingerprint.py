"""
Fingerprint Module

This module performs Operating System detection, service detection and banner grabbing.

Python implementation of the original DotDotPwn Fingerprint.pm
Original by nitr0us (nitrousenador@gmail.com)
"""

import socket
import subprocess
import re
import asyncio
import aiohttp
from typing import Optional, Tuple
import os
import platform


class Fingerprint:
    """
    Class for OS detection, service detection and banner grabbing
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize Fingerprint scanner
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout

    def detect_os_nmap(self, host: str) -> Optional[str]:
        """
        Detect target OS using nmap (requires root/admin privileges)
        
        Args:
            host: Target hostname or IP
            
        Returns:
            OS detail string or None if detection fails
        """
        # Check if running as admin/root
        if platform.system() == "Windows":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[-] You need administrator privileges to use OS detection feature (-O)")
                return None
        else:
            if os.geteuid() != 0:
                print("[-] You need root privileges to use OS detection feature (-O)")
                return None

        try:
            # Run nmap OS detection
            cmd = ["nmap", "-O", "-Pn", "-T4", host]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            if result.returncode == 0:
                # Extract OS details from nmap output
                for line in result.stdout.split('\\n'):
                    if 'OS details:' in line:
                        return line.split('OS details:')[1].strip()
                    elif 'Running:' in line:
                        return line.split('Running:')[1].strip()
                        
        except subprocess.TimeoutExpired:
            print("[-] Nmap OS detection timed out")
        except FileNotFoundError:
            print("[-] Nmap not found. Please install nmap for OS detection")
        except Exception as e:
            print(f"[-] OS detection failed: {e}")
            
        return None

    def grab_banner(self, host: str, port: int, protocol: str = "tcp") -> str:
        """
        Grab service banner from target host and port
        
        Args:
            host: Target hostname or IP
            port: Target port
            protocol: Protocol type ("tcp", "http", "https", "ftp", etc.)
            
        Returns:
            Service banner string
        """
        if protocol.lower() == "tftp":
            return "N/A"

        try:
            # For HTTP/HTTPS, use HTTP-specific banner grabbing
            if protocol.lower() in ["http", "https"]:
                return self._grab_http_banner(host, port, protocol.lower() == "https")
            
            # For other TCP services, use socket connection
            return self._grab_tcp_banner(host, port)
            
        except Exception as e:
            return f"Banner grab failed: {str(e)}"

    def _grab_tcp_banner(self, host: str, port: int) -> str:
        """
        Grab banner using raw TCP connection
        
        Args:
            host: Target hostname or IP  
            port: Target port
            
        Returns:
            Banner string
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send appropriate request based on common ports
            if port == 21:  # FTP
                pass  # FTP sends banner immediately
            elif port == 25:  # SMTP
                pass  # SMTP sends banner immediately
            elif port == 22:  # SSH
                pass  # SSH sends banner immediately
            elif port == 23:  # Telnet
                pass  # Telnet may send banner immediately
            else:
                # For unknown services, try sending a simple HTTP request
                sock.send(b"GET / HTTP/1.0\\r\\n\\r\\n")
                
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else "No banner received"
            
        except socket.timeout:
            return "Connection timed out"
        except ConnectionRefusedError:
            return "Connection refused"
        except Exception as e:
            return f"Error: {str(e)}"

    def _grab_http_banner(self, host: str, port: int, ssl: bool = False) -> str:
        """
        Grab HTTP/HTTPS banner including server headers
        
        Args:
            host: Target hostname or IP
            port: Target port  
            ssl: Use HTTPS if True
            
        Returns:
            HTTP server banner
        """
        try:
            import requests
            
            scheme = "https" if ssl else "http"
            url = f"{scheme}://{host}:{port}/"
            
            # Send HEAD request to get headers without body
            response = requests.head(
                url, 
                timeout=self.timeout,
                verify=False,  # Ignore SSL certificate errors
                allow_redirects=False
            )
            
            # Extract server information
            server = response.headers.get('Server', 'Unknown Server')
            powered_by = response.headers.get('X-Powered-By', '')
            
            banner_parts = [f"Server: {server}"]
            if powered_by:
                banner_parts.append(f"X-Powered-By: {powered_by}")
                
            return " | ".join(banner_parts)
            
        except requests.exceptions.SSLError:
            return "SSL/TLS connection error"
        except requests.exceptions.ConnectionError:
            return "Connection error"
        except requests.exceptions.Timeout:
            return "Request timed out"
        except Exception as e:
            return f"HTTP banner grab failed: {str(e)}"

    async def async_grab_banner(self, host: str, port: int, protocol: str = "tcp") -> str:
        """
        Asynchronous banner grabbing for better performance
        
        Args:
            host: Target hostname or IP
            port: Target port
            protocol: Protocol type
            
        Returns:
            Service banner string
        """
        if protocol.lower() == "tftp":
            return "N/A"

        try:
            if protocol.lower() in ["http", "https"]:
                return await self._async_grab_http_banner(host, port, protocol.lower() == "https")
            else:
                return await self._async_grab_tcp_banner(host, port)
                
        except Exception as e:
            return f"Async banner grab failed: {str(e)}"

    async def _async_grab_tcp_banner(self, host: str, port: int) -> str:
        """Async TCP banner grabbing"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Send request for specific services
            if port in [80, 8080, 8000]:
                writer.write(b"GET / HTTP/1.0\\r\\n\\r\\n")
                await writer.drain()
            
            # Read banner
            data = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return data.decode('utf-8', errors='ignore').strip() or "No banner received"
            
        except asyncio.TimeoutError:
            return "Connection timed out"
        except ConnectionRefusedError:
            return "Connection refused"
        except Exception as e:
            return f"Error: {str(e)}"

    async def _async_grab_http_banner(self, host: str, port: int, ssl: bool = False) -> str:
        """Async HTTP banner grabbing"""
        try:
            scheme = "https" if ssl else "http"
            url = f"{scheme}://{host}:{port}/"
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False) if ssl else None
            
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.head(url) as response:
                    server = response.headers.get('Server', 'Unknown Server')
                    powered_by = response.headers.get('X-Powered-By', '')
                    
                    banner_parts = [f"Server: {server}"]
                    if powered_by:
                        banner_parts.append(f"X-Powered-By: {powered_by}")
                        
                    return " | ".join(banner_parts)
                    
        except aiohttp.ClientError as e:
            return f"HTTP error: {str(e)}"
        except asyncio.TimeoutError:
            return "Request timed out"
        except Exception as e:
            return f"HTTP banner grab failed: {str(e)}"

    def detect_service_version(self, host: str, port: int) -> dict:
        """
        Detect service version using nmap service detection
        
        Args:
            host: Target hostname or IP
            port: Target port
            
        Returns:
            Dictionary with service information
        """
        try:
            cmd = ["nmap", "-sV", "-p", str(port), host]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Parse nmap service detection output
                service_info = {
                    'port': port,
                    'state': 'unknown',
                    'service': 'unknown',
                    'version': 'unknown'
                }
                
                for line in result.stdout.split('\\n'):
                    if f"{port}/" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            service_info['state'] = parts[1]
                            service_info['service'] = parts[2]
                            if len(parts) > 3:
                                service_info['version'] = ' '.join(parts[3:])
                        break
                        
                return service_info
                
        except subprocess.TimeoutExpired:
            print("[-] Service detection timed out")
        except FileNotFoundError:
            print("[-] Nmap not found. Please install nmap for service detection")
        except Exception as e:
            print(f"[-] Service detection failed: {e}")
            
        return {
            'port': port,
            'state': 'unknown', 
            'service': 'unknown',
            'version': 'unknown'
        }