"""
Command Line Interface for DotDotPwn

This module provides a command-line interface that matches the original dotdotpwn.pl
functionality while leveraging the Python implementation.
"""

# Suppress SSL warnings for security testing
from .utils.ssl_suppression import suppress_ssl_warnings

import typer
import asyncio
import time
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich import print as rprint
from typing import Optional, List
from pathlib import Path
import sys

from .core.traversal_engine import TraversalEngine, OSType
from .core.fingerprint import Fingerprint
from .protocols.http_fuzzer import HTTPFuzzer
from .protocols.http_url_fuzzer import HTTPURLFuzzer
from .protocols.ftp_fuzzer import FTPFuzzer
from .protocols.tftp_fuzzer import TFTPFuzzer
from .protocols.payload_fuzzer import PayloadFuzzer
from .utils.reporter import Reporter, generate_traversal_list

app = typer.Typer(
    name="dotdotpwn",
    help="🚀 DotDotPwn - The Directory Traversal Fuzzer (Python Implementation)",
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()


@app.command("help-examples")
def show_examples():
    """📚 Show comprehensive usage examples for all modules"""
    examples_text = """
[bold blue]🚀 DotDotPwn - Comprehensive Usage Examples[/bold blue]

[bold green]🌐 HTTP MODULE EXAMPLES:[/bold green]
[cyan]Basic HTTP scanning:[/cyan]
  dotdotpwn --module http --host example.com --file /etc/passwd --pattern "root:"
  dotdotpwn -m http -h 192.168.1.1 --port 8080 --target-file /etc/hosts --keyword "localhost"

[cyan]HTTPS with OS detection:[/cyan]
  dotdotpwn -m http -h example.com --ssl --os-detection --file /etc/passwd -k "root:"
  dotdotpwn --module http --hostname secure.example.com --https --detect-os --depth 10

[cyan]Advanced HTTP options:[/cyan]
  dotdotpwn -m http -h example.com --method POST --bisection --extra-files --delay 1.0
  dotdotpwn --module http --host example.com --http-method PUT --binary-search --break-on-first

[bold green]🔗 HTTP-URL MODULE EXAMPLES:[/bold green]
[cyan]URL-based fuzzing:[/cyan]
  dotdotpwn -m http-url --url "http://example.com/test.php?file=TRAVERSAL" --pattern "root:"
  dotdotpwn --module http-url -u "https://app.com/include.php?page=TRAVERSAL" -k "<!DOCTYPE"

[cyan]Advanced URL fuzzing:[/cyan]
  dotdotpwn -m http-url -u "http://site.com/download.php?file=TRAVERSAL" --os-detection --depth 12
  dotdotpwn --module http-url --target-url "https://cms.com/load.php?template=TRAVERSAL" --detect-os

[bold green]📁 FTP MODULE EXAMPLES:[/bold green]
[cyan]Anonymous FTP:[/cyan]
  dotdotpwn --module ftp --host ftp.example.com --file /etc/passwd --pattern "root:"
  dotdotpwn -m ftp -h 192.168.1.100 --target-file /etc/shadow --break-on-first

[cyan]Authenticated FTP:[/cyan]
  dotdotpwn -m ftp -h ftp.company.com --username user --password pass --file boot.ini
  dotdotpwn --module ftp --host 10.0.0.1 --user admin --pass secret123 --os-type windows

[bold green]📡 TFTP MODULE EXAMPLES:[/bold green]
[cyan]Basic TFTP scanning:[/cyan]
  dotdotpwn --module tftp --host 192.168.1.1 --file /etc/passwd --pattern "root:"
  dotdotpwn -m tftp -h tftp.server.com --target-file boot.ini --keyword "Windows"

[bold green]🔧 PAYLOAD MODULE EXAMPLES:[/bold green]
[cyan]Custom protocol fuzzing:[/cyan]
  dotdotpwn --module payload --host example.com --port 21 --payload-file ftp.txt --pattern "220"
  dotdotpwn -m payload -h secure.com --port 443 --ssl --payload custom.txt --keyword "root:"

[bold green]📄 STDOUT MODULE EXAMPLES:[/bold green]
[cyan]Generate traversal patterns:[/cyan]
  dotdotpwn --module stdout --depth 8 --os-type unix --file /etc/passwd
  dotdotpwn -m stdout --max-depth 6 --operating-system windows --target-file boot.ini --extension .bak

[bold green]⚡ ADVANCED USAGE EXAMPLES:[/bold green]
[cyan]Comprehensive scanning:[/cyan]
  dotdotpwn -m http -h example.com --os-detection --service-detection --extra-files --bisection
  dotdotpwn --module http --host target.com --detect-os --banner-grab --include-extras --binary-search

[cyan]Performance tuning:[/cyan]
  dotdotpwn -m http -h example.com --delay 0.1 --continue-on-error --quiet --max-depth 15
  dotdotpwn --module http --host fast.com --time-delay 2.0 --continue --silent --depth 20

[cyan]Report generation:[/cyan]
  dotdotpwn -m http -h example.com --report results.json --format json --quiet
  dotdotpwn --module http --host target.com --output report.html --report-format html

[bold yellow]💡 PARAMETER ALTERNATIVES:[/bold yellow]
You can use either short (-h) or long (--host, --hostname) parameter names:
  -h, --host, --hostname        → Target hostname
  -m, --module                  → Fuzzing module  
  -f, --file, --filename        → Target file
  -k, --pattern, --keyword      → Match pattern
  -d, --depth, --max-depth      → Traversal depth
  -o, --os-type, --operating-system → OS type
  -r, --report, --output        → Report file
  -t, --delay, --time-delay     → Request delay
  -b, --break, --break-on-first → Stop on first vuln
  -q, --quiet, --silent         → Quiet mode

[bold red]⚠️  SECURITY NOTICE:[/bold red]
This tool is for authorized security testing only. Always ensure you have proper 
authorization before testing any systems. Use responsibly!
"""
    console.print(examples_text)


@app.command("help-modules")  
def show_module_help():
    """🧩 Detailed information about each fuzzing module"""
    modules_text = """
[bold blue]🧩 DotDotPwn - Fuzzing Modules Detailed Guide[/bold blue]

[bold green]🌐 HTTP MODULE:[/bold green]
[bold]Purpose:[/bold] Tests web applications for directory traversal vulnerabilities via HTTP/HTTPS
[bold]How it works:[/bold] Sends HTTP requests with traversal payloads and analyzes responses
[bold]Required parameters:[/bold] --host, --pattern (recommended)
[bold]Optional parameters:[/bold] --port, --ssl, --method, --os-detection
[bold]Use cases:[/bold]
  • Web application security testing
  • CMS vulnerability assessment  
  • API endpoint traversal testing
[bold]Example targets:[/bold] Apache, Nginx, IIS, Tomcat web servers

[bold green]🔗 HTTP-URL MODULE:[/bold green]
[bold]Purpose:[/bold] Fuzzes specific URLs with TRAVERSAL placeholder for targeted testing
[bold]How it works:[/bold] Replaces TRAVERSAL placeholder with payloads in provided URL
[bold]Required parameters:[/bold] --url (with TRAVERSAL), --pattern
[bold]Optional parameters:[/bold] --depth, --os-detection, --delay
[bold]Use cases:[/bold]
  • Testing specific vulnerable parameters
  • File inclusion vulnerability testing
  • Template injection testing
[bold]URL format:[/bold] http://example.com/page.php?file=TRAVERSAL

[bold green]📁 FTP MODULE:[/bold green]
[bold]Purpose:[/bold] Tests FTP servers for directory traversal via file operations
[bold]How it works:[/bold] Connects via FTP and attempts file retrieval with traversal paths
[bold]Required parameters:[/bold] --host
[bold]Optional parameters:[/bold] --username, --password, --port
[bold]Use cases:[/bold]
  • FTP server security assessment
  • File server penetration testing
  • Legacy system vulnerability testing
[bold]Default credentials:[/bold] anonymous / dot@dot.pwn

[bold green]📡 TFTP MODULE:[/bold green]
[bold]Purpose:[/bold] Tests TFTP servers for directory traversal vulnerabilities
[bold]How it works:[/bold] Sends UDP TFTP requests to retrieve files with traversal paths
[bold]Required parameters:[/bold] --host
[bold]Optional parameters:[/bold] --port (default: 69), --pattern
[bold]Use cases:[/bold]
  • Network device testing (routers, switches)
  • Embedded system assessment
  • Legacy TFTP service testing
[bold]Protocol:[/bold] UDP-based, connectionless

[bold green]🔧 PAYLOAD MODULE:[/bold green]
[bold]Purpose:[/bold] Custom protocol fuzzing with user-defined payload templates
[bold]How it works:[/bold] Sends custom payloads with TRAVERSAL placeholder replacement
[bold]Required parameters:[/bold] --host, --port, --payload-file
[bold]Optional parameters:[/bold] --ssl, --pattern, --delay
[bold]Use cases:[/bold]
  • Custom protocol testing
  • Proprietary application assessment
  • Binary protocol fuzzing
[bold]Payload format:[/bold] Text file with TRAVERSAL placeholder

[bold green]📄 STDOUT MODULE:[/bold green]
[bold]Purpose:[/bold] Generates traversal patterns for use with other tools
[bold]How it works:[/bold] Outputs traversal strings without network communication
[bold]Required parameters:[/bold] None (generates generic patterns)
[bold]Optional parameters:[/bold] --depth, --os-type, --file, --extension
[bold]Use cases:[/bold]
  • Integration with custom scripts
  • Manual testing assistance
  • Pattern generation for other fuzzers
[bold]Output:[/bold] Text list of traversal patterns

[bold yellow]🔍 PATTERN MATCHING:[/bold yellow]
Patterns help identify successful traversal attempts:
  • "root:" - Unix /etc/passwd file
  • "Administrator" - Windows user accounts
  • "Windows" - Windows system files  
  • "<!DOCTYPE" - HTML documents
  • "[fontpath]" - Unix configuration files

[bold yellow]🎯 OS DETECTION:[/bold yellow]
Intelligent fuzzing based on detected operating system:
  • [bold]Windows:[/bold] Targets boot.ini, win.ini, hosts file
  • [bold]Unix/Linux:[/bold] Targets /etc/passwd, /etc/issue
  • [bold]Generic:[/bold] Tests both Windows and Unix files

[bold yellow]⚙️ ADVANCED FEATURES:[/bold yellow]
  • [bold]Bisection Algorithm:[/bold] Binary search to find exact vulnerability depth
  • [bold]SSL/TLS Support:[/bold] Encrypted communication testing
  • [bold]Multiple Encodings:[/bold] 24 dot representations + 29 slash encodings
  • [bold]Smart Delays:[/bold] Rate limiting to avoid detection
  • [bold]Banner Grabbing:[/bold] Service version detection
"""
    console.print(modules_text)


def print_banner():
    """Print the DotDotPwn banner"""
    banner = """
[bold blue]#################################################################################
#                                                                               #
#  CubilFelino                                                       Chatsubo   #
#  Security Research Lab              and            [(in)Security Dark] Labs   #
#  chr1x.sectester.net                             chatsubo-labs.blogspot.com   #
#                                                                               #
#                               pr0udly present:                                #
#                                                                               #
#  ________            __  ________            __  __________                   #
#  \\______ \\    ____ _/  |_\\______ \\    ____ _/  |_\\______   \\__  _  __ ____    #
#   |    |  \\  /  _ \\\\   __\\|    |  \\  /  _ \\\\   __\\|     ___/\\ \\/ \\/ //    \\   #
#   |    `   \\(  <_> )|  |  |    `   \\(  <_> )|  |  |    |     \\     /|   |  \\  #
#  /_______  / \\____/ |__| /_______  / \\____/ |__|  |____|      \\/\\_/ |___|  /  #
#          \\/                      \\/                                      \\/   #
#                              - DotDotPwn v3.0.2 Python -                      #
#                         The Directory Traversal Fuzzer                        #
#                         https://github.com/dotdotpwn/dotdotpwn-python         #
#                                                                               #
#                            Python Implementation                              #
#################################################################################[/bold blue]
"""
    rprint(banner)


@app.command()
def main(
    # Core Options - Both short and long parameter names for better usability
    module: str = typer.Option(..., "-m", "--module", help="🎯 Fuzzing module [http | http-url | ftp | tftp | payload | stdout]"),
    host: Optional[str] = typer.Option(None, "-h", "--host", "--hostname", help="🌐 Target hostname or IP address"),
    
    # Detection & Intelligence Options
    os_detection: bool = typer.Option(False, "-O", "--os-detection", "--detect-os", help="🔍 Enable OS detection for intelligent fuzzing (requires nmap)"),
    os_type: Optional[str] = typer.Option(None, "-o", "--os-type", "--operating-system", help="💻 Manual OS type specification [windows | unix | generic]"),
    service_detection: bool = typer.Option(False, "-s", "--service-detection", "--banner-grab", help="🔎 Service version detection and banner grabbing"),
    
    # Traversal Configuration
    depth: int = typer.Option(6, "-d", "--depth", "--max-depth", help="📏 Maximum depth of directory traversals (default: 6)"),
    filename: Optional[str] = typer.Option(None, "-f", "--file", "--filename", "--target-file", help="📄 Specific target file (e.g., /etc/passwd, boot.ini)"),
    extra_files: bool = typer.Option(False, "-E", "--extra-files", "--include-extras", help="📁 Include extra common files (web.config, httpd.conf, etc.)"),
    extension: Optional[str] = typer.Option(None, "-e", "--extension", "--file-extension", help="📎 File extension to append to each payload"),
    
    # Network & Protocol Options
    ssl: bool = typer.Option(False, "-S", "--ssl", "--https", "--tls", help="🔒 Use SSL/TLS encryption (HTTPS/FTPS)"),
    port: Optional[int] = typer.Option(None, "-x", "--port", help="🔌 Target port number"),
    url: Optional[str] = typer.Option(None, "-u", "--url", "--target-url", help="🌍 Target URL with TRAVERSAL placeholder"),
    method: str = typer.Option("GET", "-M", "--method", "--http-method", help="📤 HTTP request method [GET | POST | HEAD | COPY | MOVE]"),
    
    # Pattern Matching & Detection
    pattern: Optional[str] = typer.Option(None, "-k", "--pattern", "--keyword", "--match-pattern", help="🎯 Text pattern to detect vulnerability (e.g., 'root:', 'Administrator')"),
    
    # Authentication
    username: str = typer.Option("anonymous", "-U", "--username", "--user", help="👤 Authentication username (default: anonymous)"),
    password: str = typer.Option("dot@dot.pwn", "-P", "--password", "--pass", help="🔑 Authentication password (default: dot@dot.pwn)"),
    
    # Advanced Options
    payload_file: Optional[str] = typer.Option(None, "-p", "--payload", "--payload-file", help="📋 Custom payload file with TRAVERSAL placeholder"),
    bisection: bool = typer.Option(False, "-X", "--bisection", "--binary-search", help="🔍 Use bisection algorithm to find exact vulnerability depth"),
    time_delay: float = typer.Option(0.3, "-t", "--delay", "--time-delay", help="⏱️  Delay between requests in seconds (default: 0.3)"),
    
    # Output & Reporting
    report_file: Optional[str] = typer.Option(None, "-r", "--report", "--report-file", "--output", help="📊 Output report filename"),
    report_format: str = typer.Option("text", "--report-format", "--format", help="📄 Report format [text | json | csv | xml | html]"),
    quiet: bool = typer.Option(False, "-q", "--quiet", "--silent", help="🔇 Quiet mode with minimal output"),
    
    # Behavior Control
    break_on_first: bool = typer.Option(False, "-b", "--break", "--break-on-first", "--stop-on-first", help="🛑 Stop scanning after finding first vulnerability"),
    continue_on_error: bool = typer.Option(False, "-C", "--continue", "--continue-on-error", help="⚡ Continue scanning even if connection errors occur"),
):
    """
    🚀 DotDotPwn - The Directory Traversal Fuzzer (Python Implementation)
    
    A comprehensive directory traversal vulnerability scanner with multiple protocol support
    and intelligent fuzzing capabilities.
    
    📚 EXAMPLES:
    
    🌐 HTTP Module:
      dotdotpwn --module http --host 192.168.1.1 --port 8080 --file /etc/hosts --pattern "localhost" --depth 8
      dotdotpwn -m http -h example.com --ssl --file /etc/passwd --pattern "root:" --os-detection
    
    🔗 HTTP URL Module:
      dotdotpwn --module http-url --url "http://192.168.1.1/test.php?file=TRAVERSAL" --pattern "root:" --detect-os
      dotdotpwn -m http-url -u "https://example.com/include.php?page=TRAVERSAL" -k "<!DOCTYPE" -d 10
    
    📁 FTP Module:
      dotdotpwn --module ftp --host 192.168.1.1 --file /etc/passwd --pattern "root:" --break-on-first
      dotdotpwn -m ftp -h 192.168.1.1 --username testuser --password testpass --file /etc/shadow -k "root:"
    
    📡 TFTP Module:
      dotdotpwn --module tftp --host 192.168.1.1 --file /etc/passwd --pattern "root:" --depth 8
      dotdotpwn -m tftp -h example.com -f boot.ini -k "Windows" -d 6
    
    🔧 Payload Module:
      dotdotpwn --module payload --host 192.168.1.1 --port 21 --payload-file ftp_payload.txt --pattern "root:"
      dotdotpwn -m payload -h example.com -x 443 --ssl --payload custom.txt -k "sensitive"
    
    📄 STDOUT Module (Generate patterns only):
      dotdotpwn --module stdout --depth 8 --os-type unix --file /etc/passwd
      dotdotpwn -m stdout -d 6 --operating-system windows --target-file boot.ini --file-extension .bak
    
    🔍 Advanced Options:
      dotdotpwn -m http -h example.com --bisection --os-detection --service-detection --extra-files
      dotdotpwn -m http -h example.com --delay 1.0 --continue-on-error --report results.json --format json
    """
    
    try:
        # Print banner unless in quiet mode
        if not quiet:
            print_banner()
            
        # Enhanced parameter validation with detailed error messages
        validation_errors = []
        
        # Module validation
        valid_modules = ["http", "http-url", "ftp", "tftp", "payload", "stdout"]
        if module not in valid_modules:
            validation_errors.append(f"❌ Invalid module '{module}'. Valid options: {', '.join(valid_modules)}")
        
        # Module-specific parameter validation
        if module != "stdout" and module != "http-url" and not host:
            validation_errors.append("❌ Hostname is required for this module. Use -h/--host or --hostname")
        
        if module == "http-url":
            if not url:
                validation_errors.append("❌ URL with TRAVERSAL placeholder is required for http-url module. Use -u/--url")
            elif "TRAVERSAL" not in url:
                validation_errors.append("❌ URL must contain 'TRAVERSAL' placeholder for http-url module")
            if not pattern:
                validation_errors.append("❌ Pattern is required for http-url module. Use -k/--pattern")
        
        if module == "payload":
            if not payload_file:
                validation_errors.append("❌ Payload file is required for payload module. Use -p/--payload-file")
            elif not Path(payload_file).exists():
                validation_errors.append(f"❌ Payload file '{payload_file}' does not exist")
        
        # Range validation
        if depth < 1 or depth > 50:
            validation_errors.append("❌ Depth must be between 1 and 50")
        
        if time_delay < 0 or time_delay > 60:
            validation_errors.append("❌ Time delay must be between 0 and 60 seconds")
        
        if port and (port < 1 or port > 65535):
            validation_errors.append("❌ Port must be between 1 and 65535")
        
        # OS type validation
        valid_os_types = ["windows", "unix", "generic"]
        if os_type and os_type.lower() not in valid_os_types:
            validation_errors.append(f"❌ Invalid OS type '{os_type}'. Valid options: {', '.join(valid_os_types)}")
        
        # Report format validation
        valid_formats = ["text", "json", "csv", "xml", "html"]
        if report_format not in valid_formats:
            validation_errors.append(f"❌ Invalid report format '{report_format}'. Valid options: {', '.join(valid_formats)}")
        
        # HTTP method validation
        valid_methods = ["GET", "POST", "HEAD", "COPY", "MOVE", "PUT", "DELETE", "OPTIONS"]
        if method.upper() not in valid_methods:
            validation_errors.append(f"❌ Invalid HTTP method '{method}'. Valid options: {', '.join(valid_methods)}")
        
        # If validation errors exist, display them and exit
        if validation_errors:
            console.print("\n[red bold]🚨 Configuration Errors Found:[/red bold]")
            for error in validation_errors:
                console.print(f"  {error}")
            console.print("\n[yellow]💡 Use --help for detailed usage information[/yellow]")
            raise typer.Exit(1)
        
        # Success message for validation
        if not quiet:
            console.print("[green]✅ Configuration validated successfully[/green]")
            
    except Exception as e:
        console.print(f"[red]💥 Unexpected error during validation: {str(e)}[/red]")
        if not quiet:
            console.print("[yellow]💡 Run with --help for usage information[/yellow]")
        raise typer.Exit(1)

    try:
        # Handle stdout module (generate traversals only)
        if module == "stdout":
            handle_stdout_module(os_type, depth, filename, extra_files, extension, quiet)
            return

        # Set default ports with smart defaults
        if not port:
            port_defaults = {
                "http": 443 if ssl else 80,
                "ftp": 21,
                "tftp": 69,
                "payload": None
            }
            port = port_defaults.get(module)
            if port is None and module == "payload":
                console.print("[red]❌ Port is required for payload module. Use -x/--port[/red]")
                raise typer.Exit(1)

        # Initialize target info with enhanced details
        target_info = {
            "host": host,
            "port": port,
            "protocol": module if module != "http-url" else "http",
            "ssl_enabled": ssl,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Enhanced OS Detection with error handling
        if os_detection:
            if not quiet:
                console.print(f"🔍 [cyan]Detecting Operating System on {host}...[/cyan]")
            try:
                fingerprint = Fingerprint()
                os_detected = fingerprint.detect_os_nmap(host)
                if os_detected:
                    target_info["os_detected"] = os_detected
                    if not quiet:
                        console.print(f"✅ [green]Operating System detected: {os_detected}[/green]")
                    os_type = detect_os_type_from_string(os_detected)
                else:
                    if not quiet:
                        console.print("⚠️  [yellow]Could not detect Operating System[/yellow]")
            except Exception as e:
                if not quiet:
                    console.print(f"❌ [red]OS detection failed: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)

        # Enhanced Service Detection with error handling
        if service_detection:
            if not quiet:
                console.print(f"🔎 [cyan]Detecting service on {host}:{port}...[/cyan]")
            try:
                fingerprint = Fingerprint()
                banner = fingerprint.grab_banner(host, port, target_info["protocol"])
                if banner:
                    target_info["service_info"] = banner
                    if not quiet:
                        console.print(f"✅ [green]Service detected: {banner}[/green]")
                else:
                    if not quiet:
                        console.print("⚠️  [yellow]No service banner detected[/yellow]")
            except Exception as e:
                if not quiet:
                    console.print(f"❌ [red]Service detection failed: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)

        # Convert os_type string to enum
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(os_type.lower() if os_type else "generic", OSType.GENERIC)

        # Enhanced scan configuration
        scan_config = {
            "module": module,
            "os_type": os_type or "generic",
            "depth": depth,
            "specific_file": filename,
            "extra_files": extra_files,
            "extension": extension,
            "time_delay": time_delay,
            "break_on_first": break_on_first,
            "continue_on_error": continue_on_error,
            "bisection": bisection,
            "quiet": quiet,
            "method": method,
            "username": username,
            "ssl_enabled": ssl
        }

        # Print target information
        if not quiet:
            print_target_info(target_info, scan_config)

        # Run the appropriate scanner with enhanced error handling
        results = None
        
        if module == "http":
            if not quiet:
                console.print("🌐 [cyan]Starting HTTP directory traversal scan...[/cyan]")
            try:
                results = run_http_scan(
                    host, port, ssl, method, os_enum, depth, filename, extra_files,
                    extension, pattern, time_delay, break_on_first, continue_on_error,
                    bisection, quiet
                )
            except Exception as e:
                console.print(f"\n💥 [red]Scan error: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)
                results = None
        elif module == "http-url":
            if not quiet:
                console.print("🔗 [cyan]Starting HTTP URL fuzzing scan...[/cyan]")
            try:
                results = run_http_url_scan(
                    url, pattern, os_enum, depth, filename, extra_files, extension,
                    time_delay, break_on_first, continue_on_error, bisection, quiet
                )
            except Exception as e:
                console.print(f"\n💥 [red]Scan error: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)
                results = None
        elif module == "ftp":
            if not quiet:
                console.print("📁 [cyan]Starting FTP directory traversal scan...[/cyan]")
            try:
                results = run_ftp_scan(
                    host, port, username, password, os_enum, depth, filename,
                    extra_files, extension, time_delay, break_on_first,
                    continue_on_error, bisection, quiet
                )
            except Exception as e:
                console.print(f"\n💥 [red]Scan error: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)
                results = None
        elif module == "tftp":
            if not quiet:
                console.print("📡 [cyan]Starting TFTP directory traversal scan...[/cyan]")
            try:
                results = run_tftp_scan(
                    host, port, os_enum, depth, filename, extra_files, extension,
                    time_delay, break_on_first, continue_on_error, bisection, quiet
                )
            except Exception as e:
                console.print(f"\n💥 [red]Scan error: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)
                results = None
        elif module == "payload":
            if not quiet:
                console.print("🔧 [cyan]Starting custom payload scan...[/cyan]")
            try:
                payload_content = load_payload_file(payload_file)
                results = run_payload_scan(
                    host, port, payload_content, ssl, pattern, os_enum, depth,
                    filename, extra_files, extension, time_delay, break_on_first,
                    continue_on_error, bisection, quiet
                )
            except Exception as e:
                console.print(f"\n💥 [red]Scan error: {str(e)}[/red]")
                if not continue_on_error:
                    raise typer.Exit(1)
                results = None

        # Enhanced report generation with error handling
        if results and not quiet:
            console.print("📊 [cyan]Generating comprehensive report...[/cyan]")

        try:
            reporter = Reporter()
            
            # Generate filename if not provided
            if not report_file:
                timestamp = time.strftime("%m-%d-%Y_%H-%M")
                safe_host = host.replace(":", "_").replace("/", "_") if host else "scan"
                report_file = f"{safe_host}_{timestamp}.{report_format}"

            report_path = reporter.generate_report(
                results=results or {},
                target_info=target_info,
                scan_config=scan_config,
                format=report_format,
                filename=report_file
            )

            if not quiet:
                console.print(f"✅ [green]Report saved: {report_path}[/green]")
                
        except Exception as e:
            if not quiet:
                console.print(f"❌ [red]Failed to generate report: {str(e)}[/red]")
            if not continue_on_error:
                raise typer.Exit(1)

        # Print final summary
        if not quiet and results and isinstance(results, dict):
            console.print("\n📋 [bold blue]SCAN SUMMARY[/bold blue]")
            console.print(f"✅ [green]Scan completed successfully![/green]")
            console.print(f"🎯 Total vulnerabilities found: {results.get('vulnerabilities_found', 0)}")
            console.print(f"🔍 Total tests performed: {results.get('total_tests', 0)}")
            if results.get('false_positives_count', 0) > 0:
                console.print(f"⚠️  False positives detected: {results['false_positives_count']}")
            
            # Display found vulnerabilities
            if results.get('vulnerabilities'):
                console.print("\n🚨 [bold red]VULNERABILITIES FOUND:[/bold red]")
                for i, vuln in enumerate(results['vulnerabilities'][:5], 1):  # Show first 5
                    console.print(f"  {i}. [red]{vuln.get('traversal', 'N/A')}[/red]")
                if len(results['vulnerabilities']) > 5:
                    console.print(f"  ... and {len(results['vulnerabilities']) - 5} more")
        elif not quiet and results is None:
            console.print("\n⚠️  [yellow]Scan completed with errors - no results generated[/yellow]")

    except KeyboardInterrupt:
        console.print("\n🛑 [yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"\n💥 [red]Unexpected error: {str(e)}[/red]")
        if not quiet:
            console.print("[yellow]💡 Use --help for usage information or --continue-on-error to ignore errors[/yellow]")
        raise typer.Exit(1)


def handle_stdout_module(os_type, depth, filename, extra_files, extension, quiet):
    """Handle stdout module - generate traversals only"""
    generate_traversal_list(
        os_type=os_type or "generic",
        depth=depth,
        specific_file=filename,
        extra_files=extra_files,
        extension=extension
    )


def print_target_info(target_info, scan_config):
    """Print target information in a formatted table"""
    console.print("\\n[blue][========== TARGET INFORMATION ==========][/blue]")
    console.print(f"[+] Hostname: {target_info['host']}")
    console.print(f"[+] Protocol: {target_info['protocol']}")
    console.print(f"[+] Port: {target_info['port']}")
    
    if target_info.get('os_detected'):
        console.print(f"[+] Operating System: {target_info['os_detected']}")
    
    if target_info.get('service_info'):
        console.print(f"[+] Service: {target_info['service_info']}")

    console.print("\\n[blue][=========== SCAN CONFIGURATION ===========][/blue]")
    console.print(f"[+] Module: {scan_config['module']}")
    console.print(f"[+] OS Type: {scan_config['os_type']}")
    console.print(f"[+] Depth: {scan_config['depth']}")
    console.print(f"[+] Time delay: {scan_config['time_delay']} seconds")


def run_http_scan(host, port, ssl, method, os_enum, depth, filename, extra_files,
                  extension, pattern, time_delay, break_on_first, continue_on_error,
                  bisection, quiet):
    """Run HTTP directory traversal scan"""
    fuzzer = HTTPFuzzer(
        host=host,
        port=port,
        ssl=ssl,
        method=method,
        quiet=quiet
    )
    
    return asyncio.run(fuzzer.generate_and_fuzz(
        os_type=os_enum,
        depth=depth,
        specific_file=filename,
        extra_files=extra_files,
        extension=extension,
        pattern=pattern,
        time_delay=time_delay,
        break_on_first=break_on_first,
        continue_on_error=continue_on_error,
        bisection=bisection
    ))


def run_http_url_scan(url, pattern, os_enum, depth, filename, extra_files,
                      extension, time_delay, break_on_first, continue_on_error,
                      bisection, quiet):
    """Run HTTP URL directory traversal scan"""
    fuzzer = HTTPURLFuzzer(base_url=url, quiet=quiet)
    
    return asyncio.run(fuzzer.generate_and_fuzz(
        pattern=pattern,
        os_type=os_enum,
        depth=depth,
        specific_file=filename,
        extra_files=extra_files,
        extension=extension,
        time_delay=time_delay,
        break_on_first=break_on_first,
        continue_on_error=continue_on_error,
        bisection=bisection
    ))


def run_ftp_scan(host, port, username, password, os_enum, depth, filename,
                 extra_files, extension, time_delay, break_on_first,
                 continue_on_error, bisection, quiet):
    """Run FTP directory traversal scan"""
    fuzzer = FTPFuzzer(
        host=host,
        port=port,
        username=username,
        password=password,
        quiet=quiet
    )
    
    return fuzzer.generate_and_fuzz(
        os_type=os_enum,
        depth=depth,
        specific_file=filename,
        extra_files=extra_files,
        extension=extension,
        time_delay=time_delay,
        break_on_first=break_on_first,
        continue_on_error=continue_on_error,
        bisection=bisection
    )


def run_tftp_scan(host, port, os_enum, depth, filename, extra_files, extension,
                  time_delay, break_on_first, continue_on_error, bisection, quiet):
    """Run TFTP directory traversal scan"""
    fuzzer = TFTPFuzzer(host=host, port=port, quiet=quiet)
    
    return fuzzer.generate_and_fuzz(
        os_type=os_enum,
        depth=depth,
        specific_file=filename,
        extra_files=extra_files,
        extension=extension,
        time_delay=time_delay,
        break_on_first=break_on_first,
        continue_on_error=continue_on_error,
        bisection=bisection
    )


def run_payload_scan(host, port, payload_content, ssl, pattern, os_enum, depth,
                     filename, extra_files, extension, time_delay, break_on_first,
                     continue_on_error, bisection, quiet):
    """Run payload-based directory traversal scan"""
    fuzzer = PayloadFuzzer(
        host=host,
        port=port,
        payload_template=payload_content,
        ssl_enabled=ssl,
        quiet=quiet
    )
    
    return fuzzer.generate_and_fuzz(
        os_type=os_enum,
        depth=depth,
        specific_file=filename,
        extra_files=extra_files,
        extension=extension,
        pattern=pattern,
        time_delay=time_delay,
        break_on_first=break_on_first,
        continue_on_error=continue_on_error,
        bisection=bisection
    )


def load_payload_file(payload_file: str) -> str:
    """Load payload content from file"""
    try:
        with open(payload_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if "TRAVERSAL" not in content:
            console.print("[red][-] No 'TRAVERSAL' keyword found in payload file[/red]")
            sys.exit(1)
            
        return content
        
    except FileNotFoundError:
        console.print(f"[red][-] Payload file not found: {payload_file}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red][-] Error reading payload file: {e}[/red]")
        sys.exit(1)


def detect_os_type_from_string(os_string: str) -> str:
    """Detect OS type from nmap OS detection string"""
    os_lower = os_string.lower()
    
    if any(keyword in os_lower for keyword in ['windows', 'microsoft', 'win']):
        return "windows"
    elif any(keyword in os_lower for keyword in ['linux', 'unix', 'bsd', 'solaris', 'aix']):
        return "unix"
    else:
        return "generic"


@app.command("api")
def start_api(
    host: str = typer.Option("0.0.0.0", help="Host to bind API server"),
    port: int = typer.Option(8000, help="Port to bind API server"),
    reload: bool = typer.Option(False, help="Enable auto-reload for development")
):
    """Start the DotDotPwn API server"""
    from .api.main import start_server
    
    console.print(f"[+] Starting DotDotPwn API server on {host}:{port}")
    if reload:
        console.print("[+] Development mode: auto-reload enabled")
    
    start_server(host=host, port=port, reload=reload)


@app.command("generate")
def generate_traversals_cmd(
    os_type: str = typer.Option("generic", help="OS type: windows, unix, generic"),
    depth: int = typer.Option(6, help="Traversal depth"),
    specific_file: Optional[str] = typer.Option(None, help="Specific file to target"),
    extra_files: bool = typer.Option(False, help="Include extra files"),
    extension: Optional[str] = typer.Option(None, help="File extension to append"),
    output_file: Optional[str] = typer.Option(None, help="Save to file")
):
    """Generate traversal patterns"""
    traversals = generate_traversal_list(
        os_type=os_type,
        depth=depth,
        specific_file=specific_file,
        extra_files=extra_files,
        extension=extension,
        output_file=output_file
    )
    
    if not output_file:
        console.print(f"\\n[+] Generated {len(traversals)} traversal patterns")


if __name__ == "__main__":
    app()