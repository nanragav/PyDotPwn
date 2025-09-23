"""
STDOUT Module for DotDotPwn

This module handles output formatting and stdout functionality
equivalent to the STDOUT.pm module in the original Perl implementation.
"""

import sys
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID
from rich.text import Text
from rich import print as rprint
from enum import Enum
import time


class OutputMode(Enum):
    """Output modes for different display types"""
    NORMAL = "normal"
    QUIET = "quiet"
    VERBOSE = "verbose"
    DEBUG = "debug"


class STDOUTHandler:
    """
    Handles all stdout operations for DotDotPwn
    Provides formatted output, progress tracking, and result display
    """
    
    def __init__(self, mode: OutputMode = OutputMode.NORMAL, use_colors: bool = True):
        self.mode = mode
        self.use_colors = use_colors
        self.console = Console(color_system="auto" if use_colors else None)
        self.start_time = time.time()
        self.vulnerabilities_found = 0
        self.false_positives = 0
        self.total_tests = 0
        self.current_progress = None
        self.progress_task = None
        
    def print_banner(self):
        """Print the DotDotPwn banner"""
        if self.mode == OutputMode.QUIET:
            return
            
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
    
    def print_target_info(self, target_info: Dict[str, Any]):
        """Print target information"""
        if self.mode == OutputMode.QUIET:
            return
            
        self.console.print("\\n[blue][========== TARGET INFORMATION ==========][/blue]")
        
        for key, value in target_info.items():
            display_key = key.replace('_', ' ').title()
            self.console.print(f"[+] {display_key}: {value}")
    
    def print_scan_config(self, config: Dict[str, Any]):
        """Print scan configuration"""
        if self.mode == OutputMode.QUIET:
            return
            
        self.console.print("\\n[blue][=========== SCAN CONFIGURATION ===========][/blue]")
        
        for key, value in config.items():
            display_key = key.replace('_', ' ').title()
            self.console.print(f"[+] {display_key}: {value}")
    
    def start_progress(self, total: int, description: str = "Scanning"):
        """Start progress tracking"""
        if self.mode == OutputMode.QUIET:
            return
            
        self.total_tests = total
        self.current_progress = Progress()
        self.current_progress.start()
        self.progress_task = self.current_progress.add_task(description, total=total)
    
    def update_progress(self, advance: int = 1):
        """Update progress"""
        if self.current_progress and self.progress_task is not None:
            self.current_progress.update(self.progress_task, advance=advance)
    
    def stop_progress(self):
        """Stop progress tracking"""
        if self.current_progress:
            self.current_progress.stop()
            self.current_progress = None
            self.progress_task = None
    
    def print_vulnerability(self, result: Dict[str, Any]):
        """Print vulnerability found"""
        self.vulnerabilities_found += 1
        
        if self.mode == OutputMode.QUIET:
            # In quiet mode, only print the traversal that worked
            self.console.print(f"{result.get('traversal', '')}")
            return
        
        # Detailed vulnerability output
        self.console.print(f"\\n[bold red][VULNERABILITY FOUND #{self.vulnerabilities_found}][/bold red]")
        self.console.print(f"[+] Traversal: {result.get('traversal', 'N/A')}")
        self.console.print(f"[+] Pattern match: {result.get('pattern_match', 'N/A')}")
        
        if result.get('response_size'):
            self.console.print(f"[+] Response size: {result['response_size']} bytes")
        
        if result.get('status_code'):
            self.console.print(f"[+] Status code: {result['status_code']}")
        
        if result.get('depth'):
            self.console.print(f"[+] Depth: {result['depth']}")
        
        if result.get('response_excerpt'):
            self.console.print(f"[+] Response excerpt: {result['response_excerpt'][:200]}...")
    
    def print_false_positive(self, result: Dict[str, Any]):
        """Print false positive detection"""
        self.false_positives += 1
        
        if self.mode == OutputMode.DEBUG:
            self.console.print(f"[yellow][FALSE POSITIVE #{self.false_positives}][/yellow]")
            self.console.print(f"[+] Traversal: {result.get('traversal', 'N/A')}")
            self.console.print(f"[+] Reason: {result.get('reason', 'Unknown')}")
    
    def print_test_result(self, result: Dict[str, Any]):
        """Print individual test result"""
        if self.mode == OutputMode.VERBOSE or self.mode == OutputMode.DEBUG:
            status = result.get('status', 'unknown')
            traversal = result.get('traversal', 'N/A')
            
            if status == 'vulnerable':
                self.console.print(f"[green][+][/green] {traversal}")
            elif status == 'false_positive':
                self.console.print(f"[yellow][-][/yellow] {traversal} (false positive)")
            else:
                self.console.print(f"[red][-][/red] {traversal}")
    
    def print_error(self, message: str, error: Optional[Exception] = None):
        """Print error message"""
        self.console.print(f"[red][-] Error: {message}[/red]")
        
        if error and self.mode == OutputMode.DEBUG:
            self.console.print(f"[red][-] Exception: {str(error)}[/red]")
    
    def print_warning(self, message: str):
        """Print warning message"""
        if self.mode != OutputMode.QUIET:
            self.console.print(f"[yellow][!] Warning: {message}[/yellow]")
    
    def print_info(self, message: str):
        """Print info message"""
        if self.mode != OutputMode.QUIET:
            self.console.print(f"[blue][+] {message}[/blue]")
    
    def print_debug(self, message: str):
        """Print debug message"""
        if self.mode == OutputMode.DEBUG:
            self.console.print(f"[dim][DEBUG] {message}[/dim]")
    
    def print_summary(self, results: Dict[str, Any]):
        """Print scan summary"""
        if self.mode == OutputMode.QUIET and self.vulnerabilities_found == 0:
            return
        
        elapsed_time = time.time() - self.start_time
        
        # Create summary table
        table = Table(title="Scan Summary", show_header=True, header_style="bold blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Vulnerabilities Found", str(self.vulnerabilities_found))
        table.add_row("False Positives", str(self.false_positives))
        table.add_row("Total Tests", str(self.total_tests))
        table.add_row("Elapsed Time", f"{elapsed_time:.2f} seconds")
        
        success_rate = (self.vulnerabilities_found / self.total_tests * 100) if self.total_tests > 0 else 0
        table.add_row("Success Rate", f"{success_rate:.2f}%")
        
        self.console.print("\\n")
        self.console.print(table)
        
        # Additional summary information
        if self.mode != OutputMode.QUIET:
            self.console.print("\\n[blue][========== SCAN COMPLETED ==========][/blue]")
            
            if self.vulnerabilities_found > 0:
                self.console.print(f"[bold green][+] {self.vulnerabilities_found} vulnerabilities found![/bold green]")
            else:
                self.console.print("[red][-] No vulnerabilities found[/red]")
    
    def print_traversal_list(self, traversals: List[str]):
        """Print list of traversals (for stdout module)"""
        if self.mode == OutputMode.QUIET:
            # Just print the traversals
            for traversal in traversals:
                print(traversal)
        else:
            self.console.print(f"\\n[blue][+] Generated {len(traversals)} traversal patterns:[/blue]\\n")
            for i, traversal in enumerate(traversals, 1):
                self.console.print(f"{i:4d}: {traversal}")
    
    def print_bisection_result(self, depth: int, traversal: str):
        """Print bisection algorithm result"""
        if self.mode != OutputMode.QUIET:
            self.console.print(f"\\n[bold yellow][BISECTION ALGORITHM RESULT][/bold yellow]")
            self.console.print(f"[+] Exact vulnerability depth: {depth}")
            self.console.print(f"[+] Minimal traversal: {traversal}")
    
    def print_service_detection(self, service_info: str):
        """Print service detection result"""
        if self.mode != OutputMode.QUIET:
            self.console.print(f"[+] Service detection: {service_info}")
    
    def print_os_detection(self, os_info: str):
        """Print OS detection result"""
        if self.mode != OutputMode.QUIET:
            self.console.print(f"[+] Operating System: {os_info}")
    
    def flush(self):
        """Flush output"""
        sys.stdout.flush()
    
    def set_mode(self, mode: OutputMode):
        """Change output mode"""
        self.mode = mode
    
    def print_module_info(self, module: str, details: Dict[str, Any]):
        """Print module-specific information"""
        if self.mode == OutputMode.QUIET:
            return
            
        self.console.print(f"\\n[blue][========== {module.upper()} MODULE ==========][/blue]")
        
        for key, value in details.items():
            display_key = key.replace('_', ' ').title()
            self.console.print(f"[+] {display_key}: {value}")


# Global stdout handler instance
stdout_handler = None


def get_stdout_handler(mode: OutputMode = OutputMode.NORMAL, use_colors: bool = True) -> STDOUTHandler:
    """Get or create global stdout handler"""
    global stdout_handler
    
    if stdout_handler is None:
        stdout_handler = STDOUTHandler(mode, use_colors)
    
    return stdout_handler


def set_output_mode(mode: OutputMode):
    """Set global output mode"""
    handler = get_stdout_handler()
    handler.set_mode(mode)


# Convenience functions for common operations
def print_banner():
    """Print banner using global handler"""
    get_stdout_handler().print_banner()


def print_vulnerability(result: Dict[str, Any]):
    """Print vulnerability using global handler"""
    get_stdout_handler().print_vulnerability(result)


def print_error(message: str, error: Optional[Exception] = None):
    """Print error using global handler"""
    get_stdout_handler().print_error(message, error)


def print_info(message: str):
    """Print info using global handler"""
    get_stdout_handler().print_info(message)


def print_summary(results: Dict[str, Any]):
    """Print summary using global handler"""
    get_stdout_handler().print_summary(results)


def print_traversal_list(traversals: List[str]):
    """Print traversal list using global handler"""
    get_stdout_handler().print_traversal_list(traversals)