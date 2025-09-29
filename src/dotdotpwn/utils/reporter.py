"""
Reporter Module

Handles report generation and output formatting for DotDotPwn results.

Python implementation inspired by the original DotDotPwn reporting functionality
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import sys


class Reporter:
    """
    Report generator for DotDotPwn fuzzing results
    
    Supports multiple output formats: text, JSON, CSV, XML, HTML
    """

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize Reporter
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_report(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any],
        format: str = "text",
        filename: Optional[str] = None
    ) -> str:
        """
        Generate a comprehensive report
        
        Args:
            results: Fuzzing results
            target_info: Information about the target
            scan_config: Scan configuration details
            format: Output format (text, json, csv, xml, html)
            filename: Custom filename (auto-generated if None)
            
        Returns:
            Path to generated report file
        """
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = target_info.get('host', 'unknown')
            filename = f"{host}_{timestamp}.{format}"

        report_path = self.output_dir / filename

        # Generate report based on format
        if format.lower() == "json":
            self._generate_json_report(results, target_info, scan_config, report_path)
        elif format.lower() == "csv":
            self._generate_csv_report(results, target_info, scan_config, report_path)
        elif format.lower() == "xml":
            self._generate_xml_report(results, target_info, scan_config, report_path)
        elif format.lower() == "html":
            self._generate_html_report(results, target_info, scan_config, report_path)
        else:  # Default to text
            self._generate_text_report(results, target_info, scan_config, report_path)

        return str(report_path)

    def _generate_text_report(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any],
        report_path: Path
    ):
        """Generate text format report"""
        with open(report_path, 'w', encoding='utf-8') as f:
            # Header
            f.write(self._get_banner())
            f.write("\\n" + "="*80 + "\\n")
            f.write("DOTDOTPWN SCAN REPORT\\n")
            f.write("="*80 + "\\n\\n")

            # Timestamp
            f.write(f"Date and Time: {datetime.now().strftime('%m-%d-%Y %H:%M:%S')}\\n\\n")

            # Target Information
            f.write("[========== TARGET INFORMATION ==========]\\n")
            f.write(f"Hostname: {target_info.get('host', 'N/A')}\\n")
            f.write(f"Protocol: {target_info.get('protocol', 'N/A')}\\n")
            f.write(f"Port: {target_info.get('port', 'N/A')}\\n")
            
            if target_info.get('os_detected'):
                f.write(f"Operating System: {target_info['os_detected']}\\n")
            
            if target_info.get('service_info'):
                f.write(f"Service: {target_info['service_info']}\\n")
            
            f.write("\\n")

            # Scan Configuration
            f.write("[========= SCAN CONFIGURATION =========]\\n")
            f.write(f"Module: {scan_config.get('module', 'N/A')}\\n")
            f.write(f"Depth: {scan_config.get('depth', 'N/A')}\\n")
            f.write(f"OS Type: {scan_config.get('os_type', 'N/A')}\\n")
            
            if scan_config.get('specific_file'):
                f.write(f"Target File: {scan_config['specific_file']}\\n")
            
            if scan_config.get('pattern'):
                f.write(f"Pattern: {scan_config['pattern']}\\n")
            
            f.write(f"Time Delay: {scan_config.get('time_delay', 0.3)} seconds\\n")
            f.write(f"Total Tests: {results.get('total_tests', 0)}\\n")
            f.write("\\n")

            # Results Summary
            f.write("[=========== RESULTS SUMMARY ===========]\\n")
            f.write(f"Vulnerabilities Found: {results.get('vulnerabilities_found', 0)}\\n")
            f.write(f"False Positives: {results.get('false_positives_count', 0)}\\n")
            f.write(f"Errors: {len(results.get('errors', []))}\\n")
            
            if 'scan_duration' in results:
                f.write(f"Scan Duration: {results['scan_duration']:.2f} seconds\\n")
            
            f.write("\\n")

            # Vulnerabilities Details
            if results.get('vulnerabilities'):
                f.write("[========= VULNERABILITIES FOUND =========]\\n")
                for i, vuln in enumerate(results['vulnerabilities'], 1):
                    f.write(f"\\n[{i}] Vulnerability Details:\\n")
                    f.write(f"    Traversal: {vuln.get('traversal', 'N/A')}\\n")
                    
                    if 'url' in vuln:
                        f.write(f"    URL: {vuln['url']}\\n")
                    elif 'payload' in vuln:
                        f.write(f"    Payload: {vuln['payload'][:200]}...\\n")
                    elif 'command' in vuln:
                        f.write(f"    Command: {vuln['command']}\\n")
                    
                    if 'status_code' in vuln:
                        f.write(f"    Status Code: {vuln['status_code']}\\n")
                    
                    if 'response_time' in vuln:
                        f.write(f"    Response Time: {vuln['response_time']:.3f} seconds\\n")
                    
                    if 'matched_content' in vuln and vuln['matched_content']:
                        f.write(f"    Matched Content: {vuln['matched_content'][:100]}...\\n")
                
                f.write("\\n")

            # Errors (if any)
            if results.get('errors'):
                f.write("[============== ERRORS ================]\\n")
                for i, error in enumerate(results['errors'], 1):
                    f.write(f"\\n[{i}] Error Details:\\n")
                    f.write(f"    Traversal: {error.get('traversal', 'N/A')}\\n")
                    f.write(f"    Error: {error.get('error', 'N/A')}\\n")
                f.write("\\n")

            # Footer
            f.write("="*80 + "\\n")
            f.write("Report generated by DotDotPwn Python v3.0.2\\n")
            f.write("="*80 + "\\n")

    def _generate_json_report(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any],
        report_path: Path
    ):
        """Generate JSON format report"""
        report_data = {
            "metadata": {
                "tool": "DotDotPwn Python",
                "version": "3.0.2",
                "timestamp": datetime.now().isoformat(),
                "report_format": "json"
            },
            "target_info": target_info,
            "scan_config": scan_config,
            "results": results
        }

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

    def _generate_csv_report(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any],
        report_path: Path
    ):
        """Generate CSV format report"""
        with open(report_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Type', 'Traversal', 'URL/Payload', 'Status', 'Response_Time',
                'Error', 'Matched_Content'
            ])

            # Vulnerabilities
            for vuln in results.get('vulnerabilities', []):
                writer.writerow([
                    'Vulnerability',
                    vuln.get('traversal', ''),
                    vuln.get('url', vuln.get('payload', vuln.get('command', ''))),
                    vuln.get('status_code', ''),
                    vuln.get('response_time', ''),
                    '',
                    vuln.get('matched_content', '')[:100]
                ])

            # False Positives
            for fp in results.get('false_positives', []):
                writer.writerow([
                    'False Positive',
                    fp.get('traversal', ''),
                    fp.get('url', fp.get('payload', fp.get('command', ''))),
                    fp.get('status_code', ''),
                    fp.get('response_time', ''),
                    '',
                    ''
                ])

            # Errors
            for error in results.get('errors', []):
                writer.writerow([
                    'Error',
                    error.get('traversal', ''),
                    error.get('url', error.get('payload', error.get('command', ''))),
                    '',
                    '',
                    error.get('error', ''),
                    ''
                ])

    def _generate_xml_report(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any],
        report_path: Path
    ):
        """Generate XML format report"""
        root = ET.Element('dotdotpwn_report')
        
        # Metadata
        metadata = ET.SubElement(root, 'metadata')
        ET.SubElement(metadata, 'tool').text = 'DotDotPwn Python'
        ET.SubElement(metadata, 'version').text = '3.0.2'
        ET.SubElement(metadata, 'timestamp').text = datetime.now().isoformat()

        # Target Info
        target_elem = ET.SubElement(root, 'target_info')
        for key, value in target_info.items():
            ET.SubElement(target_elem, key).text = str(value)

        # Scan Config
        config_elem = ET.SubElement(root, 'scan_config')
        for key, value in scan_config.items():
            ET.SubElement(config_elem, key).text = str(value)

        # Results
        results_elem = ET.SubElement(root, 'results')
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(results_elem, 'vulnerabilities')
        for vuln in results.get('vulnerabilities', []):
            vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
            for key, value in vuln.items():
                ET.SubElement(vuln_elem, key).text = str(value)

        # Errors
        errors_elem = ET.SubElement(results_elem, 'errors')
        for error in results.get('errors', []):
            error_elem = ET.SubElement(errors_elem, 'error')
            for key, value in error.items():
                ET.SubElement(error_elem, key).text = str(value)

        # Write to file
        tree = ET.ElementTree(root)
        tree.write(report_path, encoding='utf-8', xml_declaration=True)

    def _generate_html_report(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any],
        report_path: Path
    ):
        """Generate HTML format report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DotDotPwn Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .vulnerability {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
        .error {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
        .info {{ background-color: #e3f2fd; border-left: 4px solid #2196f3; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DotDotPwn Scan Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="section info">
        <h2>Target Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Hostname</td><td>{target_info.get('host', 'N/A')}</td></tr>
            <tr><td>Protocol</td><td>{target_info.get('protocol', 'N/A')}</td></tr>
            <tr><td>Port</td><td>{target_info.get('port', 'N/A')}</td></tr>
            <tr><td>OS Detected</td><td>{target_info.get('os_detected', 'N/A')}</td></tr>
        </table>
    </div>

    <div class="section info">
        <h2>Scan Configuration</h2>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>Module</td><td>{scan_config.get('module', 'N/A')}</td></tr>
            <tr><td>Depth</td><td>{scan_config.get('depth', 'N/A')}</td></tr>
            <tr><td>Total Tests</td><td>{results.get('total_tests', 0)}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Results Summary</h2>
        <table>
            <tr><th>Metric</th><th>Count</th></tr>
            <tr><td>Vulnerabilities Found</td><td style="color: red; font-weight: bold;">{results.get('vulnerabilities_found', 0)}</td></tr>
            <tr><td>False Positives</td><td>{results.get('false_positives_count', 0)}</td></tr>
            <tr><td>Errors</td><td>{len(results.get('errors', []))}</td></tr>
        </table>
    </div>
"""

        # Add vulnerabilities section
        if results.get('vulnerabilities'):
            html_content += """
    <div class="section vulnerability">
        <h2>Vulnerabilities Found</h2>
        <table>
            <tr><th>#</th><th>Traversal</th><th>Target</th><th>Details</th></tr>
"""
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                target = vuln.get('url', vuln.get('payload', vuln.get('command', 'N/A')))
                details = f"Status: {vuln.get('status_code', 'N/A')}<br>"
                if vuln.get('response_time'):
                    details += f"Time: {vuln['response_time']:.3f}s<br>"
                if vuln.get('matched_content'):
                    details += f"Match: {vuln['matched_content'][:50]}..."
                
                html_content += f"""
            <tr>
                <td>{i}</td>
                <td><code>{vuln.get('traversal', 'N/A')}</code></td>
                <td><code>{target[:100]}...</code></td>
                <td>{details}</td>
            </tr>
"""
            html_content += "        </table>\\n    </div>\\n"

        html_content += """
    <div class="section">
        <p><em>Report generated by DotDotPwn Python v3.0.2</em></p>
    </div>
</body>
</html>
"""

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _get_banner(self) -> str:
        """Get the DotDotPwn banner"""
        return r"""
#################################################################################
#                                                                               #
#  CubilFelino                                                       Chatsubo   #
#  Security Research Lab              and            [(in)Security Dark] Labs   #
#  chr1x.sectester.net                             chatsubo-labs.blogspot.com   #
#                                                                               #
#                               pr0udly present:                                #
#                                                                               #
#  ________            __  ________            __  __________                   #
#  \______ \    ____ _/  |_\______ \    ____ _/  |_\______   \__  _  __ ____    #
#   |    |  \  /  _ \\   __\|    |  \  /  _ \\   __\|     ___/\ \/ \/ //    \   #
#   |    `   \(  <_> )|  |  |    `   \(  <_> )|  |  |    |     \     /|   |  \  #
#  /_______  / \____/ |__| /_______  / \____/ |__|  |____|      \/\_/ |___|  /  #
#          \/                      \/                                      \/   #
#                              - DotDotPwn v3.0.2 Python -                      #
#                         The Directory Traversal Fuzzer                        #
#                         https://github.com/dotdotpwn/dotdotpwn-python         #
#                                                                               #
#                            Python Implementation                              #
#################################################################################
"""

    def print_to_stdout(
        self,
        results: Dict[str, Any],
        target_info: Dict[str, Any],
        scan_config: Dict[str, Any]
    ):
        """Print results to stdout in a formatted way"""
        
        # Print banner
        print(self._get_banner())
        
        # Target information
        print("\\n[========== TARGET INFORMATION ==========]")
        print(f"[+] Hostname: {target_info.get('host', 'N/A')}")
        print(f"[+] Protocol: {target_info.get('protocol', 'N/A')}")
        print(f"[+] Port: {target_info.get('port', 'N/A')}")
        
        if target_info.get('os_detected'):
            print(f"[+] Operating System detected: {target_info['os_detected']}")
        
        if target_info.get('service_info'):
            print(f"[+] Service detected: {target_info['service_info']}")

        # Scan summary
        print("\\n[=========== TESTING RESULTS ============]")
        print(f"[+] Total traversals tested: {results.get('total_tests', 0)}")
        print(f"[+] Vulnerabilities found: {results.get('vulnerabilities_found', 0)}")
        
        if results.get('false_positives_count', 0) > 0:
            print(f"[+] False positives detected: {results['false_positives_count']}")
        
        if results.get('scan_duration'):
            duration_minutes = results['scan_duration'] / 60
            print(f"[+] Scan completed in {duration_minutes:.2f} minutes ({results['scan_duration']:.2f} seconds)")

        # Show vulnerabilities
        if results.get('vulnerabilities'):
            print(f"\\n[+] {len(results['vulnerabilities'])} vulnerabilities found:")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"\\n[{i}] {vuln.get('traversal', 'N/A')}")
                if 'url' in vuln:
                    print(f"    URL: {vuln['url']}")
                elif 'payload' in vuln:
                    print(f"    Payload: {vuln['payload'][:100]}...")
                elif 'command' in vuln:
                    print(f"    Command: {vuln['command']}")


def generate_traversal_list(
    os_type: str = "generic",
    depth: int = 6,
    specific_file: Optional[str] = None,
    extra_files: bool = False,
    extension: Optional[str] = None,
    output_file: Optional[str] = None,
    include_absolute: bool = True,
    detection_method: str = "any"
) -> List[str]:
    """
    Generate and optionally save traversal list to file (STDOUT module equivalent)
    
    Args:
        os_type: Operating system type
        depth: Traversal depth
        specific_file: Specific file to target
        extra_files: Include extra files
        extension: File extension to append
        output_file: File to save traversal list
        include_absolute: Include direct absolute path injection patterns
        
    Returns:
        List of generated traversal strings
    """
    from ..core.traversal_engine import TraversalEngine, OSType, DetectionMethod
    
    # Convert string to OSType enum
    os_type_map = {
        'windows': OSType.WINDOWS,
        'unix': OSType.UNIX,
        'generic': OSType.GENERIC
    }
    
    os_enum = os_type_map.get(os_type.lower(), OSType.GENERIC)
    
    # Convert detection_method string to enum
    detection_method_map = {
        "simple": DetectionMethod.SIMPLE,
        "absolute_path": DetectionMethod.ABSOLUTE_PATH,
        "non_recursive": DetectionMethod.NON_RECURSIVE,
        "url_encoding": DetectionMethod.URL_ENCODING,
        "path_validation": DetectionMethod.PATH_VALIDATION,
        "null_byte": DetectionMethod.NULL_BYTE,
        "any": DetectionMethod.ANY
    }
    detection_method_enum = detection_method_map.get(detection_method.lower(), DetectionMethod.ANY)
    
    # Generate traversals
    engine = TraversalEngine(quiet=False)
    traversals = engine.generate_traversals(
        os_type=os_enum,
        depth=depth,
        specific_file=specific_file,
        extra_files=extra_files,
        extension=extension,
        include_absolute=include_absolute,
        detection_method=detection_method_enum
    )
    
    # Save to file if specified
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            for traversal in traversals:
                f.write(traversal + '\n')
        print(f"[+] Traversal list saved to: {output_file}")
    
    # Print to stdout
    for traversal in traversals:
        print(traversal)
    
    return traversals