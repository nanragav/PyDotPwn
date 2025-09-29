---
layout: page
title: "GUI Guide"
permalink: /gui-guide/
---

# 🖥️ Complete GUI Guide

The PyDotPwn GUI provides a professional, user-friendly interface for directory traversal testing with real-time monitoring, advanced configuration options, and comprehensive reporting capabilities.

## 📋 Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Interface Layout](#interface-layout)
- [Configuration Guide](#configuration-guide)
- [Monitoring and Output](#monitoring-and-output)
- [Advanced Features](#advanced-features)
- [Report Management](#report-management)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Troubleshooting](#troubleshooting)

## 🌟 Overview

The DotDotPwn GUI is built with PyQt6 and provides:

### ✨ Key Features

- **🎨 Professional Interface**: Dark theme with modern styling
- **⚡ Real-time Monitoring**: Live scan output and system resource tracking
- **🧠 Smart Validation**: Context-aware field validation and guidance
- **📊 Visual Analytics**: CPU, memory, and performance graphs
- **💾 Comprehensive Reporting**: Multiple export formats with history tracking
- **🔧 Advanced Configuration**: Access to all CLI features through intuitive interface
- **🖱️ Intuitive Design**: Guided workflows with tooltips and help text

### 🎯 Use Cases

- **Interactive Security Testing**: Point-and-click vulnerability assessment
- **Educational Use**: Learning directory traversal concepts with visual feedback
- **Report Generation**: Professional documentation with visual charts
- **Team Collaboration**: Shareable configurations and standardized reporting

## 🚀 Getting Started

### Launch the GUI

```bash
# Method 1: Direct launch
python launch_gui.py

# Method 2: Shell script
./launch_gui.sh

# Method 3: From virtual environment
source .venv/bin/activate
python launch_gui.py
```

### First Launch

When you first open the GUI, you'll see:

1. **Welcome Screen**: Professional dark interface
2. **Configuration Panel**: Pre-configured with safe defaults
3. **Output Area**: Ready for scan results
4. **Status Bar**: Current system status

### Quick Start Workflow

1. **Select Module**: Choose from the dropdown (e.g., "http")
2. **Enter Target**: Specify hostname (e.g., "example.com")
3. **Set Pattern**: Enter success pattern (e.g., "root:")
4. **Click "Start Scan"**: Begin the security test
5. **Monitor Progress**: Watch real-time output and graphs
6. **Export Results**: Save findings in your preferred format

## 🎨 Interface Layout

The GUI is organized into three main areas with adaptive sizing:

### Left Panel - Configuration (50% width)

#### Basic Configuration Section

- **Module Selection**: Dropdown with all available fuzzing modules
- **OS Type**: Target operating system (Unix, Windows, Generic)
- **Traversal Depth**: Maximum directory traversal depth (1-20)

#### Target Configuration Section

- **Target Host**: Hostname or IP address for network modules
- **Target URL**: Full URL with TRAVERSAL placeholder (http-url module)
- **Port**: Custom port number (auto-detects defaults)
- **Target File**: File to search for during traversal
- **Pattern**: Success detection string or regex

#### Advanced Options Section

- **Authentication**: Username and password for secured services
- **HTTP Options**: Method, User-Agent, SSL settings
- **Behavior**: Delay, continue on error, break on first match
- **Intelligence**: OS detection, service detection, bisection algorithm
- **Payload**: Custom payload file for payload module

#### Output Configuration Section

- **Report Format**: Text, JSON, CSV, XML, HTML
- **Output File**: Custom filename for reports
- **Additional Options**: Quiet mode, extra files, timestamps

### Right Panel - Monitoring & Output (50% width)

#### Tab 1: Output

- **Real-time Scan Output**: Live stream of scan progress and results
- **Syntax Highlighting**: Color-coded output for easy reading
- **Auto-scroll**: Automatic scrolling to latest output
- **Search & Filter**: Find specific patterns in output

#### Tab 2: Monitoring

- **CPU Usage Graph**: Real-time system and process CPU monitoring
- **Memory Usage Graph**: RAM consumption tracking
- **Performance Metrics**: Request rate, response times, success rate
- **Resource Statistics**: Historical usage data

#### Tab 3: History

- **Scan History**: All previous scans with configurations
- **Quick Replay**: Re-run previous scans with one click
- **Export History**: Save scan history for documentation

### Bottom Panel - Status & Controls

- **Status Bar**: Current operation status and helpful messages
- **Progress Bar**: Visual indication of scan progress
- **Control Buttons**: Start/Stop scan, Clear output, Export results
- **Resource Indicators**: Quick system resource overview

## 🔧 Configuration Guide

### 🛡️ Detection Method Selection (IDS Evasion)

The GUI includes a Detection Method dropdown for IDS/IPS evasion control:

#### Detection Method Options

| Method              | Payloads | Traffic Level    | Visual Indicator | Use Case                          |
| ------------------- | -------- | ---------------- | ---------------- | --------------------------------- |
| **Simple**          | 24       | 🟢 ULTRA STEALTH | Green            | Basic recon, evade all monitoring |
| **URL Encoding**    | 30       | 🟢 ULTRA STEALTH | Green            | WAF bypass, filter evasion        |
| **Non-Recursive**   | 71       | 🟢 STEALTH       | Green            | Non-recursive filter bypass       |
| **Absolute Path**   | 23K      | 🟡 MODERATE      | Orange           | Direct path injection             |
| **Null Byte**       | 75K      | 🟠 HIGH VOLUME   | Dark Orange      | Extension validation bypass       |
| **Path Validation** | 1.7M     | 🔴 VERY HIGH     | Red              | Complex validation bypass         |
| **Any**             | 1.9M     | 🔴 IDS TRIGGER   | Red              | Comprehensive testing             |

#### Real-time Traffic Indicator

The GUI displays a real-time traffic level indicator that updates when you change the detection method:

- **🟢 ULTRA STEALTH**: Perfect for reconnaissance without detection
- **🟡 MODERATE**: Balanced approach for moderate security environments
- **🔴 HIGH VOLUME**: May trigger IDS/IPS systems

#### Choosing the Right Method

1. **Start Stealthy**: Begin with `simple` or `url_encoding` for initial reconnaissance
2. **Escalate Gradually**: Move to `non_recursive` or `absolute_path` if needed
3. **Full Coverage**: Use `path_validation` or `any` only when comprehensive testing is required

### Module-Specific Configuration

The GUI automatically adapts its interface based on the selected module:

#### HTTP Module (`http`)

**Required Fields** (highlighted in green):

- Target Host
- Pattern

**Available Options**:

- Port (default: 80/443 for SSL)
- HTTP Method (GET, POST, HEAD, PUT, DELETE, COPY, MOVE, OPTIONS)
- User Agent string
- SSL/HTTPS enable
- Username/Password for authentication

**Example Configuration**:

```
Module: http
Target Host: example.com
Port: 80
Target File: /etc/passwd
Pattern: root:
HTTP Method: GET
SSL: Disabled
```

#### HTTP-URL Module (`http-url`)

**Required Fields** (highlighted in green):

- Target URL (must contain "TRAVERSAL" placeholder)
- Pattern

**URL Format**: The URL must include the word "TRAVERSAL" which will be replaced with directory traversal patterns.

**Example Configuration**:

```
Module: http-url
Target URL: http://vulnerable.com/page.php?file=TRAVERSAL
Pattern: root:
```

**Valid URL Examples**:

- `http://example.com/include.php?template=TRAVERSAL`
- `https://app.com/api/files/TRAVERSAL`
- `http://site.com/download.php?path=TRAVERSAL&type=config`

#### FTP Module (`ftp`)

**Required Fields** (highlighted in green):

- Target Host
- Pattern

**Available Options**:

- Port (default: 21)
- Username (default: anonymous)
- Password (default: dot@dot.pwn)

**Example Configuration**:

```
Module: ftp
Target Host: ftp.example.com
Port: 21
Username: anonymous
Password: dot@dot.pwn
Pattern: confidential
```

#### TFTP Module (`tftp`)

**Required Fields** (highlighted in green):

- Target Host
- Pattern

**Available Options**:

- Port (default: 69)
- Target file specification

**Example Configuration**:

```
Module: tftp
Target Host: 192.168.1.1
Port: 69
Target File: startup-config
Pattern: enable secret
```

#### Payload Module (`payload`)

**Required Fields** (highlighted in green):

- Target Host
- Port
- Payload File
- Pattern

**Available Options**:

- SSL/TLS encryption
- Custom authentication

**Example Configuration**:

```
Module: payload
Target Host: custom-service.com
Port: 9999
Payload File: /path/to/payloads.txt
Pattern: access granted
SSL: Enabled
```

#### STDOUT Module (`stdout`)

**Required Fields**: None (pattern generation mode)

**Available Options**:

- OS Type for pattern generation
- Target file for patterns
- File extension
- Depth specification

**Example Configuration**:

```
Module: stdout
OS Type: unix
Target File: /etc/passwd
Depth: 8
```

#### Generate Mode (`generate`)

**Required Fields**: None (offline pattern generation)

**Available Options**:

- OS Type specification
- Depth configuration
- Specific file targeting
- Extra files inclusion

**Example Configuration**:

```
Module: generate
OS Type: windows
Depth: 6
Specific File: boot.ini
Extra Files: Yes
```

### Smart Field Validation

The GUI provides intelligent validation with visual feedback:

#### Visual Indicators

- **🟢 Green Border**: Required field that must be filled
- **⚪ White Border**: Optional field
- **🔒 Grayed Out**: Field disabled for current module
- **❌ Red Border**: Invalid input detected

#### Real-time Validation Messages

The status bar shows context-sensitive help:

- "HTTP Module - Specify target host and success pattern"
- "HTTP-URL Module - Use target URL field with TRAVERSAL placeholder"
- "Generate Mode - Generate patterns for offline use"
- "Please enter a target URL!" (when URL field is empty for http-url)
- "Target URL must contain 'TRAVERSAL' placeholder!" (when TRAVERSAL is missing)

### Quick Configuration Presets

Use preset buttons for common scenarios:

#### Web App Preset

```
Module: http
OS Type: generic
Depth: 8
Target File: /etc/passwd
Pattern: root:
HTTP Method: GET
Extra Files: Yes
```

#### Windows Preset

```
Module: http
OS Type: windows
Depth: 6
Target File: boot.ini
Pattern: Windows
Extra Files: Yes
```

#### Linux Preset

```
Module: http
OS Type: unix
Depth: 8
Target File: /etc/passwd
Pattern: root:
Extra Files: Yes
OS Detection: Yes
```

#### Generate Preset

```
Module: generate
OS Type: generic
Depth: 6
Extra Files: No
```

## 📊 Monitoring and Output

### Real-time Output Display

The output tab provides comprehensive scan monitoring:

#### Features

- **Live Updates**: Real-time streaming of scan progress
- **Syntax Highlighting**: Color-coded output for different message types

  - 🟢 Green: Successful matches and positive results
  - 🔴 Red: Errors and warnings
  - 🔵 Blue: Informational messages
  - ⚪ White: Standard output

- **Auto-scroll**: Automatically follows the latest output
- **Manual Control**: Scroll up to review previous output
- **Search Function**: Find specific text in output
- **Copy/Export**: Select and copy output text

#### Output Examples

```bash
[+] Starting DotDotPwn scan...
[+] Module: HTTP
[+] Target: example.com:80
[+] Pattern: root:
[+] Depth: 8

[+] Generating traversal patterns...
[+] Created 2,667 patterns for testing

[*] Testing: http://example.com/page.php?file=../etc/passwd
[*] Testing: http://example.com/page.php?file=../../etc/passwd
[*] Testing: http://example.com/page.php?file=../../../etc/passwd

[!] VULNERABILITY FOUND!
[!] URL: http://example.com/page.php?file=../../../etc/passwd
[!] Pattern matched: root:x:0:0:root:/root:/bin/bash

[+] Scan completed successfully
[+] Total requests: 247
[+] Vulnerabilities found: 1
[+] Time elapsed: 23.4 seconds
```

### Resource Monitoring

The monitoring tab displays real-time system metrics:

#### CPU Usage Graph

- **System CPU**: Overall system CPU utilization
- **Process CPU**: DotDotPwn process CPU usage
- **Historical Data**: Last 60 seconds of CPU activity
- **Visual Indicators**: Color-coded thresholds

#### Memory Usage Graph

- **System Memory**: Total system RAM usage
- **Process Memory**: DotDotPwn memory consumption
- **Memory Statistics**: Peak usage, current usage, available memory
- **Leak Detection**: Monitoring for memory leaks during long scans

#### Performance Metrics

- **Request Rate**: Requests per second
- **Response Time**: Average response time per request
- **Success Rate**: Percentage of successful requests
- **Error Rate**: Network errors and timeouts

#### Network Statistics

- **Bytes Sent**: Total data transmitted
- **Bytes Received**: Total data received
- **Connection Count**: Active network connections
- **Bandwidth Usage**: Network utilization

### Scan History

The history tab maintains a complete audit trail:

#### Features

- **Scan Records**: All previous scans with timestamps
- **Configuration Storage**: Save and reload scan configurations
- **Result Summaries**: Quick overview of findings
- **Export Options**: Export history for documentation

#### History Entry Example

```
Scan #15 - 2025-09-28 10:30:15
Module: http
Target: example.com
Duration: 23.4s
Vulnerabilities: 1 found
Status: Completed successfully
Configuration: [View] [Replay] [Export]
```

## 🎛️ Advanced Features

### OS Detection Integration

When OS Detection is enabled:

1. **Automatic Detection**: Uses nmap to identify target OS
2. **Pattern Optimization**: Adjusts traversal patterns for detected OS
3. **Visual Feedback**: Shows detected OS in status bar
4. **Manual Override**: Option to manually specify if detection fails

#### OS Detection Output

```
[+] OS Detection enabled
[*] Scanning target OS...
[+] OS Detected: Linux 2.6.X - 3.X
[+] Optimizing patterns for Unix systems
[+] Using Unix-specific file targets
```

### Service Detection

Service detection provides additional intelligence:

1. **Banner Grabbing**: Identifies service versions
2. **Vulnerability Correlation**: Matches known vulnerabilities
3. **Pattern Enhancement**: Service-specific traversal patterns
4. **Security Headers**: Analysis of security headers

#### Service Detection Output

```
[+] Service Detection enabled
[*] Grabbing service banner...
[+] Service: Apache/2.4.41 (Ubuntu)
[+] Server: nginx/1.18.0
[+] Additional headers detected
[+] Optimizing for Apache/nginx combination
```

### Bisection Algorithm

The bisection algorithm optimizes scanning efficiency:

1. **Binary Search**: Finds exact vulnerability depth
2. **Request Minimization**: Reduces total number of requests
3. **Visual Progress**: Shows bisection progress in real-time
4. **Precision Results**: Provides exact depth information

#### Bisection Output

```
[+] Bisection algorithm enabled
[*] Testing maximum depth (12)...
[+] Vulnerability found at depth 12
[*] Binary search for minimum depth...
[*] Testing depth 6... No vulnerability
[*] Testing depth 9... No vulnerability
[*] Testing depth 11... Vulnerability found
[*] Testing depth 10... No vulnerability
[+] Exact vulnerability depth: 11
[+] Bisection complete - saved 156 requests
```

### Custom Payload Integration

For the payload module:

1. **File Browser**: Easy payload file selection
2. **Syntax Validation**: Checks payload file format
3. **Preview Function**: View payload contents before scanning
4. **Template Support**: Common payload templates

#### Payload File Format

```
# Custom payloads for service testing
TRAVERSAL/config.ini
TRAVERSAL/database.conf
TRAVERSAL/../../etc/passwd
TRAVERSAL/../../windows/system32/drivers/etc/hosts
```

## 📋 Report Management

### Export Formats

The GUI supports multiple export formats:

#### Text Format

- Human-readable reports
- Console-style output
- Easy to read and share

#### JSON Format

```json
{
  "scan_info": {
    "target": "example.com",
    "timestamp": "2025-09-28T10:30:00Z",
    "module": "http",
    "duration": 23.4
  },
  "vulnerabilities": [
    {
      "url": "http://example.com/page.php?file=../../../etc/passwd",
      "depth": 3,
      "pattern": "root:",
      "method": "GET"
    }
  ],
  "statistics": {
    "total_requests": 247,
    "vulnerabilities_found": 1,
    "success_rate": 0.4
  }
}
```

#### HTML Format

- Professional web reports
- Embedded styling and graphics
- Charts and visualizations
- Suitable for presentations

#### CSV Format

```csv
Timestamp,URL,Method,Depth,Pattern,Response_Code,Content_Length
2025-09-28T10:30:15,http://example.com/page.php?file=../../../etc/passwd,GET,3,root:,200,1847
```

#### XML Format

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dotdotpwn_report>
  <scan_info>
    <target>example.com</target>
    <timestamp>2025-09-28T10:30:00Z</timestamp>
    <module>http</module>
  </scan_info>
  <vulnerabilities>
    <vulnerability>
      <url>http://example.com/page.php?file=../../../etc/passwd</url>
      <depth>3</depth>
      <pattern>root:</pattern>
    </vulnerability>
  </vulnerabilities>
</dotdotpwn_report>
```

### Report Features

#### Automatic Reporting

- **Auto-save**: Automatically save reports after scan completion
- **Timestamping**: Add timestamps to report filenames
- **Directory Organization**: Organize reports by date or target

#### Manual Export

- **Export Current Results**: Save current scan results
- **Export History**: Save all scan history
- **Custom Formatting**: Choose specific format options

#### Report Sharing

- **Professional Formatting**: Reports suitable for business use
- **Compliance Ready**: Formats suitable for security compliance
- **Team Collaboration**: Shareable formats for team review

## ⌨️ Keyboard Shortcuts

The GUI supports comprehensive keyboard navigation:

### Global Shortcuts

- **Ctrl+R**: Start scan
- **Ctrl+S**: Stop scan
- **Ctrl+E**: Export results
- **Ctrl+C**: Clear output
- **Ctrl+Q**: Quit application
- **F1**: Show help
- **F5**: Refresh/restart scan

### Navigation Shortcuts

- **Tab**: Navigate between fields
- **Shift+Tab**: Navigate backwards
- **Enter**: Activate focused button
- **Space**: Toggle checkboxes
- **Ctrl+Tab**: Switch between output tabs

### Output Control

- **Ctrl+F**: Find in output
- **Ctrl+A**: Select all output
- **Ctrl+C**: Copy selected output
- **Home**: Jump to beginning of output
- **End**: Jump to end of output
- **Page Up/Down**: Scroll output

### Configuration Shortcuts

- **F2**: Open configuration file
- **F3**: Load configuration
- **F4**: Save configuration
- **Ctrl+1**: Web App preset
- **Ctrl+2**: Windows preset
- **Ctrl+3**: Linux preset
- **Ctrl+4**: Generate preset

## 🔧 Customization

### Theme Customization

The GUI uses QDarkStyle but can be customized:

#### Custom Styling

```python
# Custom color scheme (modify in gui/dotdotpwn_gui.py)
custom_style = """
QMainWindow {
    background-color: #2b2b2b;
    color: #ffffff;
}
QLineEdit {
    background-color: #3c3c3c;
    border: 1px solid #5c5c5c;
    padding: 4px;
}
"""
```

### Configuration Persistence

#### Settings Storage

- **Window Size**: Remembers last window size and position
- **Layout Settings**: Saves splitter positions
- **Default Values**: Stores commonly used configurations
- **Theme Preferences**: Remembers UI preferences

#### Configuration Files

```yaml
# ~/.dotdotpwn/gui_config.yaml
window:
  width: 1400
  height: 900
  x: 100
  y: 50

defaults:
  module: "http"
  depth: 8
  delay: 0.3
  format: "json"

theme:
  name: "dark"
  syntax_highlighting: true
```

## 🛠️ Troubleshooting

### Common Issues

#### GUI Won't Start

```bash
# Check PyQt6 installation
python -c "import PyQt6; print('PyQt6 OK')"

# Install missing GUI dependencies
pip install PyQt6 PyQt6-tools qtawesome pyqtgraph qdarkstyle

# Check Python version
python --version  # Should be 3.8+
```

#### Resource Monitoring Not Working

```bash
# Install psutil for system monitoring
pip install psutil>=5.9.0

# Verify psutil installation
python -c "import psutil; print('CPU:', psutil.cpu_percent())"
```

#### Scan Fails to Start

1. **Check Configuration**: Ensure required fields are filled
2. **Verify Target**: Test network connectivity to target
3. **Check Permissions**: Ensure proper network access
4. **Review Output**: Check error messages in output tab

#### Performance Issues

1. **Resource Monitoring**: Check CPU/memory usage in monitoring tab
2. **Adjust Settings**: Increase delay, reduce depth
3. **System Resources**: Close other applications
4. **Network Conditions**: Check network latency

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Set debug environment variable
export DOTDOTPWN_DEBUG=1

# Launch GUI with debug output
python launch_gui.py
```

Debug output provides:

- Detailed error messages
- Internal state information
- Network communication details
- Performance metrics

### Log Files

The GUI generates log files for troubleshooting:

```bash
# Log file locations
~/.dotdotpwn/logs/gui.log          # GUI-specific logs
~/.dotdotpwn/logs/scan.log         # Scan operation logs
~/.dotdotpwn/logs/error.log        # Error messages
```

### Support Resources

- **Built-in Help**: Help menu with comprehensive documentation
- **Tooltips**: Hover over fields for contextual help
- **Status Messages**: Real-time guidance in status bar
- **Error Dialogs**: Detailed error information with suggestions

---

This GUI guide covers all aspects of the PyDotPwn graphical interface. For command-line usage, see the [CLI Reference](cli-reference), or check out the [Examples](examples) section for real-world usage scenarios.
