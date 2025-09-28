---
layout: page
title: "Getting Started"
permalink: /getting-started/
---

# 🚀 Getting Started with PyDotPwn

This guide will get you up and running with PyDotPwn in just a few minutes, from installation to performing your first directory traversal scan.

## 📋 Prerequisites

Before installing PyDotPwn, ensure your system meets these requirements:

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python Version**: 3.8 or higher (Python 3.10+ recommended)
- **Memory**: 512 MB RAM minimum (2 GB recommended)
- **Storage**: 100 MB free space (1 GB recommended for reports)
- **Network**: Internet connection for target testing

### Required Tools

- **Python 3.8+**: [Download from python.org](https://www.python.org/downloads/)
- **pip**: Usually comes with Python
- **Git**: [Download from git-scm.com](https://git-scm.com/)

### Optional Tools

- **nmap**: For OS detection features ([Download nmap](https://nmap.org/download.html))
- **Virtual Environment**: Recommended for isolated installation

## 📦 Installation

### Method 1: Quick Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/nanragav/PyDotPwn.git
cd PyDotPwn

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python dotdotpwn.py --help
```

### Method 2: Development Installation

If you plan to modify or contribute to the code:

```bash
# Clone and enter directory
git clone https://github.com/nanragav/PyDotPwn.git
cd PyDotPwn

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests to verify
python run_tests.py
```

### Method 3: Docker Installation (Coming Soon)

```bash
# Pull Docker image
docker pull dotdotpwn/PyDotPwn:latest

# Run container
docker run -it dotdotpwn/PyDotPwn:latest --help
```

## ✅ Verification

After installation, verify that everything works correctly:

### 1. Check Core Functionality

```bash
# Test basic help system
python dotdotpwn.py --help

# Test pattern generation (no network required)
python dotdotpwn.py --module stdout --depth 3 --os-type unix --file /etc/passwd

# Test help examples
python dotdotpwn.py help-examples
```

### 2. Run Comprehensive Tests

```bash
# Run the full test suite
python comprehensive_verification.py

# Expected output:
# ✅ Environment Setup: PASSED
# ✅ Module Imports: PASSED
# ✅ Pattern Generation: PASSED
# ... (all 22 tests should pass)
```

### 3. Test GUI (Optional)

```bash
# Launch the graphical interface
python launch_gui.py

# The GUI should open with a professional dark theme
```

### 4. Test API (Optional)

```bash
# Start API server (in one terminal)
python dotdotpwn.py api --host localhost --port 8000

# Test API (in another terminal)
curl http://localhost:8000/
curl http://localhost:8000/docs  # Interactive API documentation
```

## 🎯 Your First Scan

Now that DotDotPwn is installed, let's perform your first directory traversal scan:

### Basic HTTP Scan

```bash
# Simple directory traversal test against a web server
python dotdotpwn.py --module http --host example.com --file /etc/passwd --pattern "root:"

# What this does:
# --module http      : Use HTTP fuzzing module
# --host example.com : Target the specified host
# --file /etc/passwd : Look for the /etc/passwd file
# --pattern "root:"  : Success indicator (root user in passwd file)
```

### HTTPS Scan with Enhanced Features

```bash
# More advanced scan with OS detection and SSL
python dotdotpwn.py --module http --host example.com --ssl --detect-os --break-on-first --quiet

# Additional parameters:
# --ssl              : Use HTTPS instead of HTTP
# --detect-os        : Attempt to detect target OS
# --break-on-first   : Stop after finding first vulnerability
# --quiet            : Reduce output verbosity
```

### URL Parameter Testing

```bash
# Test a specific vulnerable parameter
python dotdotpwn.py --module http-url --url "http://example.com/page.php?file=TRAVERSAL" --pattern "root:"

# The TRAVERSAL placeholder will be replaced with directory traversal patterns
```

## 🖥️ Using the GUI

The graphical interface provides an intuitive way to configure and monitor scans:

```bash
# Launch GUI
python launch_gui.py
```

### GUI Quick Start:

1. **Select Module**: Choose from HTTP, FTP, TFTP, etc.
2. **Configure Target**: Enter hostname, port, and target file
3. **Set Pattern**: Specify what indicates a successful traversal
4. **Advanced Options**: Adjust depth, delays, and behavior
5. **Start Scan**: Click "Start Scan" or press Ctrl+R
6. **Monitor Progress**: Watch real-time output and resource usage
7. **Export Results**: Save findings in your preferred format

## 📝 Understanding the Output

DotDotPwn provides detailed output to help you understand the scan progress and results:

### Successful Vulnerability Detection

```
[!] FOUND: http://example.com/page.php?file=../../../etc/passwd
[+] Pattern found: root:x:0:0:root:/root:/bin/bash
[+] Vulnerability confirmed at depth: 3
```

### Scan Statistics

```
[+] Scanning finished!
[+] Total requests sent: 247
[+] Total vulnerabilities found: 1
[+] Time taken: 23.4 seconds
[+] Average response time: 0.3 seconds
```

### Report Generation

```bash
# Generate JSON report
python dotdotpwn.py --module http --host example.com --report results.json --format json

# Generate HTML report
python dotdotpwn.py --module http --host example.com --report report.html --format html
```

## 🔧 Configuration

### Environment Variables

Set optional environment variables for default behavior:

```bash
# Set default delay between requests
export DOTDOTPWN_DEFAULT_DELAY=0.5

# Set default traversal depth
export DOTDOTPWN_DEFAULT_DEPTH=6

# Enable debug mode
export DOTDOTPWN_DEBUG=1
```

### Configuration File

Create `~/.dotdotpwn/config.yaml` for persistent settings:

```yaml
# Default scan settings
default_delay: 0.3
default_depth: 6
default_format: json
continue_on_error: true
quiet_mode: false

# Default patterns for different OS types
patterns:
  unix: "root:"
  windows: "Administrator"
  web: "<?php"

# Reporting settings
reports_directory: "~/dotdotpwn-reports"
auto_timestamp: true
```

## 🎯 Next Steps

Now that you have PyDotPwn up and running:

### 📚 Learn More

- **[CLI Reference](cli-reference)**: Complete command-line documentation
- **[GUI Guide](gui-guide)**: Detailed graphical interface tutorial
- **[API Documentation](api-documentation)**: REST API integration guide
- **[Examples](examples)**: Real-world usage scenarios

### 🔧 Advanced Features

- **Bisection Algorithm**: Find exact vulnerability depth
- **OS Detection**: Automatic target system identification
- **Custom Payloads**: Test proprietary protocols
- **Report Generation**: Professional documentation

### 🛠️ Customization

- **Custom Patterns**: Create specific detection patterns
- **Module Development**: Extend functionality
- **Integration**: Use with other security tools
- **Automation**: Script repetitive tasks

## ❓ Need Help?

If you encounter any issues during installation or setup:

1. **Check Prerequisites**: Ensure Python 3.8+ is installed
2. **Verify Dependencies**: Run `pip install -r requirements.txt`
3. **Run Tests**: Execute `python comprehensive_verification.py`
4. **Check Documentation**: Review [Troubleshooting Guide](troubleshooting)
5. **Community Support**: Open an issue on GitHub

## 🔒 Ethical Usage Reminder

Before you start scanning:

- ✅ **Only test systems you own or have explicit permission to test**
- ✅ **Follow responsible disclosure practices**
- ✅ **Respect system resources and rate limits**
- ✅ **Document your findings professionally**
- ✅ **Comply with local laws and regulations**

---

**Congratulations!** You now have PyDotPwn installed and ready to use. Continue with the [CLI Reference](cli-reference) to learn about all available options and parameters.