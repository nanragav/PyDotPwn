# 📚 DotDotPwn Python Implementation - Complete User Guide

![DotDotPwn Python](https://img.shields.io/badge/DotDotPwn-Python-blue.svg) ![Version](https://img.shields.io/badge/version-3.0.2-green.svg) ![License](https://img.shields.io/badge/license-GPL--3.0-red.svg)

## 🎯 Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Module Reference](#module-reference)
6. [Parameter Reference](#parameter-reference)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)
10. [Security Considerations](#security-considerations)

---

## 🚀 Quick Start

DotDotPwn is a comprehensive directory traversal fuzzer that helps security professionals discover path traversal vulnerabilities in various protocols and applications.

### ⚡ Basic Command Structure

```bash
dotdotpwn --module <MODULE> --host <TARGET> [OPTIONS]
```

### 🎯 Most Common Usage

```bash
# Quick HTTP scan
dotdotpwn --module http --host example.com --file /etc/passwd --pattern "root:"

# Quick HTTPS scan with OS detection
dotdotpwn --module http --host example.com --ssl --detect-os --break-on-first
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Network access to target systems
- Optional: nmap (for OS detection)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Verify Installation

```bash
dotdotpwn --help
python dotdotpwn.py --help
```

---

## 🛠️ Basic Usage

### 🌐 HTTP Web Application Testing

**Basic web application scan:**

```bash
dotdotpwn --module http --host example.com --file /etc/passwd --pattern "root:"
```

**HTTPS with enhanced options:**

```bash
dotdotpwn --module http --host secure.example.com --ssl --os-detection --depth 10 --break-on-first
```

**Custom port and method:**

```bash
dotdotpwn --module http --host internal.company.com --port 8080 --method POST --file boot.ini
```

### 🔗 HTTP URL Parameter Testing

**Test specific vulnerable parameter:**

```bash
dotdotpwn --module http-url --url "http://example.com/page.php?file=TRAVERSAL" --pattern "root:"
```

**Advanced URL fuzzing:**

```bash
dotdotpwn --module http-url --url "https://app.com/include.php?template=TRAVERSAL" --depth 12 --os-detection
```

### 📁 FTP Server Testing

**Anonymous FTP testing:**

```bash
dotdotpwn --module ftp --host ftp.example.com --file /etc/passwd --pattern "root:"
```

**Authenticated FTP testing:**

```bash
dotdotpwn --module ftp --host 192.168.1.100 --username admin --password secret --file /etc/shadow
```

### 📡 TFTP Server Testing

**Basic TFTP scan:**

```bash
dotdotpwn --module tftp --host 192.168.1.1 --file /etc/passwd --pattern "root:"
```

**Windows TFTP testing:**

```bash
dotdotpwn --module tftp --host tftp.company.com --file boot.ini --pattern "Windows" --depth 8
```

### 🔧 Custom Protocol Testing

**Custom payload fuzzing:**

```bash
dotdotpwn --module payload --host example.com --port 21 --payload-file ftp_custom.txt --pattern "220"
```

**SSL custom protocol:**

```bash
dotdotpwn --module payload --host secure.app.com --port 443 --ssl --payload-file https_test.txt
```

### 📄 Pattern Generation

**Generate Unix patterns:**

```bash
dotdotpwn --module stdout --depth 8 --os-type unix --file /etc/passwd
```

**Generate Windows patterns with extension:**

```bash
dotdotpwn --module stdout --depth 6 --os-type windows --file boot.ini --extension .bak
```

---

## 🎛️ Advanced Features

### 🔍 OS Detection and Intelligence

**Automatic OS detection using nmap:**

```bash
dotdotpwn --module http --host example.com --os-detection --service-detection --extra-files
```

**Manual OS specification:**

```bash
dotdotpwn --module http --host windows-server.com --os-type windows --depth 10
```

### 🎯 Bisection Algorithm

The bisection algorithm uses binary search to find the exact depth where vulnerability exists:

```bash
dotdotpwn --module http --host example.com --bisection --file /etc/passwd --pattern "root:"
```

**How it works:**

1. Tests maximum depth first
2. If vulnerability found, searches for minimum working depth
3. Uses binary search to minimize test count
4. Provides exact vulnerability depth

### 📊 Report Generation

**Generate JSON report:**

```bash
dotdotpwn --module http --host example.com --report results.json --format json --quiet
```

**Generate HTML report:**

```bash
dotdotpwn --module http --host example.com --output report.html --report-format html
```

**Available formats:**

- `text` - Human-readable text format
- `json` - Machine-readable JSON format
- `csv` - Spreadsheet-compatible CSV format
- `xml` - Structured XML format
- `html` - Web-friendly HTML report

### ⚡ Performance Optimization

**Fast scanning (reduced delay):**

```bash
dotdotpwn --module http --host example.com --delay 0.1 --quiet --continue-on-error
```

**Thorough scanning (increased depth):**

```bash
dotdotpwn --module http --host example.com --depth 20 --delay 2.0 --extra-files
```

**Break on first vulnerability:**

```bash
dotdotpwn --module http --host example.com --break-on-first --quiet
```

---

## 🧩 Module Reference

### 🌐 HTTP Module

**Purpose:** Tests web applications for directory traversal vulnerabilities

**Technical Details:**

- Supports HTTP/1.0, HTTP/1.1, and HTTP/2
- Multiple HTTP methods: GET, POST, HEAD, PUT, DELETE, COPY, MOVE, OPTIONS
- SSL/TLS support with certificate validation options
- User-Agent rotation for stealth
- Cookie and session handling
- Custom headers support

**Parameters:**

- `--host` (required) - Target hostname or IP
- `--port` (optional) - Target port (default: 80/443)
- `--ssl` (optional) - Enable HTTPS
- `--method` (optional) - HTTP method (default: GET)
- `--pattern` (recommended) - Success detection pattern

**Use Cases:**

- Web application penetration testing
- CMS vulnerability assessment
- API security testing
- File inclusion vulnerability detection

### 🔗 HTTP-URL Module

**Purpose:** Targeted URL parameter fuzzing with TRAVERSAL placeholder

**Technical Details:**

- URL parsing and parameter injection
- Support for complex URL structures
- Query parameter manipulation
- POST data parameter testing
- Fragment and path segment testing

**Parameters:**

- `--url` (required) - URL with TRAVERSAL placeholder
- `--pattern` (required) - Success detection pattern
- Standard traversal options apply

**URL Format Examples:**

```
http://example.com/page.php?file=TRAVERSAL
https://app.com/api/v1/files/TRAVERSAL
http://site.com/download.php?path=TRAVERSAL&type=config
```

### 📁 FTP Module

**Purpose:** FTP server directory traversal testing

**Technical Details:**

- Active and passive FTP modes
- Binary and ASCII transfer modes
- Anonymous and authenticated connections
- FTPS (FTP over SSL) support
- Multiple FTP commands: RETR, LIST, NLST, SIZE

**Parameters:**

- `--host` (required) - FTP server hostname
- `--port` (optional) - FTP port (default: 21)
- `--username` (optional) - FTP username (default: anonymous)
- `--password` (optional) - FTP password (default: dot@dot.pwn)

**FTP Commands Used:**

- `USER` - Authentication
- `PASS` - Password authentication
- `RETR` - File retrieval (main testing method)
- `CWD` - Directory traversal attempts
- `LIST` - Directory listing for verification

### 📡 TFTP Module

**Purpose:** TFTP (Trivial File Transfer Protocol) server testing

**Technical Details:**

- UDP-based protocol (connectionless)
- Simple request/response mechanism
- No authentication required
- Binary file transfer support
- Timeout and retry mechanisms

**Parameters:**

- `--host` (required) - TFTP server hostname
- `--port` (optional) - TFTP port (default: 69)
- Standard traversal options

**TFTP Packet Types:**

- RRQ (Read Request) - Primary testing method
- WRQ (Write Request) - Optional testing
- DATA - File data transfer
- ACK - Acknowledgment packets
- ERROR - Error responses

### 🔧 Payload Module

**Purpose:** Custom protocol fuzzing with user-defined payloads

**Technical Details:**

- Raw socket communication
- TCP and UDP protocol support
- SSL/TLS encryption support
- Binary and text payload support
- Custom protocol implementation

**Parameters:**

- `--host` (required) - Target hostname
- `--port` (required) - Target port
- `--payload-file` (required) - Payload template file
- `--ssl` (optional) - Enable SSL/TLS
- `--pattern` (optional) - Response pattern matching

**Payload File Format:**

```
# Example FTP payload
USER anonymous
PASS dot@dot.pwn
RETR TRAVERSAL
QUIT

# Example HTTP payload
GET TRAVERSAL HTTP/1.1
Host: example.com
User-Agent: DotDotPwn/3.0.2
Connection: close

```

### 📄 STDOUT Module

**Purpose:** Generate traversal patterns for external use

**Technical Details:**

- Pattern generation without network activity
- Multiple encoding schemes
- OS-specific pattern optimization
- Custom file extension support
- Output redirection support

**Parameters:**

- `--depth` (optional) - Pattern depth (default: 6)
- `--os-type` (optional) - Target OS (windows/unix/generic)
- `--file` (optional) - Target filename
- `--extension` (optional) - File extension

**Output Usage:**

```bash
# Generate patterns and save to file
dotdotpwn --module stdout --depth 8 --os-type unix > patterns.txt

# Use with other tools
dotdotpwn --module stdout --depth 6 | grep "etc/passwd" | head -10
```

---

## 📋 Parameter Reference

### 🎯 Core Parameters

| Parameter | Short                                       | Long Alternatives | Description               | Example          |
| --------- | ------------------------------------------- | ----------------- | ------------------------- | ---------------- |
| `-m`      | `--module`                                  |                   | Fuzzing module selection  | `-m http`        |
| `-h`      | `--host`, `--hostname`                      |                   | Target hostname or IP     | `-h example.com` |
| `-x`      | `--port`                                    |                   | Target port number        | `-x 8080`        |
| `-f`      | `--file`, `--filename`, `--target-file`     |                   | Specific target file      | `-f /etc/passwd` |
| `-k`      | `--pattern`, `--keyword`, `--match-pattern` |                   | Success detection pattern | `-k "root:"`     |

### 🔍 Detection & Intelligence

| Parameter | Short                                  | Long Alternatives | Description                | Example      |
| --------- | -------------------------------------- | ----------------- | -------------------------- | ------------ |
| `-O`      | `--os-detection`, `--detect-os`        |                   | Enable OS detection (nmap) | `-O`         |
| `-o`      | `--os-type`, `--operating-system`      |                   | Manual OS specification    | `-o windows` |
| `-s`      | `--service-detection`, `--banner-grab` |                   | Service version detection  | `-s`         |

### 📏 Traversal Configuration

| Parameter | Short                               | Long Alternatives | Description                | Example   |
| --------- | ----------------------------------- | ----------------- | -------------------------- | --------- |
| `-d`      | `--depth`, `--max-depth`            |                   | Maximum traversal depth    | `-d 10`   |
| `-E`      | `--extra-files`, `--include-extras` |                   | Include extra common files | `-E`      |
| `-e`      | `--extension`, `--file-extension`   |                   | File extension to append   | `-e .bak` |
| `-X`      | `--bisection`, `--binary-search`    |                   | Use bisection algorithm    | `-X`      |

### 🔒 Security & Protocol

| Parameter | Short                       | Long Alternatives | Description               | Example        |
| --------- | --------------------------- | ----------------- | ------------------------- | -------------- |
| `-S`      | `--ssl`, `--https`, `--tls` |                   | Enable SSL/TLS encryption | `-S`           |
| `-U`      | `--username`, `--user`      |                   | Authentication username   | `-U admin`     |
| `-P`      | `--password`, `--pass`      |                   | Authentication password   | `-P secret123` |
| `-M`      | `--method`, `--http-method` |                   | HTTP request method       | `-M POST`      |

### 🌍 HTTP-URL Specific

| Parameter | Short                   | Long Alternatives | Description                    | Example                                           |
| --------- | ----------------------- | ----------------- | ------------------------------ | ------------------------------------------------- |
| `-u`      | `--url`, `--target-url` |                   | URL with TRAVERSAL placeholder | `-u "http://example.com/page.php?file=TRAVERSAL"` |

### 🔧 Custom Payload

| Parameter | Short                         | Long Alternatives | Description                  | Example         |
| --------- | ----------------------------- | ----------------- | ---------------------------- | --------------- |
| `-p`      | `--payload`, `--payload-file` |                   | Custom payload template file | `-p custom.txt` |

### ⚡ Performance & Behavior

| Parameter | Short                                            | Long Alternatives | Description                      | Example  |
| --------- | ------------------------------------------------ | ----------------- | -------------------------------- | -------- |
| `-t`      | `--delay`, `--time-delay`                        |                   | Delay between requests (seconds) | `-t 1.5` |
| `-b`      | `--break`, `--break-on-first`, `--stop-on-first` |                   | Stop after first vulnerability   | `-b`     |
| `-C`      | `--continue`, `--continue-on-error`              |                   | Continue on connection errors    | `-C`     |
| `-q`      | `--quiet`, `--silent`                            |                   | Quiet mode (minimal output)      | `-q`     |

### 📊 Output & Reporting

| Parameter | Short                                   | Long Alternatives | Description            | Example           |
| --------- | --------------------------------------- | ----------------- | ---------------------- | ----------------- |
| `-r`      | `--report`, `--report-file`, `--output` |                   | Output report filename | `-r results.json` |
|           | `--report-format`, `--format`           |                   | Report format          | `--format json`   |

---

## 💡 Examples by Use Case

### 🎯 Web Application Security Testing

**Basic CMS testing:**

```bash
# WordPress
dotdotpwn --module http --host wordpress-site.com --file wp-config.php --pattern "DB_PASSWORD"

# Drupal
dotdotpwn --module http --host drupal-site.com --file sites/default/settings.php --pattern "password"

# Joomla
dotdotpwn --module http --host joomla-site.com --file configuration.php --pattern "password"
```

**API endpoint testing:**

```bash
# REST API
dotdotpwn --module http --host api.example.com --port 443 --ssl --method GET --file /etc/passwd

# GraphQL API
dotdotpwn --module http --host graphql.example.com --method POST --file /etc/hosts --pattern "localhost"
```

**File inclusion testing:**

```bash
# Local File Inclusion (LFI)
dotdotpwn --module http-url --url "http://vulnerable-app.com/page.php?include=TRAVERSAL" --pattern "root:"

# Remote File Inclusion (RFI) testing preparation
dotdotpwn --module stdout --depth 8 --os-type unix --file /etc/passwd > lfi_payloads.txt
```

### 🏢 Enterprise Environment Testing

**Internal network scanning:**

```bash
# Windows domain controller
dotdotpwn --module http --host dc.company.local --file boot.ini --pattern "Windows" --os-type windows

# Linux file server
dotdotpwn --module ftp --host fileserver.company.local --username anonymous --file /etc/passwd --pattern "root:"

# Network equipment (TFTP)
dotdotpwn --module tftp --host 192.168.1.1 --file startup-config --pattern "enable secret"
```

**SSL/TLS services:**

```bash
# HTTPS web applications
dotdotpwn --module http --host internal-app.company.com --ssl --port 8443 --os-detection

# FTPS file servers
dotdotpwn --module ftp --host secure-ftp.company.com --port 990 --ssl --username user --password pass
```

### 🔬 Research and Development

**Custom protocol development:**

```bash
# Create custom payload file
echo "CONNECT TRAVERSAL" > custom_protocol.txt
echo "AUTH user:pass" >> custom_protocol.txt
echo "RETRIEVE TRAVERSAL" >> custom_protocol.txt

# Test custom protocol
dotdotpwn --module payload --host test-server.lab.local --port 9999 --payload-file custom_protocol.txt
```

**Pattern generation for automation:**

```bash
# Generate comprehensive pattern set
dotdotpwn --module stdout --depth 12 --os-type generic --extra-files > comprehensive_patterns.txt

# Generate Windows-specific patterns
dotdotpwn --module stdout --depth 8 --os-type windows --file boot.ini --extension .bak > windows_patterns.txt

# Generate Unix-specific patterns
dotdotpwn --module stdout --depth 10 --os-type unix --file /etc/shadow > unix_patterns.txt
```

### 📊 Automated Security Assessment

**Comprehensive scanning with reporting:**

```bash
# Full assessment with all features
dotdotpwn --module http \
          --host target.example.com \
          --os-detection \
          --service-detection \
          --extra-files \
          --bisection \
          --break-on-first \
          --report comprehensive_scan.json \
          --format json \
          --quiet

# Multiple format reporting
dotdotpwn --module http --host target.com --report results.html --format html --quiet
dotdotpwn --module http --host target.com --report results.csv --format csv --quiet
dotdotpwn --module http --host target.com --report results.xml --format xml --quiet
```

**Performance-optimized scanning:**

```bash
# Fast scanning for CI/CD
dotdotpwn --module http \
          --host staging.company.com \
          --file /etc/passwd \
          --pattern "root:" \
          --depth 6 \
          --delay 0.1 \
          --break-on-first \
          --quiet \
          --continue-on-error

# Stealth scanning (slow and careful)
dotdotpwn --module http \
          --host sensitive-target.com \
          --delay 3.0 \
          --depth 15 \
          --continue-on-error \
          --report stealth_scan.json \
          --format json
```

---

## 🔧 Troubleshooting

### ❌ Common Issues and Solutions

**1. "Module not found" errors:**

```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Install in development mode
pip install -e .

# Check dependencies
pip install -r requirements.txt
```

**2. Connection timeout issues:**

```bash
# Increase delay between requests
dotdotpwn --module http --host slow-server.com --delay 2.0 --continue-on-error

# Test connectivity first
ping target-server.com
telnet target-server.com 80
```

**3. Permission denied (OS detection):**

```bash
# Run with sudo for nmap OS detection
sudo dotdotpwn --module http --host example.com --os-detection

# Or disable OS detection
dotdotpwn --module http --host example.com --os-type generic
```

**4. SSL certificate errors:**

```bash
# Skip certificate verification (if needed for testing)
export PYTHONHTTPSVERIFY=0
dotdotpwn --module http --host self-signed.example.com --ssl

# Or use the continue-on-error flag
dotdotpwn --module http --host problem-ssl.com --ssl --continue-on-error
```

**5. False positives in results:**

```bash
# Use more specific patterns
dotdotpwn --module http --host example.com --pattern "root:x:" --file /etc/passwd

# Enable bisection for accuracy
dotdotpwn --module http --host example.com --pattern "root:" --bisection
```

### 🔍 Debug Mode and Verbose Output

**Enable verbose logging:**

```bash
# Remove quiet flag for full output
dotdotpwn --module http --host example.com --file /etc/passwd --pattern "root:"

# Use continue-on-error to see all issues
dotdotpwn --module http --host example.com --continue-on-error
```

**Test individual components:**

```bash
# Test just pattern generation
dotdotpwn --module stdout --depth 3 --file /etc/passwd

# Test connectivity without fuzzing
dotdotpwn --module http --host example.com --service-detection
```

### 📊 Performance Optimization

**Memory usage optimization:**

```bash
# Reduce depth for memory-constrained environments
dotdotpwn --module http --host example.com --depth 4 --break-on-first

# Use quiet mode to reduce memory usage
dotdotpwn --module http --host example.com --quiet --continue-on-error
```

**Network optimization:**

```bash
# Adjust delay based on network speed
dotdotpwn --module http --host local.example.com --delay 0.1      # Fast local network
dotdotpwn --module http --host remote.example.com --delay 1.0     # Internet target
dotdotpwn --module http --host slow.example.com --delay 3.0       # Slow/limited target
```

---

## 🛡️ Best Practices

### 🎯 Effective Testing Strategies

**1. Start with reconnaissance:**

```bash
# First, detect OS and services
dotdotpwn --module http --host target.com --os-detection --service-detection --depth 3

# Then perform targeted testing based on results
dotdotpwn --module http --host target.com --os-type windows --depth 8 --extra-files
```

**2. Use appropriate depth levels:**

- **Depth 3-5:** Quick testing, common vulnerabilities
- **Depth 6-8:** Standard penetration testing
- **Depth 9-12:** Thorough assessment
- **Depth 13+:** Deep assessment, research purposes

**3. Pattern selection guidelines:**

```bash
# Unix/Linux systems
--pattern "root:"           # /etc/passwd
--pattern "daemon:"         # /etc/passwd alternative
--pattern "[main]"          # Configuration files

# Windows systems
--pattern "Administrator"   # User accounts
--pattern "Windows"         # System files
--pattern "[fonts]"         # win.ini file
--pattern "Microsoft"       # Various system files

# Web applications
--pattern "<?php"           # PHP source code
--pattern "mysql_connect"   # Database configs
--pattern "password"        # Generic credential files
```

### ⚡ Performance Guidelines

**1. Request timing:**

```bash
# Public internet targets
--delay 1.0    # Respectful, avoids rate limiting

# Internal network targets
--delay 0.3    # Default, balanced performance

# Local/lab targets
--delay 0.1    # Fast testing, maximum performance
```

**2. Resource management:**

```bash
# Memory-efficient scanning
dotdotpwn --module http --host target.com --depth 6 --break-on-first --quiet

# CPU-efficient scanning
dotdotpwn --module http --host target.com --delay 0.5 --continue-on-error
```

### 📋 Documentation and Reporting

**1. Comprehensive documentation:**

```bash
# Generate multiple report formats
dotdotpwn --module http --host target.com --report scan_results.json --format json
dotdotpwn --module http --host target.com --report scan_results.html --format html
dotdotpwn --module http --host target.com --report scan_results.csv --format csv
```

**2. Evidence collection:**

```bash
# Include full scan details
dotdotpwn --module http \
          --host target.com \
          --os-detection \
          --service-detection \
          --extra-files \
          --report evidence.json \
          --format json

# Generate pattern evidence
dotdotpwn --module stdout --depth 8 --os-type unix > patterns_used.txt
```

---

## 🔐 Security Considerations

### ⚖️ Legal and Ethical Guidelines

**🔒 CRITICAL SECURITY NOTICE:**
This tool is designed for authorized security testing only. Ensure you have explicit written permission before testing any systems you do not own.

**1. Authorization requirements:**

- Written permission from system owners
- Defined scope of testing
- Clear testing timeframes
- Emergency contact procedures

**2. Responsible disclosure:**

- Report vulnerabilities to system owners
- Allow reasonable time for remediation
- Follow coordinated disclosure practices
- Document findings professionally

### 🛡️ Defensive Considerations

**Detection avoidance (for authorized testing):**

```bash
# Slower, stealthier scanning
dotdotpwn --module http --host target.com --delay 2.0 --depth 6

# Random delays (implement custom wrapper)
for i in {1..5}; do
    dotdotpwn --module http --host target.com --delay $((RANDOM % 3 + 1)) --depth 3
    sleep $((RANDOM % 10 + 5))
done
```

**Log analysis awareness:**

- Traversal attempts create distinctive log patterns
- Consider log monitoring and SIEM detection
- Plan for incident response procedures
- Coordinate with blue team if applicable

### 🔍 Vulnerability Validation

**Confirm findings manually:**

```bash
# Use generated patterns for manual verification
dotdotpwn --module stdout --depth 3 --file /etc/passwd | head -5

# Test specific payloads manually
curl "http://target.com/page.php?file=../../../etc/passwd"
```

**Document exploitation steps:**

1. Save exact payloads that worked
2. Document response content (sanitized)
3. Test impact and data exposure
4. Verify reproducibility

---

## 🆘 Help and Support

### 📚 Built-in Help System

```bash
# Main help
dotdotpwn --help

# Comprehensive examples
dotdotpwn help-examples

# Module-specific information
dotdotpwn help-modules
```

### 🔗 Additional Resources

- **GitHub Repository:** https://github.com/dotdotpwn/dotdotpwn-python
- **Original Perl Version:** https://github.com/wireghoul/dotdotpwn
- **Issue Tracking:** https://github.com/dotdotpwn/dotdotpwn-python/issues
- **Documentation:** https://dotdotpwn-python.readthedocs.io

### 💬 Community Support

- Submit issues on GitHub for bugs
- Feature requests welcome
- Security issues: responsible disclosure
- Contributions: follow coding standards

---

## 📝 Conclusion

DotDotPwn Python Implementation provides a modern, powerful platform for directory traversal vulnerability assessment. With its comprehensive module system, intelligent fuzzing capabilities, and extensive parameter options, it serves as an essential tool for security professionals.

Remember to always use this tool responsibly and within the bounds of authorized testing. The enhanced Python implementation maintains full compatibility with the original Perl version while providing modern features for integration into contemporary security workflows.

**Happy (authorized) testing! 🚀**

---

_Last updated: September 2025_
_Version: 3.0.2_
