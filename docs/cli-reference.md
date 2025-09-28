---
layout: page
title: "CLI Reference"
permalink: /cli-reference/
---

# 💻 Complete CLI Reference

This is the comprehensive command-line interface reference for PyDotPwn. Every parameter, option, and feature is documented with examples and use cases.

## 📋 Table of Contents

- [Command Structure](#command-structure)
- [Enhanced Parameter Names](#enhanced-parameter-names)
- [Core Parameters](#core-parameters)
- [Module-Specific Parameters](#module-specific-parameters)
- [Advanced Options](#advanced-options)
- [Output and Reporting](#output-and-reporting)
- [Performance Tuning](#performance-tuning)
- [Examples by Use Case](#examples-by-use-case)

## 🏗️ Command Structure

PyDotPwn uses a modern CLI structure with multiple command modes:

### Main Scanning Commands

```bash
# Primary scanning interface
python dotdotpwn.py main [OPTIONS]

# Pattern generation mode
python dotdotpwn.py generate [OPTIONS]

# API server mode
python dotdotpwn.py api [OPTIONS]

# Help and examples
python dotdotpwn.py help-examples
python dotdotpwn.py help-modules
```

### Legacy Compatibility

```bash
# Direct execution (maintains compatibility)
python dotdotpwn.py [OPTIONS]
```

## 🎯 Enhanced Parameter Names

One of the key improvements over the original Perl implementation is support for both traditional short parameters and memorable long parameter names.

### Core Parameters

| Short | Long Options | Type | Description | Example |
|-------|-------------|------|-------------|---------|
| `-m` | `--module` | choice | Fuzzing module selection | `-m http` |
| `-h` | `--host`, `--hostname` | string | Target hostname or IP address | `-h example.com` |
| `-f` | `--file`, `--filename`, `--target-file` | string | Target file to test for | `-f /etc/passwd` |
| `-k` | `--pattern`, `--keyword`, `--match-pattern` | string | Success detection pattern | `-k "root:"` |
| `-d` | `--depth`, `--max-depth` | integer | Maximum traversal depth | `-d 10` |
| `-x` | `--port` | integer | Target port number | `-x 8080` |

### Detection & Intelligence

| Short | Long Options | Type | Description | Example |
|-------|-------------|------|-------------|---------|
| `-O` | `--os-detection`, `--detect-os` | flag | Enable OS detection | `-O` |
| `-o` | `--os-type`, `--operating-system` | choice | Manual OS specification | `-o windows` |
| `-s` | `--service-detection`, `--banner-grab` | flag | Service version detection | `-s` |
| `-E` | `--extra-files` | flag | Include additional common files | `-E` |
| `-X` | `--bisection`, `--binary-search` | flag | Use bisection algorithm | `-X` |

### Protocol & Security Options

| Short | Long Options | Type | Description | Example |
|-------|-------------|------|-------------|---------|
| `-S` | `--ssl`, `--https`, `--tls` | flag | Enable SSL/TLS encryption | `-S` |
| `-U` | `--username`, `--user` | string | Authentication username | `-U admin` |
| `-P` | `--password`, `--pass` | string | Authentication password | `-P secret` |
| `-M` | `--method`, `--http-method` | choice | HTTP request method | `-M POST` |
| `-A` | `--user-agent` | string | Custom User-Agent header | `-A "Mozilla/5.0..."` |

### Performance & Behavior

| Short | Long Options | Type | Description | Example |
|-------|-------------|------|-------------|---------|
| `-t` | `--delay`, `--time-delay` | float | Delay between requests (seconds) | `-t 0.5` |
| `-b` | `--break`, `--break-on-first`, `--stop-on-first` | flag | Stop after first vulnerability | `-b` |
| `-C` | `--continue`, `--continue-on-error` | flag | Continue on connection errors | `-C` |
| `-q` | `--quiet`, `--silent` | flag | Quiet mode (minimal output) | `-q` |

### Output & Reporting

| Short | Long Options | Type | Description | Example |
|-------|-------------|------|-------------|---------|
| `-r` | `--report`, `--report-file`, `--output` | string | Output report filename | `-r results.json` |
| `-F` | `--format`, `--report-format` | choice | Report format | `-F json` |
| `-T` | `--timestamp` | flag | Add timestamp to reports | `-T` |

## 🧩 Module-Specific Parameters

### HTTP Module (`--module http`)

The HTTP module is the most versatile, designed for testing web applications.

#### Basic HTTP Parameters

```bash
# Required
--module http
--host <hostname>
--pattern <success_pattern>

# Optional
--port <port>              # Default: 80 (443 if SSL)
--ssl                      # Enable HTTPS
--method <GET|POST|HEAD>   # HTTP method
--user-agent <string>      # Custom User-Agent
```

#### HTTP Examples

```bash
# Basic HTTP scan
python dotdotpwn.py --module http --host example.com --pattern "root:"

# HTTPS with custom port
python dotdotpwn.py --module http --host secure.example.com --port 8443 --ssl --pattern "Administrator"

# POST request with authentication
python dotdotpwn.py --module http --host internal.com --method POST --username admin --password secret --pattern "sensitive"

# Custom User-Agent for stealth
python dotdotpwn.py --module http --host target.com --user-agent "Mozilla/5.0 (compatible; SecurityScanner)" --pattern "root:"
```

### HTTP-URL Module (`--module http-url`)

Specialized for testing specific URL parameters with the TRAVERSAL placeholder.

#### HTTP-URL Parameters

```bash
# Required
--module http-url
--url <url_with_TRAVERSAL_placeholder>
--pattern <success_pattern>

# The URL must contain the word "TRAVERSAL" which will be replaced with directory traversal patterns
```

#### HTTP-URL Examples

```bash
# Basic URL parameter testing
python dotdotpwn.py --module http-url --url "http://example.com/page.php?file=TRAVERSAL" --pattern "root:"

# HTTPS with complex URL
python dotdotpwn.py --module http-url --url "https://app.com/api/v1/files/TRAVERSAL?format=raw" --pattern "<?php"

# POST data parameter testing
python dotdotpwn.py --module http-url --url "http://site.com/upload.php" --method POST --data "filename=TRAVERSAL&action=view" --pattern "sensitive"
```

### FTP Module (`--module ftp`)

Tests FTP servers for directory traversal vulnerabilities.

#### FTP Parameters

```bash
# Required
--module ftp
--host <hostname>

# Optional
--port <port>              # Default: 21
--username <username>      # Default: anonymous
--password <password>      # Default: dot@dot.pwn
--pattern <pattern>        # Success detection pattern
```

#### FTP Examples

```bash
# Anonymous FTP testing
python dotdotpwn.py --module ftp --host ftp.example.com --pattern "root:"

# Authenticated FTP testing
python dotdotpwn.py --module ftp --host 192.168.1.100 --username admin --password secret --pattern "Administrator"

# Custom port FTP
python dotdotpwn.py --module ftp --host ftp.company.com --port 2121 --pattern "sensitive"
```

### TFTP Module (`--module tftp`)

Tests TFTP (Trivial File Transfer Protocol) servers, common in network devices.

#### TFTP Parameters

```bash
# Required
--module tftp
--host <hostname>

# Optional
--port <port>              # Default: 69
--pattern <pattern>        # Success detection pattern
--file <target_file>       # Target file to retrieve
```

#### TFTP Examples

```bash
# Basic TFTP testing
python dotdotpwn.py --module tftp --host 192.168.1.1 --pattern "root:"

# Network device configuration testing
python dotdotpwn.py --module tftp --host router.company.com --file startup-config --pattern "enable secret"

# Windows TFTP testing
python dotdotpwn.py --module tftp --host windows-server.com --file boot.ini --pattern "Windows"
```

### Payload Module (`--module payload`)

For testing custom protocols or services with custom payloads.

#### Payload Parameters

```bash
# Required
--module payload
--host <hostname>
--port <port>
--payload-file <filename>

# Optional
--ssl                      # Enable SSL/TLS
--pattern <pattern>        # Success detection pattern
```

#### Payload Examples

```bash
# Custom protocol testing
python dotdotpwn.py --module payload --host service.com --port 9999 --payload-file custom_payloads.txt --pattern "access granted"

# SSL custom service
python dotdotpwn.py --module payload --host secure-service.com --port 443 --ssl --payload-file ssl_payloads.txt --pattern "directory:"
```

### STDOUT Module (`--module stdout`)

Generates directory traversal patterns and outputs them to stdout for use with other tools.

#### STDOUT Parameters

```bash
# Required
--module stdout

# Optional
--depth <depth>            # Pattern depth
--os-type <unix|windows|generic>
--file <target_file>       # Target file for patterns
--extension <ext>          # File extension to append
```

#### STDOUT Examples

```bash
# Generate Unix patterns
python dotdotpwn.py --module stdout --depth 8 --os-type unix --file /etc/passwd

# Generate Windows patterns with extension
python dotdotpwn.py --module stdout --depth 6 --os-type windows --file boot.ini --extension .bak

# Generate generic patterns
python dotdotpwn.py --module stdout --depth 10 --os-type generic --file config.txt | head -50
```

## 🔍 Advanced Options

### OS Detection (`--os-detection`, `-O`)

Automatically detects the target operating system using nmap and adjusts patterns accordingly.

```bash
# Enable OS detection
python dotdotpwn.py --module http --host example.com --os-detection --pattern "root:"

# Manual OS specification (if detection fails)
python dotdotpwn.py --module http --host example.com --os-type windows --pattern "Administrator"
```

**Supported OS Types:**
- `unix` - Linux, Unix, BSD systems
- `windows` - Windows systems
- `generic` - Universal patterns

### Service Detection (`--service-detection`, `-s`)

Performs banner grabbing and service version detection.

```bash
# Enable service detection
python dotdotpwn.py --module http --host example.com --service-detection --pattern "root:"

# Combines well with OS detection
python dotdotpwn.py --module http --host example.com --os-detection --service-detection --pattern "root:"
```

### Bisection Algorithm (`--bisection`, `-X`)

Uses binary search to find the exact depth where the vulnerability exists, minimizing the number of requests.

```bash
# Enable bisection algorithm
python dotdotpwn.py --module http --host example.com --bisection --pattern "root:"

# How it works:
# 1. Tests maximum depth first
# 2. If vulnerability found, searches for minimum working depth
# 3. Uses binary search to minimize test count
# 4. Provides exact vulnerability depth
```

### Extra Files (`--extra-files`, `-E`)

Includes additional common files based on the detected or specified OS type.

```bash
# Include extra common files
python dotdotpwn.py --module http --host example.com --extra-files --pattern "root:"

# Extra files included:
# Unix: /etc/shadow, /etc/group, /etc/hosts, /proc/version
# Windows: boot.ini, win.ini, system.ini, autoexec.bat
```

## 📊 Output and Reporting

### Report Formats

DotDotPwn supports multiple output formats for different use cases:

```bash
# Text format (default, human-readable)
python dotdotpwn.py --module http --host example.com --report results.txt --format text

# JSON format (machine-readable, structured)
python dotdotpwn.py --module http --host example.com --report results.json --format json

# CSV format (spreadsheet-compatible)
python dotdotpwn.py --module http --host example.com --report results.csv --format csv

# XML format (structured data exchange)
python dotdotpwn.py --module http --host example.com --report results.xml --format xml

# HTML format (web-friendly with styling)
python dotdotpwn.py --module http --host example.com --report report.html --format html
```

### Report Structure

#### JSON Report Example

```json
{
  "scan_info": {
    "target": "example.com",
    "module": "http",
    "timestamp": "2025-09-28T10:30:00Z",
    "duration": 23.4,
    "total_requests": 247
  },
  "vulnerabilities": [
    {
      "url": "http://example.com/page.php?file=../../../etc/passwd",
      "method": "GET",
      "depth": 3,
      "pattern_matched": "root:",
      "response_code": 200,
      "content_length": 1847
    }
  ],
  "statistics": {
    "vulnerabilities_found": 1,
    "total_patterns_tested": 247,
    "average_response_time": 0.312,
    "success_rate": 0.4
  }
}
```

### Output Control

```bash
# Quiet mode (minimal output)
python dotdotpwn.py --module http --host example.com --quiet --pattern "root:"

# Verbose mode (detailed output)
python dotdotpwn.py --module http --host example.com --verbose --pattern "root:"

# Timestamped reports
python dotdotpwn.py --module http --host example.com --timestamp --report results.json
```

## ⚡ Performance Tuning

### Request Timing

```bash
# Fast scanning (be careful not to overwhelm target)
python dotdotpwn.py --module http --host example.com --delay 0.1 --pattern "root:"

# Standard scanning (recommended)
python dotdotpwn.py --module http --host example.com --delay 0.3 --pattern "root:"

# Slow/stealth scanning
python dotdotpwn.py --module http --host example.com --delay 2.0 --pattern "root:"
```

### Depth Control

```bash
# Shallow scan (faster)
python dotdotpwn.py --module http --host example.com --depth 4 --pattern "root:"

# Standard depth
python dotdotpwn.py --module http --host example.com --depth 6 --pattern "root:"

# Deep scan (thorough but slower)
python dotdotpwn.py --module http --host example.com --depth 12 --pattern "root:"
```

### Optimization Flags

```bash
# Break on first vulnerability found
python dotdotpwn.py --module http --host example.com --break-on-first --pattern "root:"

# Continue on connection errors
python dotdotpwn.py --module http --host example.com --continue-on-error --pattern "root:"

# Combine for fastest scanning
python dotdotpwn.py --module http --host example.com --break-on-first --continue-on-error --quiet --delay 0.1 --pattern "root:"
```

## 🎯 Examples by Use Case

### Web Application Testing

```bash
# Basic web app scan
python dotdotpwn.py --module http --host webapp.com --pattern "<?php" --depth 8

# E-commerce site testing
python dotdotpwn.py --module http --host shop.com --pattern "mysql_connect" --extra-files --os-detection

# API endpoint testing
python dotdotpwn.py --module http --host api.service.com --port 8080 --method POST --pattern "database" --user-agent "API-Scanner/1.0"
```

### Infrastructure Assessment

```bash
# FTP server assessment
python dotdotpwn.py --module ftp --host ftp.company.com --pattern "confidential" --username test --password test

# Network device testing
python dotdotpwn.py --module tftp --host 192.168.1.1 --pattern "enable secret" --file startup-config

# Custom service testing
python dotdotpwn.py --module payload --host custom-service.com --port 9999 --payload-file custom.txt --pattern "access"
```

### Stealth and Evasion

```bash
# Low and slow scanning
python dotdotpwn.py --module http --host target.com --delay 3.0 --depth 6 --quiet --continue-on-error

# Custom User-Agent
python dotdotpwn.py --module http --host target.com --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" --pattern "root:"

# Minimal footprint
python dotdotpwn.py --module http --host target.com --break-on-first --delay 1.0 --quiet --pattern "sensitive"
```

### Comprehensive Assessment

```bash
# Full-featured scan with all intelligence
python dotdotpwn.py --module http --host target.com --os-detection --service-detection --extra-files --bisection --report full_assessment.json --format json --timestamp

# Multi-format reporting
python dotdotpwn.py --module http --host target.com --pattern "root:" --report results.json --format json --continue-on-error
python dotdotpwn.py --module http --host target.com --pattern "root:" --report results.html --format html --continue-on-error
```

### Pattern Generation

```bash
# Generate patterns for external tools
python dotdotpwn.py --module stdout --depth 8 --os-type unix --file /etc/passwd > unix_patterns.txt

# Generate Windows patterns
python dotdotpwn.py --module stdout --depth 6 --os-type windows --file boot.ini --extension .bak > windows_patterns.txt

# Generate and pipe to other tools
python dotdotpwn.py --module stdout --depth 10 --file config.txt | head -100 | while read pattern; do echo "Testing: $pattern"; done
```

## 🔧 Environment Variables

Set these environment variables to customize default behavior:

```bash
# Default delay between requests
export DOTDOTPWN_DEFAULT_DELAY=0.5

# Default traversal depth
export DOTDOTPWN_DEFAULT_DEPTH=6

# Default report format
export DOTDOTPWN_DEFAULT_FORMAT=json

# Enable debug mode
export DOTDOTPWN_DEBUG=1

# SSL verification (for testing environments)
export PYTHONHTTPSVERIFY=0  # Use with caution
```

## 📝 Configuration File

Create `~/.dotdotpwn/config.yaml` for persistent settings:

```yaml
# Default scan settings
default_delay: 0.3
default_depth: 6
default_format: json
continue_on_error: true
quiet_mode: false

# Default patterns for different scenarios
patterns:
  unix: "root:"
  windows: "Administrator"
  web: "<?php"
  database: "mysql_connect"
  config: "[main]"

# HTTP settings
http:
  default_user_agent: "DotDotPwn/3.0.2"
  timeout: 30
  max_redirects: 5

# Reporting settings
reports:
  directory: "~/dotdotpwn-reports"
  auto_timestamp: true
  default_format: "json"

# Performance settings
performance:
  default_delay: 0.3
  max_concurrent: 10
  timeout: 30
```

---

This CLI reference covers all available options and parameters. For specific examples and real-world scenarios, check out the [Examples section](examples) or continue with the [GUI Guide](gui-guide) for the graphical interface documentation.