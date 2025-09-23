# 🚀 DotDotPwn Python Implementation

A comprehensive directory traversal fuzzer ported from Perl to Python with enhanced API capabilities for GUI integration.

![DotDotPwn Python](https://img.shields.io/badge/DotDotPwn-Python-blue.svg)
![Version](https://img.shields.io/badge/version-3.0.2-green.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-red.svg)

## ✨ Key Enhancements Over Original Perl Version

### 🎯 Enhanced User Experience

- **Memorable Parameter Names**: Both short (`-h`) and long (`--host`, `--hostname`) options for better usability
- **Rich Terminal Output**: Beautiful colored output with emojis and progress indicators
- **Comprehensive Help System**: Built-in examples and module documentation
- **Smart Error Handling**: Graceful error recovery and detailed error messages

### 🚀 Modern Python Features

- **Async/Await Support**: Non-blocking HTTP requests for better performance
- **REST API**: Complete FastAPI implementation for GUI integration
- **Type Safety**: Full type hints for better development experience
- **Modern Packaging**: Proper Python packaging with `pyproject.toml`

### 📊 Enhanced Reporting

- **Multiple Formats**: JSON, CSV, XML, HTML, and text reports
- **Comprehensive Documentation**: Detailed guides for beginners and experts
- **Better Error Handling**: Graceful degradation and continue-on-error options

## 📚 Documentation

- **📋 [Complete User Guide](COMPREHENSIVE_GUIDE.md)** - Detailed documentation from A-Z
- **⚡ [Quick Reference](QUICK_REFERENCE.md)** - Essential commands and parameters
- **🛠️ [Installation Guide](INSTALLATION.md)** - Step-by-step setup instructions

## 🎯 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Enhanced Parameter Names](#enhanced-parameter-names)
- [Usage Examples](#usage-examples)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## 🌟 Enhanced Parameter Names

One of the key improvements over the original Perl implementation is the support for both traditional short parameters and memorable long parameter names:

### 🎯 Core Parameters

| Traditional | Enhanced Alternatives                       | Description               |
| ----------- | ------------------------------------------- | ------------------------- |
| `-m`        | `--module`                                  | Fuzzing module selection  |
| `-h`        | `--host`, `--hostname`                      | Target hostname or IP     |
| `-f`        | `--file`, `--filename`, `--target-file`     | Target file to test       |
| `-k`        | `--pattern`, `--keyword`, `--match-pattern` | Success detection pattern |
| `-d`        | `--depth`, `--max-depth`                    | Maximum traversal depth   |

### 🔍 Detection & Intelligence

| Traditional | Enhanced Alternatives                  | Description               |
| ----------- | -------------------------------------- | ------------------------- |
| `-O`        | `--os-detection`, `--detect-os`        | Enable OS detection       |
| `-o`        | `--os-type`, `--operating-system`      | Manual OS specification   |
| `-s`        | `--service-detection`, `--banner-grab` | Service version detection |

### 🔒 Security & Protocol Options

| Traditional | Enhanced Alternatives       | Description               |
| ----------- | --------------------------- | ------------------------- |
| `-S`        | `--ssl`, `--https`, `--tls` | Enable SSL/TLS encryption |
| `-U`        | `--username`, `--user`      | Authentication username   |
| `-P`        | `--password`, `--pass`      | Authentication password   |
| `-M`        | `--method`, `--http-method` | HTTP request method       |

### ⚡ Performance & Behavior

| Traditional | Enhanced Alternatives                            | Description                    |
| ----------- | ------------------------------------------------ | ------------------------------ |
| `-t`        | `--delay`, `--time-delay`                        | Delay between requests         |
| `-b`        | `--break`, `--break-on-first`, `--stop-on-first` | Stop after first vulnerability |
| `-C`        | `--continue`, `--continue-on-error`              | Continue on connection errors  |
| `-q`        | `--quiet`, `--silent`                            | Quiet mode                     |

### 📊 Output & Reporting

| Traditional | Enhanced Alternatives                   | Description             |
| ----------- | --------------------------------------- | ----------------------- |
| `-r`        | `--report`, `--report-file`, `--output` | Output report filename  |
|             | `--report-format`, `--format`           | Report format selection |

**Examples:**

```bash
# Traditional style (still supported)
dotdotpwn -m http -h example.com -f /etc/passwd -k "root:" -d 8 -S -O -b -q

# Enhanced readable style
dotdotpwn --module http --hostname example.com --target-file /etc/passwd --pattern "root:" --max-depth 8 --ssl --detect-os --break-on-first --quiet

# Mixed style (both work together)
dotdotpwn --module http -h example.com --file /etc/passwd -k "root:" --depth 8 --ssl -O --break-on-first
```

## 📦 Installation

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python

# 2. Create virtual environment (recommended)
python3 -m venv dotdotpwn-env
source dotdotpwn-env/bin/activate  # Linux/macOS
# dotdotpwn-env\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python dotdotpwn.py --help
```

### System Requirements

- **Python 3.8+** (Python 3.10+ recommended)
- **pip** package manager
- **Optional:** nmap (for OS detection features)

### Dependencies

All dependencies are listed in `requirements.txt`:

- Core: `typer`, `rich`, `aiohttp`, `requests`
- API: `fastapi`, `uvicorn`, `pydantic`
- Security: `cryptography`, `dnspython`
- Protocols: `python-nmap`, `ftplib2`

See [📋 Installation Guide](INSTALLATION.md) for detailed setup instructions.

## 🚀 Quick Start

### Basic HTTP Scan

```bash
# Simple directory traversal test
python dotdotpwn.py --module http --host example.com --file /etc/passwd --pattern "root:"

# HTTPS with OS detection
python dotdotpwn.py --module http --host example.com --ssl --detect-os --break-on-first
```

### Get Help and Examples

```bash
# Show all available options
python dotdotpwn.py --help

# Show comprehensive usage examples
python dotdotpwn.py help-examples

# Show detailed module information
python dotdotpwn.py help-modules
```

### Command Line Interface

The CLI interface maintains compatibility with the original dotdotpwn.pl syntax:

#### Basic HTTP Scanning

```bash
# Basic HTTP directory traversal scan
python dotdotpwn.py -m http -h 192.168.1.1 -x 8080 -f /etc/hosts -k "localhost" -d 8

# HTTPS scanning with OS detection
python dotdotpwn.py -m http -h example.com -x 443 -S -O -f /etc/passwd -k "root:"

# HTTP with specific method and authentication
python dotdotpwn.py -m http -h 192.168.1.1 -M POST -f /etc/passwd -k "root:" -b
```

#### HTTP-URL Module

```bash
# URL-based fuzzing with TRAVERSAL placeholder
python dotdotpwn.py -m http-url -u "http://example.com/test.php?file=TRAVERSAL" -k "root:" -O

# URL fuzzing with specific depth and pattern
python dotdotpwn.py -m http-url -u "http://example.com/include.php?page=TRAVERSAL" -k "<!DOCTYPE" -d 10
```

#### FTP Scanning

```bash
# FTP anonymous login
python dotdotpwn.py -m ftp -h 192.168.1.1 -f /etc/passwd -k "root:" -b

# FTP with credentials
python dotdotpwn.py -m ftp -h 192.168.1.1 -U testuser -P testpass -f /etc/shadow -k "root:"
```

#### TFTP Scanning

```bash
# TFTP scanning
python dotdotpwn.py -m tftp -h 192.168.1.1 -f /etc/passwd -k "root:" -d 8
```

#### Payload Module

```bash
# Custom payload fuzzing
python dotdotpwn.py -m payload -h 192.168.1.1 -x 21 -p ftp_payload.txt -k "root:"

# SSL payload fuzzing
python dotdotpwn.py -m payload -h 192.168.1.1 -x 443 -p https_payload.txt -S -k "root:"
```

#### Generate Traversals (STDOUT)

```bash
# Generate traversal patterns for Unix systems
python dotdotpwn.py -m stdout -d 8 -o unix -f /etc/passwd

# Generate Windows traversals with extension
python dotdotpwn.py -m stdout -d 6 -o windows -f boot.ini -e .bak
```

#### Advanced Options

```bash
# Bisection algorithm to find exact depth
python dotdotpwn.py -m http -h example.com -f /etc/passwd -k "root:" -X

# Custom time delay and continue on errors
python dotdotpwn.py -m http -h example.com -f /etc/passwd -k "root:" -t 1.0 -C

# Quiet mode with specific report format
python dotdotpwn.py -m http -h example.com -f /etc/passwd -k "root:" -q -r report.json --report-format json
```

### REST API

Start the API server:

```bash
# Start API server
python dotdotpwn.py api --host 0.0.0.0 --port 8000

# Development mode with auto-reload
python dotdotpwn.py api --host localhost --port 8000 --reload
```

#### API Endpoints

- `GET /` - API information and status
- `POST /scan/http` - HTTP directory traversal scanning
- `POST /scan/http-url` - HTTP URL fuzzing
- `POST /scan/ftp` - FTP directory traversal scanning
- `POST /scan/tftp` - TFTP directory traversal scanning
- `POST /scan/payload` - Custom payload fuzzing
- `GET /scan/{scan_id}/status` - Get scan status
- `GET /scan/{scan_id}/results` - Get scan results
- `POST /utils/generate-traversals` - Generate traversal patterns
- `POST /utils/fingerprint` - OS and service detection

#### API Usage Examples

```python
import requests

# Start HTTP scan
response = requests.post("http://localhost:8000/scan/http", json={
    "host": "example.com",
    "port": 80,
    "os_type": "unix",
    "depth": 6,
    "specific_file": "/etc/passwd",
    "pattern": "root:"
})

scan_id = response.json()["scan_id"]

# Check status
status = requests.get(f"http://localhost:8000/scan/{scan_id}/status")
print(status.json())

# Get results
results = requests.get(f"http://localhost:8000/scan/{scan_id}/results")
print(results.json())
```

### Python Library

Use DotDotPwn as a Python library:

```python
import asyncio
from dotdotpwn import HTTPFuzzer, TraversalEngine, OSType

async def main():
    # Create HTTP fuzzer
    fuzzer = HTTPFuzzer(host="example.com", port=80)

    # Run scan
    results = await fuzzer.generate_and_fuzz(
        os_type=OSType.UNIX,
        depth=6,
        specific_file="/etc/passwd",
        pattern="root:",
        break_on_first=True
    )

    print(f"Found {results['vulnerabilities_found']} vulnerabilities")
    for vuln in results['vulnerabilities']:
        print(f"Vulnerable: {vuln['traversal']}")

# Run async main
asyncio.run(main())
```

## Modules

### Core Modules

- **TraversalEngine** - Generates directory traversal patterns with 24 dot representations and 29 slash encodings
- **Fingerprint** - OS detection, service fingerprinting, and banner grabbing
- **BisectionAlgorithm** - Binary search to find exact vulnerability depth

### Protocol Modules

- **HTTPFuzzer** - HTTP/HTTPS directory traversal testing with async support
- **HTTPURLFuzzer** - URL-based fuzzing with TRAVERSAL placeholder replacement
- **FTPFuzzer** - FTP directory traversal testing with authentication
- **TFTPFuzzer** - TFTP directory traversal testing over UDP
- **PayloadFuzzer** - Custom protocol fuzzing with SSL support

### Utility Modules

- **Reporter** - Multi-format report generation (text, JSON, CSV, XML, HTML)
- **STDOUTHandler** - Formatted console output with progress tracking

## Examples

### Example Payload Files

**HTTP Payload (http_payload.txt):**

```
GET TRAVERSAL HTTP/1.1
Host: example.com
User-Agent: DotDotPwn/3.0.2
Connection: close

```

**FTP Payload (ftp_payload.txt):**

```
USER anonymous
PASS dot@dot.pwn
RETR TRAVERSAL
QUIT
```

### Example Reports

The tool generates comprehensive reports in multiple formats:

- **Text Report** - Human-readable format with detailed vulnerability information
- **JSON Report** - Machine-readable format for integration with other tools
- **CSV Report** - Spreadsheet-compatible format for analysis
- **XML Report** - Structured format for data processing
- **HTML Report** - Web-friendly format with syntax highlighting

## API Documentation

When the API server is running, visit `http://localhost:8000/docs` for interactive API documentation powered by FastAPI and Swagger UI.

## Testing

Run the test suite:

```bash
# Run all tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_dotdotpwn.py::TestTraversalEngine

# Run basic tests without external dependencies
python tests/test_dotdotpwn.py
```

## Project Structure

```
dotdotpwn-python/
├── src/dotdotpwn/              # Main package
│   ├── core/                   # Core components
│   │   ├── traversal_engine.py
│   │   ├── fingerprint.py
│   │   └── bisection_algorithm.py
│   ├── protocols/              # Protocol fuzzers
│   │   ├── http_fuzzer.py
│   │   ├── http_url_fuzzer.py
│   │   ├── ftp_fuzzer.py
│   │   ├── tftp_fuzzer.py
│   │   └── payload_fuzzer.py
│   ├── utils/                  # Utilities
│   │   └── reporter.py
│   ├── api/                    # REST API
│   │   ├── app.py
│   │   └── main.py
│   ├── cli.py                  # Command line interface
│   ├── stdout.py               # Output handling
│   └── __init__.py
├── tests/                      # Test suite
├── docs/                       # Documentation
├── requirements.txt            # Dependencies
├── pyproject.toml             # Project configuration
├── dotdotpwn.py               # Main entry point
└── README.md                  # This file
```

## Original Perl Implementation Credits

- **Authors**: chr1x & nitr0us
- **Original Project**: [DotDotPwn](https://github.com/wireghoul/dotdotpwn)
- **License**: GPL-3.0-or-later

## Python Implementation

This Python implementation maintains 100% feature parity with the original Perl version while adding modern enhancements for better performance, usability, and integration capabilities.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the GPL-3.0-or-later license, maintaining compatibility with the original DotDotPwn Perl implementation.

## Security Notice

This tool is intended for authorized security testing only. Always ensure you have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

---

**Note**: This Python implementation is designed to be a drop-in replacement for the original Perl version with additional API capabilities for GUI integration. All original command-line options and functionality are preserved.
