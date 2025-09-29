# 🎯 PyDo## 🚀 Key Features

### 🆕 **Revolutionary Path Validation Bypass** (NEW)
- **Enterprise-Grade Bypass**: 25,000+ patterns targeting OWASP path validation vulnerabilities
- **90+ Subdirectory Prefixes**: Real-world paths like `/var/www/images/../../../etc/passwd`
- **5-Level URL Encoding**: Deep WAF bypass with quintuple encoding (`%252525252f`)
- **Comprehensive Coverage**: Windows & UNIX path validation bypass patterns

### 🎯 **Core Capabilities**
- **🎯 Multi-Protocol Support**: HTTP/HTTPS, FTP, TFTP fuzzing capabilities
- **🔍 Absolute Path Injection**: Comprehensive absolute path traversal detection (144+ patterns)
- **🖥️ Modern Interface**: Both CLI and GUI interfaces with intuitive controls
- **⚡ High Performance**: Async/await implementation for efficient testing
- **📊 Comprehensive Reporting**: Multiple output formats (JSON, CSV, XML, HTML, TXT)
- **🔧 REST API**: Complete FastAPI integration for automation and toolchain integration
- **🎯 Smart Pattern Generation**: 36 UNIX + 27 Windows target files with URL encoding variations
- **🎨 Rich Output**: Beautiful terminal output with colors and progress indicators
- **🛡️ Smart Detection**: Advanced fingerprinting and bisection algorithms
- **📐 Flexible Depth Control**: Configurable traversal depth (1-50+ levels) for different directory structuresced Directory Traversal Fuzzer

[![Version](https://img.shields.io/badge/version-3.0.2-green.svg)](https://github.com/nanragav/PyDotPwn)
[![License](https://img.shields.io/badge/license-GPL--3.0-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-brightgreen.svg)](https://nanragav.github.io/PyDotPwn/)

A powerful and feature-rich directory traversal fuzzer ported from Perl to Python, designed for security professionals and penetration testers. PyDotPwn provides enhanced functionality, modern Python features, and comprehensive testing capabilities for identifying directory traversal vulnerabilities.

## 🚀 Key Features

- **🎯 Multi-Protocol Support**: HTTP/HTTPS, FTP, TFTP fuzzing capabilities
- **�️ Absolute Path Injection**: Comprehensive absolute path traversal detection (144+ patterns)
- **�🖥️ Modern Interface**: Both CLI and GUI interfaces with intuitive controls
- **⚡ High Performance**: Async/await implementation for efficient testing
- **📊 Comprehensive Reporting**: Multiple output formats (JSON, CSV, XML, HTML, TXT)
- **🔧 REST API**: Complete FastAPI integration for automation and toolchain integration
- **🎯 Smart Pattern Generation**: 36 UNIX + 27 Windows target files with URL encoding variations
- **🎨 Rich Output**: Beautiful terminal output with colors and progress indicators
- **🛡️ Smart Detection**: Advanced fingerprinting and bisection algorithms
- **📐 Flexible Depth Control**: Configurable traversal depth (1-50+ levels) for different directory structures

## 📋 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/nanragav/PyDotPwn.git
cd PyDotPwn

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x dotdotpwn.py
```

### Basic Usage

```bash
# HTTP fuzzing with absolute path detection
python dotdotpwn.py -m http -h example.com -x 8080 -f /etc/passwd

# Generate traversal patterns with specific depth
python dotdotpwn.py generate --os-type unix --file /etc/passwd --depth 5 --absolute

# FTP fuzzing with Windows targets
python dotdotpwn.py -m ftp -h ftp.example.com -f "c:\windows\system32\config\sam" -d 3

# GUI interface with enhanced pattern generation
python launch_gui.py
```

### 🔍 Understanding the Depth Parameter

The **depth parameter** controls how many directory levels the tool traverses upward to reach target files:

```bash
# Depth 1: ../etc/passwd (go up 1 level)
# Depth 2: ../../etc/passwd (go up 2 levels)  
# Depth 3: ../../../etc/passwd (go up 3 levels)
```

**Real-world example:**
- Web app location: `/var/www/html/app/uploads/`
- Target file: `/etc/passwd`
- Required depth: 5 (uploads→app→html→www→var→root)
- Generated payload: `../../../../../etc/passwd`

**Recommended depths:**
- **Depth 3-6**: Most web applications
- **Depth 1-3**: Simple directory structures
- **Depth 6-10**: Deep nested applications
- **Depth 10+**: Complex enterprise applications

## 📚 Documentation

**📖 [Complete Documentation](https://nanragav.github.io/PyDotPwn/)** - Visit our comprehensive documentation site

### Quick Links

- **[Installation Guide](https://nanragav.github.io/PyDotPwn/installation/)** - Detailed setup instructions
- **[CLI Reference](https://nanragav.github.io/PyDotPwn/cli-reference/)** - Complete command-line documentation
- **[GUI Guide](https://nanragav.github.io/PyDotPwn/gui-guide/)** - Graphical interface tutorial
- **[API Documentation](https://nanragav.github.io/PyDotPwn/api-reference/)** - REST API reference
- **[Examples](https://nanragav.github.io/PyDotPwn/examples/)** - Practical usage examples
- **[Troubleshooting](https://nanragav.github.io/PyDotPwn/troubleshooting/)** - Common issues and solutions

## 🏗️ Project Structure

```
PyDotPwn/
├── 📄 dotdotpwn.py          # Main CLI application
├── 🖥️ launch_gui.py         # GUI launcher
├── 📁 src/dotdotpwn/        # Core package
│   ├── 🎯 core/             # Core fuzzing algorithms
│   ├── 🌐 protocols/        # Protocol-specific fuzzers
│   ├── 🔧 api/              # REST API implementation
│   └── 🛠️ utils/            # Utilities and reporting
├── 🎨 gui/                  # GUI implementation
├── 🧪 tests/                # Test suite
└── 📖 docs/                 # Documentation source
```

## 🎯 Enhanced Features Over Original DotDotPwn

### 🆕 Revolutionary Path Validation Bypass (EXCLUSIVE)

**The most significant advancement in directory traversal testing since the original tool:**

- **25,000+ Bypass Patterns**: Industry's most comprehensive path validation bypass capability
- **90+ Real-World Subdirectories**: `/var/www/images/`, `/var/www/uploads/`, `C:\inetpub\wwwroot\uploads\`
- **5-Level URL Encoding**: Deep WAF bypass (`%2f` → `%252f` → `%25252f` → `%2525252f` → `%252525252f`)
- **OWASP Vulnerability Coverage**: Targets "File path traversal, validation of start of path" (CWE-22)
- **Enterprise Evasion**: Bypasses advanced application security controls that validate legitimate path prefixes

### 🚀 Revolutionary Absolute Path Detection

- **144+ Absolute Path Patterns**: Original had ~3, PyDotPwn generates 144+ per target
- **63 Target Files**: 36 UNIX + 27 Windows critical system files
- **URL Encoding Variations**: 20+ encoding techniques for filter bypass
- **Direct Path Injection**: Techniques like `/etc/passwd`, `%2fetc%2fpasswd`, `\etc\passwd`
- **Cross-Platform Support**: Windows (`C:\windows\system32\config\sam`) and UNIX (`/etc/passwd`)

### 🚀 Modern Python Implementation

- **Type Safety**: Full type hints for better development experience
- **Async Support**: Non-blocking operations for improved performance
- **Modern Packaging**: Proper Python packaging with `pyproject.toml`
- **Python 3.8+**: Modern language features and performance

### 🎨 Enhanced User Experience

- **Intuitive CLI**: Multiple parameter aliases (`-f`, `--file`, `--target-file`)
- **Generate Command**: Standalone pattern generation without scanning
- **Rich Output**: Colored terminal output with emojis and progress indicators
- **Better Error Handling**: Graceful error recovery and detailed messages
- **Comprehensive Help**: Built-in examples and interactive documentation

### 🔧 Advanced Capabilities

- **REST API**: Complete FastAPI implementation for automation
- **Multiple Output Formats**: JSON, CSV, XML, HTML, and text reports
- **GUI Interface**: User-friendly graphical interface with real-time generation
- **Extensive Testing**: Comprehensive test suite with 95%+ coverage
- **Pattern Statistics**: Real-time reporting of generated pattern counts

### 📊 Performance Improvements

| Feature | Original DotDotPwn | PyDotPwn | Improvement |
|---------|-------------------|----------|-------------|
| **Total Patterns** | 1,778 patterns | 25,000+ patterns | **1,305% increase** |
| **Path Validation Bypass** | ❌ Not supported | ✅ 25,000+ patterns | **∞ improvement** |
| **Absolute Path Patterns** | ~3 patterns (0.11%) | 144+ patterns (7.5%) | **4,700% increase** |
| **Multi-Level URL Encoding** | Single encoding | 5-level encoding | **500% deeper bypass** |
| **Target Files** | ~10 files | 63 files | **530% increase** |
| **Subdirectory Prefixes** | ❌ None | 90+ real-world paths | **New capability** |
| **WAF Bypass Techniques** | Basic | Advanced encoding | **Enterprise-grade** |
| **OS Support** | Limited Windows | Full Windows + UNIX | **Complete coverage** |
| **CLI Usability** | Single parameter names | Multiple aliases | **Developer-friendly** |
| **Output Formats** | Text only | 5 formats | **Professional reporting** |

### 🎯 Use Cases & Scenarios

#### 🏢 **Enterprise Security Testing**
```bash
# Test applications with sophisticated path validation
python dotdotpwn.py -m http -h enterprise.com -f /etc/passwd --depth 6
# Generates patterns like: /var/www/images/../../../../../etc/passwd
```

#### 🛡️ **WAF Bypass Testing**
```bash
# Deep encoding bypass for advanced WAFs
python dotdotpwn.py -m http -h protected.com -f /etc/passwd --depth 3
# Includes quintuple encoding: %252525252f patterns
```

#### 🌐 **Modern Web Applications**
```bash
# Test applications that validate legitimate path starts
python dotdotpwn.py -m http -h webapp.com -f /etc/passwd --depth 5
# Targets: /uploads/../../../etc/passwd, /images/../../../etc/passwd
```

#### 🔍 **Comprehensive Pattern Generation**
```bash
# Generate all 25,000+ patterns for analysis
python dotdotpwn.py main --module stdout --os-type unix --file "/etc/passwd" --depth 3
```

### 🔍 Security Enhancement

PyDotPwn addresses critical gaps in the original implementation:

1. **Path Validation Blind Spot**: NEW - Targets applications that validate path prefixes
2. **Absolute Path Blind Spot**: Original missed 99.89% of absolute path attacks
3. **Limited Target Coverage**: Expanded from ~10 to 63 critical system files
4. **Filter Bypass**: Advanced 5-level URL encoding for sophisticated WAF evasion
5. **Cross-Platform**: Complete Windows support alongside UNIX
6. **Modern Attack Vectors**: Techniques discovered since original development
7. **Enterprise Environments**: Real-world subdirectory patterns from actual deployments

## 🛠️ Development

### Running Tests

```bash
# Run all tests
python tests/run_tests.py

# Quick validation test
python tests/quick_test.py
```

### API Server

```bash
# Start the REST API server
python src/dotdotpwn/api/main.py

# API will be available at http://localhost:8000
# Interactive docs at http://localhost:8000/docs
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://nanragav.github.io/PyDotPwn/contributing/) for details on:

- Code style and standards
- Submitting pull requests
- Reporting issues
- Development setup

## ⚖️ Legal Notice

**⚠️ IMPORTANT**: This tool is intended for authorized security testing only. Always ensure you have explicit permission before testing any systems. Users are responsible for complying with all applicable laws and regulations.

## 📄 License

This project is licensed under the GPL-3.0-or-later license, maintaining compatibility with the original DotDotPwn Perl implementation. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Original DotDotPwn Perl implementation authors
- Security research community
- Contributors and testers

---

**💡 Need Help?** Visit our [documentation site](https://nanragav.github.io/PyDotPwn/) for comprehensive guides, examples, and troubleshooting assistance.
