# 🎯 PyDotPwn - Advanced Directory Traversal Fuzzer

[![Version](https://img.shields.io/badge/version-3.0.2-green.svg)](https://github.com/nanragav/PyDotPwn)
[![License](https://img.shields.io/badge/license-GPL--3.0-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-brightgreen.svg)](https://nanragav.github.io/PyDotPwn/)

A powerful and feature-rich directory traversal fuzzer ported from Perl to Python, designed for security professionals and penetration testers. PyDotPwn provides enhanced functionality, modern Python features, and comprehensive testing capabilities for identifying directory traversal vulnerabilities.

## 🚀 Key Features

- **🎯 Multi-Protocol Support**: HTTP/HTTPS, FTP, TFTP fuzzing capabilities
- **🖥️ Modern Interface**: Both CLI and GUI interfaces with intuitive controls
- **⚡ High Performance**: Async/await implementation for efficient testing
- **📊 Comprehensive Reporting**: Multiple output formats (JSON, CSV, XML, HTML, TXT)
- **🔧 REST API**: Complete FastAPI integration for automation and toolchain integration
- **🎨 Rich Output**: Beautiful terminal output with colors and progress indicators
- **🛡️ Smart Detection**: Advanced fingerprinting and bisection algorithms

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
# HTTP fuzzing
python dotdotpwn.py -m http -h example.com -x 8080

# FTP fuzzing with custom wordlist
python dotdotpwn.py -m ftp -h ftp.example.com -w custom_wordlist.txt

# GUI interface
python launch_gui.py
```

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

## 🎯 Enhanced Features Over Original

### Modern Python Implementation

- **Type Safety**: Full type hints for better development experience
- **Async Support**: Non-blocking operations for improved performance
- **Modern Packaging**: Proper Python packaging with `pyproject.toml`

### Enhanced User Experience

- **Flexible Parameters**: Both short and long parameter names
- **Rich Output**: Colored terminal output with progress indicators
- **Better Error Handling**: Graceful error recovery and detailed messages
- **Comprehensive Help**: Built-in examples and documentation

### Advanced Capabilities

- **REST API**: Complete FastAPI implementation for automation
- **Multiple Output Formats**: JSON, CSV, XML, HTML, and text reports
- **GUI Interface**: User-friendly graphical interface
- **Extensive Testing**: Comprehensive test suite with validation

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
