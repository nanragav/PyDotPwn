---
layout: home
title: "PyDotPwn Documentation"
---

# 🚀 PyDotPwn - Complete Documentation

Welcome to the comprehensive documentation for PyDotPwn, a powerful directory traversal fuzzer with modern Python implementation, GUI interface, and REST API capabilities.

![PyDotPwn](https://img.shields.io/badge/PyDotPwn-Python-blue.svg)
![Version](https://img.shields.io/badge/version-3.0.2-green.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-red.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## 📚 Documentation Overview

This documentation provides everything you need to master PyDotPwn, from basic usage to advanced features and API integration.

### 🎯 Quick Navigation

<div class="grid-container">
  <div class="grid-item">
    <h3>🚀 <a href="getting-started">Getting Started</a></h3>
    <p>Installation, setup, and your first scan in 5 minutes</p>
  </div>
  <div class="grid-item">
    <h3>💻 <a href="cli-reference">CLI Reference</a></h3>
    <p>Complete command-line interface documentation</p>
  </div>
  <div class="grid-item">
    <h3>🖥️ <a href="gui-guide">GUI Guide</a></h3>
    <p>Graphical interface tutorial and feature overview</p>
  </div>
  <div class="grid-item">
    <h3>🔌 <a href="api-documentation">API Documentation</a></h3>
    <p>REST API endpoints and integration guide</p>
  </div>
  <div class="grid-item">
    <h3>📝 <a href="examples">Examples</a></h3>
    <p>Real-world usage examples and scenarios</p>
  </div>
  <div class="grid-item">
    <h3>🔧 <a href="troubleshooting">Troubleshooting</a></h3>
    <p>Common issues, solutions, and best practices</p>
  </div>
</div>

## ✨ What is PyDotPwn?

PyDotPwn is a comprehensive directory traversal fuzzer that helps security professionals discover path traversal vulnerabilities across various protocols and applications. This Python implementation enhances the original Perl version with:

### 🎯 Key Features

- **🌐 Multiple Protocols**: HTTP/HTTPS, FTP, TFTP, and custom payload fuzzing
- **🖥️ Modern GUI**: Professional PyQt6 interface with real-time monitoring
- **🔌 REST API**: Complete FastAPI implementation for automation and integration
- **🧠 Smart Intelligence**: OS detection, service fingerprinting, and bisection algorithms
- **📊 Rich Reporting**: Multiple output formats (JSON, XML, HTML, CSV, Text)
- **⚡ High Performance**: Async operations and optimized pattern generation
- **🔒 Security Focused**: Input validation, safe defaults, and ethical usage guidelines

### 🎖️ Enhanced Over Original

- **Memorable Parameters**: Both short (`-h`) and long (`--hostname`) options
- **Rich Terminal Output**: Beautiful colored output with progress indicators
- **Type Safety**: Full type hints for better development experience
- **Modern Packaging**: Proper Python packaging with `pyproject.toml`
- **Comprehensive Testing**: Full test suite with 100% core functionality coverage

## 🚀 Quick Start

Get up and running in minutes:

```bash
# 1. Clone the repository
git clone https://github.com/nanragav/PyDotPwn.git
cd PyDotPwn

# 2. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run your first scan
python dotdotpwn.py --module http --host example.com --file /etc/passwd --pattern "root:"

# 5. Launch GUI
python launch_gui.py
```

## 🎯 Use Cases

### 🔍 Security Testing

- **Web Application Testing**: Discover directory traversal vulnerabilities in web apps
- **Infrastructure Assessment**: Test FTP, TFTP, and other file services
- **API Security**: Test REST APIs and web services for path traversal
- **Penetration Testing**: Comprehensive vulnerability assessment toolkit

### 🛠️ Development & Research

- **Security Research**: Pattern analysis and vulnerability research
- **Automation**: API integration for automated security testing
- **Education**: Learning about directory traversal vulnerabilities
- **Tool Development**: Extend functionality with custom modules

## 🎨 Interface Options

### 💻 Command Line Interface
Perfect for automation, scripting, and advanced users who prefer terminal operations.

```bash
dotdotpwn --module http --hostname example.com --target-file /etc/passwd --pattern "root:" --depth 8
```

### 🖥️ Graphical User Interface
Professional PyQt6 interface with real-time monitoring, perfect for interactive use.

- Real-time scan output with syntax highlighting
- System resource monitoring
- Scan history and management
- Multiple export formats
- Intuitive configuration

### 🔌 REST API
Complete API for integration with other tools and automation workflows.

```bash
# Start API server
python dotdotpwn.py api --host localhost --port 8000

# Use API endpoints
curl -X POST "http://localhost:8000/scan" -H "Content-Type: application/json" -d '{"module": "http", "host": "example.com"}'
```

## 📋 Module Overview

| Module | Purpose | Use Case |
|--------|---------|----------|
| **http** | Web application testing | Standard web app security testing |
| **http-url** | URL parameter fuzzing | Testing specific vulnerable parameters |
| **ftp** | FTP server testing | File server vulnerability assessment |
| **tftp** | TFTP server testing | Network device and embedded system testing |
| **payload** | Custom protocol testing | Testing proprietary or custom services |
| **stdout** | Pattern generation | Generate patterns for use in other tools |

## 🔒 Ethical Usage

PyDotPwn is designed for legitimate security testing purposes:

- ✅ **Authorized Testing Only**: Only test systems you own or have explicit permission to test
- ✅ **Professional Use**: Designed for security professionals, researchers, and educators
- ✅ **Responsible Disclosure**: Follow proper vulnerability disclosure practices
- ✅ **Legal Compliance**: Ensure compliance with local laws and regulations

## 🤝 Community & Support

- **📖 Documentation**: Comprehensive guides and references (you're here!)
- **🐛 Issues**: Report bugs and request features on GitHub
- **💬 Discussions**: Join community discussions and share experiences
- **🔧 Contributions**: Contribute code, documentation, or bug reports

## 📊 Project Status

- **✅ Core Functionality**: 100% operational with full test coverage
- **✅ GUI Application**: Professional interface with advanced features
- **✅ API Integration**: Complete REST API with OpenAPI documentation
- **✅ Documentation**: Comprehensive guides and references
- **✅ Cross-Platform**: Windows, Linux, and macOS support

---

Ready to get started? Head over to the [Getting Started Guide](getting-started) or explore specific sections using the navigation above!

<style>
.grid-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
  margin: 20px 0;
}

.grid-item {
  border: 1px solid #e1e4e8;
  border-radius: 6px;
  padding: 16px;
  background-color: #f6f8fa;
}

.grid-item h3 {
  margin-top: 0;
  margin-bottom: 8px;
}

.grid-item p {
  margin-bottom: 0;
  color: #586069;
}

.grid-item h3 a {
  text-decoration: none;
  color: #0366d6;
}

.grid-item h3 a:hover {
  text-decoration: underline;
}
</style>