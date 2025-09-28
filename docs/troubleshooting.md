---
layout: page
title: "Troubleshooting"
permalink: /troubleshooting/
---

# 🔧 Troubleshooting Guide

This comprehensive troubleshooting guide helps you resolve common issues with PyDotPwn, providing solutions for installation, configuration, runtime, and performance problems.

## 📋 Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Runtime Errors](#runtime-errors)
- [Network and Connectivity](#network-and-connectivity)
- [Performance Issues](#performance-issues)
- [GUI-Specific Problems](#gui-specific-problems)
- [API Server Issues](#api-server-issues)
- [Output and Reporting](#output-and-reporting)
- [Platform-Specific Issues](#platform-specific-issues)
- [Advanced Diagnostics](#advanced-diagnostics)

## 🔧 Installation Issues

### Python Version Compatibility

**Problem**: Python version conflicts or unsupported versions.

```bash
# Check Python version
python --version
python3 --version

# Expected output: Python 3.8.x or higher
```

**Solution**:
```bash
# Install Python 3.8+ if needed (Ubuntu/Debian)
sudo apt update
sudo apt install python3.10 python3.10-pip python3.10-venv

# Install Python 3.8+ (CentOS/RHEL/Fedora)
sudo dnf install python3.10 python3.10-pip

# macOS with Homebrew
brew install python@3.10

# Create virtual environment with specific Python version
python3.10 -m venv dotdotpwn-env
source dotdotpwn-env/bin/activate
```

### Dependency Installation Failures

**Problem**: `pip install` failures or missing dependencies.

**Common Error Messages**:
- `error: Microsoft Visual C++ 14.0 is required`
- `Failed building wheel for [package]`
- `No module named 'requests'`

**Solutions**:

#### Windows Solutions
```powershell
# Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Alternative: Use pre-compiled wheels
pip install --only-binary=all -r requirements.txt

# If specific package fails, try conda
conda install requests urllib3 cryptography
```

#### Linux Solutions
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential python3-dev libffi-dev libssl-dev

# Install system dependencies (CentOS/RHEL/Fedora)
sudo dnf groupinstall "Development Tools"
sudo dnf install python3-devel openssl-devel libffi-devel

# Upgrade pip and setuptools
pip install --upgrade pip setuptools wheel

# Install requirements
pip install -r requirements.txt
```

#### macOS Solutions
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install with Homebrew dependencies
brew install openssl libffi
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
pip install -r requirements.txt
```

### Virtual Environment Issues

**Problem**: Virtual environment not working or not found.

```bash
# Check if virtual environment exists
ls -la dotdotpwn-env/

# Check if virtual environment is activated
echo $VIRTUAL_ENV
```

**Solution**:
```bash
# Create new virtual environment
python3 -m venv dotdotpwn-env

# Activate virtual environment
source dotdotpwn-env/bin/activate  # Linux/macOS
# OR
dotdotpwn-env\Scripts\activate.bat  # Windows

# Verify activation
which python
pip list

# Install requirements in virtual environment
pip install -r requirements.txt
```

### Permission Errors

**Problem**: Permission denied errors during installation.

```bash
# Error example
# PermissionError: [Errno 13] Permission denied: '/usr/local/lib/python3.x/site-packages/'
```

**Solution**:
```bash
# Use user installation
pip install --user -r requirements.txt

# Or use virtual environment (recommended)
python3 -m venv dotdotpwn-env
source dotdotpwn-env/bin/activate
pip install -r requirements.txt

# Fix ownership (if needed)
sudo chown -R $USER:$USER ~/.local/
```

## ⚙️ Configuration Problems

### Module Not Found Errors

**Problem**: DotDotPwn modules not found or import errors.

```python
# Error examples
# ModuleNotFoundError: No module named 'dotdotpwn'
# ImportError: cannot import name 'traversal_engine' from 'dotdotpwn.core'
```

**Diagnostic Commands**:
```bash
# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Check if DotDotPwn is in path
python -c "import dotdotpwn; print(dotdotpwn.__file__)"

# List installed packages
pip list | grep dotdotpwn
```

**Solutions**:
```bash
# Install in development mode (if working from source)
pip install -e .

# Add to Python path temporarily
export PYTHONPATH="${PYTHONPATH}:/path/to/PyDotPwn/src"

# Verify installation
python -c "from dotdotpwn.core import traversal_engine; print('Success!')"
```

### Configuration File Issues

**Problem**: Configuration not loading or invalid settings.

```bash
# Check if config file exists and is readable
ls -la ~/.dotdotpwn/config.yaml
cat ~/.dotdotpwn/config.yaml
```

**Solution**:
```bash
# Create default config directory
mkdir -p ~/.dotdotpwn

# Create basic config file
cat << EOF > ~/.dotdotpwn/config.yaml
default_settings:
  depth: 8
  delay: 0.5
  timeout: 10
  user_agent: "DotDotPwn/3.0"
  
logging:
  level: INFO
  file: ~/.dotdotpwn/dotdotpwn.log
EOF

# Set proper permissions
chmod 600 ~/.dotdotpwn/config.yaml
```

### Environment Variable Issues

**Problem**: Environment variables not being recognized.

```bash
# Check current environment variables
env | grep -i dotdotpwn
echo $DOTDOTPWN_CONFIG_PATH
```

**Solution**:
```bash
# Set environment variables
export DOTDOTPWN_CONFIG_PATH="$HOME/.dotdotpwn"
export DOTDOTPWN_LOG_LEVEL="DEBUG"

# Make permanent (add to ~/.bashrc or ~/.profile)
echo 'export DOTDOTPWN_CONFIG_PATH="$HOME/.dotdotpwn"' >> ~/.bashrc
source ~/.bashrc
```

## 🚨 Runtime Errors

### Connection Timeout Errors

**Problem**: Network timeouts or connection failures.

```bash
# Error examples
# requests.exceptions.ConnectTimeout: HTTPSConnectionPool(host='target.com', port=443)
# socket.timeout: timed out
```

**Diagnostic Commands**:
```bash
# Test basic connectivity
ping target.com
telnet target.com 80
curl -I http://target.com

# Check DNS resolution
nslookup target.com
dig target.com
```

**Solutions**:
```bash
# Increase timeout values
python dotdotpwn.py --module http --host target.com --timeout 30 --pattern "root:"

# Use proxy if network restrictions
python dotdotpwn.py --module http --host target.com --proxy http://proxy.company.com:8080

# Check and adjust firewall rules
sudo ufw status
sudo iptables -L
```

### SSL/TLS Certificate Errors

**Problem**: SSL certificate verification failures.

```bash
# Error examples
# requests.exceptions.SSLError: HTTPSConnectionPool(host='target.com', port=443)
# ssl.SSLCertVerificationError: certificate verify failed
```

**Solutions**:
```bash
# Skip SSL verification (for testing only)
python dotdotpwn.py --module http --host target.com --ssl --skip-ssl-verification

# Use custom CA bundle
export REQUESTS_CA_BUNDLE=/path/to/custom/ca-bundle.crt
python dotdotpwn.py --module http --host target.com --ssl

# Check certificate details
openssl s_client -connect target.com:443 -showcerts
```

### Authentication Failures

**Problem**: Authentication not working with credentials.

```bash
# Test authentication manually
curl -u username:password http://target.com/admin/
```

**Solutions**:
```bash
# Verify credentials format
python dotdotpwn.py --module http --host target.com --username "user@domain.com" --password "pass123"

# Use authentication token (if supported by custom headers)
python dotdotpwn.py --module http --host target.com --user-agent "Bearer: your-token-here"

# Check for special characters in password
python dotdotpwn.py --module http --host target.com --username "user" --password 'pass$with#special!chars'
```

### Memory and Resource Errors

**Problem**: Out of memory or resource exhaustion errors.

```python
# Error examples
# MemoryError: Unable to allocate memory
# OSError: [Errno 24] Too many open files
```

**Diagnostic Commands**:
```bash
# Check system resources
free -h
df -h
ulimit -a
ps aux | grep python
```

**Solutions**:
```bash
# Increase system limits
ulimit -n 4096  # Increase file descriptor limit
export PYTHONHASHSEED=0  # Reduce memory fragmentation

# Use resource-efficient options
python dotdotpwn.py --module http --host target.com --depth 4 --delay 1.0 --break-on-first

# Monitor memory usage during execution
while true; do
    ps aux | grep dotdotpwn | grep -v grep
    sleep 5
done
```

## 🌐 Network and Connectivity

### Proxy Configuration Issues

**Problem**: Proxy settings not working or being ignored.

```bash
# Test proxy connectivity
curl --proxy http://proxy.company.com:8080 http://example.com
```

**Solutions**:
```bash
# Set proxy environment variables
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,internal.company.com"

# Use proxy with authentication
export HTTP_PROXY="http://username:password@proxy.company.com:8080"

# Test with DotDotPwn
python dotdotpwn.py --module http --host target.com --proxy http://proxy.company.com:8080
```

### Firewall and Security Software Interference

**Problem**: Firewall or antivirus blocking connections.

**Diagnostic Steps**:
```bash
# Check if firewall is blocking
sudo iptables -L OUTPUT
sudo ufw status verbose

# Test with different user agents
python dotdotpwn.py --module http --host target.com --user-agent "Mozilla/5.0 (compatible; bot)"

# Check for rate limiting
python dotdotpwn.py --module http --host target.com --delay 2.0
```

**Solutions**:
```bash
# Temporarily disable firewall (for testing)
sudo ufw disable  # Ubuntu/Debian
sudo systemctl stop firewalld  # CentOS/RHEL

# Add firewall rules
sudo ufw allow out 80/tcp
sudo ufw allow out 443/tcp

# Configure antivirus exclusions
# Add DotDotPwn directory to antivirus exclusions
# Whitelist Python executable in security software
```

### DNS Resolution Problems

**Problem**: Cannot resolve target hostnames.

```bash
# Test DNS resolution
nslookup target.com
dig target.com
host target.com
```

**Solutions**:
```bash
# Use different DNS servers
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf

# Use IP address instead of hostname
python dotdotpwn.py --module http --host 192.168.1.100 --pattern "root:"

# Clear DNS cache
sudo systemctl restart systemd-resolved  # Ubuntu/Debian
sudo dscacheutil -flushcache  # macOS
```

## ⚡ Performance Issues

### Slow Scanning Speed

**Problem**: Scans taking too long to complete.

**Diagnostic Commands**:
```bash
# Monitor network usage
sudo iftop
sudo nethogs
sudo tcpdump -i eth0 host target.com
```

**Solutions**:
```bash
# Reduce delay between requests
python dotdotpwn.py --module http --host target.com --delay 0.1

# Use break-on-first to stop at first finding
python dotdotpwn.py --module http --host target.com --break-on-first

# Reduce depth for faster scanning
python dotdotpwn.py --module http --host target.com --depth 4

# Use parallel scanning
echo "host1 host2 host3" | xargs -n 1 -P 3 -I {} python dotdotpwn.py --module http --host {} --quiet
```

### High CPU Usage

**Problem**: DotDotPwn consuming too much CPU.

```bash
# Monitor CPU usage
top -p $(pgrep -f dotdotpwn)
htop
```

**Solutions**:
```bash
# Add delays to reduce CPU load
python dotdotpwn.py --module http --host target.com --delay 0.5

# Use nice to lower priority
nice -n 10 python dotdotpwn.py --module http --host target.com

# Limit number of concurrent operations
# (Use single-threaded approach if available)
```

### Network Bandwidth Issues

**Problem**: Too much network traffic or bandwidth limitations.

**Solutions**:
```bash
# Increase delay between requests
python dotdotpwn.py --module http --host target.com --delay 2.0

# Use Quality of Service (QoS) limiting
sudo tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms

# Monitor bandwidth usage
sudo iftop -i eth0
sudo vnstat -i eth0 -l
```

## 🖥️ GUI-Specific Problems

### PyQt6 Installation Issues

**Problem**: GUI not starting due to PyQt6 problems.

```python
# Error examples
# ModuleNotFoundError: No module named 'PyQt6'
# qt.qpa.plugin: Could not load the Qt platform plugin
```

**Solutions**:
```bash
# Install PyQt6 system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install python3-pyqt6 python3-pyqt6-dev qt6-base-dev

# Install PyQt6 system dependencies (CentOS/RHEL/Fedora)
sudo dnf install python3-qt6 python3-qt6-devel qt6-qtbase-devel

# Install via pip
pip install PyQt6

# Alternative: Use PyQt5
pip uninstall PyQt6
pip install PyQt5
# Then modify gui imports in source code if needed
```

### Display Issues

**Problem**: GUI not displaying properly or blank window.

**Diagnostic Commands**:
```bash
# Check display environment
echo $DISPLAY
echo $XDG_SESSION_TYPE

# Test basic Qt functionality
python -c "from PyQt6.QtWidgets import QApplication, QLabel; app = QApplication([]); label = QLabel('Test'); label.show(); print('GUI test successful')"
```

**Solutions**:
```bash
# Set display variables (if using SSH X11 forwarding)
export DISPLAY=:0.0
ssh -X user@remote_host

# Use virtual display (headless)
sudo apt install xvfb
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 &
python launch_gui.py

# Fix Qt platform plugin
export QT_QPA_PLATFORM=xcb  # Linux
export QT_QPA_PLATFORM=cocoa  # macOS
```

### GUI Crashes and Freezes

**Problem**: GUI application crashing or becoming unresponsive.

**Solutions**:
```bash
# Run with debug output
python launch_gui.py --debug

# Check for Qt-specific issues
export QT_LOGGING_RULES="*.debug=true"
python launch_gui.py

# Use alternative launch methods
python -m dotdotpwn.gui.dotdotpwn_gui

# Clear Qt cache
rm -rf ~/.cache/qt_*
rm -rf ~/.config/qt_*
```

## 🌐 API Server Issues

### Server Won't Start

**Problem**: API server fails to start or bind to port.

```python
# Error examples
# OSError: [Errno 98] Address already in use
# PermissionError: [Errno 13] Permission denied: bind to port 80
```

**Diagnostic Commands**:
```bash
# Check what's using the port
sudo lsof -i :8000
sudo netstat -tulnp | grep :8000
sudo ss -tulnp | grep :8000
```

**Solutions**:
```bash
# Use different port
python dotdotpwn.py api --host localhost --port 8080

# Stop conflicting service
sudo systemctl stop service-using-port-8000
sudo pkill -f process-using-port-8000

# Use non-privileged port (>1024)
python dotdotpwn.py api --host 0.0.0.0 --port 8000

# Check permissions for privileged ports (<1024)
sudo python dotdotpwn.py api --host 0.0.0.0 --port 80
```

### API Authentication Issues

**Problem**: API authentication failing or not working.

```bash
# Test API authentication
curl -X POST "http://localhost:8000/auth" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

**Solutions**:
```bash
# Check API configuration
cat ~/.dotdotpwn/api_config.yaml

# Reset API credentials
python dotdotpwn.py api --reset-auth

# Use environment variables for API auth
export DOTDOTPWN_API_KEY="your-api-key"
export DOTDOTPWN_API_SECRET="your-secret"
```

### CORS Issues

**Problem**: Cross-Origin Resource Sharing (CORS) errors in web browser.

**Solutions**:
```python
# Configure CORS in API settings
# Edit api/app.py or create custom CORS configuration
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

```bash
# Start API with CORS enabled
python dotdotpwn.py api --host 0.0.0.0 --port 8000 --cors
```

## 📊 Output and Reporting

### Report Generation Issues

**Problem**: Reports not being generated or corrupted.

```bash
# Test report generation
python dotdotpwn.py --module http --host example.com --report test_report.json --format json --pattern "test"
ls -la test_report.json
```

**Solutions**:
```bash
# Check write permissions
ls -la ./
touch test_write_permission.txt

# Use absolute path for report
python dotdotpwn.py --module http --host example.com --report "/tmp/dotdotpwn_report.json" --format json

# Check disk space
df -h

# Verify JSON format
python -m json.tool report.json
```

### Log File Issues

**Problem**: Logging not working or log files not created.

```bash
# Check log configuration
python -c "import logging; logging.basicConfig(level=logging.DEBUG); logging.debug('Test log entry')"
```

**Solutions**:
```bash
# Create log directory
mkdir -p ~/.dotdotpwn/logs

# Set logging permissions
chmod 755 ~/.dotdotpwn/logs

# Use explicit log file
python dotdotpwn.py --module http --host example.com --log-file /tmp/dotdotpwn.log --log-level DEBUG

# Check log rotation
logrotate -f /etc/logrotate.conf
```

### Output Encoding Issues

**Problem**: Special characters not displaying correctly.

**Solutions**:
```bash
# Set locale environment variables
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Use UTF-8 encoding
python dotdotpwn.py --module http --host example.com > output.txt
file output.txt  # Should show UTF-8

# Configure terminal encoding
# Add to ~/.bashrc:
export PYTHONIOENCODING=utf-8
```

## 💻 Platform-Specific Issues

### Windows-Specific Problems

#### PowerShell Execution Policy
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Windows Path Issues
```powershell
# Use forward slashes or raw strings
python dotdotpwn.py --module http --host example.com --report "C:/temp/report.json"

# Or use Python raw strings in scripts
python -c "print(r'C:\temp\report.json')"
```

#### Windows Service Integration
```powershell
# Create Windows service (requires additional setup)
# Install python-windows-service package
pip install python-windows-service

# Run as Windows service
python dotdotpwn.py api --install-service
net start dotdotpwn-api
```

### macOS-Specific Problems

#### Security and Privacy Settings
```bash
# Allow Python network access
# System Preferences > Security & Privacy > Privacy > Full Disk Access
# Add Python interpreter to allowed applications

# Code signing issues
codesign --force --deep --sign - /path/to/python
```

#### Homebrew Path Issues
```bash
# Add Homebrew Python to PATH
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Use specific Python version
/opt/homebrew/bin/python3.10 dotdotpwn.py --module http --host example.com
```

### Linux Distribution-Specific Issues

#### Ubuntu/Debian
```bash
# Missing system dependencies
sudo apt update
sudo apt install python3-dev libffi-dev libssl-dev build-essential

# Python version issues
sudo apt install python3.10 python3.10-dev python3.10-venv
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
```

#### CentOS/RHEL/Fedora
```bash
# Enable EPEL repository (CentOS/RHEL)
sudo yum install epel-release

# Install development tools
sudo dnf groupinstall "Development Tools"
sudo dnf install python3-devel openssl-devel libffi-devel
```

#### Arch Linux
```bash
# Install dependencies
sudo pacman -S python python-pip python-virtualenv gcc make

# Install from AUR (if available)
yay -S PyDotPwn-git
```

## 🔍 Advanced Diagnostics

### Debug Mode Troubleshooting

**Enable comprehensive debugging**:
```bash
# Maximum verbosity
python dotdotpwn.py --module http --host example.com --debug --verbose --log-level DEBUG

# Enable Python debugging
export PYTHONPATH="${PYTHONPATH}:."
python -u -X dev dotdotpwn.py --module http --host example.com --debug

# Network debugging
export PYTHONHTTPSVERIFY=0
python dotdotpwn.py --module http --host example.com --debug --skip-ssl-verification
```

### Network Traffic Analysis

**Capture and analyze network traffic**:
```bash
# Capture HTTP traffic
sudo tcpdump -i any -s 0 -A 'host example.com and port 80' -w dotdotpwn_traffic.pcap

# Analyze with tshark
tshark -r dotdotpwn_traffic.pcap -T fields -e http.request.uri -e http.response.code

# Use mitmproxy for HTTPS
pip install mitmproxy
mitmdump -s capture_script.py --set confdir=~/.mitmproxy
```

### System Resource Monitoring

**Monitor system resources during execution**:
```bash
# Create monitoring script
cat << 'EOF' > monitor_dotdotpwn.sh
#!/bin/bash
while true; do
    echo "=== $(date) ==="
    ps aux | grep dotdotpwn | grep -v grep | head -5
    echo "Memory usage:"
    free -h | head -2
    echo "Network connections:"
    ss -tuln | grep :80
    echo "---"
    sleep 10
done
EOF

chmod +x monitor_dotdotpwn.sh
./monitor_dotdotpwn.sh &

# Run DotDotPwn
python dotdotpwn.py --module http --host example.com --pattern "root:"

# Stop monitoring
pkill -f monitor_dotdotpwn.sh
```

### Dependency Verification

**Verify all dependencies are correctly installed**:
```python
#!/usr/bin/env python3
# dependency_check.py

import sys
import importlib

required_modules = [
    'requests', 'urllib3', 'cryptography', 'pycryptodome',
    'PyQt6', 'fastapi', 'uvicorn', 'pydantic'
]

print("Python version:", sys.version)
print("\nChecking dependencies...")

for module in required_modules:
    try:
        mod = importlib.import_module(module)
        version = getattr(mod, '__version__', 'unknown')
        print(f"✓ {module}: {version}")
    except ImportError as e:
        print(f"✗ {module}: NOT FOUND - {e}")

print("\nPATH directories:")
for path in sys.path:
    print(f"  {path}")
```

### Configuration Validation

**Validate configuration files and settings**:
```bash
# Validate YAML configuration
python -c "
import yaml
import sys

try:
    with open('~/.dotdotpwn/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print('Configuration is valid YAML')
    print('Configuration contents:')
    import json
    print(json.dumps(config, indent=2))
except Exception as e:
    print(f'Configuration error: {e}')
    sys.exit(1)
"

# Test configuration loading
python -c "
from dotdotpwn.utils import load_config
try:
    config = load_config()
    print('Configuration loaded successfully')
except Exception as e:
    print(f'Configuration loading failed: {e}')
"
```

## 📞 Getting Additional Help

### Community Resources

- **GitHub Issues**: [Report bugs and request features](https://github.com/your-repo/PyDotPwn/issues)
- **Discussions**: [Community Q&A and discussions](https://github.com/your-repo/PyDotPwn/discussions)
- **Documentation**: [Comprehensive documentation](https://your-username.github.io/PyDotPwn/)

### Professional Support

For enterprise environments or critical security assessments, consider:

1. **Professional Security Services**: Engage with cybersecurity consultants
2. **Managed Security Testing**: Use managed penetration testing services
3. **Training and Certification**: Security testing training programs

### Reporting Security Issues

If you discover security vulnerabilities in PyDotPwn itself:

1. **Do NOT** create public issues for security vulnerabilities
2. Email security@your-domain.com with details
3. Allow reasonable time for patches before disclosure
4. Follow responsible disclosure practices

---

If your issue persists after trying these solutions, please create a detailed issue report including:

- Operating system and version
- Python version
- DotDotPwn version
- Complete error messages
- Steps to reproduce
- System configuration details

For more help, see our [Getting Started Guide](getting-started) or [CLI Reference](cli-reference).