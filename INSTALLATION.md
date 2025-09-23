# 🛠️ DotDotPwn Python - Installation & Setup Guide

## 📋 System Requirements

### Minimum Requirements

- **Python:** 3.8 or higher
- **Operating System:** Linux, macOS, or Windows
- **Memory:** 512 MB RAM minimum
- **Storage:** 100 MB free space
- **Network:** Internet connection for target testing

### Recommended Requirements

- **Python:** 3.10 or higher
- **Memory:** 2 GB RAM for optimal performance
- **Storage:** 1 GB free space (for reports and logs)
- **Additional Tools:** nmap (for OS detection)

## 🚀 Quick Installation

### Option 1: Clone and Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python

# Install dependencies
pip install -r requirements.txt

# Verify installation
python dotdotpwn.py --help
```

### Option 2: Development Installation

```bash
# Clone repository
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio black flake8 mypy

# Verify installation
dotdotpwn --help
```

## 🐍 Python Environment Setup

### Using Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv dotdotpwn-env

# Activate virtual environment
# Linux/macOS:
source dotdotpwn-env/bin/activate
# Windows:
dotdotpwn-env\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt

# Verify
python dotdotpwn.py --help
```

### Using Conda

```bash
# Create conda environment
conda create -n dotdotpwn python=3.10

# Activate environment
conda activate dotdotpwn

# Install dependencies
pip install -r requirements.txt

# Verify
python dotdotpwn.py --help
```

## 📦 Dependency Installation

### Core Dependencies

The `requirements.txt` includes all necessary dependencies:

```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install fastapi uvicorn aiohttp requests typer rich
pip install pydantic cryptography python-nmap ftplib2
pip install dnspython aiofiles python-multipart pydantic-settings
```

### Optional Dependencies

```bash
# Development tools
pip install pytest pytest-asyncio pytest-cov
pip install black isort flake8 mypy pre-commit

# Performance monitoring
pip install psutil memory-profiler

# Additional reporting
pip install matplotlib plotly
```

## 🔧 System-Specific Setup

### Linux Setup

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv git nmap

# CentOS/RHEL/Fedora
sudo yum install python3 python3-pip git nmap
# or
sudo dnf install python3 python3-pip git nmap

# Install DotDotPwn
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python
pip3 install -r requirements.txt
```

### macOS Setup

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and dependencies
brew install python git nmap

# Install DotDotPwn
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python
pip3 install -r requirements.txt
```

### Windows Setup

```bash
# Install Python from python.org or Microsoft Store
# Install Git from git-scm.com
# Optionally install nmap from nmap.org

# Clone and install
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python
pip install -r requirements.txt
```

## 🔍 Verification and Testing

### Basic Functionality Test

```bash
# Test CLI help
python dotdotpwn.py --help

# Test module help
python dotdotpwn.py help-examples

# Test pattern generation (no network required)
python dotdotpwn.py --module stdout --depth 3 --os-type unix
```

### Network Connectivity Test

```bash
# Test HTTP module (safe test)
python dotdotpwn.py --module http --host httpbin.org --file /etc/passwd --pattern "root:" --depth 3 --quiet

# Test STDOUT module
python dotdotpwn.py --module stdout --depth 5 --file /etc/passwd
```

### API Server Test

```bash
# Start API server
python dotdotpwn.py api --host localhost --port 8000

# Test API (in another terminal)
curl http://localhost:8000/
```

## ⚙️ Configuration

### Environment Variables

```bash
# Optional: Configure HTTP verification
export PYTHONHTTPSVERIFY=0  # Only for testing with self-signed certs

# Optional: Set default delays
export DOTDOTPWN_DEFAULT_DELAY=0.5

# Optional: Set default depth
export DOTDOTPWN_DEFAULT_DEPTH=6
```

### Configuration File (Optional)

Create `~/.dotdotpwn/config.yaml`:

```yaml
# Default configuration
default_delay: 0.3
default_depth: 6
default_format: json
continue_on_error: true
quiet_mode: false

# Default patterns
patterns:
  unix: "root:"
  windows: "Administrator"
  web: "<?php"

# Reporting
reports_directory: "~/dotdotpwn-reports"
auto_timestamp: true
```

## 🐛 Troubleshooting Installation

### Common Issues and Solutions

#### Issue: "Module not found" errors

```bash
# Solution 1: Check Python path
python -c "import sys; print('\\n'.join(sys.path))"

# Solution 2: Install in development mode
pip install -e .

# Solution 3: Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

#### Issue: Permission denied for nmap

```bash
# Solution: Install nmap properly or run with sudo
sudo apt install nmap              # Linux
brew install nmap                  # macOS
# Download from nmap.org           # Windows

# Alternative: Disable OS detection
python dotdotpwn.py --module http --host example.com --os-type generic
```

#### Issue: SSL certificate verification errors

```bash
# Solution 1: Update certificates
pip install --upgrade certifi

# Solution 2: Temporary workaround (testing only)
export PYTHONHTTPSVERIFY=0

# Solution 3: Use continue-on-error flag
python dotdotpwn.py --module http --host example.com --ssl --continue-on-error
```

#### Issue: Slow performance

```bash
# Solution 1: Reduce depth and increase delay
python dotdotpwn.py --module http --host example.com --depth 4 --delay 0.1

# Solution 2: Use break-on-first
python dotdotpwn.py --module http --host example.com --break-on-first

# Solution 3: Enable quiet mode
python dotdotpwn.py --module http --host example.com --quiet
```

#### Issue: Memory usage too high

```bash
# Solution 1: Use lower depth
python dotdotpwn.py --module http --host example.com --depth 3

# Solution 2: Enable quiet mode
python dotdotpwn.py --module http --host example.com --quiet

# Solution 3: Use STDOUT module for pattern generation
python dotdotpwn.py --module stdout --depth 6 | head -100
```

## 🔧 Advanced Setup

### Development Environment

```bash
# Clone repository
git clone https://github.com/dotdotpwn/dotdotpwn-python.git
cd dotdotpwn-python

# Create development environment
python -m venv dev-env
source dev-env/bin/activate  # Linux/macOS
# dev-env\\Scripts\\activate  # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
python -m pytest tests/

# Code formatting
black src/
isort src/
flake8 src/
mypy src/
```

### Docker Setup (Optional)

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN pip install -e .

ENTRYPOINT ["python", "dotdotpwn.py"]
```

```bash
# Build and run
docker build -t dotdotpwn-python .
docker run --rm dotdotpwn-python --help
docker run --rm dotdotpwn-python --module stdout --depth 5
```

### API Server Setup

```bash
# Production API server setup
pip install gunicorn

# Start with gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker src.dotdotpwn.api.app:app --bind 0.0.0.0:8000

# Or use uvicorn directly
uvicorn src.dotdotpwn.api.app:app --host 0.0.0.0 --port 8000 --workers 4
```

## 📊 Performance Optimization

### System Optimization

```bash
# Increase file descriptor limits (Linux)
ulimit -n 65536

# Optimize Python for performance
export PYTHONUNBUFFERED=1
export PYTHONOPTIMIZE=1

# Use faster DNS resolution
echo "nameserver 8.8.8.8" >> /etc/resolv.conf  # Linux
```

### Memory Optimization

```bash
# Monitor memory usage
pip install psutil
python -c "
import psutil
print(f'Memory: {psutil.virtual_memory().percent}%')
print(f'CPU: {psutil.cpu_percent()}%')
"

# Run with memory profiling
pip install memory-profiler
mprof run python dotdotpwn.py --module stdout --depth 8
mprof plot
```

## ✅ Installation Verification Checklist

- [ ] Python 3.8+ installed and accessible
- [ ] Git installed and working
- [ ] Repository cloned successfully
- [ ] Dependencies installed without errors
- [ ] Basic help command works: `python dotdotpwn.py --help`
- [ ] Pattern generation works: `python dotdotpwn.py --module stdout --depth 3`
- [ ] Network connectivity test passes
- [ ] Optional: nmap installed for OS detection
- [ ] Optional: API server starts successfully

## 🆘 Getting Help

### Built-in Help

```bash
python dotdotpwn.py --help
python dotdotpwn.py help-examples
python dotdotpwn.py help-modules
```

### Community Support

- **GitHub Issues:** https://github.com/dotdotpwn/dotdotpwn-python/issues
- **Documentation:** See COMPREHENSIVE_GUIDE.md
- **Quick Reference:** See QUICK_REFERENCE.md

### Reporting Issues

When reporting issues, please include:

1. Operating system and version
2. Python version (`python --version`)
3. Full error message
4. Command that caused the issue
5. Expected vs actual behavior

---

## 🎉 You're Ready!

Once installation is complete, you can start using DotDotPwn:

```bash
# Basic scan
python dotdotpwn.py --module http --host example.com --file /etc/passwd --pattern "root:"

# Get comprehensive examples
python dotdotpwn.py help-examples

# Start the API server
python dotdotpwn.py api --host localhost --port 8000
```

**Happy (authorized) testing! 🚀**

---

_Last updated: September 2025_
