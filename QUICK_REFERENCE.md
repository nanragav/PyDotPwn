# 🚀 DotDotPwn Python - Quick Reference Card

## ⚡ Quick Commands

```bash
# HTTP basic scan
dotdotpwn -m http -h example.com -f /etc/passwd -k "root:"

# HTTPS with OS detection
dotdotpwn -m http -h example.com -S -O -b

# HTTP-URL fuzzing
dotdotpwn -m http-url -u "http://example.com/page.php?file=TRAVERSAL" -k "root:"

# FTP anonymous
dotdotpwn -m ftp -h ftp.example.com -f /etc/passwd -k "root:"

# TFTP scan
dotdotpwn -m tftp -h 192.168.1.1 -f /etc/passwd -k "root:"

# Generate patterns
dotdotpwn -m stdout -d 8 -o unix -f /etc/passwd
```

## 📋 Essential Parameters

| Short | Long Alternative          | Description       | Example          |
| ----- | ------------------------- | ----------------- | ---------------- |
| `-m`  | `--module`                | Fuzzing module    | `-m http`        |
| `-h`  | `--host`, `--hostname`    | Target host       | `-h example.com` |
| `-f`  | `--file`, `--target-file` | Target file       | `-f /etc/passwd` |
| `-k`  | `--pattern`, `--keyword`  | Success pattern   | `-k "root:"`     |
| `-d`  | `--depth`, `--max-depth`  | Traversal depth   | `-d 10`          |
| `-x`  | `--port`                  | Port number       | `-x 8080`        |
| `-S`  | `--ssl`, `--https`        | Enable SSL        | `-S`             |
| `-O`  | `--os-detection`          | OS detection      | `-O`             |
| `-b`  | `--break-on-first`        | Stop on first hit | `-b`             |
| `-q`  | `--quiet`                 | Quiet mode        | `-q`             |

## 🎯 Common Patterns

```bash
# Unix/Linux
-k "root:"              # /etc/passwd
-k "daemon:"            # /etc/passwd alternative
-k "[main]"             # Config files

# Windows
-k "Administrator"      # User accounts
-k "Windows"            # System files
-k "[fonts]"            # win.ini

# Web Apps
-k "<?php"              # PHP source
-k "mysql_connect"      # DB configs
-k "password"           # Credentials
```

## 🏗️ Module Quick Guide

| Module     | Purpose         | Required         | Example                |
| ---------- | --------------- | ---------------- | ---------------------- |
| `http`     | Web apps        | `-h`, `-k`       | Basic web testing      |
| `http-url` | URL fuzzing     | `-u`, `-k`       | Parameter testing      |
| `ftp`      | FTP servers     | `-h`             | File server testing    |
| `tftp`     | TFTP servers    | `-h`             | Network device testing |
| `payload`  | Custom protocol | `-h`, `-x`, `-p` | Custom fuzzing         |
| `stdout`   | Pattern gen     | none             | Pattern output         |

## 🚀 Advanced Examples

```bash
# Comprehensive scan
dotdotpwn -m http -h example.com -O -s -E -X -b -r results.json --format json

# Stealth scan
dotdotpwn -m http -h example.com -t 2.0 -d 6 -C -q

# Windows specific
dotdotpwn -m http -h windows-server.com -o windows -f boot.ini -k "Windows"

# Custom payload
dotdotpwn -m payload -h example.com -x 21 -p ftp.txt -k "220" -S

# Bisection algorithm
dotdotpwn -m http -h example.com -X -f /etc/passwd -k "root:"
```

## 📊 Report Formats

```bash
--format text           # Human readable
--format json           # Machine readable
--format csv            # Spreadsheet compatible
--format xml            # Structured XML
--format html           # Web friendly
```

## 🔧 Performance Tuning

```bash
# Fast (local/lab)
-t 0.1 -d 6 -b -q

# Standard (internal network)
-t 0.3 -d 8 -C

# Slow/Stealth (internet)
-t 2.0 -d 6 -C -q

# Thorough (comprehensive)
-t 1.0 -d 12 -E -O -s
```

## 🆘 Help Commands

```bash
dotdotpwn --help                # Main help
dotdotpwn help-examples         # Usage examples
dotdotpwn help-modules          # Module details
```

## ⚠️ Security Notice

**🔒 AUTHORIZATION REQUIRED**

- Only test systems you own or have explicit written permission to test
- Follow responsible disclosure practices
- Document all findings professionally
- Respect rate limits and system resources

---

_DotDotPwn Python v3.0.2 - Directory Traversal Fuzzer_
