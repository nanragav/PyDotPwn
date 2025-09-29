---
layout: page
title: "API Documentation"
permalink: /api-documentation/
---

# 🔌 Complete API Documentation

PyDotPwn includes a comprehensive REST API built with FastAPI, providing programmatic access to all directory traversal fuzzing capabilities for integration with other security tools and automation workflows.

## 📋 Table of Contents

- [API Overview](#api-overview)
- [Getting Started](#getting-started)
- [Authentication](#authentication)
- [Core Endpoints](#core-endpoints)
- [Scan Management](#scan-management)
- [Real-time Operations](#real-time-operations)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [SDK and Integration](#sdk-and-integration)
- [Examples and Use Cases](#examples-and-use-cases)

## 🌟 API Overview

The DotDotPwn API provides:

### ✨ Key Features

- **🔄 RESTful Design**: Standard HTTP methods and status codes
- **📊 Real-time Updates**: WebSocket support for live scan monitoring
- **🔒 Security First**: Input validation and secure defaults
- **📝 OpenAPI Spec**: Complete Swagger/OpenAPI 3.0 documentation
- **🎯 Full Feature Parity**: All CLI features available via API
- **⚡ High Performance**: Async operations with concurrent scanning
- **📋 Comprehensive Logging**: Detailed audit trails and debugging

### 🎯 Use Cases

- **🤖 Automation**: Integrate with CI/CD pipelines and security workflows
- **🔗 Tool Integration**: Connect with other security testing tools
- **📊 Custom Dashboards**: Build custom monitoring and reporting interfaces
- **🎮 Orchestration**: Manage multiple scans across different targets
- **📈 Analytics**: Collect and analyze vulnerability data
- **🔄 Batch Processing**: Process multiple targets efficiently

## 🚀 Getting Started

### Start the API Server

```bash
# Method 1: Using the CLI
python dotdotpwn.py api --host 0.0.0.0 --port 8000

# Method 2: Direct FastAPI launch
uvicorn src.dotdotpwn.api.app:app --host 0.0.0.0 --port 8000 --reload

# Method 3: Production deployment
uvicorn src.dotdotpwn.api.app:app --host 0.0.0.0 --port 8000 --workers 4
```

### API Server Options

```bash
# Custom host and port
python dotdotpwn.py api --host localhost --port 8080

# Enable auto-reload for development
python dotdotpwn.py api --host localhost --port 8000 --reload

# Production with multiple workers
python dotdotpwn.py api --host 0.0.0.0 --port 8000 --workers 4
```

### Access Interactive Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Spec**: `http://localhost:8000/openapi.json`

### Basic Health Check

```bash
# Test API availability
curl http://localhost:8000/

# Expected response:
{
  "message": "DotDotPwn API Server",
  "version": "3.0.2",
  "status": "running",
  "timestamp": "2025-09-28T10:30:00Z"
}
```

## 🔒 Authentication

### API Key Authentication

The API supports API key authentication for secure access:

#### Generate API Key

```bash
# Generate a new API key
curl -X POST "http://localhost:8000/auth/generate-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-security-tool", "permissions": ["scan", "read", "write"]}'

# Response:
{
  "api_key": "ddp_1234567890abcdef",
  "name": "my-security-tool",
  "created_at": "2025-09-28T10:30:00Z",
  "permissions": ["scan", "read", "write"]
}
```

#### Using API Key

```bash
# Include API key in headers
curl -X GET "http://localhost:8000/scans" \
  -H "X-API-Key: ddp_1234567890abcdef"
```

### Basic Authentication (Optional)

```bash
# Configure basic auth (in production)
export DOTDOTPWN_API_USERNAME="admin"
export DOTDOTPWN_API_PASSWORD="secure_password"

# Use basic auth
curl -X GET "http://localhost:8000/scans" \
  -u admin:secure_password
```

## 🎯 Core Endpoints

### Root Endpoint

```http
GET /
```

Returns API server information and status.

```bash
curl http://localhost:8000/

# Response:
{
  "message": "DotDotPwn API Server",
  "version": "3.0.2",
  "status": "running",
  "timestamp": "2025-09-28T10:30:00Z",
  "docs_url": "/docs",
  "features": ["http", "ftp", "tftp", "payload", "stdout"]
}
```

### Health Check

```http
GET /health
```

Detailed health status with system information.

```bash
curl http://localhost:8000/health

# Response:
{
  "status": "healthy",
  "timestamp": "2025-09-28T10:30:00Z",
  "uptime": 3600,
  "system": {
    "cpu_percent": 15.2,
    "memory_percent": 45.8,
    "disk_percent": 67.3
  },
  "api": {
    "total_requests": 1247,
    "active_scans": 2,
    "total_scans": 156
  }
}
```

### Version Information

```http
GET /version
```

Detailed version and feature information.

```bash
curl http://localhost:8000/version

# Response:
{
  "version": "3.0.2",
  "api_version": "1.0",
  "python_version": "3.10.12",
  "build_date": "2025-09-28",
  "features": {
    "modules": ["http", "http-url", "ftp", "tftp", "payload", "stdout"],
    "formats": ["json", "xml", "csv", "html", "text"],
    "authentication": ["api-key", "basic"],
    "websockets": true
  }
}
```

## 🔍 Scan Management

### Create New Scan

```http
POST /scans
```

Create and optionally start a new directory traversal scan.

#### Request Body

```json
{
  "module": "http",
  "target": {
    "host": "example.com",
    "port": 80,
    "url": null
  },
  "config": {
    "file": "/etc/passwd",
    "pattern": "root:",
    "depth": 8,
    "delay": 0.3,
    "os_type": "unix",
    "include_absolute": true
  },
  "options": {
    "ssl": false,
    "os_detection": true,
    "service_detection": false,
    "bisection": false,
    "break_on_first": false,
    "continue_on_error": true,
    "quiet": false,
    "extra_files": true
  },
  "auth": {
    "username": null,
    "password": null
  },
  "http_options": {
    "method": "GET",
    "user_agent": "DotDotPwn/3.0.2",
    "timeout": 30
  },
  "output": {
    "format": "json",
    "filename": null,
    "timestamp": true
  },
  "auto_start": true
}
```

#### Example Request

```bash
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -d '{
    "module": "http",
    "target": {
      "host": "example.com",
      "port": 80
    },
    "config": {
      "file": "/etc/passwd",
      "pattern": "root:",
      "depth": 8,
      "include_absolute": true
    },
    "options": {
      "ssl": false,
      "os_detection": true,
      "break_on_first": true
    },
    "auto_start": true
  }'

# Response:
{
  "scan_id": "scan_2025092810300001",
  "status": "running",
  "created_at": "2025-09-28T10:30:00Z",
  "estimated_duration": 120,
  "total_patterns": 2667,
  "websocket_url": "ws://localhost:8000/ws/scan_2025092810300001"
}
```

### List All Scans

```http
GET /scans
```

Retrieve all scans with optional filtering.

```bash
# Get all scans
curl "http://localhost:8000/scans" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Filter by status
curl "http://localhost:8000/scans?status=running" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Filter by module and limit results
curl "http://localhost:8000/scans?module=http&limit=10" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Response:
{
  "scans": [
    {
      "scan_id": "scan_2025092810300001",
      "module": "http",
      "target": "example.com:80",
      "status": "completed",
      "created_at": "2025-09-28T10:30:00Z",
      "completed_at": "2025-09-28T10:32:15Z",
      "duration": 135,
      "vulnerabilities_found": 1,
      "total_requests": 247
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

### Get Scan Details

```http
GET /scans/{scan_id}
```

Retrieve detailed information about a specific scan.

```bash
curl "http://localhost:8000/scans/scan_2025092810300001" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Response:
{
  "scan_id": "scan_2025092810300001",
  "module": "http",
  "target": {
    "host": "example.com",
    "port": 80
  },
  "config": {
    "file": "/etc/passwd",
    "pattern": "root:",
    "depth": 8,
    "delay": 0.3,
    "include_absolute": true
  },
  "status": "completed",
  "progress": {
    "current_pattern": 247,
    "total_patterns": 247,
    "percentage": 100,
    "requests_per_second": 1.83
  },
  "results": {
    "vulnerabilities_found": 1,
    "total_requests": 247,
    "success_rate": 0.4,
    "average_response_time": 0.312
  },
  "vulnerabilities": [
    {
      "url": "http://example.com/page.php?file=../../../etc/passwd",
      "method": "GET",
      "depth": 3,
      "pattern_matched": "root:",
      "response_code": 200,
      "content_length": 1847,
      "found_at": "2025-09-28T10:31:45Z"
    }
  ],
  "timestamps": {
    "created_at": "2025-09-28T10:30:00Z",
    "started_at": "2025-09-28T10:30:05Z",
    "completed_at": "2025-09-28T10:32:15Z"
  }
}
```

### Control Scan Operations

#### Start Scan

```http
POST /scans/{scan_id}/start
```

Start a previously created scan.

```bash
curl -X POST "http://localhost:8000/scans/scan_2025092810300001/start" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Response:
{
  "scan_id": "scan_2025092810300001",
  "status": "running",
  "started_at": "2025-09-28T10:30:00Z",
  "message": "Scan started successfully"
}
```

#### Stop Scan

```http
POST /scans/{scan_id}/stop
```

Stop a running scan.

```bash
curl -X POST "http://localhost:8000/scans/scan_2025092810300001/stop" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Response:
{
  "scan_id": "scan_2025092810300001",
  "status": "stopped",
  "stopped_at": "2025-09-28T10:31:30Z",
  "message": "Scan stopped by user request"
}
```

#### Pause/Resume Scan

```http
POST /scans/{scan_id}/pause
POST /scans/{scan_id}/resume
```

Pause or resume a running scan.

```bash
# Pause scan
curl -X POST "http://localhost:8000/scans/scan_2025092810300001/pause" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Resume scan
curl -X POST "http://localhost:8000/scans/scan_2025092810300001/resume" \
  -H "X-API-Key: ddp_1234567890abcdef"
```

### Delete Scan

```http
DELETE /scans/{scan_id}
```

Delete a scan and all associated data.

```bash
curl -X DELETE "http://localhost:8000/scans/scan_2025092810300001" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Response:
{
  "scan_id": "scan_2025092810300001",
  "status": "deleted",
  "deleted_at": "2025-09-28T10:45:00Z",
  "message": "Scan and all data deleted successfully"
}
```

## 🆕 Pattern Generation API

### Generate Traversal Patterns

```http
POST /generate
```

**NEW FEATURE**: Generate directory traversal patterns without performing scans. Perfect for testing, integration, and custom payload creation.

#### Request Body

```json
{
  "os_type": "unix",
  "file": "/etc/passwd",
  "depth": 6,
  "include_absolute": true,
  "quiet": false
}
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `os_type` | string | `"unix"` | Target OS type (`unix`, `windows`, `generic`) |
| `file` | string | `"/etc/passwd"` | Target file to generate patterns for |
| `depth` | integer | `6` | Maximum traversal depth (1-50) |
| `include_absolute` | boolean | `false` | Include absolute path patterns |
| `quiet` | boolean | `false` | Suppress progress messages |

#### Example Request

```bash
# Generate UNIX patterns with absolute paths
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -d '{
    "os_type": "unix",
    "file": "/etc/passwd",
    "depth": 5,
    "include_absolute": true
  }'

# Response:
{
  "status": "success",
  "config": {
    "os_type": "unix",
    "file": "/etc/passwd",
    "depth": 5,
    "include_absolute": true
  },
  "statistics": {
    "total_patterns": 1922,
    "relative_patterns": 1778,
    "absolute_patterns": 144,
    "generation_time": 0.312
  },
  "patterns": [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "/etc/passwd",
    "%2fetc%2fpasswd",
    "%2Fetc%2Fpasswd",
    "\\etc\\passwd",
    "%5cetc%5cpasswd",
    "...additional 1917 patterns..."
  ]
}
```

#### Windows Example

```bash
# Generate Windows patterns
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -d '{
    "os_type": "windows",
    "file": "c:\\\\windows\\\\system32\\\\config\\\\sam",
    "depth": 4,
    "include_absolute": true
  }'

# Response:
{
  "status": "success",
  "config": {
    "os_type": "windows",
    "file": "c:\\windows\\system32\\config\\sam",
    "depth": 4,
    "include_absolute": true
  },
  "statistics": {
    "total_patterns": 1234,
    "relative_patterns": 1122,
    "absolute_patterns": 112,
    "generation_time": 0.256
  },
  "patterns": [
    "../c:/windows/system32/config/sam",
    "../../c:/windows/system32/config/sam",
    "../../../c:/windows/system32/config/sam",
    "../../../../c:/windows/system32/config/sam",
    "c:\\windows\\system32\\config\\sam",
    "%2fc%5cwindows%5csystem32%5cconfig%5csam",
    "...additional 1228 patterns..."
  ]
}
```

### Get Pattern Statistics

```http
GET /generate/stats
```

Get statistics about pattern generation capabilities.

```bash
curl "http://localhost:8000/generate/stats" \
  -H "X-API-Key: ddp_1234567890abcdef"

# Response:
{
  "supported_os_types": ["unix", "windows", "generic"],
  "target_files": {
    "unix": 36,
    "windows": 27,
    "generic": 15
  },
  "pattern_types": {
    "relative_patterns": 24,
    "absolute_patterns": 144,
    "encoding_variations": 20
  },
  "performance": {
    "average_generation_time": 0.287,
    "patterns_per_second": 6734,
    "max_recommended_depth": 15
  }
}
```

## ⚡ Real-time Operations

### WebSocket Connection

Connect to live scan updates via WebSocket.

```javascript
// JavaScript WebSocket example
const ws = new WebSocket('ws://localhost:8000/ws/scan_2025092810300001');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Scan update:', data);
};

// Message types:
// - progress: Scan progress updates
// - vulnerability: New vulnerability found
// - error: Error occurred
// - completed: Scan completed
// - stopped: Scan stopped
```

#### WebSocket Message Examples

**Progress Update:**
```json
{
  "type": "progress",
  "scan_id": "scan_2025092810300001",
  "timestamp": "2025-09-28T10:30:30Z",
  "current_pattern": 156,
  "total_patterns": 2667,
  "percentage": 5.8,
  "requests_per_second": 2.1,
  "estimated_time_remaining": 1195
}
```

**Vulnerability Found:**
```json
{
  "type": "vulnerability",
  "scan_id": "scan_2025092810300001",
  "timestamp": "2025-09-28T10:31:45Z",
  "vulnerability": {
    "url": "http://example.com/page.php?file=../../../etc/passwd",
    "method": "GET",
    "depth": 3,
    "pattern_matched": "root:",
    "response_code": 200,
    "content_length": 1847
  }
}
```

**Scan Completed:**
```json
{
  "type": "completed",
  "scan_id": "scan_2025092810300001",
  "timestamp": "2025-09-28T10:32:15Z",
  "summary": {
    "duration": 135,
    "total_requests": 247,
    "vulnerabilities_found": 1,
    "success_rate": 0.4
  }
}
```

### Server-Sent Events (SSE)

Alternative to WebSocket for real-time updates.

```http
GET /scans/{scan_id}/events
```

```bash
# Connect to SSE stream
curl -N "http://localhost:8000/scans/scan_2025092810300001/events" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -H "Accept: text/event-stream"

# Stream output:
event: progress
data: {"current_pattern": 156, "total_patterns": 2667, "percentage": 5.8}

event: vulnerability
data: {"url": "http://example.com/page.php?file=../../../etc/passwd", "depth": 3}

event: completed
data: {"duration": 135, "vulnerabilities_found": 1}
```

## 📊 Data Models

### Scan Configuration Model

```json
{
  "module": "http|http-url|ftp|tftp|payload|stdout",
  "target": {
    "host": "string",
    "port": "integer",
    "url": "string|null"
  },
  "config": {
    "file": "string",
    "pattern": "string",
    "depth": "integer (1-20)",
    "delay": "float (0.0-10.0)",
    "os_type": "unix|windows|generic",
    "extension": "string|null"
  },
  "options": {
    "ssl": "boolean",
    "os_detection": "boolean",
    "service_detection": "boolean",
    "bisection": "boolean",
    "break_on_first": "boolean",
    "continue_on_error": "boolean",
    "quiet": "boolean",
    "extra_files": "boolean"
  },
  "auth": {
    "username": "string|null",
    "password": "string|null"
  },
  "http_options": {
    "method": "GET|POST|HEAD|PUT|DELETE|COPY|MOVE|OPTIONS",
    "user_agent": "string",
    "timeout": "integer",
    "headers": "object|null"
  },
  "payload_options": {
    "payload_file": "string|null",
    "custom_payloads": "array|null"
  },
  "output": {
    "format": "json|xml|csv|html|text",
    "filename": "string|null",
    "timestamp": "boolean"
  }
}
```

### Vulnerability Model

```json
{
  "id": "string",
  "scan_id": "string",
  "url": "string",
  "method": "string",
  "depth": "integer",
  "pattern_matched": "string",
  "response_code": "integer",
  "content_length": "integer",
  "response_headers": "object",
  "response_content": "string|null",
  "found_at": "datetime",
  "severity": "low|medium|high|critical",
  "confidence": "low|medium|high"
}
```

### Scan Status Model

```json
{
  "scan_id": "string",
  "status": "created|running|paused|completed|stopped|error",
  "progress": {
    "current_pattern": "integer",
    "total_patterns": "integer",
    "percentage": "float",
    "requests_per_second": "float",
    "estimated_time_remaining": "integer"
  },
  "results": {
    "vulnerabilities_found": "integer",
    "total_requests": "integer",
    "success_rate": "float",
    "average_response_time": "float",
    "error_count": "integer"
  },
  "timestamps": {
    "created_at": "datetime",
    "started_at": "datetime|null",
    "completed_at": "datetime|null",
    "last_update": "datetime"
  }
}
```

## ❌ Error Handling

### HTTP Status Codes

The API uses standard HTTP status codes:

- **200 OK**: Successful request
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **422 Unprocessable Entity**: Validation error
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

### Error Response Format

```json
{
  "error": {
    "type": "ValidationError",
    "message": "Invalid configuration provided",
    "details": {
      "field": "target.host",
      "issue": "Host is required for HTTP module",
      "received": null,
      "expected": "string"
    },
    "code": "MISSING_REQUIRED_FIELD",
    "timestamp": "2025-09-28T10:30:00Z"
  }
}
```

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `MISSING_REQUIRED_FIELD` | Required field not provided | 400 |
| `INVALID_MODULE` | Unsupported module specified | 400 |
| `INVALID_HOST` | Invalid hostname or IP | 400 |
| `INVALID_PORT` | Port out of valid range | 400 |
| `INVALID_DEPTH` | Depth out of range (1-20) | 400 |
| `INVALID_DELAY` | Delay out of range (0.0-10.0) | 400 |
| `SCAN_NOT_FOUND` | Scan ID does not exist | 404 |
| `SCAN_ALREADY_RUNNING` | Cannot start running scan | 409 |
| `API_KEY_INVALID` | Invalid API key | 401 |
| `RATE_LIMIT_EXCEEDED` | Too many requests | 429 |
| `INTERNAL_ERROR` | Server error | 500 |

### Error Handling Examples

```bash
# Handle validation error
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -d '{"module": "http"}'  # Missing required fields

# Response (400 Bad Request):
{
  "error": {
    "type": "ValidationError",
    "message": "Missing required fields",
    "details": {
      "missing_fields": ["target.host", "config.pattern"],
      "received": {"module": "http"},
      "required_for_module": "http"
    },
    "code": "MISSING_REQUIRED_FIELD"
  }
}
```

## 🛠️ SDK and Integration

### Python SDK

```python
import requests
import json

class DotDotPwnClient:
    def __init__(self, base_url="http://localhost:8000", api_key=None):
        self.base_url = base_url
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})
    
    def create_scan(self, config):
        """Create a new scan"""
        response = self.session.post(f"{self.base_url}/scans", json=config)
        response.raise_for_status()
        return response.json()
    
    def get_scan(self, scan_id):
        """Get scan details"""
        response = self.session.get(f"{self.base_url}/scans/{scan_id}")
        response.raise_for_status()
        return response.json()
    
    def start_scan(self, scan_id):
        """Start a scan"""
        response = self.session.post(f"{self.base_url}/scans/{scan_id}/start")
        response.raise_for_status()
        return response.json()
    
    def stop_scan(self, scan_id):
        """Stop a scan"""
        response = self.session.post(f"{self.base_url}/scans/{scan_id}/stop")
        response.raise_for_status()
        return response.json()

# Usage example
client = DotDotPwnClient(api_key="ddp_1234567890abcdef")

# Create and start a scan
scan_config = {
    "module": "http",
    "target": {"host": "example.com"},
    "config": {"pattern": "root:", "depth": 8},
    "auto_start": True
}

scan = client.create_scan(scan_config)
print(f"Scan created: {scan['scan_id']}")

# Monitor scan progress
import time
while True:
    status = client.get_scan(scan['scan_id'])
    print(f"Progress: {status['progress']['percentage']}%")
    
    if status['status'] in ['completed', 'stopped', 'error']:
        break
    
    time.sleep(5)

print(f"Scan completed. Vulnerabilities found: {status['results']['vulnerabilities_found']}")
```

### JavaScript SDK

```javascript
class DotDotPwnClient {
    constructor(baseUrl = 'http://localhost:8000', apiKey = null) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.headers = {
            'Content-Type': 'application/json'
        };
        if (apiKey) {
            this.headers['X-API-Key'] = apiKey;
        }
    }

    async createScan(config) {
        const response = await fetch(`${this.baseUrl}/scans`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify(config)
        });
        return await response.json();
    }

    async getScan(scanId) {
        const response = await fetch(`${this.baseUrl}/scans/${scanId}`, {
            headers: this.headers
        });
        return await response.json();
    }

    connectWebSocket(scanId) {
        const ws = new WebSocket(`ws://${this.baseUrl.replace('http://', '')}/ws/${scanId}`);
        return ws;
    }
}

// Usage example
const client = new DotDotPwnClient('http://localhost:8000', 'ddp_1234567890abcdef');

const scanConfig = {
    module: 'http',
    target: { host: 'example.com' },
    config: { pattern: 'root:', depth: 8 },
    auto_start: true
};

client.createScan(scanConfig).then(scan => {
    console.log(`Scan created: ${scan.scan_id}`);
    
    // Connect to real-time updates
    const ws = client.connectWebSocket(scan.scan_id);
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('Scan update:', data);
    };
});
```

### cURL Integration

```bash
#!/bin/bash
# Bash script for API integration

API_BASE="http://localhost:8000"
API_KEY="ddp_1234567890abcdef"

# Function to make authenticated requests
api_request() {
    curl -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" "$@"
}

# Create scan
SCAN_CONFIG='{
    "module": "http",
    "target": {"host": "example.com"},
    "config": {"pattern": "root:", "depth": 8},
    "auto_start": true
}'

echo "Creating scan..."
SCAN_RESPONSE=$(api_request -X POST "$API_BASE/scans" -d "$SCAN_CONFIG")
SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')

echo "Scan created: $SCAN_ID"

# Monitor progress
while true; do
    STATUS_RESPONSE=$(api_request "$API_BASE/scans/$SCAN_ID")
    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
    PERCENTAGE=$(echo "$STATUS_RESPONSE" | jq -r '.progress.percentage')
    
    echo "Status: $STATUS ($PERCENTAGE%)"
    
    if [[ "$STATUS" == "completed" || "$STATUS" == "stopped" || "$STATUS" == "error" ]]; then
        break
    fi
    
    sleep 5
done

# Get final results
FINAL_RESULTS=$(api_request "$API_BASE/scans/$SCAN_ID")
VULNERABILITIES=$(echo "$FINAL_RESULTS" | jq -r '.results.vulnerabilities_found')

echo "Scan completed. Vulnerabilities found: $VULNERABILITIES"
```

## 📝 Examples and Use Cases

### Basic HTTP Scan

```bash
# Create and start HTTP scan
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -d '{
    "module": "http",
    "target": {
      "host": "example.com",
      "port": 80
    },
    "config": {
      "file": "/etc/passwd",
      "pattern": "root:",
      "depth": 8
    },
    "options": {
      "ssl": false,
      "break_on_first": true
    },
    "auto_start": true
  }'
```

### HTTPS Scan with Authentication

```bash
# HTTPS scan with authentication
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -d '{
    "module": "http",
    "target": {
      "host": "secure.example.com",
      "port": 443
    },
    "config": {
      "file": "/etc/shadow",
      "pattern": "root:",
      "depth": 10
    },
    "options": {
      "ssl": true,
      "os_detection": true,
      "service_detection": true
    },
    "auth": {
      "username": "admin",
      "password": "secret"
    },
    "auto_start": true
  }'
```

### URL Parameter Fuzzing

```bash
# HTTP-URL module for parameter testing
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ddp_1234567890abcdef" \
  -d '{
    "module": "http-url",
    "target": {
      "url": "http://vulnerable.com/page.php?file=TRAVERSAL"
    },
    "config": {
      "pattern": "root:",
      "depth": 12
    },
    "options": {
      "bisection": true,
      "break_on_first": true
    },
    "auto_start": true
  }'
```

### Batch Scanning

```bash
# Script for scanning multiple targets
#!/bin/bash

API_BASE="http://localhost:8000"
API_KEY="ddp_1234567890abcdef"

TARGETS=("example1.com" "example2.com" "example3.com")

for target in "${TARGETS[@]}"; do
    echo "Starting scan for $target..."
    
    SCAN_CONFIG=$(cat <<EOF
{
    "module": "http",
    "target": {"host": "$target"},
    "config": {"pattern": "root:", "depth": 8},
    "options": {"break_on_first": true},
    "auto_start": true
}
EOF
    )
    
    RESPONSE=$(curl -s -X POST "$API_BASE/scans" \
        -H "X-API-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$SCAN_CONFIG")
    
    SCAN_ID=$(echo "$RESPONSE" | jq -r '.scan_id')
    echo "Scan created for $target: $SCAN_ID"
done
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]

jobs:
  dotdotpwn-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Start DotDotPwn API
        run: |
          python dotdotpwn.py api --host localhost --port 8000 &
          sleep 10
      
      - name: Run Security Scan
        run: |
          SCAN_RESPONSE=$(curl -X POST "http://localhost:8000/scans" \
            -H "Content-Type: application/json" \
            -d '{
              "module": "http",
              "target": {"host": "${{ secrets.TEST_HOST }}"},
              "config": {"pattern": "root:", "depth": 8},
              "auto_start": true
            }')
          
          SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
          
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
            echo "::error::Vulnerabilities found: $VULNS"
            exit 1
          fi
```

---

This API documentation provides complete coverage of the PyDotPwn REST API. For more examples and advanced usage, check out the [Examples section](examples) or refer to the interactive API documentation at `/docs` when running the server.