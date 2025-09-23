"""
FastAPI application for DotDotPwn REST API

This module provides REST API endpoints for all DotDotPwn functionality
to enable integration with GUIs and other applications.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import uuid
import asyncio
from datetime import datetime
import tempfile
import os
from pathlib import Path

from ..core.traversal_engine import TraversalEngine, OSType
from ..core.fingerprint import Fingerprint
from ..protocols.http_fuzzer import HTTPFuzzer
from ..protocols.http_url_fuzzer import HTTPURLFuzzer
from ..protocols.ftp_fuzzer import FTPFuzzer
from ..protocols.tftp_fuzzer import TFTPFuzzer
from ..protocols.payload_fuzzer import PayloadFuzzer
from ..utils.reporter import Reporter


# Pydantic models for request/response
class TargetInfo(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    port: Optional[int] = Field(None, description="Target port")
    protocol: Optional[str] = Field(None, description="Protocol (http, https, ftp, tftp)")


class ScanConfig(BaseModel):
    os_type: str = Field("generic", description="OS type: windows, unix, generic")
    depth: int = Field(6, ge=1, le=20, description="Traversal depth")
    specific_file: Optional[str] = Field(None, description="Specific file to target")
    extra_files: bool = Field(False, description="Include extra files")
    extension: Optional[str] = Field(None, description="File extension to append")
    time_delay: float = Field(0.3, ge=0, le=10, description="Delay between requests")
    break_on_first: bool = Field(False, description="Stop after first vulnerability")
    continue_on_error: bool = Field(False, description="Continue on connection errors")
    bisection: bool = Field(False, description="Enable bisection algorithm")
    quiet: bool = Field(False, description="Quiet mode")


class HTTPScanRequest(BaseModel):
    target: TargetInfo
    config: ScanConfig
    ssl: bool = Field(False, description="Use SSL/HTTPS")
    method: str = Field("GET", description="HTTP method")
    pattern: Optional[str] = Field(None, description="Pattern to match in response")
    user_agent_file: Optional[str] = Field(None, description="Path to user agent file")


class HTTPURLScanRequest(BaseModel):
    url: str = Field(..., description="URL with TRAVERSAL placeholder")
    pattern: str = Field(..., description="Pattern to match in response")
    config: ScanConfig
    user_agent_file: Optional[str] = Field(None, description="Path to user agent file")


class FTPScanRequest(BaseModel):
    target: TargetInfo
    config: ScanConfig
    username: str = Field("anonymous", description="FTP username")
    password: str = Field("dot@dot.pwn", description="FTP password")


class TFTPScanRequest(BaseModel):
    target: TargetInfo
    config: ScanConfig


class PayloadScanRequest(BaseModel):
    target: TargetInfo
    config: ScanConfig
    payload_template: str = Field(..., description="Payload template with TRAVERSAL placeholder")
    pattern: Optional[str] = Field(None, description="Pattern to match in response")
    ssl_enabled: bool = Field(False, description="Use SSL/TLS")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    results: Optional[Dict[str, Any]] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # "running", "completed", "failed"
    progress: Optional[Dict[str, Any]] = None
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# Global storage for scan results (in production, use Redis or database)
scan_results = {}


# Create FastAPI app
app = FastAPI(
    title="DotDotPwn API",
    description="REST API for DotDotPwn Directory Traversal Fuzzer",
    version="3.0.2",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "DotDotPwn API",
        "version": "3.0.2",
        "description": "REST API for Directory Traversal Fuzzing",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "scan": {
                "http": "/scan/http",
                "http-url": "/scan/http-url",
                "ftp": "/scan/ftp",
                "tftp": "/scan/tftp",
                "payload": "/scan/payload"
            },
            "utils": {
                "generate-traversals": "/utils/generate-traversals",
                "fingerprint": "/utils/fingerprint",
                "test-connection": "/utils/test-connection"
            }
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/scan/http", response_model=ScanResponse)
async def scan_http(request: HTTPScanRequest, background_tasks: BackgroundTasks):
    """Start HTTP directory traversal scan"""
    scan_id = str(uuid.uuid4())
    
    # Initialize scan status
    scan_results[scan_id] = {
        "status": "running",
        "start_time": datetime.now(),
        "progress": {"current": 0, "total": 0},
        "results": None,
        "error": None
    }
    
    # Start background task
    background_tasks.add_task(run_http_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="HTTP scan started successfully"
    )


@app.post("/scan/http-url", response_model=ScanResponse)
async def scan_http_url(request: HTTPURLScanRequest, background_tasks: BackgroundTasks):
    """Start HTTP URL directory traversal scan"""
    scan_id = str(uuid.uuid4())
    
    scan_results[scan_id] = {
        "status": "running",
        "start_time": datetime.now(),
        "progress": {"current": 0, "total": 0},
        "results": None,
        "error": None
    }
    
    background_tasks.add_task(run_http_url_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="HTTP URL scan started successfully"
    )


@app.post("/scan/ftp", response_model=ScanResponse)
async def scan_ftp(request: FTPScanRequest, background_tasks: BackgroundTasks):
    """Start FTP directory traversal scan"""
    scan_id = str(uuid.uuid4())
    
    scan_results[scan_id] = {
        "status": "running",
        "start_time": datetime.now(),
        "progress": {"current": 0, "total": 0},
        "results": None,
        "error": None
    }
    
    background_tasks.add_task(run_ftp_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="FTP scan started successfully"
    )


@app.post("/scan/tftp", response_model=ScanResponse)
async def scan_tftp(request: TFTPScanRequest, background_tasks: BackgroundTasks):
    """Start TFTP directory traversal scan"""
    scan_id = str(uuid.uuid4())
    
    scan_results[scan_id] = {
        "status": "running",
        "start_time": datetime.now(),
        "progress": {"current": 0, "total": 0},
        "results": None,
        "error": None
    }
    
    background_tasks.add_task(run_tftp_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="TFTP scan started successfully"
    )


@app.post("/scan/payload", response_model=ScanResponse)
async def scan_payload(request: PayloadScanRequest, background_tasks: BackgroundTasks):
    """Start payload-based directory traversal scan"""
    scan_id = str(uuid.uuid4())
    
    scan_results[scan_id] = {
        "status": "running",
        "start_time": datetime.now(),
        "progress": {"current": 0, "total": 0},
        "results": None,
        "error": None
    }
    
    background_tasks.add_task(run_payload_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message="Payload scan started successfully"
    )


@app.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get scan status and results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    return ScanStatus(
        scan_id=scan_id,
        status=scan_data["status"],
        progress=scan_data["progress"],
        results=scan_data["results"],
        error=scan_data["error"]
    )


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scan_results[scan_id]
    return {"message": "Scan deleted successfully"}


@app.get("/scans")
async def list_scans():
    """List all scans"""
    scans = []
    for scan_id, scan_data in scan_results.items():
        scans.append({
            "scan_id": scan_id,
            "status": scan_data["status"],
            "start_time": scan_data["start_time"],
            "vulnerabilities_found": scan_data.get("results", {}).get("vulnerabilities_found", 0)
        })
    
    return {"scans": scans}


@app.post("/utils/generate-traversals")
async def generate_traversals(
    os_type: str = Query("generic", description="OS type: windows, unix, generic"),
    depth: int = Query(6, ge=1, le=20, description="Traversal depth"),
    specific_file: Optional[str] = Query(None, description="Specific file to target"),
    extra_files: bool = Query(False, description="Include extra files"),
    extension: Optional[str] = Query(None, description="File extension to append")
):
    """Generate traversal patterns"""
    try:
        # Convert string to OSType
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(os_type.lower(), OSType.GENERIC)
        
        engine = TraversalEngine(quiet=True)
        traversals = engine.generate_traversals(
            os_type=os_enum,
            depth=depth,
            specific_file=specific_file,
            extra_files=extra_files,
            extension=extension
        )
        
        return {
            "traversals": traversals,
            "count": len(traversals),
            "config": {
                "os_type": os_type,
                "depth": depth,
                "specific_file": specific_file,
                "extra_files": extra_files,
                "extension": extension
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/utils/fingerprint")
async def fingerprint_target(
    host: str = Query(..., description="Target hostname or IP"),
    port: int = Query(80, description="Target port"),
    protocol: str = Query("tcp", description="Protocol type"),
    os_detection: bool = Query(False, description="Enable OS detection"),
    service_detection: bool = Query(False, description="Enable service detection")
):
    """Fingerprint target system"""
    try:
        fingerprint = Fingerprint()
        
        result = {
            "host": host,
            "port": port,
            "protocol": protocol
        }
        
        # OS detection
        if os_detection:
            os_info = fingerprint.detect_os_nmap(host)
            result["os_detected"] = os_info
        
        # Service detection
        if service_detection:
            service_info = fingerprint.detect_service_version(host, port)
            result["service_info"] = service_info
        
        # Banner grabbing
        banner = fingerprint.grab_banner(host, port, protocol)
        result["banner"] = banner
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/utils/test-connection")
async def test_connection(
    host: str = Query(..., description="Target hostname or IP"),
    port: int = Query(..., description="Target port"),
    protocol: str = Query("tcp", description="Protocol type"),
    ssl: bool = Query(False, description="Use SSL/TLS")
):
    """Test connection to target"""
    try:
        if protocol.lower() == "http":
            fuzzer = HTTPFuzzer(host=host, port=port, ssl=ssl, quiet=True)
            # Test connection by creating a simple request
            result = {"connected": True, "error": None}
        elif protocol.lower() == "ftp":
            fuzzer = FTPFuzzer(host=host, port=port, quiet=True)
            result = fuzzer.test_connection()
        elif protocol.lower() == "tftp":
            fuzzer = TFTPFuzzer(host=host, port=port, quiet=True)
            result = fuzzer.test_connection()
        else:
            # Generic TCP connection test
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((host, port))
                result = {"connected": True, "error": None}
                sock.close()
            except Exception as e:
                result = {"connected": False, "error": str(e)}
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/reports/generate")
async def generate_report(
    scan_id: str = Query(..., description="Scan ID"),
    format: str = Query("json", description="Report format: text, json, csv, xml, html"),
    filename: Optional[str] = Query(None, description="Custom filename")
):
    """Generate report for scan results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    if scan_data["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed")
    
    try:
        reporter = Reporter()
        
        # Dummy target and config info (should be stored with scan results)
        target_info = {"host": "unknown", "protocol": "unknown", "port": "unknown"}
        scan_config = {"module": "unknown", "depth": 6}
        
        report_path = reporter.generate_report(
            results=scan_data["results"],
            target_info=target_info,
            scan_config=scan_config,
            format=format,
            filename=filename
        )
        
        return FileResponse(
            path=report_path,
            filename=os.path.basename(report_path),
            media_type="application/octet-stream"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Background task functions
async def run_http_scan(scan_id: str, request: HTTPScanRequest):
    """Background task for HTTP scanning"""
    try:
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(request.config.os_type.lower(), OSType.GENERIC)
        
        fuzzer = HTTPFuzzer(
            host=request.target.host,
            port=request.target.port or (443 if request.ssl else 80),
            ssl=request.ssl,
            method=request.method,
            quiet=request.config.quiet
        )
        
        # Progress callback
        def progress_callback(current: int, total: int, traversal: str):
            scan_results[scan_id]["progress"] = {
                "current": current,
                "total": total,
                "current_traversal": traversal
            }
        
        start_time = datetime.now()
        results = await fuzzer.generate_and_fuzz(
            os_type=os_enum,
            depth=request.config.depth,
            specific_file=request.config.specific_file,
            extra_files=request.config.extra_files,
            extension=request.config.extension,
            pattern=request.pattern,
            time_delay=request.config.time_delay,
            break_on_first=request.config.break_on_first,
            continue_on_error=request.config.continue_on_error,
            bisection=request.config.bisection
        )
        
        end_time = datetime.now()
        results["scan_duration"] = (end_time - start_time).total_seconds()
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["results"] = results
        scan_results[scan_id]["end_time"] = end_time
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)


async def run_http_url_scan(scan_id: str, request: HTTPURLScanRequest):
    """Background task for HTTP URL scanning"""
    try:
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(request.config.os_type.lower(), OSType.GENERIC)
        
        fuzzer = HTTPURLFuzzer(
            base_url=request.url,
            quiet=request.config.quiet
        )
        
        def progress_callback(current: int, total: int, traversal: str):
            scan_results[scan_id]["progress"] = {
                "current": current,
                "total": total,
                "current_traversal": traversal
            }
        
        start_time = datetime.now()
        results = await fuzzer.generate_and_fuzz(
            pattern=request.pattern,
            os_type=os_enum,
            depth=request.config.depth,
            specific_file=request.config.specific_file,
            extra_files=request.config.extra_files,
            extension=request.config.extension,
            time_delay=request.config.time_delay,
            break_on_first=request.config.break_on_first,
            continue_on_error=request.config.continue_on_error,
            bisection=request.config.bisection
        )
        
        end_time = datetime.now()
        results["scan_duration"] = (end_time - start_time).total_seconds()
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["results"] = results
        scan_results[scan_id]["end_time"] = end_time
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)


async def run_ftp_scan(scan_id: str, request: FTPScanRequest):
    """Background task for FTP scanning"""
    try:
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(request.config.os_type.lower(), OSType.GENERIC)
        
        fuzzer = FTPFuzzer(
            host=request.target.host,
            port=request.target.port or 21,
            username=request.username,
            password=request.password,
            quiet=request.config.quiet
        )
        
        def progress_callback(current: int, total: int, traversal: str):
            scan_results[scan_id]["progress"] = {
                "current": current,
                "total": total,
                "current_traversal": traversal
            }
        
        start_time = datetime.now()
        results = fuzzer.generate_and_fuzz(
            os_type=os_enum,
            depth=request.config.depth,
            specific_file=request.config.specific_file,
            extra_files=request.config.extra_files,
            extension=request.config.extension,
            time_delay=request.config.time_delay,
            break_on_first=request.config.break_on_first,
            continue_on_error=request.config.continue_on_error,
            bisection=request.config.bisection
        )
        
        end_time = datetime.now()
        results["scan_duration"] = (end_time - start_time).total_seconds()
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["results"] = results
        scan_results[scan_id]["end_time"] = end_time
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)


async def run_tftp_scan(scan_id: str, request: TFTPScanRequest):
    """Background task for TFTP scanning"""
    try:
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(request.config.os_type.lower(), OSType.GENERIC)
        
        fuzzer = TFTPFuzzer(
            host=request.target.host,
            port=request.target.port or 69,
            quiet=request.config.quiet
        )
        
        def progress_callback(current: int, total: int, traversal: str):
            scan_results[scan_id]["progress"] = {
                "current": current,
                "total": total,
                "current_traversal": traversal
            }
        
        start_time = datetime.now()
        results = fuzzer.generate_and_fuzz(
            os_type=os_enum,
            depth=request.config.depth,
            specific_file=request.config.specific_file,
            extra_files=request.config.extra_files,
            extension=request.config.extension,
            time_delay=request.config.time_delay,
            break_on_first=request.config.break_on_first,
            continue_on_error=request.config.continue_on_error,
            bisection=request.config.bisection
        )
        
        end_time = datetime.now()
        results["scan_duration"] = (end_time - start_time).total_seconds()
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["results"] = results
        scan_results[scan_id]["end_time"] = end_time
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)


async def run_payload_scan(scan_id: str, request: PayloadScanRequest):
    """Background task for payload scanning"""
    try:
        os_type_map = {"windows": OSType.WINDOWS, "unix": OSType.UNIX, "generic": OSType.GENERIC}
        os_enum = os_type_map.get(request.config.os_type.lower(), OSType.GENERIC)
        
        fuzzer = PayloadFuzzer(
            host=request.target.host,
            port=request.target.port,
            payload_template=request.payload_template,
            ssl_enabled=request.ssl_enabled,
            quiet=request.config.quiet
        )
        
        def progress_callback(current: int, total: int, traversal: str):
            scan_results[scan_id]["progress"] = {
                "current": current,
                "total": total,
                "current_traversal": traversal
            }
        
        start_time = datetime.now()
        results = fuzzer.generate_and_fuzz(
            os_type=os_enum,
            depth=request.config.depth,
            specific_file=request.config.specific_file,
            extra_files=request.config.extra_files,
            extension=request.config.extension,
            pattern=request.pattern,
            time_delay=request.config.time_delay,
            break_on_first=request.config.break_on_first,
            continue_on_error=request.config.continue_on_error,
            bisection=request.config.bisection
        )
        
        end_time = datetime.now()
        results["scan_duration"] = (end_time - start_time).total_seconds()
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["results"] = results
        scan_results[scan_id]["end_time"] = end_time
        
    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)