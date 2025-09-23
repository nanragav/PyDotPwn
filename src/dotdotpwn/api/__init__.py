"""
API package for DotDotPwn

This package contains the FastAPI REST API:
- app: Main FastAPI application with all endpoints
- main: Entry point for starting the API server
"""

from .app import app
from .main import start_server

__all__ = [
    "app",
    "start_server",
]