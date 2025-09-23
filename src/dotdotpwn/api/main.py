"""
Main entry point for DotDotPwn API server
"""

import uvicorn
from .app import app


def start_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    log_level: str = "info"
):
    """
    Start the DotDotPwn API server
    
    Args:
        host: Host to bind to
        port: Port to bind to
        reload: Enable auto-reload for development
        log_level: Log level
    """
    uvicorn.run(
        "dotdotpwn.api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level
    )


if __name__ == "__main__":
    start_server(reload=True)