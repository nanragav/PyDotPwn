#!/usr/bin/env python3
"""
DotDotPwn Python Implementation - Main Entry Point

This script provides the main entry point for the DotDotPwn application.
It can be used to run either the CLI interface or start the API server.
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

def main():
    """Main entry point"""
    try:
        from dotdotpwn.cli import app
        app()
    except ImportError as e:
        print(f"Error: Missing dependencies. Please install required packages:")
        print("pip install typer rich fastapi uvicorn aiohttp pydantic")
        print(f"Import error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()