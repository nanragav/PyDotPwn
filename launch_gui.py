#!/usr/bin/env python3
"""
DotDotPwn GUI Launcher

Simple launcher script for the DotDotPwn GUI application.
Handles dependency checks and provides helpful error messages.
"""

import sys
import os

# Suppress SSL warnings for security testing
try:
    import urllib3
    import warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
except ImportError:
    pass

def main():
    """Launch the DotDotPwn GUI application."""
    try:
        # Check if GUI dependencies are available
        try:
            from PyQt6.QtWidgets import QApplication
            from PyQt6.QtGui import QAction
            from PyQt6.QtCore import Qt
            print("✅ PyQt6 dependencies found")
        except ImportError as e:
            print("❌ Missing GUI dependencies. Please install PyQt6:")
            print("pip install PyQt6 PyQt6-tools qtawesome pyqtgraph qdarkstyle")
            print(f"Import error: {e}")
            print("\nMake sure you have activated your virtual environment if you're using one.")
            return 1
        
        # Check if GUI file exists
        gui_path = os.path.join(os.path.dirname(__file__), 'gui', 'dotdotpwn_gui.py')
        if not os.path.exists(gui_path):
            print(f"❌ GUI file not found: {gui_path}")
            return 1
        
        print("🚀 Launching DotDotPwn GUI...")
        
        # Launch the GUI directly
        from gui.dotdotpwn_gui import main as gui_main
        gui_main()
        
        return 0
        
    except Exception as e:
        print(f"❌ Error launching GUI: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())