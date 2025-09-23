#!/usr/bin/env python3
"""
DotDotPwn GUI Launcher

Simple launcher script for the DotDotPwn GUI application.
Handles dependency checks and provides helpful error messages.
"""

import sys
import os
import subprocess

def get_venv_python():
    """Get the correct Python executable from virtual environment."""
    # Check if we're in the correct directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    venv_python = os.path.join(current_dir, 'dotdotpwn-env', 'bin', 'python')
    
    if os.path.exists(venv_python):
        return venv_python
    return sys.executable

def main():
    """Launch the DotDotPwn GUI application."""
    try:
        # Get the correct Python executable
        python_exe = get_venv_python()
        
        # Check if we're using the virtual environment
        if 'dotdotpwn-env' not in python_exe:
            print("Warning: Not using virtual environment. Some dependencies might be missing.")
        
        # Import required modules to check dependencies
        try:
            from PyQt6.QtWidgets import QApplication
            from PyQt6.QtGui import QAction
            from PyQt6.QtCore import Qt
            print("✅ PyQt6 dependencies found")
        except ImportError as e:
            print("❌ Missing GUI dependencies. Please install PyQt6:")
            print("pip install PyQt6 PyQt6-tools qtawesome pyqtgraph qdarkstyle")
            print(f"Import error: {e}")
            return 1
        
        # Launch the GUI
        gui_path = os.path.join(os.path.dirname(__file__), 'gui', 'dotdotpwn_gui.py')
        if not os.path.exists(gui_path):
            print(f"❌ GUI file not found: {gui_path}")
            return 1
        
        print("🚀 Launching DotDotPwn GUI...")
        
        # If we're not using the right Python, relaunch with virtual environment
        if python_exe != sys.executable:
            subprocess.run([python_exe, gui_path])
        else:
            from gui.dotdotpwn_gui import main as gui_main
            gui_main()
        
        return 0
        
    except Exception as e:
        print(f"❌ Error launching GUI: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())