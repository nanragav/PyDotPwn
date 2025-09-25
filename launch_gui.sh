#!/bin/bash
# DotDotPwn GUI Launcher Script
# Simple launcher that uses the currently active Python environment

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Launch the GUI
echo "🚀 Launching DotDotPwn GUI..."
echo "Using Python: $(which python)"
python "$SCRIPT_DIR/launch_gui.py"