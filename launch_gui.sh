#!/bin/bash
# DotDotPwn GUI Launcher Script
# Activates virtual environment and launches the GUI

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate virtual environment
source "$SCRIPT_DIR/dotdotpwn-env/bin/activate"

# Launch the GUI
echo "🚀 Launching DotDotPwn GUI..."
python "$SCRIPT_DIR/launch_gui.py"