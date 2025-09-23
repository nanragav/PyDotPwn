"""
Test package for DotDotPwn Python Implementation
"""

import sys
from pathlib import Path

# Add src directory to path for testing
src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))