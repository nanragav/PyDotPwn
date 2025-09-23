#!/usr/bin/env python3
"""
Quick Test Script for DotDotPwn Python Implementation

This script runs essential tests to verify the installation and basic functionality.
Perfect for CI/CD pipelines and quick verification.
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def quick_test():
    """Run quick essential tests"""
    print("🚀 DotDotPwn Quick Test")
    print("=" * 40)
    
    try:
        # Test core imports
        from dotdotpwn.core.traversal_engine import TraversalEngine, OSType
        from dotdotpwn.stdout import STDOUTHandler, OutputMode
        print("✅ Core imports successful")
        
        # Test traversal generation
        engine = TraversalEngine()
        traversals = engine.generate_traversals(OSType.UNIX, 3, "/etc/passwd")
        assert len(traversals) > 1000, f"Expected >1000 traversals, got {len(traversals)}"
        print(f"✅ Generated {len(traversals)} traversals")
        
        # Test STDOUT handler
        handler = STDOUTHandler(mode=OutputMode.QUIET)
        handler.print_info("Test successful")
        print("✅ STDOUT handler working")
        
        # Test CLI availability
        cli_path = project_root / "dotdotpwn.py"
        if cli_path.exists():
            print("✅ CLI script available")
        else:
            print("⚠️  CLI script not found")
        
        print("\n🎉 Quick test PASSED! DotDotPwn is ready to use.")
        return True
        
    except Exception as e:
        print(f"\n❌ Quick test FAILED: {e}")
        return False

if __name__ == "__main__":
    success = quick_test()
    sys.exit(0 if success else 1)