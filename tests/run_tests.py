#!/usr/bin/env python3
"""
Enhanced Test Runner for DotDotPwn Python Implementation

This script sets up the environment and runs comprehensive tests.
"""

import sys
import os
import subprocess
from pathlib import Path

def setup_development_environment():
    """Set up the development environment for testing"""
    print("🔧 Setting up development environment...")
    
    # Install the package in development mode
    try:
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-e", "."
        ], check=True, capture_output=True, text=True)
        print("✅ Package installed in development mode")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install package: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False

def run_tests():
    """Run the test suite"""
    print("\n🧪 Running DotDotPwn Test Suite...")
    
    # Add current directory to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    
    try:
        # Import and run the test module
        from tests.test_dotdotpwn import run_basic_tests, run_performance_tests, run_integration_tests
        
        # Run basic tests
        basic_success = run_basic_tests()
        
        if basic_success:
            print("\n" + "="*60)
            run_performance_tests()
            
            print("\n" + "="*60)
            run_integration_tests()
            
            print("\n🎯 All tests completed successfully!")
            return True
        else:
            print("\n❌ Basic tests failed. Fix these before running advanced tests.")
            return False
            
    except ImportError as e:
        print(f"❌ Failed to import test module: {e}")
        return False
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False

def main():
    """Main test runner function"""
    print("🚀 DotDotPwn Enhanced Test Runner")
    print("="*60)
    
    # Check if we're in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Running in virtual environment")
    else:
        print("⚠️  Not in virtual environment - consider using one")
    
    # Setup development environment
    if not setup_development_environment():
        print("❌ Failed to set up development environment")
        sys.exit(1)
    
    # Run tests
    if run_tests():
        print("\n🎉 All tests passed! DotDotPwn is ready for use.")
        sys.exit(0)
    else:
        print("\n🔧 Some tests failed. Check the output above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()