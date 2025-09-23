#!/usr/bin/env python3
"""
Simple test script for DotDotPwn Python Implementation
Tests core functionality without requiring external dependencies
"""

import sys
import os
from pathlib import Path

# Add src directory to path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

def test_core_imports():
    """Test that core modules can be imported"""
    print("🧪 Testing core module imports...")
    try:
        from dotdotpwn.core.traversal_engine import TraversalEngine, OSType
        print("✅ TraversalEngine imported successfully")
        
        from dotdotpwn.core.fingerprint import Fingerprint
        print("✅ Fingerprint imported successfully")
        
        from dotdotpwn.core.bisection_algorithm import BisectionAlgorithm
        print("✅ BisectionAlgorithm imported successfully")
        
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_traversal_engine():
    """Test basic traversal engine functionality"""
    print("\n🧪 Testing TraversalEngine functionality...")
    try:
        from dotdotpwn.core.traversal_engine import TraversalEngine, OSType
        
        engine = TraversalEngine(quiet=True)
        print("✅ TraversalEngine created successfully")
        
        # Test pattern generation
        traversals = engine.generate_traversals(
            os_type=OSType.UNIX,
            depth=3,
            specific_file="/etc/passwd"
        )
        
        if len(traversals) > 0:
            print(f"✅ Generated {len(traversals)} traversal patterns")
            print(f"   Sample patterns:")
            for i, pattern in enumerate(traversals[:3]):
                print(f"   {i+1}. {pattern}")
            return True
        else:
            print("❌ No traversal patterns generated")
            return False
            
    except Exception as e:
        print(f"❌ TraversalEngine test failed: {e}")
        return False

def test_pattern_generation():
    """Test various pattern generation scenarios"""
    print("\n🧪 Testing pattern generation scenarios...")
    try:
        from dotdotpwn.core.traversal_engine import TraversalEngine, OSType
        
        engine = TraversalEngine(quiet=True)
        
        # Test Windows patterns
        win_patterns = engine.generate_traversals(
            os_type=OSType.WINDOWS,
            depth=2,
            specific_file="boot.ini"
        )
        print(f"✅ Windows patterns: {len(win_patterns)} generated")
        
        # Test generic patterns with extension
        ext_patterns = engine.generate_traversals(
            os_type=OSType.GENERIC,
            depth=2,
            specific_file="config.txt",
            extension=".bak"
        )
        print(f"✅ Extension patterns: {len(ext_patterns)} generated")
        
        # Test extra files
        extra_patterns = engine.generate_traversals(
            os_type=OSType.UNIX,
            depth=2,
            extra_files=True
        )
        print(f"✅ Extra files patterns: {len(extra_patterns)} generated")
        
        return True
        
    except Exception as e:
        print(f"❌ Pattern generation test failed: {e}")
        return False

def test_protocol_imports():
    """Test protocol module imports"""
    print("\n🧪 Testing protocol module imports...")
    success = True
    
    protocols = [
        ("HTTP Fuzzer", "dotdotpwn.protocols.http_fuzzer", "HTTPFuzzer"),
        ("FTP Fuzzer", "dotdotpwn.protocols.ftp_fuzzer", "FTPFuzzer"),
        ("TFTP Fuzzer", "dotdotpwn.protocols.tftp_fuzzer", "TFTPFuzzer"),
        ("Payload Fuzzer", "dotdotpwn.protocols.payload_fuzzer", "PayloadFuzzer"),
        ("HTTP URL Fuzzer", "dotdotpwn.protocols.http_url_fuzzer", "HTTPURLFuzzer"),
    ]
    
    for name, module_path, class_name in protocols:
        try:
            module = __import__(module_path, fromlist=[class_name])
            getattr(module, class_name)
            print(f"✅ {name} imported successfully")
        except ImportError as e:
            print(f"⚠️  {name} import failed (missing dependencies): {e}")
            # Don't mark as failure since dependencies might not be installed
        except Exception as e:
            print(f"❌ {name} import error: {e}")
            success = False
    
    return success

def test_utils():
    """Test utility modules"""
    print("\n🧪 Testing utility modules...")
    try:
        from dotdotpwn.utils.reporter import Reporter
        print("✅ Reporter imported successfully")
        
        from dotdotpwn.stdout import STDOUTHandler, OutputMode
        print("✅ STDOUT handler imported successfully")
        
        return True
    except ImportError as e:
        print(f"⚠️  Utility import failed (missing dependencies): {e}")
        return True  # Don't fail for missing dependencies
    except Exception as e:
        print(f"❌ Utility test failed: {e}")
        return False

def test_package_structure():
    """Test package structure and __init__.py files"""
    print("\n🧪 Testing package structure...")
    
    expected_files = [
        "src/dotdotpwn/__init__.py",
        "src/dotdotpwn/core/__init__.py",
        "src/dotdotpwn/protocols/__init__.py",
        "src/dotdotpwn/utils/__init__.py",
        "src/dotdotpwn/api/__init__.py",
        "requirements.txt",
        "pyproject.toml",
        "COMPREHENSIVE_GUIDE.md",
        "QUICK_REFERENCE.md",
        "INSTALLATION.md"
    ]
    
    missing_files = []
    for file_path in expected_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All expected files present")
        return True

def run_all_tests():
    """Run all tests and return overall result"""
    print("🚀 DotDotPwn Python Implementation - Core Functionality Test")
    print("=" * 60)
    
    tests = [
        ("Package Structure", test_package_structure),
        ("Core Imports", test_core_imports),
        ("TraversalEngine", test_traversal_engine),
        ("Pattern Generation", test_pattern_generation),
        ("Protocol Imports", test_protocol_imports),
        ("Utilities", test_utils),
    ]
    
    results = []
    for test_name, test_func in tests:
        result = test_func()
        results.append((test_name, result))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    total = len(results)
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All core functionality tests passed!")
        print("💡 To test full functionality, install dependencies with:")
        print("   pip install -r requirements.txt")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)