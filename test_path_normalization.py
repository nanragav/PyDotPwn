#!/usr/bin/env python3
"""
Test script to demonstrate the path normalization fix for PyDotPwn

This script shows how the normalization prevents double slashes in traversal payloads
when target files start with path separators.
"""

import sys
sys.path.insert(0, 'src')

from dotdotpwn.core.traversal_engine import TraversalEngine, OSType, DetectionMethod

def test_path_normalization():
    """Test the path normalization fix with various input formats"""
    print("=== PyDotPwn Path Normalization Fix Test ===\n")
    
    # Initialize engine
    engine = TraversalEngine(quiet=True)
    
    # Test cases that previously caused double slashes
    test_cases = [
        ("/etc/passwd", "Unix absolute path"),
        ("\\windows\\system32\\drivers\\etc\\hosts", "Windows absolute path"),
        ("etc/passwd", "Relative path (should work as before)"),
        ("/var/log/apache/access.log", "Deep Unix path"),
        ("\\\\Program Files\\\\test.txt", "Windows UNC-style path")
    ]
    
    detection_methods = [
        (DetectionMethod.SIMPLE, "Simple traversal"),
        (DetectionMethod.NON_RECURSIVE, "Non-recursive bypass"),
        (DetectionMethod.URL_ENCODING, "URL encoding")
    ]
    
    for target_file, description in test_cases:
        print(f"Testing: {description}")
        print(f"Input: '{target_file}'")
        print("─" * 50)
        
        for method, method_desc in detection_methods:
            print(f"\n{method_desc} patterns:")
            
            try:
                patterns = engine.generate_traversals(
                    os_type=OSType.UNIX,
                    depth=3,
                    specific_file=target_file,
                    detection_method=method
                )
                
                # Show first 3 patterns
                for i, pattern in enumerate(patterns[:3]):
                    print(f"  {i+1}: {pattern}")
                    
                    # Check for issues
                    if '//' in pattern and '//' not in target_file:
                        print(f"     ❌ WARNING: Unexpected double slash detected!")
                    elif '\\\\\\\\' in pattern and '\\\\\\\\' not in target_file:
                        print(f"     ❌ WARNING: Unexpected quadruple backslash detected!")
                    else:
                        print(f"     ✅ Clean pattern")
                        
            except Exception as e:
                print(f"  Error: {e}")
        
        print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    test_path_normalization()