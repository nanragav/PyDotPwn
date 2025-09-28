#!/usr/bin/env python3
"""
Test script to verify GUI fixes
"""

def test_psutil_import():
    """Test if psutil can be imported for resource monitoring"""
    try:
        import psutil
        print("✅ psutil import successful")
        
        # Test basic functionality
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        print(f"✅ CPU: {cpu}%")
        print(f"✅ Memory: {memory.percent}%")
        return True
    except ImportError as e:
        print(f"❌ psutil import failed: {e}")
        return False

def test_gui_import():
    """Test if GUI can be imported"""
    try:
        import sys
        from pathlib import Path
        
        # Add src to path
        project_root = Path(__file__).parent
        src_path = project_root / "src"
        sys.path.insert(0, str(src_path))
        
        from gui.dotdotpwn_gui import DotDotPwnGUI, ScanConfiguration
        print("✅ GUI import successful")
        
        # Test new configuration fields
        config = ScanConfiguration()
        print(f"✅ New fields available:")
        print(f"   - target_url: {config.target_url}")
        print(f"   - payload_file: {config.payload_file}")
        print(f"   - os_detection: {config.os_detection}")
        print(f"   - service_detection: {config.service_detection}")
        print(f"   - bisection: {config.bisection}")
        print(f"   - user_agent: {config.user_agent}")
        
        return True
    except ImportError as e:
        print(f"❌ GUI import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ GUI test failed: {e}")
        return False

def main():
    print("🧪 Testing GUI fixes...")
    print("=" * 50)
    
    psutil_ok = test_psutil_import()
    print("-" * 30)
    gui_ok = test_gui_import()
    
    print("=" * 50)
    if psutil_ok and gui_ok:
        print("✅ All tests passed! GUI fixes are working.")
    else:
        print("❌ Some tests failed. Check the errors above.")

if __name__ == '__main__':
    main()