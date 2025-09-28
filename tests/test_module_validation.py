#!/usr/bin/env python3
"""
Test the GUI module validation and command generation
"""

import sys
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from gui.dotdotpwn_gui import ScanConfiguration, ScanWorker

def test_module_configurations():
    """Test different module configurations"""
    print("🧪 Testing Module Configurations...")
    
    # Test 1: http-url module
    print("\n1. Testing HTTP-URL module:")
    config = ScanConfiguration()
    config.module = "http-url"
    config.target_url = "http://example.com/test.php?file=TRAVERSAL"
    config.pattern = "root:"
    
    worker = ScanWorker(config, "python3", "dotdotpwn.py")
    cmd = worker.build_command()
    print(f"   Command: {' '.join(cmd)}")
    expected = ["python3", "dotdotpwn.py", "main", "--module", "http-url", "--url", "http://example.com/test.php?file=TRAVERSAL"]
    if all(part in cmd for part in expected):
        print("   ✅ http-url command correct")
    else:
        print("   ❌ http-url command incorrect")
    
    # Test 2: generate module  
    print("\n2. Testing GENERATE module:")
    config = ScanConfiguration()
    config.module = "generate"
    config.os_type = "unix"
    config.depth = 6
    config.target_file = "/etc/passwd"
    
    worker = ScanWorker(config, "python3", "dotdotpwn.py")
    cmd = worker.build_command()
    print(f"   Command: {' '.join(cmd)}")
    expected = ["python3", "dotdotpwn.py", "generate", "--os-type", "unix", "--depth", "6"]
    if all(part in cmd for part in expected):
        print("   ✅ generate command correct")
    else:
        print("   ❌ generate command incorrect")
    
    # Test 3: stdout module
    print("\n3. Testing STDOUT module:")
    config = ScanConfiguration()
    config.module = "stdout"
    config.target_host = "example.com"  # Should be ignored
    config.depth = 8
    config.target_file = "/etc/passwd"
    config.pattern = "root:"
    
    worker = ScanWorker(config, "python3", "dotdotpwn.py")
    cmd = worker.build_command()
    print(f"   Command: {' '.join(cmd)}")
    expected = ["python3", "dotdotpwn.py", "main", "--module", "stdout"]
    if all(part in cmd for part in expected):
        print("   ✅ stdout command correct")
    else:
        print("   ❌ stdout command incorrect")
    
    # Test 4: payload module
    print("\n4. Testing PAYLOAD module:")
    config = ScanConfiguration()
    config.module = "payload"
    config.target_host = "example.com"
    config.target_port = 443
    config.payload_file = "custom.txt"
    config.pattern = "sensitive"
    config.use_ssl = True
    
    worker = ScanWorker(config, "python3", "dotdotpwn.py")
    cmd = worker.build_command()
    print(f"   Command: {' '.join(cmd)}")
    expected = ["python3", "dotdotpwn.py", "main", "--module", "payload", "--host", "example.com", "--payload", "custom.txt"]
    if all(part in cmd for part in expected):
        print("   ✅ payload command correct")
    else:
        print("   ❌ payload command incorrect")
    
    # Test 5: Standard HTTP module
    print("\n5. Testing HTTP module:")
    config = ScanConfiguration()
    config.module = "http"
    config.target_host = "example.com"
    config.target_port = 80
    config.target_file = "/etc/passwd"
    config.pattern = "root:"
    config.depth = 6
    
    worker = ScanWorker(config, "python3", "dotdotpwn.py")
    cmd = worker.build_command()
    print(f"   Command: {' '.join(cmd)}")
    expected = ["python3", "dotdotpwn.py", "main", "--module", "http", "--host", "example.com"]
    if all(part in cmd for part in expected):
        print("   ✅ http command correct")
    else:
        print("   ❌ http command incorrect")

def main():
    print("🚀 Testing DotDotPwn GUI Module Configurations")
    print("=" * 60)
    
    test_module_configurations()
    
    print("\n" + "=" * 60)
    print("✅ All module configuration tests completed!")
    print("\n📋 Module Summary:")
    print("   • http, ftp, tftp, payload, stdout → use 'main' subcommand")
    print("   • http-url → requires target URL with TRAVERSAL placeholder")
    print("   • generate → uses separate 'generate' subcommand")
    print("   • Pattern generation modes (stdout, generate) don't require host/pattern")

if __name__ == '__main__':
    main()