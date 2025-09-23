#!/usr/bin/env python3
"""
Comprehensive DotDotPwn Verification Suite

This script performs a thorough verification of all DotDotPwn components
including CLI, API, core modules, error handling, and performance tests.
"""

import sys
import os
import json
import time
import asyncio
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Any
import tempfile

# Add src directory to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

class DotDotPwnVerifier:
    def __init__(self):
        self.results = {
            "overall": {"passed": 0, "failed": 0, "warnings": 0},
            "tests": []
        }
        self.python_cmd = str(project_root / "dotdotpwn-env" / "bin" / "python")
        self.dotdotpwn_script = str(project_root / "dotdotpwn.py")
        
    def log_test(self, test_name: str, status: str, message: str, details: str = ""):
        """Log test results"""
        test_result = {
            "name": test_name,
            "status": status,  # "PASS", "FAIL", "WARN"
            "message": message,
            "details": details,
            "timestamp": time.time()
        }
        self.results["tests"].append(test_result)
        
        if status == "PASS":
            self.results["overall"]["passed"] += 1
            icon = "✅"
        elif status == "FAIL":
            self.results["overall"]["failed"] += 1
            icon = "❌"
        else:  # WARN
            self.results["overall"]["warnings"] += 1
            icon = "⚠️"
            
        print(f"{icon} {test_name}: {message}")
        if details:
            print(f"   Details: {details}")

    def test_environment_setup(self) -> bool:
        """Test if environment is properly set up"""
        print("🔍 Testing Environment Setup...")
        
        # Check Python environment
        if not os.path.exists(self.python_cmd):
            self.log_test("Environment", "FAIL", "Python virtual environment not found")
            return False
        
        # Check main script
        if not os.path.exists(self.dotdotpwn_script):
            self.log_test("Environment", "FAIL", "Main dotdotpwn.py script not found")
            return False
            
        # Check src directory
        if not os.path.exists(src_path):
            self.log_test("Environment", "FAIL", "Source directory not found")
            return False
            
        self.log_test("Environment", "PASS", "Environment setup verified")
        return True

    def test_core_imports(self) -> bool:
        """Test if all core modules can be imported"""
        print("\n🧩 Testing Core Module Imports...")
        
        modules_to_test = [
            "dotdotpwn.core.traversal_engine",
            "dotdotpwn.core.fingerprint", 
            "dotdotpwn.protocols.http_fuzzer",
            "dotdotpwn.protocols.ftp_fuzzer",
            "dotdotpwn.protocols.tftp_fuzzer",
            "dotdotpwn.utils.reporter",
            "dotdotpwn.stdout",
            "dotdotpwn.cli",
            "dotdotpwn.api.app"
        ]
        
        failed_imports = []
        
        for module in modules_to_test:
            try:
                __import__(module)
                self.log_test(f"Import {module}", "PASS", "Module imported successfully")
            except ImportError as e:
                failed_imports.append(module)
                self.log_test(f"Import {module}", "FAIL", f"Import failed: {str(e)}")
        
        if failed_imports:
            return False
        
        self.log_test("Core Imports", "PASS", "All core modules imported successfully")
        return True

    def test_pattern_generation(self) -> bool:
        """Test pattern generation functionality"""
        print("\n🎯 Testing Pattern Generation...")
        
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "generate", 
                   "--os-type", "unix", "--depth", "3", "--specific-file", "/etc/passwd"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log_test("Pattern Generation", "FAIL", 
                             f"Command failed with return code {result.returncode}",
                             result.stderr)
                return False
            
            # Count patterns generated
            patterns = result.stdout.strip().split('\n')
            pattern_count = len([p for p in patterns if p.strip()])
            
            if pattern_count < 100:
                self.log_test("Pattern Generation", "FAIL", 
                             f"Too few patterns generated: {pattern_count}")
                return False
            
            self.log_test("Pattern Generation", "PASS", 
                         f"Generated {pattern_count} patterns successfully")
            return True
            
        except Exception as e:
            self.log_test("Pattern Generation", "FAIL", f"Exception: {str(e)}")
            return False

    def test_cli_functionality(self) -> bool:
        """Test CLI functionality"""
        print("\n💻 Testing CLI Functionality...")
        
        # Test help command
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "--help"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                self.log_test("CLI Help", "FAIL", "Help command failed")
                return False
            
            if "DotDotPwn" not in result.stdout:
                self.log_test("CLI Help", "FAIL", "Help output doesn't contain DotDotPwn")
                return False
            
            self.log_test("CLI Help", "PASS", "Help command works correctly")
            
        except Exception as e:
            self.log_test("CLI Help", "FAIL", f"Exception: {str(e)}")
            return False

        # Test examples command
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "help-examples"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.log_test("CLI Examples", "PASS", "Examples command works")
            else:
                self.log_test("CLI Examples", "WARN", "Examples command not available")
                
        except Exception as e:
            self.log_test("CLI Examples", "WARN", f"Examples command issue: {str(e)}")

        return True

    def test_api_functionality(self) -> bool:
        """Test API functionality"""
        print("\n🌐 Testing API Functionality...")
        
        # Start API server
        api_process = None
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "api", 
                   "--host", "localhost", "--port", "8001"]
            
            api_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE)
            
            # Wait for API to start
            time.sleep(3)
            
            # Test health endpoint
            response = requests.get("http://localhost:8001/health", timeout=5)
            if response.status_code == 200:
                self.log_test("API Health", "PASS", "Health endpoint responding")
            else:
                self.log_test("API Health", "FAIL", f"Health endpoint failed: {response.status_code}")
                return False
            
            # Test docs endpoint
            response = requests.get("http://localhost:8001/docs", timeout=5)
            if response.status_code == 200:
                self.log_test("API Docs", "PASS", "Documentation endpoint working")
            else:
                self.log_test("API Docs", "WARN", "Documentation endpoint issue")
            
            # Test OpenAPI schema
            response = requests.get("http://localhost:8001/openapi.json", timeout=5)
            if response.status_code == 200:
                schema = response.json()
                if "openapi" in schema:
                    self.log_test("API Schema", "PASS", "OpenAPI schema valid")
                else:
                    self.log_test("API Schema", "FAIL", "Invalid OpenAPI schema")
            else:
                self.log_test("API Schema", "FAIL", "OpenAPI schema not accessible")
            
            return True
            
        except Exception as e:
            self.log_test("API Functionality", "FAIL", f"API test failed: {str(e)}")
            return False
            
        finally:
            if api_process:
                api_process.terminate()
                api_process.wait(timeout=5)

    def test_error_handling(self) -> bool:
        """Test error handling and robustness"""
        print("\n🛡️ Testing Error Handling...")
        
        # Test invalid parameters
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "generate", 
                   "--invalid-param", "test"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Should fail gracefully
            if result.returncode != 0:
                self.log_test("Invalid Parameters", "PASS", "Invalid parameters handled correctly")
            else:
                self.log_test("Invalid Parameters", "WARN", "Invalid parameters not caught")
                
        except Exception as e:
            self.log_test("Invalid Parameters", "FAIL", f"Exception during error test: {str(e)}")
        
        # Test with extreme depth values
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "generate", 
                   "--depth", "100", "--os-type", "unix"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.log_test("Extreme Depth", "PASS", "High depth handled correctly")
            else:
                self.log_test("Extreme Depth", "WARN", "High depth rejected")
                
        except subprocess.TimeoutExpired:
            self.log_test("Extreme Depth", "WARN", "High depth timed out (may need optimization)")
        except Exception as e:
            self.log_test("Extreme Depth", "FAIL", f"Exception: {str(e)}")

        return True

    def test_performance(self) -> bool:
        """Test performance benchmarks"""
        print("\n⚡ Testing Performance...")
        
        try:
            # Test pattern generation speed
            start_time = time.time()
            
            cmd = [self.python_cmd, self.dotdotpwn_script, "generate", 
                   "--os-type", "unix", "--depth", "6", "--specific-file", "/etc/passwd"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            end_time = time.time()
            duration = end_time - start_time
            
            if result.returncode == 0:
                patterns = result.stdout.strip().split('\n')
                pattern_count = len([p for p in patterns if p.strip()])
                patterns_per_second = pattern_count / duration
                
                if patterns_per_second > 1000:
                    self.log_test("Performance", "PASS", 
                                 f"Generated {pattern_count} patterns in {duration:.2f}s ({patterns_per_second:.0f} patterns/sec)")
                else:
                    self.log_test("Performance", "WARN", 
                                 f"Performance below target: {patterns_per_second:.0f} patterns/sec")
            else:
                self.log_test("Performance", "FAIL", "Performance test failed")
                return False
                
        except Exception as e:
            self.log_test("Performance", "FAIL", f"Performance test exception: {str(e)}")
            return False

        return True

    def test_file_operations(self) -> bool:
        """Test file operations and report generation"""
        print("\n📁 Testing File Operations...")
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Test pattern generation with file output
            cmd = [self.python_cmd, self.dotdotpwn_script, "generate", 
                   "--os-type", "unix", "--depth", "3", "--output-file", temp_path]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                    self.log_test("File Output", "PASS", "File output generated successfully")
                else:
                    self.log_test("File Output", "FAIL", "File output not created")
                    return False
            else:
                self.log_test("File Output", "FAIL", "File output command failed")
                return False
            
            # Cleanup
            try:
                os.unlink(temp_path)
            except:
                pass
                
        except Exception as e:
            self.log_test("File Operations", "FAIL", f"File operations failed: {str(e)}")
            return False

        return True

    def test_security_features(self) -> bool:
        """Test security-related features"""
        print("\n🔒 Testing Security Features...")
        
        # Test that patterns include security bypass techniques
        try:
            cmd = [self.python_cmd, self.dotdotpwn_script, "generate", 
                   "--os-type", "unix", "--depth", "3"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for various encoding techniques
                security_features = [
                    ("%c0%ae", "Null byte encoding"),
                    ("%2e%2e", "URL encoding"),
                    ("\\\\", "Windows path separators"),
                    ("/etc/passwd", "Unix system files"),
                ]
                
                found_features = []
                for pattern, description in security_features:
                    if pattern in output:
                        found_features.append(description)
                
                if len(found_features) >= 2:
                    self.log_test("Security Features", "PASS", 
                                 f"Found security features: {', '.join(found_features)}")
                else:
                    self.log_test("Security Features", "WARN", 
                                 "Limited security features detected")
            else:
                self.log_test("Security Features", "FAIL", "Security feature test failed")
                return False
                
        except Exception as e:
            self.log_test("Security Features", "FAIL", f"Security test exception: {str(e)}")
            return False

        return True

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive verification report"""
        print("\n📊 Generating Verification Report...")
        
        total_tests = (self.results["overall"]["passed"] + 
                      self.results["overall"]["failed"] + 
                      self.results["overall"]["warnings"])
        
        success_rate = (self.results["overall"]["passed"] / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            "verification_timestamp": time.time(),
            "summary": {
                "total_tests": total_tests,
                "passed": self.results["overall"]["passed"],
                "failed": self.results["overall"]["failed"],
                "warnings": self.results["overall"]["warnings"],
                "success_rate": round(success_rate, 2)
            },
            "tests": self.results["tests"],
            "recommendations": []
        }
        
        # Add recommendations based on results
        if self.results["overall"]["failed"] > 0:
            report["recommendations"].append("Address failed tests before proceeding to GUI development")
        
        if self.results["overall"]["warnings"] > 3:
            report["recommendations"].append("Review warnings for potential improvements")
        
        if success_rate >= 90:
            report["recommendations"].append("System ready for GUI development")
        elif success_rate >= 75:
            report["recommendations"].append("System mostly ready - address critical issues")
        else:
            report["recommendations"].append("System needs significant improvements before GUI development")
        
        return report

    def run_all_tests(self) -> bool:
        """Run all verification tests"""
        print("🚀 DotDotPwn Comprehensive Verification Suite")
        print("=" * 60)
        
        test_functions = [
            self.test_environment_setup,
            self.test_core_imports,
            self.test_pattern_generation,
            self.test_cli_functionality,
            self.test_api_functionality,
            self.test_error_handling,
            self.test_performance,
            self.test_file_operations,
            self.test_security_features
        ]
        
        overall_success = True
        
        for test_func in test_functions:
            try:
                if not test_func():
                    overall_success = False
            except Exception as e:
                self.log_test(test_func.__name__, "FAIL", f"Test function failed: {str(e)}")
                overall_success = False
        
        # Generate final report
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print("📋 VERIFICATION SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {report['summary']['total_tests']}")
        print(f"✅ Passed: {report['summary']['passed']}")
        print(f"❌ Failed: {report['summary']['failed']}")
        print(f"⚠️  Warnings: {report['summary']['warnings']}")
        print(f"Success Rate: {report['summary']['success_rate']}%")
        
        print("\n📝 RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"• {rec}")
        
        # Save detailed report
        report_file = project_root / "verification_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        if overall_success and report['summary']['success_rate'] >= 80:
            print("\n🎉 VERIFICATION PASSED - Ready for GUI development!")
            return True
        else:
            print("\n❌ VERIFICATION FAILED - Address issues before proceeding")
            return False


def main():
    verifier = DotDotPwnVerifier()
    success = verifier.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()