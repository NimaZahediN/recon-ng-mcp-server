#!/usr/bin/env python3
"""
Simple startup test for the MCP server
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_imports():
    """Test that all modules can be imported"""
    try:
        print("Testing imports...")

        from security import SecurityValidator
        print("✓ SecurityValidator imported")

        from utils import sanitize_input, format_module_list
        print("✓ Utils imported")

        from recon_wrapper import ReconWrapper
        print("✓ ReconWrapper imported")

        # Test FastMCP import
        from fastmcp import FastMCP
        print("✓ FastMCP imported")

        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_security_validator():
    """Test security validator functionality"""
    try:
        print("\nTesting SecurityValidator...")

        from security import SecurityValidator
        validator = SecurityValidator()

        # Test basic functionality
        assert validator.validate_workspace_name("test_workspace")
        assert not validator.validate_workspace_name("../invalid")
        print("✓ Workspace name validation works")

        # Test module approval
        safe_modules = validator.get_approved_modules()
        assert len(safe_modules) > 0
        print(f"✓ Found {len(safe_modules)} approved modules")

        return True
    except Exception as e:
        print(f"✗ SecurityValidator error: {e}")
        return False

def test_mcp_server_creation():
    """Test that MCP server can be created"""
    try:
        print("\nTesting MCP server creation...")

        from fastmcp import FastMCP

        # Create a test server
        test_server = FastMCP(name="Test Server")
        print("✓ FastMCP server created")

        return True
    except Exception as e:
        print(f"✗ MCP server creation error: {e}")
        return False

def main():
    """Run all tests"""
    print("=== Recon-ng MCP Server Startup Test ===\n")

    tests = [
        test_imports,
        test_security_validator,
        test_mcp_server_creation
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        else:
            break

    print(f"\n=== Results: {passed}/{total} tests passed ===")

    if passed == total:
        print("✓ All tests passed! The MCP server should work correctly.")
        print("\nNext steps:")
        print("1. Start the server: uv run src/mcp_server.py")
        print("2. Configure Claude Desktop with the MCP server")
        print("3. Test OSINT operations through the AI assistant")
        return True
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)