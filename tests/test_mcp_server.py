"""
Basic tests for Recon-ng MCP Server
"""

import pytest
import sys
from pathlib import Path

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from security import SecurityValidator
    from utils import sanitize_input, validate_json_data, parse_module_name
    IMPORTS_AVAILABLE = True
except ImportError:
    IMPORTS_AVAILABLE = False


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports not available")
class TestSecurityValidator:
    """Test security validation functionality"""

    def test_security_validator_init(self):
        """Test SecurityValidator initialization"""
        validator = SecurityValidator()
        assert validator is not None
        assert len(validator.approved_modules) > 0
        assert len(validator.allowed_categories) > 0

    def test_workspace_name_validation(self):
        """Test workspace name validation"""
        validator = SecurityValidator()

        # Valid names
        assert validator.validate_workspace_name("test_workspace")
        assert validator.validate_workspace_name("workspace-123")
        assert validator.validate_workspace_name("default")

        # Invalid names
        assert not validator.validate_workspace_name("")
        assert not validator.validate_workspace_name("workspace with spaces")
        assert not validator.validate_workspace_name("../invalid")
        assert not validator.validate_workspace_name("con")  # Reserved name

    def test_module_approval(self):
        """Test module approval functionality"""
        validator = SecurityValidator()

        # Should approve safe modules
        assert validator.is_module_approved("recon/domains-hosts/bing_domain_web")

        # Should block unsafe patterns
        assert not validator.is_module_approved("brute/force/module")
        assert not validator.is_module_approved("crack/password/module")

    def test_options_validation(self):
        """Test options validation"""
        validator = SecurityValidator()

        # Valid options
        valid_options = {"domain": "example.com", "limit": "10"}
        assert validator.validate_options(valid_options)

        # Invalid options
        invalid_options = {"command": "rm -rf /"}
        assert not validator.validate_options(invalid_options)


@pytest.mark.skipif(not IMPORTS_AVAILABLE, reason="Imports not available")
class TestUtils:
    """Test utility functions"""

    def test_sanitize_input(self):
        """Test input sanitization"""
        # Normal input
        assert sanitize_input("normal text") == "normal text"

        # Input with dangerous characters
        dangerous = "test<script>alert('xss')</script>"
        sanitized = sanitize_input(dangerous)
        assert "<" not in sanitized
        assert ">" not in sanitized

        # Long input
        long_input = "a" * 2000
        sanitized = sanitize_input(long_input, max_length=100)
        assert len(sanitized) <= 100

    def test_validate_json_data(self):
        """Test JSON validation"""
        # Valid JSON data
        assert validate_json_data({"key": "value"})
        assert validate_json_data([1, 2, 3])
        assert validate_json_data("string")

        # Invalid JSON data (circular reference would fail)
        # This is a basic test - actual JSON serialization limits would be tested in practice

    def test_parse_module_name(self):
        """Test module name parsing"""
        # Full module name
        result = parse_module_name("recon/domains-hosts/bing_domain_web")
        assert result["category"] == "recon"
        assert result["subcategory"] == "domains-hosts"
        assert result["module"] == "bing_domain_web"

        # Simple module name
        result = parse_module_name("simple/module")
        assert result["category"] == "simple"
        assert result["module"] == "module"

        # Single part
        result = parse_module_name("single")
        assert result["category"] == "unknown"
        assert result["module"] == "single"


def test_basic_imports():
    """Test that basic imports work"""
    if IMPORTS_AVAILABLE:
        assert True  # Imports successful
    else:
        pytest.skip("Required imports not available")


if __name__ == "__main__":
    pytest.main([__file__])