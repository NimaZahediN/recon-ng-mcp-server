"""
Security module for Recon-ng MCP Server

Implements security checks and validation for defensive security use.
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Set
import yaml

logger = logging.getLogger(__name__)


class SecurityValidator:
    """Validates operations for defensive security compliance"""

    def __init__(self):
        self.approved_modules: Set[str] = set()
        self.blocked_patterns: List[str] = []
        self.allowed_categories: Set[str] = set()
        self.max_option_length = 1000
        self._load_default_config()

    def _load_default_config(self):
        """Load default security configuration"""
        # Default safe categories for defensive security
        self.allowed_categories = {
            'recon',
            'discovery',
            'reporting',
            'import',
            'export'
        }

        # Default blocked patterns (case-insensitive)
        self.blocked_patterns = [
            r'\bbrute\b',
            r'\bcrack\b',
            r'\bexploit\b',
            r'\battack\b',
            r'\bpassword\b',
            r'\bhash\b',
            r'\bcredential\b',
            r'\bpwn\b',
            r'\bshell\b',
            r'\bbackdoor\b',
            r'\btrojan\b',
            r'\bmalware\b',
            r'\bvirus\b'
        ]

        # Default approved modules for OSINT
        self.approved_modules = {
            'recon/domains-hosts/bing_domain_web',
            'recon/domains-hosts/google_site_web',
            'recon/domains-hosts/netcraft',
            'recon/domains-hosts/shodan_hostname',
            'recon/domains-hosts/ssl_san',
            'recon/domains-hosts/threatcrowd',
            'recon/domains-contacts/whois_pocs',
            'recon/contacts-profiles/fullcontact',
            'recon/profiles-profiles/twitter',
            'reporting/html',
            'reporting/json',
            'reporting/xml'
        }

    def load_config(self, config_path: Path = None):
        """Load security configuration from file"""
        if not config_path:
            config_path = Path(__file__).parent.parent / "config" / "security_config.yaml"

        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)

                if 'approved_modules' in config:
                    self.approved_modules.update(config['approved_modules'])

                if 'blocked_patterns' in config:
                    self.blocked_patterns.extend(config['blocked_patterns'])

                if 'allowed_categories' in config:
                    self.allowed_categories.update(config['allowed_categories'])

                logger.info(f"Loaded security config from {config_path}")
            else:
                logger.info("Using default security configuration")
        except Exception as e:
            logger.warning(f"Error loading security config: {e}, using defaults")

    def is_module_approved(self, module_name: str) -> bool:
        """Check if a module is approved for defensive security use"""
        try:
            # Check explicit approval list
            if module_name in self.approved_modules:
                return True

            # Check category
            category = module_name.split('/')[0] if '/' in module_name else ''
            if category not in self.allowed_categories:
                logger.warning(f"Module category '{category}' not in allowed categories")
                return False

            # Check for blocked patterns
            module_lower = module_name.lower()
            for pattern in self.blocked_patterns:
                if re.search(pattern, module_lower, re.IGNORECASE):
                    logger.warning(f"Module '{module_name}' matches blocked pattern: {pattern}")
                    return False

            # If module passes all checks and is in allowed category, approve it
            return True

        except Exception as e:
            logger.error(f"Error validating module {module_name}: {e}")
            return False

    def validate_options(self, options: Dict[str, Any]) -> bool:
        """Validate module options for security"""
        try:
            if not isinstance(options, dict):
                return False

            for key, value in options.items():
                # Check key length and content
                if len(str(key)) > 100:
                    logger.warning(f"Option key too long: {key[:50]}...")
                    return False

                # Check value length and content
                if len(str(value)) > self.max_option_length:
                    logger.warning(f"Option value too long for key '{key}'")
                    return False

                # Check for suspicious patterns in values
                value_str = str(value).lower()
                for pattern in self.blocked_patterns:
                    if re.search(pattern, value_str, re.IGNORECASE):
                        logger.warning(f"Option value contains blocked pattern: {pattern}")
                        return False

                # Block potentially dangerous characters and commands
                dangerous_chars = ['<', '>', '&', '|', ';', '`', '$', '(', ')']
                dangerous_commands = ['rm ', 'del ', 'format', 'mkfs', 'dd if=']

                value_str_lower = str(value).lower()
                if any(char in str(value) for char in dangerous_chars):
                    logger.warning(f"Option value contains potentially dangerous characters")
                    return False

                if any(cmd in value_str_lower for cmd in dangerous_commands):
                    logger.warning(f"Option value contains potentially dangerous commands")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error validating options: {e}")
            return False

    def validate_workspace_name(self, workspace_name: str) -> bool:
        """Validate workspace name for security"""
        try:
            # Basic validation
            if not workspace_name or not isinstance(workspace_name, str):
                return False

            # Length check
            if len(workspace_name) > 50 or len(workspace_name) < 1:
                return False

            # Character validation (alphanumeric, underscore, hyphen only)
            if not re.match(r'^[a-zA-Z0-9_-]+$', workspace_name):
                return False

            # Reserved names
            reserved_names = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'lpt1', 'lpt2']
            if workspace_name.lower() in reserved_names:
                return False

            return True

        except Exception as e:
            logger.error(f"Error validating workspace name: {e}")
            return False

    def validate_file_path(self, file_path: str) -> bool:
        """Validate file paths for security"""
        try:
            # Basic validation
            if not file_path or not isinstance(file_path, str):
                return False

            # Check for path traversal attempts
            if '..' in file_path or file_path.startswith('/'):
                return False

            # Check for suspicious patterns
            dangerous_patterns = ['\\', '|', '<', '>', '&', ';', '`', '$']
            if any(pattern in file_path for pattern in dangerous_patterns):
                return False

            return True

        except Exception as e:
            logger.error(f"Error validating file path: {e}")
            return False

    def get_approved_modules(self) -> List[str]:
        """Get list of explicitly approved modules"""
        return sorted(list(self.approved_modules))

    def get_allowed_categories(self) -> List[str]:
        """Get list of allowed module categories"""
        return sorted(list(self.allowed_categories))

    def add_approved_module(self, module_name: str) -> bool:
        """Add a module to the approved list"""
        try:
            if self.is_module_approved(module_name):
                self.approved_modules.add(module_name)
                logger.info(f"Added module to approved list: {module_name}")
                return True
            else:
                logger.warning(f"Module failed security validation: {module_name}")
                return False
        except Exception as e:
            logger.error(f"Error adding approved module: {e}")
            return False