"""
Recon-ng Wrapper for MCP Integration

This module provides a safe wrapper around recon-ng framework for OSINT operations.
Focuses on defensive security capabilities with proper safety checks.
"""

import sys
import os
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import subprocess
import json

# Add recon-ng to path
RECON_NG_PATH = Path(__file__).parent.parent.parent / "recon-ng"
sys.path.insert(0, str(RECON_NG_PATH))

try:
    from recon.core import base
    from recon.core.framework import Framework
    RECON_AVAILABLE = True
except ImportError as e:
    RECON_AVAILABLE = False
    logging.warning(f"Recon-ng not available: {e}")


class ReconWrapper:
    """Wrapper class for safe recon-ng operations"""

    def __init__(self, workspace: str = "default"):
        self.workspace = workspace
        self.recon_instance = None
        self._initialize_recon()

    def _initialize_recon(self):
        """Initialize recon-ng framework instance"""
        if not RECON_AVAILABLE:
            raise RuntimeError("Recon-ng framework not available")

        try:
            # Create a minimal framework instance
            params = {
                'workspace': self.workspace,
                'stealth': True,  # Disable analytics and version checks
                'no_check': True,
                'no_analytics': True,
                'no_marketplace': True
            }
            self.recon_instance = base.Recon(params)
        except Exception as e:
            logging.error(f"Failed to initialize recon-ng: {e}")
            raise

    def list_modules(self) -> List[Dict[str, Any]]:
        """List available recon-ng modules with metadata"""
        if not self.recon_instance:
            return []

        try:
            modules = []
            loaded_modules = getattr(self.recon_instance, '_loaded_modules', {})

            for module_name, module_class in loaded_modules.items():
                try:
                    # Get module metadata
                    module_info = {
                        'name': module_name,
                        'category': module_name.split('/')[0] if '/' in module_name else 'misc',
                        'description': getattr(module_class, '__doc__', 'No description available'),
                        'meta': getattr(module_class, 'meta', {}),
                        'safe_for_defensive': self._is_module_safe(module_name)
                    }
                    modules.append(module_info)
                except Exception as e:
                    logging.warning(f"Error processing module {module_name}: {e}")
                    continue

            return sorted(modules, key=lambda x: x['name'])
        except Exception as e:
            logging.error(f"Error listing modules: {e}")
            return []

    def _is_module_safe(self, module_name: str) -> bool:
        """Check if module is safe for defensive security use"""
        # Define unsafe module patterns
        unsafe_patterns = [
            'brute',
            'crack',
            'exploit',
            'attack',
            'password',
            'hash',
            'credential'
        ]

        module_lower = module_name.lower()
        return not any(pattern in module_lower for pattern in unsafe_patterns)

    def get_module_info(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific module"""
        if not self.recon_instance:
            return None

        try:
            loaded_modules = getattr(self.recon_instance, '_loaded_modules', {})
            if module_name not in loaded_modules:
                return None

            module_class = loaded_modules[module_name]

            # Extract module information
            info = {
                'name': module_name,
                'description': getattr(module_class, '__doc__', 'No description'),
                'meta': getattr(module_class, 'meta', {}),
                'safe_for_defensive': self._is_module_safe(module_name),
                'category': module_name.split('/')[0] if '/' in module_name else 'misc'
            }

            # Get options if available
            if hasattr(module_class, 'meta') and 'options' in module_class.meta:
                info['options'] = module_class.meta['options']

            return info
        except Exception as e:
            logging.error(f"Error getting module info for {module_name}: {e}")
            return None

    def run_module_safe(self, module_name: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Safely execute a recon-ng module with security checks"""
        if not self.recon_instance:
            return {'error': 'Recon-ng not available'}

        # Security check
        if not self._is_module_safe(module_name):
            return {'error': f'Module {module_name} not approved for defensive use'}

        try:
            # Get module info first
            module_info = self.get_module_info(module_name)
            if not module_info:
                return {'error': f'Module {module_name} not found'}

            # For now, return module info and simulation
            # Actual module execution would require more careful implementation
            result = {
                'module': module_name,
                'status': 'simulated',
                'message': 'Module execution simulated for safety',
                'module_info': module_info,
                'options_used': options or {}
            }

            return result
        except Exception as e:
            logging.error(f"Error running module {module_name}: {e}")
            return {'error': str(e)}

    def list_workspaces(self) -> List[str]:
        """List available recon-ng workspaces"""
        if not self.recon_instance:
            return []

        try:
            # Get workspace directory
            workspace_dir = Path.home() / '.recon-ng' / 'workspaces'
            if workspace_dir.exists():
                workspaces = [d.name for d in workspace_dir.iterdir() if d.is_dir()]
                return sorted(workspaces)
            return ['default']
        except Exception as e:
            logging.error(f"Error listing workspaces: {e}")
            return ['default']

    def get_workspace_data(self, table: str = None) -> Dict[str, Any]:
        """Get data from current workspace"""
        if not self.recon_instance:
            return {'error': 'Recon-ng not available'}

        try:
            # Common recon-ng tables
            tables = ['hosts', 'contacts', 'domains', 'ports', 'netblocks']
            if table and table not in tables:
                return {'error': f'Unknown table: {table}'}

            result = {
                'workspace': self.workspace,
                'available_tables': tables,
                'data': {}
            }

            # For safety, return empty data structure
            # Real implementation would query the SQLite database
            for t in (tables if not table else [table]):
                result['data'][t] = []

            return result
        except Exception as e:
            logging.error(f"Error getting workspace data: {e}")
            return {'error': str(e)}


def get_recon_wrapper(workspace: str = "default") -> ReconWrapper:
    """Factory function to create ReconWrapper instance"""
    return ReconWrapper(workspace)