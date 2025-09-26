"""
Recon-ng MCP Server

A Model Context Protocol server that provides AI assistants with secure access
to recon-ng's OSINT capabilities for defensive security purposes.
"""

import logging
import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml

from fastmcp import FastMCP

# Import modules with proper relative imports
from .recon_wrapper import get_recon_wrapper, RECON_AVAILABLE
from .security import SecurityValidator
from .utils import format_module_list, format_workspace_data

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP(
    name="Recon-ng OSINT Server",
    instructions="""
    This server provides secure access to recon-ng OSINT capabilities for defensive security.

    Available tools:
    - list_modules: Get available recon-ng modules
    - get_module_info: Get detailed information about a module
    - run_module: Execute a module safely (simulation mode for safety)
    - list_workspaces: Show available workspaces
    - create_workspace: Create a new workspace

    Available resources:
    - recon://workspace/{workspace}/data: Access workspace data
    - recon://modules/categories: Get module categories
    - recon://security/approved_modules: Get security-approved modules

    All operations include security checks to ensure defensive use only.
    """
)

# Global instances
current_workspace = "default"
security_validator = SecurityValidator()


@mcp.tool
def list_modules(category: Optional[str] = None, safe_only: bool = True) -> Dict[str, Any]:
    """
    List available recon-ng modules with optional filtering.

    Args:
        category: Optional category filter (e.g., 'recon', 'reporting', 'discovery')
        safe_only: Only return modules approved for defensive security use

    Returns:
        Dictionary containing module list and metadata
    """
    try:
        if not RECON_AVAILABLE:
            return {
                'error': 'Recon-ng framework not available',
                'modules': [],
                'available': False
            }

        wrapper = get_recon_wrapper(current_workspace)
        modules = wrapper.list_modules()

        # Filter by category if specified
        if category:
            modules = [m for m in modules if m.get('category', '').lower() == category.lower()]

        # Filter by safety if requested
        if safe_only:
            modules = [m for m in modules if m.get('safe_for_defensive', False)]

        return {
            'modules': modules,
            'total_count': len(modules),
            'workspace': current_workspace,
            'filters_applied': {
                'category': category,
                'safe_only': safe_only
            },
            'available': True
        }
    except Exception as e:
        logger.error(f"Error listing modules: {e}")
        return {
            'error': str(e),
            'modules': [],
            'available': False
        }


@mcp.tool
def get_module_info(module_name: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific recon-ng module.

    Args:
        module_name: Name of the module (e.g., 'recon/domains-hosts/bing_domain_web')

    Returns:
        Dictionary containing module information and metadata
    """
    try:
        if not RECON_AVAILABLE:
            return {'error': 'Recon-ng framework not available'}

        # Security validation
        if not security_validator.is_module_approved(module_name):
            return {
                'error': f'Module {module_name} not approved for defensive security use',
                'approved': False
            }

        wrapper = get_recon_wrapper(current_workspace)
        module_info = wrapper.get_module_info(module_name)

        if not module_info:
            return {'error': f'Module {module_name} not found'}

        return {
            'module_info': module_info,
            'approved': True,
            'workspace': current_workspace
        }
    except Exception as e:
        logger.error(f"Error getting module info: {e}")
        return {'error': str(e)}


@mcp.tool
def run_module(module_name: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Execute a recon-ng module safely with security checks.

    Args:
        module_name: Name of the module to execute
        options: Dictionary of module options/parameters

    Returns:
        Dictionary containing execution results
    """
    try:
        if not RECON_AVAILABLE:
            return {'error': 'Recon-ng framework not available'}

        # Security validation
        if not security_validator.is_module_approved(module_name):
            return {
                'error': f'Module {module_name} not approved for defensive security use',
                'reason': 'Security policy violation'
            }

        # Validate options
        if options and not security_validator.validate_options(options):
            return {
                'error': 'Invalid or unsafe options provided',
                'reason': 'Options failed security validation'
            }

        wrapper = get_recon_wrapper(current_workspace)
        result = wrapper.run_module_safe(module_name, options or {})

        return {
            'execution_result': result,
            'workspace': current_workspace,
            'security_validated': True
        }
    except Exception as e:
        logger.error(f"Error running module: {e}")
        return {'error': str(e)}


@mcp.tool
def list_workspaces() -> Dict[str, Any]:
    """
    List available recon-ng workspaces.

    Returns:
        Dictionary containing workspace list and current workspace
    """
    try:
        if not RECON_AVAILABLE:
            return {
                'error': 'Recon-ng framework not available',
                'workspaces': [],
                'current': current_workspace
            }

        wrapper = get_recon_wrapper(current_workspace)
        workspaces = wrapper.list_workspaces()

        return {
            'workspaces': workspaces,
            'current': current_workspace,
            'total_count': len(workspaces)
        }
    except Exception as e:
        logger.error(f"Error listing workspaces: {e}")
        return {
            'error': str(e),
            'workspaces': [],
            'current': current_workspace
        }


@mcp.tool
def create_workspace(workspace_name: str) -> Dict[str, Any]:
    """
    Create a new recon-ng workspace.

    Args:
        workspace_name: Name for the new workspace

    Returns:
        Dictionary containing operation result
    """
    try:
        if not RECON_AVAILABLE:
            return {'error': 'Recon-ng framework not available'}

        # Security validation for workspace name
        if not security_validator.validate_workspace_name(workspace_name):
            return {
                'error': 'Invalid workspace name',
                'reason': 'Workspace name failed security validation'
            }

        # For now, return success simulation
        # Real implementation would create actual workspace
        return {
            'workspace_created': workspace_name,
            'status': 'simulated',
            'message': 'Workspace creation simulated for safety'
        }
    except Exception as e:
        logger.error(f"Error creating workspace: {e}")
        return {'error': str(e)}


@mcp.tool
def switch_workspace(workspace_name: str) -> Dict[str, Any]:
    """
    Switch to a different workspace.

    Args:
        workspace_name: Name of workspace to switch to

    Returns:
        Dictionary containing operation result
    """
    global current_workspace

    try:
        if not RECON_AVAILABLE:
            return {'error': 'Recon-ng framework not available'}

        # Security validation
        if not security_validator.validate_workspace_name(workspace_name):
            return {
                'error': 'Invalid workspace name',
                'reason': 'Workspace name failed security validation'
            }

        # Check if workspace exists
        wrapper = get_recon_wrapper(current_workspace)
        workspaces = wrapper.list_workspaces()

        if workspace_name not in workspaces:
            return {
                'error': f'Workspace {workspace_name} not found',
                'available_workspaces': workspaces
            }

        previous_workspace = current_workspace
        current_workspace = workspace_name

        return {
            'previous_workspace': previous_workspace,
            'current_workspace': current_workspace,
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Error switching workspace: {e}")
        return {'error': str(e)}


# MCP Resources

@mcp.resource("recon://workspace/{workspace}/data")
def get_workspace_data_resource(workspace: str) -> str:
    """
    Access workspace data as a resource.

    Args:
        workspace: Name of the workspace

    Returns:
        JSON string containing workspace data
    """
    try:
        if not RECON_AVAILABLE:
            return json.dumps({'error': 'Recon-ng framework not available'})

        # Security validation
        if not security_validator.validate_workspace_name(workspace):
            return json.dumps({'error': 'Invalid workspace name'})

        wrapper = get_recon_wrapper(workspace)
        data = wrapper.get_workspace_data()

        formatted_data = format_workspace_data(data)
        return json.dumps(formatted_data, indent=2)

    except Exception as e:
        logger.error(f"Error accessing workspace data resource: {e}")
        return json.dumps({'error': str(e)})


@mcp.resource("recon://modules/categories")
def get_module_categories_resource() -> str:
    """
    Get module categories as a resource.

    Returns:
        JSON string containing module categories
    """
    try:
        if not RECON_AVAILABLE:
            return json.dumps({'error': 'Recon-ng framework not available'})

        wrapper = get_recon_wrapper(current_workspace)
        modules = wrapper.list_modules()

        categories_data = format_module_list(modules, "categories")
        return json.dumps(categories_data, indent=2)

    except Exception as e:
        logger.error(f"Error accessing module categories resource: {e}")
        return json.dumps({'error': str(e)})


@mcp.resource("recon://security/approved_modules")
def get_approved_modules_resource() -> str:
    """
    Get security-approved modules as a resource.

    Returns:
        JSON string containing approved modules
    """
    try:
        approved_modules = security_validator.get_approved_modules()
        allowed_categories = security_validator.get_allowed_categories()

        data = {
            'approved_modules': approved_modules,
            'allowed_categories': allowed_categories,
            'total_approved': len(approved_modules),
            'last_updated': datetime.now().isoformat()
        }

        return json.dumps(data, indent=2)

    except Exception as e:
        logger.error(f"Error accessing approved modules resource: {e}")
        return json.dumps({'error': str(e)})


@mcp.resource("recon://workspace/{workspace}/summary")
def get_workspace_summary_resource(workspace: str) -> str:
    """
    Get workspace summary as a resource.

    Args:
        workspace: Name of the workspace

    Returns:
        JSON string containing workspace summary
    """
    try:
        if not RECON_AVAILABLE:
            return json.dumps({'error': 'Recon-ng framework not available'})

        # Security validation
        if not security_validator.validate_workspace_name(workspace):
            return json.dumps({'error': 'Invalid workspace name'})

        wrapper = get_recon_wrapper(workspace)
        data = wrapper.get_workspace_data()

        # Create summary
        summary = {
            'workspace': workspace,
            'timestamp': datetime.now().isoformat(),
            'data_summary': {}
        }

        if 'data' in data:
            for table_name, records in data['data'].items():
                summary['data_summary'][table_name] = {
                    'record_count': len(records) if records else 0,
                    'has_data': bool(records)
                }

        return json.dumps(summary, indent=2)

    except Exception as e:
        logger.error(f"Error accessing workspace summary resource: {e}")
        return json.dumps({'error': str(e)})


def main():
    """Main entry point for the MCP server"""
    try:
        logger.info("Starting Recon-ng MCP Server...")

        if not RECON_AVAILABLE:
            logger.warning("Recon-ng framework not available - server will run in limited mode")
        else:
            logger.info("Recon-ng framework loaded successfully")

        # Initialize security validator
        security_validator.load_config()

        logger.info(f"Server starting with workspace: {current_workspace}")
        logger.info("MCP Server ready to accept connections")

        # Run the FastMCP server
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()