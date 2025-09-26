"""
Recon-ng MCP Server Package

This package provides a Model Context Protocol server for secure access
to recon-ng's OSINT capabilities for defensive security purposes.
"""

__version__ = "0.1.0"
__author__ = "Recon-ng MCP Server Team"

from .mcp_server import mcp

__all__ = ['mcp']