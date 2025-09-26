#!/usr/bin/env python3
"""
Simple entry point for the Recon-ng MCP Server.

This file provides a direct entry point that exposes the FastMCP server object
following FastMCP best practices for MCP client connections.
"""

from recon_ng_mcp_server.mcp_server import mcp

# Export the server for MCP client access
__all__ = ['mcp']

if __name__ == "__main__":
    mcp.run()