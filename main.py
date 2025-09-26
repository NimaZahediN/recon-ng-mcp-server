#!/usr/bin/env python3
"""
Main entry point for the Recon-ng MCP Server.

This follows the FastMCP pattern from the official MCP Python SDK.
Run with: python main.py
"""

from recon_ng_mcp_server.mcp_server import mcp

if __name__ == "__main__":
    # Run the FastMCP server directly as shown in SDK examples
    mcp.run()
