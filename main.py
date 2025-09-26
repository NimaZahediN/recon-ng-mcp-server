#!/usr/bin/env python3
"""
Main entry point for the Recon-ng MCP Server.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recon_ng_mcp_server.mcp_server import main

if __name__ == "__main__":
    main()
