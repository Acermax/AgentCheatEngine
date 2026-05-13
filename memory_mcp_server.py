#!/usr/bin/env python3
"""Compatibility entrypoint for the Windows Process Memory MCP server."""

from windows_process_memory_mcp.server import mcp


if __name__ == "__main__":
    mcp.run()
