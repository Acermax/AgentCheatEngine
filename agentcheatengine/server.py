"""MCP server assembly for AgentCheatEngine."""

from .runtime import mcp

# Importing tool modules registers their @mcp.tool handlers.
from .tools import core as _core
from .tools import disassembly as _disassembly
from .tools import debugging as _debugging
from .tools import data as _data
from .tools import scanning as _scanning

__all__ = ["mcp", "main"]


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
