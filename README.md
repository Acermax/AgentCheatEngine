# AgentCheatEngine

Repository: https://github.com/Acermax/AgentCheatEngine

AgentCheatEngine is an MCP server for inspecting Windows process memory from
Model Context Protocol clients such as Codex, Claude Desktop, and other agents.
It provides a reusable memory-inspection layer for automated reads, scans,
disassembly, and structure exploration.

This project is intended for research, debugging, reverse-engineering education,
and work on your own processes or systems where you have authorization. Some
tools can modify process memory, so use them carefully and only in permitted
environments.

## Contents

- `memory_mcp_server.py`: compatibility entrypoint for existing MCP configs.
- `agentcheatengine/`: internal server package with runtime helpers and tool modules.
- `agentcheatengine/tools/`: grouped MCP tool registrations.
- `requirements.txt`: Python dependencies.
- `install.bat`: quick Windows installer.
- `docs/agent_usage.md`: examples and operational notes for MCP clients.

## Features

- Process, module, and memory-region enumeration.
- Memory reads with basic interpretation and hexdumps.
- Address expressions such as `DemoApp.exe+0x414F6D0+0x4`, plus a resolver tool
  that normalizes VA/RVA/module metadata for agents.
- Typed structure reads and pointer-chain traversal.
- Batch reads to reduce MCP round trips.
- Integer, float, and string value searches.
- Persistent scan sessions with filters such as `changed`, `decreased`,
  `increased`, `eq_prev`, and more.
- AOB scans with byte-level wildcards and preflight checks for overly broad scans.
- File-backed background jobs for long scans, with JSONL results.
- x86-64 disassembly through Capstone.
- Thread snapshots with registers, stack bytes, and disassembly at RIP without
  attaching a debugger, with live-context fallback when suspension is denied.
- Debugger sessions with software breakpoints, event wait/continue, and safe
  detach that restores breakpoint bytes.
- Direct caller discovery by resolving `CALL rel32` targets mathematically.
- Memory comparison against previous byte snapshots.
- Controlled byte writes through `mem_write` for authorized use cases.

## Requirements

- Windows.
- Python 3.10 or newer.
- Sufficient permissions to open the target process. Some processes may require
  running the MCP client as administrator.

Main dependencies:

```txt
mcp[cli]>=1.0.0
pydantic>=2.0.0
psutil>=5.9.0
capstone>=5.0.0
```

## Installation

Quick install:

```bat
install.bat
```

Manual install:

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## MCP Configuration

Example configuration for an MCP stdio client. Replace
`C:\\path\\to\\AgentCheatEngine` with the absolute path where you cloned the
repository:

```json
{
  "mcpServers": {
    "memory": {
      "command": "C:\\path\\to\\AgentCheatEngine\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\AgentCheatEngine\\memory_mcp_server.py"
      ]
    }
  }
}
```

## Agent Usage

Many MCP clients expose these tools with a single required top-level argument
named `params`. When the schema expects that shape, always wrap tool arguments
inside `params`.

Correct:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x123456",
    "size": 128
  }
}
```

If your MCP client exposes the schema as `params: string`, pass the same JSON
payload serialized into that string:

```json
{
  "params": "{\"pid\":1234,\"address\":\"DemoApp.exe+0x123456\",\"size\":128}"
}
```

Incorrect:

```json
{
  "pid": 1234,
  "address": "DemoApp.exe+0x123456",
  "size": 128
}
```

See [docs/agent_usage.md](docs/agent_usage.md) for more examples.

## MCP Tools

| Tool | Purpose |
| --- | --- |
| `mem_list_processes` | List processes with an optional name filter. |
| `mem_get_modules` | List loaded modules and base addresses. |
| `mem_resolve_address` | Normalize address expressions to VA plus module/RVA metadata. |
| `mem_memory_map` | Enumerate readable regions with `VirtualQueryEx`. |
| `mem_read` | Read bytes and return a hexdump plus basic interpretation. |
| `mem_disassemble` | Disassemble x86-64 code with Capstone. |
| `mem_thread_snapshot` | Capture thread registers, stack, and RIP disassembly without debugger attach. |
| `mem_debug_attach` | Attach a Win32 debugger session to a process. |
| `mem_debug_set_breakpoint` | Set a persistent software breakpoint with `0xCC`. |
| `mem_debug_wait_event` | Wait for a debugger event and return context, stack, and disassembly. |
| `mem_debug_continue` | Continue the pending debugger event. |
| `mem_debug_detach` | Restore breakpoints and detach the debugger; refuses unsafe second-chance continuation by default. |
| `mem_find_callers` | Find direct calls to target functions. |
| `mem_read_struct` | Read multiple typed fields from a base address. |
| `mem_follow_pointers` | Traverse pointer chains. |
| `mem_watch_batch` | Read many typed addresses in one MCP call. |
| `mem_search_value` | Search memory for values or strings. |
| `mem_scan_start` | Start a persistent candidate scan session. |
| `mem_scan_next` | Filter candidates by current or previous values. |
| `mem_scan_results` | Page and refresh scan-session results. |
| `mem_scan_clear` | Clear scan sessions. |
| `mem_aob_scan` | Search byte patterns with wildcards. |
| `mem_aob_scan_file_start` | Start long AOB scans in the background. |
| `mem_scan_file_status` | Check the status of a file-backed scan. |
| `mem_scan_file_cancel` | Cancel a file-backed scan. |
| `mem_scan_linked_list` | Walk generic linked lists or bucket chains. |
| `mem_compare` | Compare current memory against previous bytes. |
| `mem_write` | Write bytes to memory. Destructive operation. |
| `mem_close` | Close the cached handle for a PID. |

## Quick Examples

List processes:

```json
{
  "params": {
    "filter_name": "demo"
  }
}
```

Read memory:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x414F6D0+0x4",
    "size": 64,
    "interpret": true
  }
}
```

Resolve an address without reading memory:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x414F6D0+0x4"
  }
}
```

Resolve an RVA relative to a module:

```json
{
  "params": {
    "pid": 1234,
    "address": "0x4630",
    "module_name": "DemoApp.exe"
  }
}
```

Disassemble:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x123456",
    "size": 160,
    "max_instructions": 40,
    "syntax": "intel"
  }
}
```

Thread snapshot:

```json
{
  "params": {
    "pid": 1234,
    "max_threads": 8,
    "stack_bytes": 128,
    "disasm_bytes": 96
  }
}
```

Debugger breakpoint:

```json
{
  "params": {
    "pid": 1234
  }
}
```

Tool: `mem_debug_attach`.

```json
{
  "params": {
    "session_id": "abc123def456",
    "address": "DemoApp.exe+0x123456",
    "label": "interesting_call"
  }
}
```

Tool: `mem_debug_set_breakpoint`. Then use `mem_debug_wait_event`,
`mem_debug_continue`, and `mem_debug_detach`.

If `mem_debug_continue` or `mem_debug_detach` reports
`pending_second_chance_exception`, inspect the event before forcing anything.
`DBG_EXCEPTION_NOT_HANDLED` can terminate the target, while `DBG_CONTINUE` can
reexecute the faulting instruction and leave the target hung or crashed.

Find direct callers:

```json
{
  "params": {
    "pid": 1234,
    "target_addresses": ["0x4630", "0x4710"],
    "module_name": "DemoApp.exe"
  }
}
```

Bounded AOB scan:

Use `??` or `?` for full-byte wildcards. Nibble wildcards are also supported:
`4?` fixes the high nibble and `?F` fixes the low nibble. Keep tokens
space-separated.

```json
{
  "params": {
    "pid": 1234,
    "pattern": "48 8B 4? ?F B0 01 C3",
    "module_name": "DemoApp.exe",
    "max_results": 30
  }
}
```

## Recommended Rules

- Bound scans with `module_name`, `region_start`, or `region_end` whenever
  possible.
- If a tool returns `scan_too_broad`, do not repeat the same call unchanged.
  Narrow the range or use a file-backed scan job.
- Use `mem_disassemble` before manually counting instruction bytes.
- Use `mem_find_callers` for direct callers instead of scanning for bare `E8`
  bytes.
- Use `mem_watch_batch` for many small reads.
- Treat `mem_write` as destructive: validate the process, address, and bytes
  before running it.
- Close handles with `mem_close` when a session is done.

## Large File-Backed Scans

For queries that may take a long time, use file-backed jobs. The MCP call
returns quickly while the server writes progress and results under
`artifacts/scan_jobs/`.

```json
{
  "params": {
    "pid": 1234,
    "pattern": "B0 01 C3",
    "module_name": "DemoApp.exe",
    "max_results": 100000
  }
}
```

Tool: `mem_aob_scan_file_start`.

Then poll:

```json
{
  "params": {
    "job_id": "abc123def456",
    "tail_results": 5
  }
}
```

Tool: `mem_scan_file_status`.

## Common Errors

- `params Field required`: wrap arguments inside `params`.
- Schema says `params: string`: JSON-serialize the same payload inside the
  string, for example `{"params":"{\"pid\":1234}"}`.
- `scan_too_broad`: narrow the module or range before retrying.
- `ERROR_PARTIAL_COPY` / WinError 299: the read crossed an unreadable or
  changing page; reduce `size` or align the read.
- `Access denied` / WinError 5: run the MCP client as administrator.
- `missing_dependency capstone`: install dependencies with
  `pip install -r requirements.txt`.

## Development

Check syntax:

```bat
python -m py_compile memory_mcp_server.py
python -m compileall agentcheatengine
```

The repository ignores `venv/`, `__pycache__/`, `.pytest_cache/`, and temporary
scan results under `artifacts/scan_jobs/`.

## License

This project is distributed under the MIT license. See [LICENSE](LICENSE).
