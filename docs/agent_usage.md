# Agent Usage Guide

This guide is for agents using the AgentCheatEngine MCP server.

## 1. Call Envelope

In Codex-style MCP tool schemas, AgentCheatEngine tools are usually exposed as
a single required argument named `params`.

When the schema says:

```json
{
  "properties": {
    "params": {"$ref": "..."}
  },
  "required": ["params"]
}
```

call the tool like this:

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x123456",
    "size": 128
  }
}
```

Do not call it like this:

```json
{
  "pid": 1234,
  "address": "DemoApp.exe+0x123456",
  "size": 128
}
```

If you get a validation error saying `params Field required`, fix only the
wrapper. Do not change the semantic query.

## 2. Common Workflows

### Find A Process

```json
{
  "params": {
    "filter_name": "demo"
  }
}
```

Use with `mem_list_processes`.

### Get Module Base

```json
{
  "params": {
    "pid": 1234,
    "filter_name": "DemoApp.exe"
  }
}
```

Use with `mem_get_modules`.

### Read Memory

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

Use with `mem_read`.

### Disassemble Code

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

Use with `mem_disassemble`. Prefer this over manually counting instruction
bytes. It returns branch targets and RIP-relative targets.

### Find Direct Callers

Do not scan for bare `E8`; it is too noisy. Use `mem_find_callers`, which
resolves every `E8 disp32` mathematically:

```json
{
  "params": {
    "pid": 1234,
    "target_addresses": [
      "0x7FF6CBC74630",
      "0x7FF6CBC74710"
    ],
    "module_name": "DemoApp.exe"
  }
}
```

If you only know RVAs, pass `module_name` and short targets:

```json
{
  "params": {
    "pid": 1234,
    "target_addresses": ["0x4630", "0x4710"],
    "module_name": "DemoApp.exe"
  }
}
```

The output gives `call_site`, `target`, `next_ip`, `disp32`, bytes and RVA.
Then call `mem_disassemble` around each `call_site`.

### Batch Reads

```json
{
  "params": {
    "pid": 1234,
    "items": [
      {
        "name": "x",
        "address": "DemoApp.exe+0x414F6D0",
        "type": "f32"
      },
      {
        "name": "y",
        "address": "DemoApp.exe+0x414F6D0+0x4",
        "type": "f32"
      }
    ]
  }
}
```

Use with `mem_watch_batch`. It is better than many small `mem_read` calls.

## 3. Scans

Always narrow expensive scans when possible.

Good:

```json
{
  "params": {
    "pid": 1234,
    "pattern": "B0 01 C3",
    "module_name": "DemoApp.exe",
    "max_results": 30
  }
}
```

Risky:

```json
{
  "params": {
    "pid": 1234,
    "pattern": "B0 01 C3",
    "max_results": 30
  }
}
```

If the server returns:

```json
{
  "error": "scan_too_broad",
  "estimated_scan_mb": 5000
}
```

do not retry the same call. Choose one:

- Add `module_name`.
- Add `region_start` and `region_end`.
- Use `mem_aob_scan_file_start`.
- Explicitly raise `max_scan_mb` only when the broad scan is intentional.

## 4. File Jobs

Use file jobs for scans that may take longer than a normal MCP request.

Start:

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

Wait until `state` is `completed`, `failed`, or `cancelled`. Results are JSONL
in `results_path`.

## 5. Error Handling

- `params Field required`: wrap arguments under `params`.
- `scan_too_broad`: narrow the scan; do not retry unchanged.
- `ERROR_PARTIAL_COPY` / WinError 299: the read crossed into an unreadable or changing page. `mem_read` returns partial bytes by default with `complete=false`; retry with a smaller/page-aligned `size` when exact bytes are required.
- `Access denied` or WinError 5: run the MCP host/client as administrator.
- `Not connected`: restart Codex/MCP; a previous long call may have killed the server.
- `missing_dependency capstone`: run `pip install -r requirements.txt` in the project venv.

## 6. Address Syntax

Accepted:

```text
0x7FF600001000
140694538686464
DemoApp.exe+0x39310D8
DemoApp.exe+0x414F6D0+0x4
ExampleModule.dll-0x20
```

Use module expressions instead of manually adding module bases.
