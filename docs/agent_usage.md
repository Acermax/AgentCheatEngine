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

Some clients expose the tool schema as `params: string` instead of a nested
object. In that case, JSON-serialize the same payload into the string:

```json
{
  "params": "{\"pid\":1234,\"address\":\"DemoApp.exe+0x123456\",\"size\":128}"
}
```

Follow the schema the client shows. Do not change the actual memory query.

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

### Resolve Address

```json
{
  "params": {
    "pid": 1234,
    "address": "DemoApp.exe+0x414F6D0+0x4"
  }
}
```

Use with `mem_resolve_address` to normalize an expression to an absolute
address plus module/RVA metadata. This tool does not read memory and does not
dereference pointers.

If you have an RVA and want it interpreted relative to a module:

```json
{
  "params": {
    "pid": 1234,
    "address": "0x4630",
    "module_name": "DemoApp.exe"
  }
}
```

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

For several addresses, prefer `mem_disassemble_batch` instead of several tool
calls in one turn:

```json
{
  "params": {
    "pid": 1234,
    "ranges": [
      {"label": "site_a", "address": "DemoApp.exe+0x123450", "size": 160},
      {"label": "site_b", "address": "DemoApp.exe+0x123730", "size": 160}
    ],
    "syntax": "intel"
  }
}
```

### Thread Snapshot

Use `mem_thread_snapshot` when you need live execution context without attaching
a debugger:

```json
{
  "params": {
    "pid": 1234,
    "max_threads": 8,
    "stack_bytes": 128,
    "disasm_bytes": 96,
    "max_instructions": 24
  }
}
```

The tool suspends each selected thread when permissions allow, calls
`GetThreadContext`, reads stack bytes from `RSP`, disassembles from `RIP`, and
resumes the thread in a `finally` block. If suspension is denied, it can fall
back to live `GetThreadContext` without pausing the thread; those records are
marked with `live_context_without_suspend=true`. It does not use
`DebugActiveProcess` and does not set breakpoints.

### Debugger Breakpoints

Use debugger tools only when you need direct execution proof. A pending debug
event stops the target process until you continue or detach.

Attach:

```json
{
  "params": {
    "pid": 1234
  }
}
```

Tool: `mem_debug_attach`.

Set a software breakpoint:

```json
{
  "params": {
    "session_id": "abc123def456",
    "address": "DemoApp.exe+0x123456",
    "label": "interesting_call"
  }
}
```

Tool: `mem_debug_set_breakpoint`. It saves the original byte, writes `0xCC`,
and flushes the instruction cache.

Wait:

```json
{
  "params": {
    "session_id": "abc123def456",
    "timeout_ms": 10000,
    "stack_bytes": 128,
    "disasm_bytes": 96
  }
}
```

Tool: `mem_debug_wait_event`. For breakpoint hits, disassembly is shown from
the breakpoint address with the original byte restored in the local decode
buffer.

Continue:

```json
{
  "params": {
    "session_id": "abc123def456",
    "event_id": 34
  }
}
```

Tool: `mem_debug_continue`. For software breakpoints, it restores the original
byte, rewinds `RIP`, enables trap flag for one internal single-step, reinserts
`0xCC`, then continues.

Detach:

```json
{
  "params": {
    "session_id": "abc123def456"
  }
}
```

Tool: `mem_debug_detach`. Always detach before ending the task.

If continue or detach returns `pending_second_chance_exception`, the MCP refused
to continue a non-owned second-chance exception. There is no generic safe choice
at that point: `DBG_EXCEPTION_NOT_HANDLED` can terminate the target process, and
`DBG_CONTINUE` can reexecute the same faulting instruction and leave the target
looping, hung, or crashed. Inspect the event and ask for human confirmation
before forcing the operation with `allow_second_chance_continue=true`.

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
Then call `mem_disassemble_batch` around the interesting `call_site` addresses.

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

AOB wildcards support `??`/`?` for full bytes and nibble wildcards such as
`4?` and `?F`. Keep tokens space-separated.

Good:

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
- Tool schema shows `params: string`: JSON-serialize the payload inside that
  string, for example `{"params":"{\"pid\":1234}"}`.
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

Use module expressions instead of manually adding module bases. When in doubt,
call `mem_resolve_address` first and use its `absolute` result in later tools.
