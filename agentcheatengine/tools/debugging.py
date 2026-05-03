"""Thread snapshot and debugger tools."""

from ..runtime import *
from .disassembly import _disassemble_x64_bytes

# ---- Tool: Snapshot de threads ----

class ThreadSnapshotInput(BaseModel):
    """Input para inspeccionar contextos de threads sin adjuntar debugger."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    thread_id: Optional[int] = Field(default=None, description="Thread ID especifico. Si se omite, enumera varios threads.", ge=1)
    max_threads: int = Field(default=16, description="Maximo de threads a capturar cuando thread_id se omite", ge=1, le=128)
    include_stack: bool = Field(default=True, description="Lee bytes alrededor de RSP")
    stack_bytes: int = Field(default=128, description="Bytes de stack a leer desde RSP", ge=0, le=4096)
    include_disassembly: bool = Field(default=True, description="Desensambla bytes desde RIP")
    disasm_bytes: int = Field(default=96, description="Bytes a leer desde RIP para desensamblar", ge=0, le=4096)
    max_instructions: int = Field(default=24, description="Maximo de instrucciones por thread", ge=1, le=256)
    syntax: str = Field(default="intel", description="intel o att")
    skip_current_thread: bool = Field(default=True, description="Evita suspender el thread actual cuando pid es el proceso MCP")
    allow_live_context_without_suspend: bool = Field(
        default=True,
        description="Si no se puede suspender un thread, intenta GetThreadContext sin suspension. Menos consistente, pero util en procesos protegidos.",
    )


def _thread_registers_to_dict(ctx: CONTEXT64) -> Dict[str, Any]:
    return {
        "rip": f"0x{int(ctx.Rip):X}",
        "rsp": f"0x{int(ctx.Rsp):X}",
        "rbp": f"0x{int(ctx.Rbp):X}",
        "rax": f"0x{int(ctx.Rax):X}",
        "rbx": f"0x{int(ctx.Rbx):X}",
        "rcx": f"0x{int(ctx.Rcx):X}",
        "rdx": f"0x{int(ctx.Rdx):X}",
        "rsi": f"0x{int(ctx.Rsi):X}",
        "rdi": f"0x{int(ctx.Rdi):X}",
        "r8": f"0x{int(ctx.R8):X}",
        "r9": f"0x{int(ctx.R9):X}",
        "r10": f"0x{int(ctx.R10):X}",
        "r11": f"0x{int(ctx.R11):X}",
        "r12": f"0x{int(ctx.R12):X}",
        "r13": f"0x{int(ctx.R13):X}",
        "r14": f"0x{int(ctx.R14):X}",
        "r15": f"0x{int(ctx.R15):X}",
        "eflags": f"0x{int(ctx.EFlags):X}",
    }


def _module_summary_for_address(modules: List[Dict[str, Any]], address: int) -> Optional[Dict[str, Any]]:
    for module in modules:
        base = int(module["base"])
        size = int(module["size"])
        if base <= address < base + size:
            return {
                "name": module["name"],
                "base": module.get("base_hex", f"0x{base:X}"),
                "size": module.get("size_hex", f"0x{size:X}"),
                "path": module.get("path", ""),
                "rva": f"0x{address - base:X}",
            }
    return None


def _get_debug_session(session_id: str) -> Dict[str, Any]:
    with _debug_sessions_lock:
        session = _debug_sessions.get(session_id)
    if not session:
        raise ValueError(f"Sesion debugger no encontrada: {session_id}")
    return session


def _debug_enrich_event(
    session: Dict[str, Any],
    event_record: Dict[str, Any],
    include_context: bool,
    include_stack: bool,
    stack_bytes: int,
    include_disassembly: bool,
    disasm_bytes: int,
    max_instructions: int,
    syntax: str,
) -> Dict[str, Any]:
    result = dict(event_record)
    if not include_context:
        return result

    process_handle = session.get("process_handle")
    if not process_handle:
        result["context_error"] = "debug process handle is not available"
        return result

    thread_handle = None
    try:
        thread_handle = _open_thread(
            int(event_record["thread_id"]),
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
        )
        ctx = _get_thread_context64(thread_handle)
        rip = int(ctx.Rip)
        rsp = int(ctx.Rsp)
        try:
            modules = _get_modules(int(session["pid"]))
        except Exception:
            modules = []

        result["registers"] = _thread_registers_to_dict(ctx)
        result["rip_module"] = _module_summary_for_address(modules, rip)
        result["rip_region"] = _memory_region_at(process_handle, rip)

        if include_stack and stack_bytes > 0 and rsp:
            stack = _read_bytes_best_effort(process_handle, rsp, stack_bytes)
            result["stack"] = {
                "address": f"0x{rsp:X}",
                "region": _memory_region_at(process_handle, rsp),
                "bytes_requested": stack_bytes,
                "bytes_read": stack["bytes_read"],
                "complete": stack["complete"],
                "segments": stack["segments"],
                "errors": stack["errors"],
                "hex_dump": _format_hex_dump(stack["data"], rsp),
            }

        disasm_addr = rip
        original_patch: Optional[int] = None
        breakpoint_id = result.get("breakpoint_id")
        if breakpoint_id and breakpoint_id in session.get("breakpoints", {}):
            bp = session["breakpoints"][breakpoint_id]
            disasm_addr = int(bp["address"])
            original_patch = int(bp["original_byte"])
            result["breakpoint_original_byte"] = f"0x{original_patch:02X}"
            result["breakpoint_note"] = "Disassembly is shown from the breakpoint address with the original byte restored in the local decode buffer."

        if include_disassembly and disasm_bytes > 0 and disasm_addr:
            code = _read_bytes_best_effort(process_handle, disasm_addr, disasm_bytes)
            decode_data = code["data"]
            if original_patch is not None and decode_data:
                decode_data = bytes([original_patch]) + decode_data[1:]
            disasm: Dict[str, Any] = {
                "address": f"0x{disasm_addr:X}",
                "bytes_requested": disasm_bytes,
                "bytes_read": code["bytes_read"],
                "complete": code["complete"],
                "read_errors": code["errors"],
            }
            if decode_data:
                try:
                    disasm.update(_disassemble_x64_bytes(
                        decode_data,
                        disasm_addr,
                        max_instructions,
                        syntax,
                        include_bytes=True,
                    ))
                except Exception as exc:
                    disasm["error"] = str(exc)
            result["disassembly"] = disasm

    except Exception as exc:
        result["context_error"] = str(exc)
    finally:
        if thread_handle:
            kernel32.CloseHandle(thread_handle)
    return result


class DebugAttachInput(BaseModel):
    """Input para adjuntar debugger a un proceso."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    attach_timeout_ms: int = Field(default=5000, description="Tiempo maximo para completar DebugActiveProcess", ge=100, le=60000)
    auto_continue_initial_events: bool = Field(default=True, description="Auto-continua CREATE/LOAD y breakpoint inicial mientras no haya breakpoints del usuario")
    auto_continue_first_chance_exceptions: bool = Field(default=True, description="Auto-continua excepciones first-chance no propias con DBG_EXCEPTION_NOT_HANDLED")
    event_history_limit: int = Field(default=200, description="Eventos retenidos en historial", ge=10, le=5000)


@mcp.tool(
    name="mem_debug_attach",
    annotations={
        "title": "Adjuntar debugger",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_debug_attach(params: DebugAttachInput) -> str:
    """Adjunta un debugger Win32 al proceso y crea una sesion.

    Usa DebugActiveProcess y DebugSetProcessKillOnExit(False). Un worker de
    fondo gestiona WaitForDebugEvent/ContinueDebugEvent.
    """
    session_id = uuid.uuid4().hex[:12]
    condition = threading.Condition()
    session: Dict[str, Any] = {
        "session_id": session_id,
        "pid": params.pid,
        "state": "attaching",
        "condition": condition,
        "attached_event": threading.Event(),
        "auto_continue_initial_events": params.auto_continue_initial_events,
        "auto_continue_first_chance_exceptions": params.auto_continue_first_chance_exceptions,
        "event_history_limit": params.event_history_limit,
        "events": [],
        "history": [],
        "pending_event": None,
        "continue_command": None,
        "breakpoints": {},
        "single_step_reinsert": None,
        "initial_breakpoint_seen": False,
        "next_event_id": 1,
        "created_at": time.time(),
    }
    worker = threading.Thread(
        target=_debug_session_worker,
        args=(session,),
        name=f"mem-debug-{session_id}",
        daemon=True,
    )
    session["thread"] = worker
    with _debug_sessions_lock:
        _debug_sessions[session_id] = session
    worker.start()

    attached = session["attached_event"].wait(params.attach_timeout_ms / 1000)
    if not attached:
        session["stop_requested"] = True
        return json.dumps({
            "error": "attach_timeout",
            "session_id": session_id,
            "pid": params.pid,
            "state": session.get("state"),
        }, indent=2, ensure_ascii=False)

    if session.get("state") == "failed":
        return json.dumps({
            "error": "attach_failed",
            "session_id": session_id,
            "pid": params.pid,
            "message": session.get("error"),
        }, indent=2, ensure_ascii=False)

    return json.dumps({
        "session_id": session_id,
        "pid": params.pid,
        "state": session.get("state"),
        "kill_on_exit": False,
        "auto_continue_initial_events": params.auto_continue_initial_events,
        "auto_continue_first_chance_exceptions": params.auto_continue_first_chance_exceptions,
        "worker_alive": worker.is_alive(),
        "note": "Proceso adjuntado. Usa mem_debug_set_breakpoint, mem_debug_wait_event y mem_debug_continue. Usa mem_debug_detach para limpiar.",
    }, indent=2, ensure_ascii=False)


class DebugSetBreakpointInput(BaseModel):
    """Input para software breakpoint."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: str = Field(..., description="Sesion devuelta por mem_debug_attach")
    address: str = Field(..., description="Direccion o expresion tipo modulo+offset")
    label: Optional[str] = Field(default=None, description="Etiqueta opcional")


@mcp.tool(
    name="mem_debug_set_breakpoint",
    annotations={
        "title": "Poner breakpoint software",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_debug_set_breakpoint(params: DebugSetBreakpointInput) -> str:
    """Escribe 0xCC en una direccion y guarda el byte original."""
    try:
        session = _get_debug_session(params.session_id)
        if session.get("state") != "attached":
            return json.dumps({"error": "session_not_attached", "state": session.get("state")})
        address = _parse_address_expression(params.address, int(session["pid"]))
        handle = session.get("process_handle")
        if not handle:
            return json.dumps({"error": "process_handle_unavailable"})

        with session["condition"]:
            for breakpoint_id, bp in session["breakpoints"].items():
                if int(bp["address"]) == address:
                    return json.dumps({
                        "session_id": params.session_id,
                        "breakpoint_id": breakpoint_id,
                        "address": f"0x{address:X}",
                        "existing": True,
                        "enabled": bp.get("enabled"),
                    }, indent=2, ensure_ascii=False)

            original = _read_bytes(handle, address, 1)[0]
            breakpoint_id = f"bp_{uuid.uuid4().hex[:8]}"
            session["breakpoints"][breakpoint_id] = {
                "breakpoint_id": breakpoint_id,
                "address": address,
                "address_hex": f"0x{address:X}",
                "original_byte": original,
                "enabled": False,
                "label": params.label,
                "hit_count": 0,
            }
            _debug_enable_breakpoint(session, breakpoint_id)
            bp = session["breakpoints"][breakpoint_id]

        return json.dumps({
            "session_id": params.session_id,
            "breakpoint_id": breakpoint_id,
            "address": f"0x{address:X}",
            "label": params.label,
            "original_byte": f"0x{original:02X}",
            "enabled": bp["enabled"],
            "persistent": True,
            "note": "Breakpoint software activo. Al dispararse, mem_debug_continue restaura byte, retrocede RIP y usa single-step interno para reinsertarlo.",
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "error": "set_breakpoint_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)


class DebugWaitEventInput(BaseModel):
    """Input para esperar un evento debugger."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: str = Field(..., description="Sesion debugger")
    timeout_ms: int = Field(default=10000, description="Timeout de espera", ge=0, le=300000)
    include_context: bool = Field(default=True, description="Incluye registros del thread")
    include_stack: bool = Field(default=True, description="Incluye stack desde RSP")
    stack_bytes: int = Field(default=128, description="Bytes de stack", ge=0, le=4096)
    include_disassembly: bool = Field(default=True, description="Desensambla desde RIP")
    disasm_bytes: int = Field(default=96, description="Bytes de codigo desde RIP", ge=0, le=4096)
    max_instructions: int = Field(default=24, description="Maximo de instrucciones", ge=1, le=256)
    syntax: str = Field(default="intel", description="intel o att")


@mcp.tool(
    name="mem_debug_wait_event",
    annotations={
        "title": "Esperar evento debugger",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_debug_wait_event(params: DebugWaitEventInput) -> str:
    """Espera un evento debugger detenido y devuelve JSON enriquecido."""
    try:
        session = _get_debug_session(params.session_id)
        deadline = time.time() + (params.timeout_ms / 1000)
        with session["condition"]:
            while session.get("pending_event") is None and session.get("state") == "attached":
                remaining = deadline - time.time()
                if params.timeout_ms == 0 or remaining <= 0:
                    break
                session["condition"].wait(min(0.25, remaining))
            event_record = session.get("pending_event")
            if not event_record:
                return json.dumps({
                    "session_id": params.session_id,
                    "state": session.get("state"),
                    "timeout": True,
                    "pending_event": None,
                    "history_count": len(session.get("history", [])),
                }, indent=2, ensure_ascii=False)
            event_copy = dict(event_record)

        enriched = _debug_enrich_event(
            session,
            event_copy,
            params.include_context,
            params.include_stack,
            params.stack_bytes,
            params.include_disassembly,
            params.disasm_bytes,
            params.max_instructions,
            params.syntax,
        )
        return json.dumps({
            "session_id": params.session_id,
            "state": session.get("state"),
            "timeout": False,
            "event": enriched,
            "agent_instruction": "Despues de inspeccionar este evento llama mem_debug_continue o mem_debug_detach; el proceso queda detenido mientras haya un pending event.",
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "error": "wait_event_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)


class DebugContinueInput(BaseModel):
    """Input para continuar un evento debugger."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: str = Field(..., description="Sesion debugger")
    event_id: Optional[int] = Field(default=None, description="Evento esperado; protege contra continuar el evento equivocado")
    continue_status: str = Field(default="auto", description="auto, DBG_CONTINUE o DBG_EXCEPTION_NOT_HANDLED")
    timeout_ms: int = Field(default=5000, description="Tiempo maximo esperando confirmacion", ge=100, le=60000)
    allow_second_chance_continue: bool = Field(
        default=False,
        description="Permite continuar una excepcion second-chance ajena. Puede colgar o terminar el proceso objetivo.",
    )


@mcp.tool(
    name="mem_debug_continue",
    annotations={
        "title": "Continuar evento debugger",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_debug_continue(params: DebugContinueInput) -> str:
    """Reanuda el evento debugger pendiente con ContinueDebugEvent."""
    try:
        session = _get_debug_session(params.session_id)
        requested_status = _debug_continue_status(params.continue_status)
        deadline = time.time() + (params.timeout_ms / 1000)
        with session["condition"]:
            pending = session.get("pending_event")
            if not pending:
                return json.dumps({
                    "error": "no_pending_event",
                    "session_id": params.session_id,
                    "state": session.get("state"),
                }, indent=2, ensure_ascii=False)
            if params.event_id is not None and int(pending["event_id"]) != params.event_id:
                return json.dumps({
                    "error": "event_id_mismatch",
                    "expected": params.event_id,
                    "pending_event_id": pending["event_id"],
                }, indent=2, ensure_ascii=False)
            event_id = int(pending["event_id"])
            status = _debug_auto_continue_status(pending) if requested_status == -1 else requested_status
            if _debug_is_second_chance_exception(pending) and not params.allow_second_chance_continue:
                return _debug_second_chance_guard_response(
                    params.session_id,
                    session.get("state"),
                    pending,
                    "continue",
                    status,
                )
            session["continue_command"] = {"action": "continue", "status": status, "event_id": event_id}
            session["condition"].notify_all()
            while session.get("pending_event") is not None and session.get("state") == "attached":
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                session["condition"].wait(min(0.25, remaining))
            completed = session.get("pending_event") is None

        return json.dumps({
            "session_id": params.session_id,
            "event_id": event_id,
            "continued": completed,
            "state": session.get("state"),
            "continue_status": f"0x{status:X}",
            "timeout": not completed,
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "error": "continue_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)


class DebugDetachInput(BaseModel):
    """Input para detach debugger."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: str = Field(..., description="Sesion debugger")
    timeout_ms: int = Field(default=5000, description="Tiempo maximo para detach", ge=100, le=60000)
    remove_session: bool = Field(default=True, description="Elimina la sesion del registro cuando termina")
    continue_status: str = Field(default="auto", description="auto, DBG_CONTINUE o DBG_EXCEPTION_NOT_HANDLED para el evento pendiente")
    allow_second_chance_not_handled: bool = Field(
        default=False,
        description="Deprecated: use allow_second_chance_continue. Permite detach con DBG_EXCEPTION_NOT_HANDLED sobre una excepcion second-chance ajena.",
    )
    allow_second_chance_continue: bool = Field(
        default=False,
        description="Permite continuar una excepcion second-chance ajena durante detach. Puede colgar o terminar el proceso objetivo.",
    )


@mcp.tool(
    name="mem_debug_detach",
    annotations={
        "title": "Desadjuntar debugger",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_debug_detach(params: DebugDetachInput) -> str:
    """Restaura breakpoints y llama DebugActiveProcessStop."""
    try:
        session = _get_debug_session(params.session_id)
        requested_status = _debug_continue_status(params.continue_status)
        deadline = time.time() + (params.timeout_ms / 1000)
        with session["condition"]:
            pending = session.get("pending_event")
            if pending is not None:
                status = _debug_auto_continue_status(pending) if requested_status == -1 else requested_status
                allow_second_chance = params.allow_second_chance_continue or (
                    status == DBG_EXCEPTION_NOT_HANDLED and params.allow_second_chance_not_handled
                )
                if _debug_is_second_chance_exception(pending) and not allow_second_chance:
                    return _debug_second_chance_guard_response(
                        params.session_id,
                        session.get("state"),
                        pending,
                        "detach",
                        status,
                    )
                session["continue_command"] = {"action": "detach", "status": status}
            session["stop_requested"] = True
            session["condition"].notify_all()
            while session.get("state") not in ("detached", "failed"):
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                session["condition"].wait(min(0.25, remaining))

        state = session.get("state")
        if params.remove_session and state in ("detached", "failed"):
            with _debug_sessions_lock:
                _debug_sessions.pop(params.session_id, None)
        return json.dumps({
            "session_id": params.session_id,
            "state": state,
            "detached": state == "detached",
            "cleanup_errors": session.get("cleanup_errors", []),
            "worker_errors": session.get("worker_errors", []),
            "timeout": state not in ("detached", "failed"),
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "error": "detach_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)


@mcp.tool(
    name="mem_thread_snapshot",
    annotations={
        "title": "Snapshot de threads",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_thread_snapshot(params: ThreadSnapshotInput) -> str:
    """Suspende threads brevemente y captura registros, stack y codigo en RIP.

    No usa DebugActiveProcess ni crea una sesion debugger. Cada thread se
    suspende individualmente, se consulta con GetThreadContext y se reanuda en
    un bloque finally.
    """
    try:
        process_handle = _get_handle(params.pid)
        all_threads = _get_threads(params.pid)
        current_tid = int(kernel32.GetCurrentThreadId()) if params.pid == os.getpid() else None

        if params.thread_id is not None:
            selected = [thread for thread in all_threads if int(thread["thread_id"]) == params.thread_id]
            if not selected:
                return json.dumps({
                    "error": "thread_not_found",
                    "pid": params.pid,
                    "thread_id": params.thread_id,
                    "threads_total": len(all_threads),
                }, indent=2, ensure_ascii=False)
        else:
            selected = all_threads[:params.max_threads]

        modules = []
        try:
            modules = _get_modules(params.pid)
        except Exception:
            modules = []

        snapshots: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []

        for thread in selected:
            tid = int(thread["thread_id"])
            if params.skip_current_thread and current_tid is not None and tid == current_tid:
                skipped.append({
                    "thread_id": tid,
                    "reason": "current_mcp_thread",
                })
                continue

            thread_handle = None
            suspended = False
            live_without_suspend = False
            previous_suspend_count: Optional[int] = None
            try:
                try:
                    thread_handle = _open_thread(tid)
                    previous_suspend_count = int(kernel32.SuspendThread(thread_handle))
                    if previous_suspend_count == 0xFFFFFFFF:
                        err = ctypes.get_last_error()
                        raise OSError(f"SuspendThread fallo (error {err})")
                    suspended = True
                except Exception as suspend_exc:
                    if thread_handle:
                        kernel32.CloseHandle(thread_handle)
                        thread_handle = None
                    if not params.allow_live_context_without_suspend:
                        raise
                    thread_handle = _open_thread(tid, THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)
                    live_without_suspend = True

                ctx = _get_thread_context64(thread_handle)
                rip = int(ctx.Rip)
                rsp = int(ctx.Rsp)
                record: Dict[str, Any] = {
                    **thread,
                    "suspend_previous_count": previous_suspend_count,
                    "suspended": suspended,
                    "live_context_without_suspend": live_without_suspend,
                    "registers": _thread_registers_to_dict(ctx),
                    "rip_module": _module_summary_for_address(modules, rip),
                    "rip_region": _memory_region_at(process_handle, rip),
                }
                if live_without_suspend:
                    record["warning"] = "Thread could not be suspended; context/stack/disassembly are a live snapshot and may race with execution."

                if params.include_stack and params.stack_bytes > 0 and rsp:
                    stack = _read_bytes_best_effort(process_handle, rsp, params.stack_bytes)
                    record["stack"] = {
                        "address": f"0x{rsp:X}",
                        "region": _memory_region_at(process_handle, rsp),
                        "bytes_requested": params.stack_bytes,
                        "bytes_read": stack["bytes_read"],
                        "complete": stack["complete"],
                        "segments": stack["segments"],
                        "errors": stack["errors"],
                        "hex_dump": _format_hex_dump(stack["data"], rsp),
                    }

                if params.include_disassembly and params.disasm_bytes > 0 and rip:
                    code = _read_bytes_best_effort(process_handle, rip, params.disasm_bytes)
                    disasm: Dict[str, Any] = {
                        "address": f"0x{rip:X}",
                        "bytes_requested": params.disasm_bytes,
                        "bytes_read": code["bytes_read"],
                        "complete": code["complete"],
                        "read_errors": code["errors"],
                    }
                    if code["data"]:
                        try:
                            disasm.update(_disassemble_x64_bytes(
                                code["data"],
                                rip,
                                params.max_instructions,
                                params.syntax,
                                include_bytes=True,
                            ))
                        except Exception as exc:
                            disasm["error"] = str(exc)
                    record["disassembly"] = disasm

                snapshots.append(record)

            except Exception as exc:
                errors.append({
                    "thread_id": tid,
                    "error": str(exc),
                })
            finally:
                if suspended and thread_handle:
                    kernel32.ResumeThread(thread_handle)
                if thread_handle:
                    kernel32.CloseHandle(thread_handle)

        return json.dumps({
            "pid": params.pid,
            "threads_total": len(all_threads),
            "threads_selected": len(selected),
            "captured_count": len(snapshots),
            "skipped": skipped,
            "errors": errors,
            "snapshots": snapshots,
            "note": "No debugger is attached. Threads are suspended one at a time and resumed immediately after context capture.",
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return json.dumps({
            "error": "thread_snapshot_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)
