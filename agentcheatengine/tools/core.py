"""Core process, module, address, read, and handle tools."""

from ..runtime import *

# ---- Tool: Listar procesos ----

class ListProcessesInput(BaseModel):
    """Filtros para listar procesos."""
    model_config = ConfigDict(str_strip_whitespace=True)

    filter_name: Optional[str] = Field(
        default=None,
        description="Filtro parcial por nombre de proceso (case-insensitive). Ej: 'demo', 'target'"
    )

@mcp.tool(
    name="mem_list_processes",
    annotations={
        "title": "Listar procesos",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_list_processes(params: ListProcessesInput) -> str:
    """Lista procesos en ejecución con PID, nombre y uso de memoria.

    Usa el filtro para buscar procesos por nombre parcial.
    Ejemplo: filter_name='demo' encontrara 'DemoApp.exe', 'DemoTool.exe', etc.
    """
    try:
        procs = []
        for p in psutil.process_iter(["pid", "name", "memory_info", "exe"]):
            try:
                info = p.info
                name = info.get("name", "")
                if params.filter_name and params.filter_name.lower() not in name.lower():
                    continue
                mem = info.get("memory_info")
                procs.append({
                    "pid": info["pid"],
                    "name": name,
                    "exe": info.get("exe", ""),
                    "rss_mb": round(mem.rss / 1048576, 1) if mem else 0,
                    "vms_mb": round(mem.vms / 1048576, 1) if mem else 0,
                })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        procs.sort(key=lambda x: x["rss_mb"], reverse=True)
        return json.dumps({"count": len(procs), "processes": procs[:100]}, indent=2)
    except Exception as e:
        return f"Error listando procesos: {e}"


# ---- Tool: Obtener módulos ----

class GetModulesInput(BaseModel):
    """Input para obtener módulos de un proceso."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso objetivo", ge=1)
    filter_name: Optional[str] = Field(
        default=None,
        description="Filtro parcial por nombre de modulo. Ej: 'DemoApp' para el exe principal"
    )

@mcp.tool(
    name="mem_get_modules",
    annotations={
        "title": "Obtener módulos del proceso",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_get_modules(params: GetModulesInput) -> str:
    """Lista módulos (DLLs, exe) cargados en un proceso con sus direcciones base.

    Esencial para encontrar la base del ejecutable principal. En procesos grandes,
    la mayoria de offsets son relativos al modulo principal (RVA).
    Ej: base del exe + RVA del offset = dirección absoluta.
    """
    try:
        modules = _get_modules(params.pid)
        if params.filter_name:
            flt = params.filter_name.lower()
            modules = [m for m in modules if flt in m["name"].lower()]
        return json.dumps({"count": len(modules), "modules": modules}, indent=2)
    except Exception as e:
        return f"Error obteniendo módulos: {e}"


# ---- Tool: Resolver direccion ----

class ResolveAddressInput(BaseModel):
    """Input para normalizar una expresion de direccion."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    address: str = Field(..., description="Direccion absoluta o expresion tipo modulo.exe+0xRVA+0xoffset")
    module_name: Optional[str] = Field(
        default=None,
        description="Modulo opcional para interpretar direcciones pequenas como RVA. Ej: address='0x4630', module_name='DemoApp.exe'",
    )


def _module_metadata_for_address(pid: int, address: int) -> Optional[Dict[str, Any]]:
    for module in _get_modules(pid):
        base = int(module["base"])
        size = int(module["size"])
        if base <= address < base + size:
            return module
    return None


def _address_resolution_payload(
    expression: str,
    absolute: int,
    module: Optional[Dict[str, Any]],
    resolved_as: str,
    input_module_name: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "expression": expression,
        "absolute": f"0x{absolute:X}",
        "absolute_int": absolute,
        "inside_module": module is not None,
        "resolved_as": resolved_as,
        "note": "Address resolution only normalizes arithmetic/module expressions; it does not read memory or dereference pointers.",
    }
    if input_module_name:
        payload["input_module_name"] = input_module_name

    if module is None:
        payload.update({
            "module": None,
            "module_base": None,
            "module_size": None,
            "module_path": None,
            "rva": None,
        })
        return payload

    module_base = int(module["base"])
    payload.update({
        "module": module["name"],
        "module_base": module.get("base_hex", f"0x{module_base:X}"),
        "module_size": module.get("size_hex", f"0x{int(module['size']):X}"),
        "module_path": module.get("path", ""),
        "rva": f"0x{absolute - module_base:X}",
    })
    return payload


@mcp.tool(
    name="mem_resolve_address",
    annotations={
        "title": "Resolver direccion",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_resolve_address(params: ResolveAddressInput) -> str:
    """Normaliza una expresion de direccion a VA absoluta y metadata de modulo.

    No lee memoria y no dereferencia punteros. Sirve para que agentes resuelvan
    expresiones como DemoApp.exe+0x414F6D0+0x4 sin hacer matematicas manuales.
    Si `module_name` se proporciona y `address` resuelve a un valor dentro del
    tamano del modulo, se trata como RVA de ese modulo.
    """
    try:
        parsed = _parse_address_expression(params.address, params.pid)
        resolved_as = "address_expression"

        if params.module_name:
            module = _find_module(params.pid, params.module_name, None)
            module_base = int(module["base"])
            module_size = int(module["size"])
            if 0 <= parsed < module_size:
                absolute = module_base + parsed
                resolved_as = "module_rva"
                return json.dumps(
                    _address_resolution_payload(params.address, absolute, module, resolved_as, params.module_name),
                    indent=2,
                    ensure_ascii=False,
                )

        absolute = parsed
        module = _module_metadata_for_address(params.pid, absolute)
        return json.dumps(
            _address_resolution_payload(params.address, absolute, module, resolved_as, params.module_name),
            indent=2,
            ensure_ascii=False,
        )
    except Exception as e:
        return json.dumps({
            "error": "resolve_address_failed",
            "expression": params.address,
            "message": str(e),
        }, indent=2, ensure_ascii=False)


# ---- Tool: Leer memoria ----

class ReadMemoryInput(BaseModel):
    """Input para leer memoria."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    address: str = Field(..., description="Dirección de memoria en hex (0x...) o decimal")
    size: int = Field(
        default=256,
        description="Cantidad de bytes a leer (max 65536)",
        ge=1, le=65536,
    )
    interpret: bool = Field(
        default=True,
        description="Si True, interpreta los primeros bytes como distintos tipos (u32, f32, ptr, string...)"
    )
    allow_partial: bool = Field(
        default=True,
        description="Si True, lee por paginas y devuelve bytes parciales cuando ReadProcessMemory da error 299"
    )

@mcp.tool(
    name="mem_read",
    annotations={
        "title": "Leer memoria",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_read(params: ReadMemoryInput) -> str:
    """Lee bytes de la memoria de un proceso y los muestra como hex dump.

    Opcionalmente interpreta los primeros bytes como distintos tipos de datos:
    u8/i8, u16/i16, u32/i32, u64/i64, f32, f64, punteros, strings UTF-8/UTF-16.

    El hex dump incluye representación ASCII (como en un editor hex).
    """
    try:
        addr = _parse_address_expression(params.address, params.pid)
        handle = _get_handle(params.pid)
        if params.allow_partial:
            read_result = _read_bytes_best_effort(handle, addr, params.size)
            data = read_result["data"]
        else:
            data = _read_bytes(handle, addr, params.size)
            read_result = {
                "complete": len(data) == params.size,
                "segments": [{"address": f"0x{addr:X}", "size": len(data), "requested": params.size, "partial": False}],
                "errors": [],
            }

        result: Dict[str, Any] = {
            "address": f"0x{addr:X}",
            "bytes_requested": params.size,
            "bytes_read": len(data),
            "complete": read_result["complete"],
            "segments": read_result["segments"],
            "hex_dump": _format_hex_dump(data, addr),
        }
        if read_result["errors"]:
            result["partial_read"] = True
            result["errors"] = read_result["errors"]
            result["hint"] = "ReadProcessMemory returned a partial read, commonly WinError 299 / ERROR_PARTIAL_COPY. Retry with a smaller size or page-aligned range if exact bytes are required."

        if params.interpret and len(data) >= 1:
            result["interpreted"] = _interpret_bytes(data, addr)

        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error leyendo memoria: {e}"




# ---- Tool: Cerrar handle ----

class CloseHandleInput(BaseModel):
    """Input para cerrar un handle abierto."""
    pid: int = Field(..., description="PID del proceso cuyo handle cerrar", ge=1)

@mcp.tool(
    name="mem_close",
    annotations={
        "title": "Cerrar handle de proceso",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_close(params: CloseHandleInput) -> str:
    """Cierra el handle abierto a un proceso. Buena práctica al terminar."""
    if params.pid in _open_handles:
        kernel32.CloseHandle(_open_handles[params.pid])
        del _open_handles[params.pid]
        return f"Handle cerrado para PID {params.pid}"
    return f"No había handle abierto para PID {params.pid}"


# ---------------------------------------------------------------------------
# Entry point
