"""Search, scan, AOB, memory-map, linked-list, and compare tools."""

from ..runtime import *
from .data import StructField

# ---- Tool: Buscar valor en memoria ----

class SearchValueInput(BaseModel):
    """Input para buscar un valor en memoria."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    value: str = Field(
        ...,
        description="Valor a buscar. Ej: '12345' (int), '3.14' (float), 'ExampleName' (string)"
    )
    value_type: str = Field(
        default="auto",
        description="Tipo del valor: u8, u16, u32, u64, i32, i64, f32, f64, utf8, utf16, auto"
    )
    region_start: Optional[str] = Field(
        default=None,
        description="Dirección inicio del rango de búsqueda (default: todo el proceso)"
    )
    region_end: Optional[str] = Field(
        default=None,
        description="Dirección fin del rango de búsqueda"
    )
    max_scan_mb: int = Field(default=DEFAULT_MAX_SCAN_MB, description="Maximo estimado de MB antes de avisar", ge=1, le=4096)
    max_results: int = Field(default=50, description="Maximo de resultados", ge=1, le=500)

@mcp.tool(
    name="mem_search_value",
    annotations={
        "title": "Buscar valor en memoria",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_search_value(params: SearchValueInput) -> str:
    """Busca un valor específico (entero, float, string) en la memoria del proceso.

    Similar a la función 'First Scan' de Cheat Engine.
    Recorre todas las regiones legibles del proceso buscando coincidencias.
    Util para encontrar donde se almacena un valor conocido (contador, posicion, estado, etc.).

    Tip: usa region_start/region_end para acotar al modulo objetivo y acelerar.
    """
    try:
        handle = _get_handle(params.pid)

        # Construir bytes a buscar
        vtype = params.value_type.lower()
        search_bytes_list: List[Tuple[bytes, str]] = []

        if vtype == "auto":
            # Intentar múltiples interpretaciones
            try:
                ival = int(params.value)
                if 0 <= ival <= 0xFF:
                    search_bytes_list.append((struct.pack("<B", ival), "u8"))
                if 0 <= ival <= 0xFFFF:
                    search_bytes_list.append((struct.pack("<H", ival), "u16"))
                if -2147483648 <= ival <= 4294967295:
                    search_bytes_list.append((struct.pack("<I", ival & 0xFFFFFFFF), "u32"))
                search_bytes_list.append((struct.pack("<Q", ival & 0xFFFFFFFFFFFFFFFF), "u64"))
            except ValueError:
                pass
            try:
                fval = float(params.value)
                search_bytes_list.append((struct.pack("<f", fval), "f32"))
                search_bytes_list.append((struct.pack("<d", fval), "f64"))
            except ValueError:
                pass
            if not search_bytes_list:
                # Tratar como string
                search_bytes_list.append((params.value.encode("utf-8"), "utf8"))
                search_bytes_list.append((params.value.encode("utf-16-le"), "utf16"))
        else:
            val = params.value
            FORMAT_MAP = {
                "u8": ("<B", int), "u16": ("<H", int), "u32": ("<I", int), "u64": ("<Q", int),
                "i8": ("<b", int), "i16": ("<h", int), "i32": ("<i", int), "i64": ("<q", int),
                "f32": ("<f", float), "f64": ("<d", float),
            }
            if vtype in FORMAT_MAP:
                fmt, converter = FORMAT_MAP[vtype]
                search_bytes_list.append((struct.pack(fmt, converter(val)), vtype))
            elif vtype == "utf8":
                search_bytes_list.append((val.encode("utf-8"), "utf8"))
            elif vtype == "utf16":
                search_bytes_list.append((val.encode("utf-16-le"), "utf16"))
            else:
                return f"Error: tipo '{vtype}' no soportado"

        # Rango de búsqueda
        start = _parse_address_expression(params.region_start, params.pid) if params.region_start else 0
        end = _parse_address_expression(params.region_end, params.pid) if params.region_end else 0x7FFFFFFFFFFF

        regions = _memory_regions(handle, readable_only=True)
        scan_regions = []
        for region in regions:
            rbase = int(region["base"])
            rsize = int(region["size"])
            if rbase + rsize <= start or rbase >= end:
                continue
            if rsize > 64 * 1024 * 1024:
                continue
            scan_regions.append(region)
        preflight = _too_expensive_scan_response(
            "mem_search_value",
            scan_regions,
            params.max_scan_mb,
            "Busqueda de valor sin rango puede recorrer muchos MB. Acota con region_start/region_end o sube max_scan_mb si de verdad quieres un scan amplio.",
        )
        if preflight:
            return preflight
        results = []
        total_scanned = 0

        for region in scan_regions:
            rbase = region["base"]
            rsize = region["size"]

            try:
                data = _read_bytes(handle, rbase, rsize)
                total_scanned += len(data)
            except Exception:
                continue

            for search_bytes, stype in search_bytes_list:
                offset = 0
                while offset < len(data) - len(search_bytes) + 1:
                    idx = data.find(search_bytes, offset)
                    if idx == -1:
                        break
                    results.append({
                        "address": f"0x{rbase + idx:X}",
                        "type": stype,
                        "region_base": region["base_hex"],
                        "region_protect": region["protect"],
                    })
                    if len(results) >= params.max_results:
                        break
                    offset = idx + 1

                if len(results) >= params.max_results:
                    break

            if len(results) >= params.max_results:
                break

        return json.dumps({
            "query": params.value,
            "total_found": len(results),
            "total_scanned_mb": round(total_scanned / 1048576, 1),
            "results": results,
        }, indent=2)

    except Exception as e:
        return f"Error buscando valor: {e}"


# ---- Tool: Escaneo incremental tipo Cheat Engine ----

class ScanStartInput(BaseModel):
    """Input para iniciar una sesion de escaneo incremental."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    value_type: str = Field(default="u32", description="Tipo numerico: u8/i8/u16/i16/u32/i32/u64/i64/f32/f64")
    scan_mode: str = Field(default="exact", description="exact, range o unknown")
    value: Optional[str] = Field(default=None, description="Valor exacto para scan_mode=exact")
    value_min: Optional[str] = Field(default=None, description="Minimo para scan_mode=range")
    value_max: Optional[str] = Field(default=None, description="Maximo para scan_mode=range")
    tolerance: float = Field(default=0.0, description="Tolerancia para floats", ge=0.0)
    module_name: Optional[str] = Field(default=None, description="Modulo a escanear. Ej: DemoApp.exe")
    region_start: Optional[str] = Field(default=None, description="Inicio del rango; admite modulo+offset")
    region_end: Optional[str] = Field(default=None, description="Fin del rango; admite modulo+offset")
    alignment: int = Field(default=0, description="Stride del escaneo. 0 usa tamano del tipo", ge=0, le=64)
    chunk_mb: int = Field(default=8, description="Tamano de bloque de lectura", ge=1, le=32)
    max_scan_mb: int = Field(default=DEFAULT_MAX_SCAN_MB, description="Maximo estimado de MB antes de avisar", ge=1, le=4096)
    max_candidates: int = Field(default=100000, description="Maximo de candidatos guardados", ge=1, le=MAX_SCAN_CANDIDATES)


@mcp.tool(
    name="mem_scan_start",
    annotations={
        "title": "Iniciar escaneo incremental",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_scan_start(params: ScanStartInput) -> str:
    """Crea una sesion persistente de candidatos para filtrar con mem_scan_next.

    Es el equivalente headless de First Scan. Para evitar explosiones de memoria,
    los candidatos se limitan por max_candidates y el resultado indica si fue truncado.
    """
    try:
        vtype = params.value_type.lower()
        if vtype not in NUMERIC_TYPE_FORMATS or vtype.startswith("ptr"):
            return json.dumps({"error": f"Tipo numerico no soportado para escaneo: {params.value_type}"})

        scan_mode = params.scan_mode.lower()
        target = lower = upper = None
        if scan_mode == "exact":
            if params.value is None:
                return json.dumps({"error": "scan_mode=exact requiere value"})
            target = _coerce_scan_value(params.value, vtype)
        elif scan_mode == "range":
            if params.value_min is None or params.value_max is None:
                return json.dumps({"error": "scan_mode=range requiere value_min y value_max"})
            lower = _coerce_scan_value(params.value_min, vtype)
            upper = _coerce_scan_value(params.value_max, vtype)
        elif scan_mode != "unknown":
            return json.dumps({"error": f"scan_mode no soportado: {scan_mode}"})

        handle = _get_handle(params.pid)
        regions = _scan_regions(params.pid, handle, params.module_name, params.region_start, params.region_end)
        preflight = _too_expensive_scan_response(
            "mem_scan_start",
            regions,
            params.max_scan_mb,
            "First Scan sin modulo/rango puede tardar mucho. Acota con module_name, region_start/region_end, o sube max_scan_mb explicitamente.",
        )
        if preflight:
            return preflight
        candidates, stats = _scan_numeric_candidates(
            handle=handle,
            regions=regions,
            value_type=vtype,
            scan_mode=scan_mode,
            target=target,
            lower=lower,
            upper=upper,
            tolerance=params.tolerance,
            alignment=params.alignment,
            chunk_size=params.chunk_mb * 1024 * 1024,
            max_candidates=params.max_candidates,
        )

        session_id = uuid.uuid4().hex[:12]
        _scan_sessions[session_id] = {
            "pid": params.pid,
            "value_type": vtype,
            "scan_mode": scan_mode,
            "candidates": candidates,
            "created_at": time.time() if "time" in globals() else None,
        }

        sample = [
            {"address": f"0x{c['address']:X}", "value": c["previous"]}
            for c in candidates[:25]
        ]
        return json.dumps({
            "session_id": session_id,
            "pid": params.pid,
            "value_type": vtype,
            "scan_mode": scan_mode,
            "candidate_count": len(candidates),
            "truncated": stats["truncated"],
            "bytes_scanned_mb": round(stats["bytes_scanned"] / 1048576, 2),
            "regions_seen": stats["regions_seen"],
            "read_errors": stats["read_errors"],
            "sample": sample,
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error iniciando escaneo: {e}"


class ScanNextInput(BaseModel):
    """Input para filtrar una sesion de escaneo."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: str = Field(..., description="ID devuelto por mem_scan_start")
    op: str = Field(
        ...,
        description="eq/ne/lt/le/gt/ge/between/not_between/changed/unchanged/increased/decreased/eq_prev/ne_prev/gt_prev/lt_prev",
    )
    value: Optional[str] = Field(default=None, description="Valor para op contra valor absoluto")
    value_min: Optional[str] = Field(default=None, description="Minimo para between/not_between")
    value_max: Optional[str] = Field(default=None, description="Maximo para between/not_between")
    tolerance: float = Field(default=0.0, description="Tolerancia para floats y unchanged", ge=0.0)
    max_candidates: int = Field(default=MAX_SCAN_CANDIDATES, description="Maximo de candidatos conservados", ge=1, le=MAX_SCAN_CANDIDATES)


@mcp.tool(
    name="mem_scan_next",
    annotations={
        "title": "Filtrar escaneo incremental",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_scan_next(params: ScanNextInput) -> str:
    """Filtra candidatos existentes contra valor actual o valor previo.

    Operaciones tipicas: decreased/increased/changed/unchanged para workflows tipo
    Cheat Engine sin GUI. Los candidatos conservados actualizan su valor previous.
    """
    try:
        session = _scan_sessions.get(params.session_id)
        if not session:
            return json.dumps({"error": f"Sesion no encontrada: {params.session_id}"})

        vtype = session["value_type"]
        op = params.op.lower()
        target = lower = upper = None
        if op in ("eq", "eq_value", "ne", "ne_value", "lt", "lt_value", "le", "le_value", "gt", "gt_value", "ge", "ge_value"):
            if params.value is None:
                return json.dumps({"error": f"op={op} requiere value"})
            target = _coerce_scan_value(params.value, vtype)
        elif op in ("between", "not_between"):
            if params.value_min is None or params.value_max is None:
                return json.dumps({"error": f"op={op} requiere value_min y value_max"})
            lower = _coerce_scan_value(params.value_min, vtype)
            upper = _coerce_scan_value(params.value_max, vtype)

        handle = _get_handle(session["pid"])
        before = len(session["candidates"])
        kept = []
        read_errors = 0
        truncated = False
        for candidate in session["candidates"]:
            try:
                current = _read_numeric_value(handle, int(candidate["address"]), vtype)
            except Exception:
                read_errors += 1
                continue

            if _next_scan_match(current, candidate["previous"], vtype, op, target, lower, upper, params.tolerance):
                kept.append({
                    "address": candidate["address"],
                    "initial": candidate["initial"],
                    "previous": current,
                })
                if len(kept) >= params.max_candidates:
                    truncated = True
                    break

        session["candidates"] = kept
        session["last_op"] = op
        sample = [
            {"address": f"0x{c['address']:X}", "value": c["previous"], "initial": c["initial"]}
            for c in kept[:25]
        ]
        return json.dumps({
            "session_id": params.session_id,
            "before": before,
            "after": len(kept),
            "read_errors": read_errors,
            "truncated": truncated,
            "sample": sample,
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error filtrando escaneo: {e}"


class ScanResultsInput(BaseModel):
    """Input para consultar resultados de una sesion."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: str = Field(..., description="ID de sesion")
    offset: int = Field(default=0, description="Offset de paginacion", ge=0)
    limit: int = Field(default=50, description="Maximo de resultados", ge=1, le=1000)
    refresh: bool = Field(default=True, description="Releer valor actual antes de devolver")


@mcp.tool(
    name="mem_scan_results",
    annotations={
        "title": "Resultados de escaneo",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_scan_results(params: ScanResultsInput) -> str:
    """Devuelve candidatos paginados de una sesion de escaneo."""
    try:
        session = _scan_sessions.get(params.session_id)
        if not session:
            return json.dumps({"error": f"Sesion no encontrada: {params.session_id}"})

        vtype = session["value_type"]
        handle = _get_handle(session["pid"])
        subset = session["candidates"][params.offset:params.offset + params.limit]
        results = []
        for candidate in subset:
            address = int(candidate["address"])
            item = {
                "address": f"0x{address:X}",
                "initial": candidate["initial"],
                "previous": candidate["previous"],
            }
            if params.refresh:
                try:
                    item["current"] = _read_numeric_value(handle, address, vtype)
                except Exception as e:
                    item["error"] = str(e)
            results.append(item)

        return json.dumps({
            "session_id": params.session_id,
            "pid": session["pid"],
            "value_type": vtype,
            "total_candidates": len(session["candidates"]),
            "offset": params.offset,
            "limit": params.limit,
            "results": results,
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error consultando resultados: {e}"


class ScanClearInput(BaseModel):
    """Input para cerrar una o todas las sesiones de escaneo."""
    model_config = ConfigDict(str_strip_whitespace=True)

    session_id: Optional[str] = Field(default=None, description="ID concreto. Si se omite, limpia todas.")


@mcp.tool(
    name="mem_scan_clear",
    annotations={
        "title": "Limpiar sesiones de escaneo",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_scan_clear(params: ScanClearInput) -> str:
    """Descarta sesiones de escaneo en memoria del MCP server."""
    if params.session_id:
        existed = params.session_id in _scan_sessions
        _scan_sessions.pop(params.session_id, None)
        return json.dumps({"cleared": [params.session_id] if existed else [], "remaining": len(_scan_sessions)})
    count = len(_scan_sessions)
    _scan_sessions.clear()
    return json.dumps({"cleared_count": count, "remaining": 0})


# ---- Tool: AOB Scan (Array of Bytes) ----

class AOBScanInput(BaseModel):
    """Input para búsqueda de patrón de bytes."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    pattern: str = Field(
        ...,
        description="Patron AOB con wildcards. Ej: 'A1 ?? 4? ?F 8B 0D'. Soporta ?, ??, 4? y ?F."
    )
    module_name: Optional[str] = Field(
        default=None,
        description="Nombre del modulo donde buscar (mas rapido que escanear todo). Ej: 'DemoApp.exe'"
    )
    region_start: Optional[str] = Field(default=None, description="Inicio del rango; admite modulo+offset")
    region_end: Optional[str] = Field(default=None, description="Fin del rango; admite modulo+offset")
    max_scan_mb: int = Field(default=DEFAULT_MAX_SCAN_MB, description="Maximo estimado de MB antes de avisar", ge=1, le=4096)
    time_budget_sec: int = Field(default=DEFAULT_MAX_TOOL_SECONDS, description="Segundos maximos aproximados antes de devolver parcial", ge=1, le=110)
    max_results: int = Field(default=20, description="Maximo de resultados", ge=1, le=100)

@mcp.tool(
    name="mem_aob_scan",
    annotations={
        "title": "AOB Scan (Array of Bytes)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_aob_scan(params: AOBScanInput) -> str:
    """Busca un patrón de bytes (signature) en la memoria del proceso.

    Equivalente al 'AOB Scan' de Cheat Engine. Ideal para encontrar
    instrucciones o patrones de código que llevan a estructuras de datos.
    Usa ?? o ? para bytes variables completos. Tambien soporta wildcards por
    nibble: 4? fija el nibble alto y ?F fija el nibble bajo.

    Ej: 'A1 ?? ?? ?? ?? 8B 0D' busca una instrucción mov eax,[???]; mov ecx,[...]
    Los bytes entre ?? varían entre versiones del ejecutable.

    Si proporcionas module_name, solo escanea ese módulo (mucho más rápido).
    """
    try:
        handle = _get_handle(params.pid)
        pattern, mask = _parse_pattern(params.pattern)

        scan_regions = _scan_regions(
            params.pid,
            handle,
            module_name=params.module_name,
            region_start=params.region_start,
            region_end=params.region_end,
        )
        preflight = _too_expensive_scan_response(
            "mem_aob_scan",
            scan_regions,
            params.max_scan_mb,
            "AOB sin module_name/rango puede recorrer GB y bloquear el servidor MCP. Acota con module_name='DemoApp.exe' o region_start/region_end.",
        )
        if preflight:
            return preflight

        results = []
        total_scanned = 0
        started = time.monotonic()
        timed_out = False

        for region in scan_regions:
            if time.monotonic() - started >= params.time_budget_sec:
                timed_out = True
                break
            try:
                data = _read_bytes(handle, region["base"], region["size"])
                total_scanned += len(data)
            except Exception:
                continue

            offsets = _aob_search(data, pattern, mask, max_results=params.max_results - len(results))
            for off in offsets:
                addr = region["base"] + off
                # Leer contexto alrededor del match
                context_data = data[off:off + max(len(pattern) + 16, 32)]
                results.append({
                    "address": f"0x{addr:X}",
                    "context": " ".join(f"{b:02X}" for b in context_data),
                })
                if len(results) >= params.max_results:
                    break

            if len(results) >= params.max_results:
                break

        return json.dumps({
            "pattern": params.pattern,
            "total_found": len(results),
            "total_scanned_mb": round(total_scanned / 1048576, 1),
            "region_count": len(scan_regions),
            "partial": timed_out,
            "time_budget_sec": params.time_budget_sec,
            "results": results,
        }, indent=2)

    except Exception as e:
        return f"Error en AOB scan: {e}"


# ---- Tool: AOB Scan a archivo ----

class AOBScanFileStartInput(BaseModel):
    """Input para lanzar un AOB scan largo en background y escribir resultados a archivo."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    pattern: str = Field(..., description="Patron AOB con wildcards. Ej: 'B0 01 C3', '48 8B ?? ??', '48 8B 4? ?F'. Soporta ?, ??, 4? y ?F.")
    module_name: Optional[str] = Field(default=None, description="Modulo a escanear. Ej: DemoApp.exe")
    region_start: Optional[str] = Field(default=None, description="Inicio del rango; admite modulo+offset")
    region_end: Optional[str] = Field(default=None, description="Fin del rango; admite modulo+offset")
    max_scan_mb: int = Field(default=DEFAULT_JOB_MAX_SCAN_MB, description="Maximo estimado de MB antes de rechazar el job", ge=1, le=32768)
    max_results: int = Field(default=100000, description="Maximo de matches a escribir", ge=1, le=1000000)
    context_bytes: int = Field(default=32, description="Bytes de contexto despues del match", ge=0, le=256)


@mcp.tool(
    name="mem_aob_scan_file_start",
    annotations={
        "title": "AOB Scan a archivo",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_aob_scan_file_start(params: AOBScanFileStartInput) -> str:
    """Lanza un AOB scan largo en background y escribe resultados JSONL.

    Esta herramienta devuelve enseguida. El agente debe esperar a que
    `status.json` indique state=completed, o consultar `mem_scan_file_status`.
    Es la via recomendada para scans grandes que no caben en una llamada MCP.
    """
    try:
        handle = _get_handle(params.pid)
        pattern, mask = _parse_pattern(params.pattern)
        regions = _scan_regions(
            params.pid,
            handle,
            module_name=params.module_name,
            region_start=params.region_start,
            region_end=params.region_end,
        )
        preflight = _too_expensive_scan_response(
            "mem_aob_scan_file_start",
            regions,
            params.max_scan_mb,
            "El job a archivo tambien tiene limite. Acota con module_name/rango o sube max_scan_mb explicitamente.",
        )
        if preflight:
            return preflight

        job_id = uuid.uuid4().hex[:12]
        paths = _job_paths(job_id)
        paths["dir"].mkdir(parents=True, exist_ok=True)
        meta = {
            "job_id": job_id,
            "operation": "mem_aob_scan_file",
            "pid": params.pid,
            "pattern": params.pattern,
            "module_name": params.module_name,
            "region_start": params.region_start,
            "region_end": params.region_end,
            "max_results": params.max_results,
            "context_bytes": params.context_bytes,
            "estimated_scan_mb": round(_regions_total_bytes(regions) / 1048576, 1),
            "region_count": len(regions),
            "status_path": str(paths["status"]),
            "results_path": str(paths["results"]),
        }
        _write_json_atomic(paths["meta"], meta)
        _write_json_atomic(paths["status"], {
            **meta,
            "state": "queued",
            "regions_done": 0,
            "bytes_scanned": 0,
            "bytes_scanned_mb": 0.0,
            "results_found": 0,
            "read_errors": 0,
            "created_at": time.time(),
        })

        cancel_event = threading.Event()
        thread = threading.Thread(
            target=_aob_scan_file_worker,
            args=(job_id, params.pid, params.pattern, pattern, mask, regions, params.max_results, params.context_bytes),
            name=f"mem-aob-file-{job_id}",
            daemon=True,
        )
        _file_jobs[job_id] = {
            "thread": thread,
            "cancel_event": cancel_event,
            "state": "queued",
            "status_path": str(paths["status"]),
            "results_path": str(paths["results"]),
        }
        thread.start()

        return json.dumps({
            **meta,
            "state": "started",
            "agent_instruction": "Espera a state='completed' consultando mem_scan_file_status o leyendo status_path. Los resultados se escriben como JSONL en results_path.",
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error lanzando AOB scan a archivo: {e}"


class ScanFileStatusInput(BaseModel):
    """Input para consultar un job de scan a archivo."""
    model_config = ConfigDict(str_strip_whitespace=True)

    job_id: str = Field(..., description="ID devuelto por mem_aob_scan_file_start")
    tail_results: int = Field(default=0, description="Incluye las ultimas N lineas de results.jsonl", ge=0, le=100)


@mcp.tool(
    name="mem_scan_file_status",
    annotations={
        "title": "Estado de scan a archivo",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_scan_file_status(params: ScanFileStatusInput) -> str:
    """Consulta estado de un scan a archivo y opcionalmente devuelve una cola de resultados."""
    try:
        paths = _job_paths(params.job_id)
        if not paths["status"].exists():
            return json.dumps({"error": f"job no encontrado: {params.job_id}"})
        status = _read_json_file(paths["status"])
        active = _file_jobs.get(params.job_id)
        if active:
            thread = active.get("thread")
            status["thread_alive"] = bool(thread and thread.is_alive())
        if params.tail_results and paths["results"].exists():
            lines = paths["results"].read_text(encoding="utf-8", errors="replace").splitlines()
            status["tail_results"] = [json.loads(line) for line in lines[-params.tail_results:] if line.strip()]
        return json.dumps(status, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error consultando job: {e}"


class ScanFileCancelInput(BaseModel):
    """Input para cancelar un job de scan a archivo."""
    model_config = ConfigDict(str_strip_whitespace=True)

    job_id: str = Field(..., description="ID devuelto por mem_aob_scan_file_start")


@mcp.tool(
    name="mem_scan_file_cancel",
    annotations={
        "title": "Cancelar scan a archivo",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_scan_file_cancel(params: ScanFileCancelInput) -> str:
    """Solicita cancelar un scan a archivo."""
    try:
        paths = _job_paths(params.job_id)
        paths["dir"].mkdir(parents=True, exist_ok=True)
        paths["cancel"].write_text("cancel\n", encoding="utf-8")
        active = _file_jobs.get(params.job_id)
        if active and active.get("cancel_event"):
            active["cancel_event"].set()
        return json.dumps({"job_id": params.job_id, "cancel_requested": True, "status_path": str(paths["status"])})
    except Exception as e:
        return f"Error cancelando job: {e}"


# ---- Tool: Memory Map ----

class MemoryMapInput(BaseModel):
    """Input para ver mapa de memoria."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    readable_only: bool = Field(
        default=True,
        description="Solo mostrar regiones legibles"
    )
    min_size: int = Field(
        default=0,
        description="Tamaño mínimo de región en bytes para incluir",
        ge=0,
    )

@mcp.tool(
    name="mem_memory_map",
    annotations={
        "title": "Mapa de memoria del proceso",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_memory_map(params: MemoryMapInput) -> str:
    """Muestra el mapa de regiones de memoria del proceso (VirtualQueryEx).

    Lista todas las regiones committed con su dirección base, tamaño,
    y protección (R, RW, ERW, etc.). Útil para entender el layout de
    memoria antes de escanear.
    """
    try:
        handle = _get_handle(params.pid)
        regions = _memory_regions(handle, readable_only=params.readable_only)

        if params.min_size > 0:
            regions = [r for r in regions if r["size"] >= params.min_size]

        total_size = sum(r["size"] for r in regions)
        return json.dumps({
            "total_regions": len(regions),
            "total_size_mb": round(total_size / 1048576, 1),
            "regions": regions[:500],  # Limitar output
        }, indent=2)

    except Exception as e:
        return f"Error obteniendo mapa de memoria: {e}"


# ---- Tool: Escanear hash table generica ----

class ScanLinkedListInput(BaseModel):
    """Input para recorrer una linked list / hash table."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    start_address: str = Field(
        ...,
        description="Dirección del primer nodo de la lista"
    )
    next_offset: str = Field(
        ...,
        description="Offset dentro del nodo al puntero 'next'. Ej: '0x158'"
    )
    fields: List[StructField] = Field(
        default_factory=list,
        description="Campos a leer de cada nodo (opcional, para inspeccionar contenido)",
        max_length=20,
    )
    max_nodes: int = Field(default=100, description="Máximo de nodos a recorrer", ge=1, le=5000)

@mcp.tool(
    name="mem_scan_linked_list",
    annotations={
        "title": "Recorrer linked list",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_scan_linked_list(params: ScanLinkedListInput) -> str:
    """Recorre una linked list en memoria, leyendo nodos hasta NULL o max_nodes.

    Fundamental para explorar hash tables y object managers genericos.
    Caso generico: una tabla de N slots donde cada slot apunta al primer nodo
    y cada nodo contiene un puntero next en un offset conocido.

    Puedes definir campos opcionales para leer datos de cada nodo
    (ej: type, id, position, etc.).
    """
    TYPE_SIZES = {
        "u8": 1, "i8": 1, "u16": 2, "i16": 2,
        "u32": 4, "i32": 4, "f32": 4, "ptr32": 4,
        "u64": 8, "i64": 8, "f64": 8, "ptr64": 8,
    }
    TYPE_FORMATS = {
        "u8": "<B", "i8": "<b", "u16": "<H", "i16": "<h",
        "u32": "<I", "i32": "<i", "f32": "<f", "ptr32": "<I",
        "u64": "<Q", "i64": "<q", "f64": "<d", "ptr64": "<Q",
    }

    try:
        handle = _get_handle(params.pid)
        current = _parse_address_expression(params.start_address, params.pid)
        next_off = _parse_address(params.next_offset)

        nodes = []
        visited = set()

        while current != 0 and len(nodes) < params.max_nodes:
            if current in visited:
                nodes.append({"warning": f"Ciclo detectado en 0x{current:X}!"})
                break
            visited.add(current)

            node: Dict[str, Any] = {"address": f"0x{current:X}"}

            # Leer campos opcionales
            for field in params.fields:
                offset = _parse_address(field.offset)
                ftype = field.type.lower()
                try:
                    if ftype in TYPE_SIZES:
                        data = _read_bytes(handle, current + offset, TYPE_SIZES[ftype])
                        val = struct.unpack(TYPE_FORMATS[ftype], data)[0]
                        if "ptr" in ftype:
                            node[field.name] = f"0x{val:X}"
                        elif "f" in ftype:
                            node[field.name] = round(val, 6)
                        else:
                            node[field.name] = val
                    elif ftype in ("utf8", "utf16"):
                        sz = field.size if field.size > 0 else 64
                        data = _read_bytes(handle, current + offset, sz)
                        if ftype == "utf8":
                            null_idx = data.find(b"\x00")
                            node[field.name] = data[:null_idx if null_idx >= 0 else len(data)].decode("utf-8", errors="replace")
                        else:
                            txt = data.decode("utf-16-le", errors="replace")
                            null_idx = txt.find("\x00")
                            node[field.name] = txt[:null_idx] if null_idx >= 0 else txt
                except Exception as e:
                    node[field.name] = f"[error: {e}]"

            nodes.append(node)

            # Leer puntero next
            try:
                next_data = _read_bytes(handle, current + next_off, 8)
                current = struct.unpack("<Q", next_data)[0]
            except Exception:
                break

        return json.dumps({
            "nodes_found": len(nodes),
            "nodes": nodes,
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return f"Error recorriendo linked list: {e}"


# ---- Tool: Comparar memoria (diff entre dos lecturas) ----

class CompareMemoryInput(BaseModel):
    """Input para comparar dos regiones o momentos."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    address: str = Field(..., description="Dirección de memoria")
    size: int = Field(default=256, description="Bytes a leer", ge=1, le=65536)
    previous_hex: str = Field(
        ...,
        description="Hex dump previo para comparar (output de mem_read, campo hex_dump o bytes en hex separados por espacio)"
    )

@mcp.tool(
    name="mem_compare",
    annotations={
        "title": "Comparar memoria (diff)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_compare(params: CompareMemoryInput) -> str:
    """Compara el estado actual de una región de memoria contra datos previos.

    Ideal para detectar que bytes cambian cuando algo ocurre en la app objetivo
    (ej: mover un control, cambiar un contador, alternar un estado).

    Workflow: 1) mem_read -> copiar hex, 2) interactuar con la app objetivo,
    3) mem_compare con el hex previo -> ver que cambio.
    """
    try:
        addr = _parse_address_expression(params.address, params.pid)
        handle = _get_handle(params.pid)
        current_data = _read_bytes(handle, addr, params.size)

        # Parsear hex previo
        hex_str = params.previous_hex.strip()
        # Eliminar prefijos de dirección y caracteres ASCII del hex dump
        clean_hex = []
        for line in hex_str.split("\n"):
            # Intentar extraer la parte hex de un dump formateado
            parts = line.strip().split("  ")
            if len(parts) >= 2:
                # Formato hex dump: "0x... XX XX XX ...  ASCII"
                hex_part = parts[1] if parts[0].startswith("0x") else parts[0]
                clean_hex.append(hex_part.strip())
            else:
                clean_hex.append(line.strip())

        hex_joined = " ".join(clean_hex)
        # Filtrar solo hex válido
        hex_tokens = [t for t in hex_joined.split() if re.match(r'^[0-9A-Fa-f]{2}$', t)]
        prev_data = bytes([int(t, 16) for t in hex_tokens])

        compare_len = min(len(current_data), len(prev_data))
        diffs = []

        for i in range(compare_len):
            if current_data[i] != prev_data[i]:
                diffs.append({
                    "offset": f"+0x{i:X}",
                    "address": f"0x{addr + i:X}",
                    "old": f"0x{prev_data[i]:02X}",
                    "new": f"0x{current_data[i]:02X}",
                })

        # Interpretar diffs agrupados (4-byte aligned)
        aligned_diffs = {}
        for d in diffs:
            off = int(d["offset"][3:], 16)
            aligned = (off // 4) * 4
            if aligned not in aligned_diffs:
                aligned_diffs[aligned] = {"offset": f"+0x{aligned:X}"}

        for aligned_off in aligned_diffs:
            if aligned_off + 4 <= len(current_data) and aligned_off + 4 <= len(prev_data):
                old_val = struct.unpack_from("<I", prev_data, aligned_off)[0]
                new_val = struct.unpack_from("<I", current_data, aligned_off)[0]
                old_f = struct.unpack_from("<f", prev_data, aligned_off)[0]
                new_f = struct.unpack_from("<f", current_data, aligned_off)[0]
                aligned_diffs[aligned_off]["old_u32"] = old_val
                aligned_diffs[aligned_off]["new_u32"] = new_val
                aligned_diffs[aligned_off]["old_f32"] = round(old_f, 4)
                aligned_diffs[aligned_off]["new_f32"] = round(new_f, 4)

        return json.dumps({
            "address": f"0x{addr:X}",
            "bytes_compared": compare_len,
            "total_diffs": len(diffs),
            "byte_diffs": diffs[:100],
            "aligned_diffs": list(aligned_diffs.values())[:50],
        }, indent=2)

    except Exception as e:
        return f"Error comparando memoria: {e}"
