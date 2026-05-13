"""Disassembly and code-reference tools."""

from ..runtime import *

# ---- Tool: Desensamblar memoria ----

def _disassemble_x64_bytes(
    data: bytes,
    addr: int,
    max_instructions: int,
    syntax: str,
    include_bytes: bool,
) -> Dict[str, Any]:
    """Disassembles an x86-64 byte buffer and returns JSON-ready data."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT, CS_OPT_SYNTAX_INTEL
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    except ImportError as exc:
        raise RuntimeError("missing_dependency: capstone") from exc

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    cs.syntax = CS_OPT_SYNTAX_ATT if syntax.lower() == "att" else CS_OPT_SYNTAX_INTEL

    instructions = []
    last_end = addr
    for index, insn in enumerate(cs.disasm(data, addr)):
        if index >= max_instructions:
            break

        groups = [cs.group_name(group_id) or str(group_id) for group_id in insn.groups]
        is_call = "call" in groups
        is_jump = "jump" in groups
        is_ret = "ret" in groups or insn.mnemonic.startswith("ret")
        branch_kind = "call" if is_call else "jump" if is_jump else "ret" if is_ret else None

        target = None
        operands = []
        rip_relative = []
        for op in insn.operands:
            item: Dict[str, Any] = {"type": str(op.type)}
            if op.type == X86_OP_IMM:
                imm = int(op.imm)
                item["kind"] = "imm"
                item["imm"] = imm
                item["imm_hex"] = f"0x{imm & 0xFFFFFFFFFFFFFFFF:X}"
                if branch_kind in ("call", "jump"):
                    target = imm
                    item["relative_target"] = f"0x{imm & 0xFFFFFFFFFFFFFFFF:X}"
                    item["relative_delta"] = imm - (insn.address + insn.size)
            elif op.type == X86_OP_MEM:
                item["kind"] = "mem"
                item["disp"] = int(op.mem.disp)
                item["scale"] = int(op.mem.scale)
                if op.mem.base:
                    item["base"] = insn.reg_name(op.mem.base)
                if op.mem.index:
                    item["index"] = insn.reg_name(op.mem.index)
                if op.mem.base == X86_REG_RIP:
                    rip_target = insn.address + insn.size + op.mem.disp
                    item["rip_relative_target"] = f"0x{rip_target:X}"
                    rip_relative.append({
                        "target": f"0x{rip_target:X}",
                        "disp": op.mem.disp,
                    })
            else:
                item["kind"] = "reg" if getattr(op, "reg", 0) else "other"
                if getattr(op, "reg", 0):
                    item["reg"] = insn.reg_name(op.reg)
            operands.append(item)

        record: Dict[str, Any] = {
            "address": f"0x{insn.address:X}",
            "address_int": insn.address,
            "size": insn.size,
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "text": f"{insn.mnemonic} {insn.op_str}".strip(),
            "groups": groups,
            "branch": branch_kind,
            "operands": operands,
        }
        if include_bytes:
            record["bytes"] = " ".join(f"{b:02X}" for b in insn.bytes)
        if target is not None:
            record["target"] = f"0x{target & 0xFFFFFFFFFFFFFFFF:X}"
            record["target_int"] = target
        if rip_relative:
            record["rip_relative"] = rip_relative

        instructions.append(record)
        last_end = insn.address + insn.size

    return {
        "instruction_count": len(instructions),
        "max_instructions": max_instructions,
        "next_address": f"0x{last_end:X}",
        "instructions": instructions,
    }


def _read_for_disassemble(
    handle: wt.HANDLE,
    addr: int,
    size: int,
    allow_partial: bool,
) -> Tuple[bytes, Dict[str, Any]]:
    if allow_partial:
        read_result = _read_bytes_best_effort(handle, addr, size)
        return read_result["data"], read_result

    data = _read_bytes(handle, addr, size)
    return data, {
        "bytes_read": len(data),
        "complete": len(data) == size,
        "segments": [{"address": f"0x{addr:X}", "size": len(data), "requested": size, "partial": False}],
        "errors": [],
    }


def _disassemble_range(
    pid: int,
    handle: wt.HANDLE,
    address: str,
    size: int,
    max_instructions: int,
    syntax: str,
    include_bytes: bool,
    allow_partial: bool,
) -> Dict[str, Any]:
    addr = _parse_address_expression(address, pid)
    data, read_result = _read_for_disassemble(handle, addr, size, allow_partial)
    result: Dict[str, Any] = {
        "address": f"0x{addr:X}",
        "bytes_requested": size,
        "bytes_read": len(data),
        "complete": read_result.get("complete", len(data) == size),
        "read_segments": read_result.get("segments", []),
        "read_errors": read_result.get("errors", []),
    }
    if not data:
        result.update({
            "error": "read_failed",
            "message": "No bytes could be read from the requested address.",
            "instruction_count": 0,
            "instructions": [],
        })
        return result

    result.update(_disassemble_x64_bytes(data, addr, max_instructions, syntax, include_bytes))
    return result


class DisassembleInput(BaseModel):
    """Input para desensamblar bytes x86-64 con Capstone."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    address: str = Field(..., description="Direccion o expresion tipo modulo+offset")
    size: int = Field(default=128, description="Bytes a leer y desensamblar", ge=1, le=65536)
    max_instructions: int = Field(default=64, description="Maximo de instrucciones", ge=1, le=2000)
    syntax: str = Field(default="intel", description="intel o att")
    include_bytes: bool = Field(default=True, description="Incluye bytes de cada instruccion")
    allow_partial: bool = Field(default=True, description="Si True, devuelve desensamblado parcial si ReadProcessMemory falla a mitad")


@mcp.tool(
    name="mem_disassemble",
    annotations={
        "title": "Desensamblar memoria",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_disassemble(params: DisassembleInput) -> str:
    """Lee memoria y desensambla x86-64 con Capstone.

    Devuelve JSON con instrucciones limpias, targets absolutos de calls/jumps
    relativos y targets RIP-relative para referencias tipo [rip+disp].
    """
    try:
        handle = _get_handle(params.pid)
        result = _disassemble_range(
            params.pid,
            handle,
            params.address,
            params.size,
            params.max_instructions,
            params.syntax,
            params.include_bytes,
            params.allow_partial,
        )
        return json.dumps(result, indent=2, ensure_ascii=False)

    except Exception as e:
        if "missing_dependency: capstone" in str(e):
            return json.dumps({
                "error": "missing_dependency",
                "dependency": "capstone",
                "install": "pip install -r requirements.txt",
            }, indent=2)
        return json.dumps({
            "error": "disassemble_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)


class DisassembleBatchItem(BaseModel):
    """Un rango para mem_disassemble_batch."""
    model_config = ConfigDict(str_strip_whitespace=True)

    address: str = Field(..., description="Direccion o expresion tipo modulo+offset")
    size: int = Field(default=128, description="Bytes a leer y desensamblar", ge=1, le=65536)
    max_instructions: int = Field(default=64, description="Maximo de instrucciones para este rango", ge=1, le=2000)
    label: Optional[str] = Field(default=None, description="Etiqueta opcional para identificar el rango")


class DisassembleBatchInput(BaseModel):
    """Input para desensamblar varios rangos en una sola llamada MCP."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    ranges: List[DisassembleBatchItem] = Field(..., description="Rangos a desensamblar", min_length=1, max_length=32)
    syntax: str = Field(default="intel", description="intel o att")
    include_bytes: bool = Field(default=True, description="Incluye bytes de cada instruccion")
    allow_partial: bool = Field(default=True, description="Si True, devuelve resultados parciales por rango")
    max_total_bytes: int = Field(default=65536, description="Limite total de bytes del batch", ge=1, le=1048576)


@mcp.tool(
    name="mem_disassemble_batch",
    annotations={
        "title": "Desensamblar varios rangos",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_disassemble_batch(params: DisassembleBatchInput) -> str:
    """Desensambla varios rangos x86-64 en una sola llamada.

    Recomendado para agentes cuando necesitan inspeccionar varias direcciones
    cercanas, porque evita emitir muchas tool calls consecutivas.
    """
    try:
        total_bytes = sum(item.size for item in params.ranges)
        if total_bytes > params.max_total_bytes:
            return json.dumps({
                "error": "batch_too_large",
                "requested_bytes": total_bytes,
                "max_total_bytes": params.max_total_bytes,
                "hint": "Reduce ranges or increase max_total_bytes deliberately.",
            }, indent=2, ensure_ascii=False)

        handle = _get_handle(params.pid)
        results = []
        for item in params.ranges:
            try:
                result = _disassemble_range(
                    params.pid,
                    handle,
                    item.address,
                    item.size,
                    item.max_instructions,
                    params.syntax,
                    params.include_bytes,
                    params.allow_partial,
                )
                if item.label:
                    result["label"] = item.label
                results.append(result)
            except Exception as exc:
                results.append({
                    "address": item.address,
                    "label": item.label,
                    "error": "disassemble_failed",
                    "message": str(exc),
                    "instruction_count": 0,
                    "instructions": [],
                })

        return json.dumps({
            "pid": params.pid,
            "range_count": len(params.ranges),
            "total_bytes_requested": total_bytes,
            "results": results,
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return json.dumps({
            "error": "disassemble_batch_failed",
            "message": str(e),
        }, indent=2, ensure_ascii=False)




# ---- Tool: Encontrar callers directos ----

class FindCallersInput(BaseModel):
    """Input para encontrar CALL rel32 directos hacia uno o varios targets."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    target_addresses: List[str] = Field(
        default_factory=list,
        description="Targets absolutos o RVAs si se proporciona module_name. Ej: ['DemoApp.exe+0x4630', '0x7FF...4710']",
        max_length=32,
    )
    target_address: Optional[str] = Field(default=None, description="Target unico alternativo")
    module_name: Optional[str] = Field(default=None, description="Modulo cuyo codigo escanear. Si se omite, se usa el modulo que contiene el primer target absoluto.")
    section_names: List[str] = Field(default_factory=lambda: [".text"], description="Secciones PE a escanear. Lista vacia = todas las ejecutables.", max_length=16)
    scan_start: Optional[str] = Field(default=None, description="Inicio de rango manual; si se usa, ignora secciones")
    scan_end: Optional[str] = Field(default=None, description="Fin de rango manual")
    max_scan_mb: int = Field(default=512, description="Maximo estimado de MB antes de avisar", ge=1, le=8192)
    chunk_mb: int = Field(default=16, description="Tamano de lectura por bloque", ge=1, le=64)
    max_results: int = Field(default=1000, description="Maximo total de callers", ge=1, le=100000)
    include_indirect_rip: bool = Field(default=False, description="Tambien intenta resolver FF 15 rel32 como call qword ptr [rip+rel32]")


@mcp.tool(
    name="mem_find_callers",
    annotations={
        "title": "Encontrar callers directos",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_find_callers(params: FindCallersInput) -> str:
    """Escanea codigo y resuelve matematicamente CALL rel32 hacia targets.

    Para cada byte E8 encontrado:
        disp = int32_le(bytes[p+1:p+5])
        target = p + 5 + disp

    Si target coincide con uno de los objetivos, devuelve el call_site.
    Opcionalmente resuelve `FF 15 rel32` leyendo el puntero RIP-relative.
    """
    try:
        raw_targets = list(params.target_addresses)
        if params.target_address:
            raw_targets.append(params.target_address)
        if not raw_targets:
            return json.dumps({"error": "target_addresses o target_address requerido"})

        handle = _get_handle(params.pid)
        first_target = _parse_address_expression(raw_targets[0], params.pid)
        if params.module_name:
            module = _find_module(params.pid, params.module_name, None)
        elif params.scan_start:
            scan_start_for_module = _parse_address_expression(params.scan_start, params.pid)
            try:
                module = _find_module(params.pid, None, scan_start_for_module)
            except Exception:
                scan_end_for_module = _parse_address_expression(params.scan_end, params.pid) if params.scan_end else scan_start_for_module + 1
                module = {
                    "name": "manual",
                    "base": scan_start_for_module,
                    "base_hex": f"0x{scan_start_for_module:X}",
                    "size": max(1, scan_end_for_module - scan_start_for_module),
                    "size_hex": f"0x{max(1, scan_end_for_module - scan_start_for_module):X}",
                    "path": "",
                }
        else:
            module = _find_module(params.pid, None, first_target)
        module_base = int(module["base"])
        module_size = int(module["size"])

        resolved_targets: Dict[int, List[str]] = {}
        for raw in raw_targets:
            value = _parse_address_expression(raw, params.pid)
            # Si el usuario pasa 0x4630 con module_name, tratarlo como RVA.
            if params.module_name and 0 <= value < module_size:
                value = module_base + value
            resolved_targets.setdefault(value, []).append(raw)

        target_set = set(resolved_targets.keys())

        if params.scan_start or params.scan_end:
            if not (params.scan_start and params.scan_end):
                return json.dumps({"error": "scan_start y scan_end deben proporcionarse juntos"})
            start = _parse_address_expression(params.scan_start, params.pid)
            end = _parse_address_expression(params.scan_end, params.pid)
            if end <= start:
                return json.dumps({"error": "scan_end debe ser mayor que scan_start"})
            logical_regions = [{
                "name": "manual",
                "base": start,
                "base_hex": f"0x{start:X}",
                "rva": start - module_base,
                "rva_hex": f"0x{start - module_base:X}",
                "size": end - start,
                "size_hex": f"0x{end - start:X}",
            }]
            scan_regions = _clip_ranges_to_readable_regions(handle, logical_regions, module)
        else:
            try:
                sections = _module_code_sections(handle, module)
                using_pe_sections = True
            except Exception:
                sections = _module_executable_regions(handle, module)
                using_pe_sections = False
            wanted_sections = {name.lower() for name in params.section_names}
            if using_pe_sections or wanted_sections != {".text"}:
                selected_regions = [
                    section for section in sections
                    if not wanted_sections or section["name"].lower() in wanted_sections
                ]
            else:
                selected_regions = sections
            scan_regions = _clip_ranges_to_readable_regions(handle, selected_regions, module)
            if not scan_regions:
                return json.dumps({
                    "error": "no_sections_selected",
                    "module": module["name"],
                    "requested_sections": params.section_names,
                    "available_sections": [
                        {
                            "name": section["name"],
                            "base": section["base_hex"],
                            "size": section["size_hex"],
                            "executable": section.get("executable"),
                            "code": section.get("code"),
                        }
                        for section in sections
                    ],
                    "hint": "Las secciones existen, pero ninguna se solapo con regiones legibles de VirtualQueryEx. Prueba scan_start/scan_end o revisa permisos/admin.",
                }, indent=2, ensure_ascii=False)

        preflight = _too_expensive_scan_response(
            "mem_find_callers",
            scan_regions,
            params.max_scan_mb,
            "Caller scan lee codigo y filtra E8 rel32 matematicamente. Acota con module_name/section_names/rango o sube max_scan_mb.",
        )
        if preflight:
            return preflight

        results: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {f"0x{target:X}": 0 for target in target_set}
        bytes_scanned = 0
        read_errors = 0
        read_error_details: List[Dict[str, Any]] = []
        chunk_size = params.chunk_mb * 1024 * 1024
        seen_sites = set()

        for region in scan_regions:
            region_base = int(region["base"])
            region_size = int(region["size"])
            cursor = 0
            while cursor < region_size:
                if len(results) >= params.max_results:
                    break
                read_size = min(chunk_size + 6, region_size - cursor)
                read_addr = region_base + cursor
                try:
                    data = _read_bytes(handle, read_addr, read_size)
                    bytes_scanned += len(data)
                except Exception as exc:
                    read_errors += 1
                    if len(read_error_details) < 20:
                        read_error_details.append({
                            "address": f"0x{read_addr:X}",
                            "size": read_size,
                            "region": region.get("name"),
                            "protect": region.get("protect"),
                            "error": str(exc),
                        })
                    cursor += min(chunk_size, region_size - cursor)
                    continue

                limit = max(0, len(data) - 5)
                for offset in range(limit + 1):
                    site = read_addr + offset
                    if site in seen_sites:
                        continue
                    opcode = data[offset]

                    if opcode == 0xE8 and offset + 5 <= len(data):
                        disp = struct.unpack_from("<i", data, offset + 1)[0]
                        next_ip = site + 5
                        target = next_ip + disp
                        if target in target_set:
                            seen_sites.add(site)
                            counts[f"0x{target:X}"] += 1
                            results.append({
                                "kind": "call_rel32",
                                "call_site": f"0x{site:X}",
                                "call_site_int": site,
                                "target": f"0x{target:X}",
                                "target_int": target,
                                "target_inputs": resolved_targets[target],
                                "next_ip": f"0x{next_ip:X}",
                                "disp32": disp,
                                "disp32_hex": f"0x{disp & 0xFFFFFFFF:X}",
                                "bytes": " ".join(f"{b:02X}" for b in data[offset:offset + 5]),
                                "module": module["name"],
                                "section": region.get("name"),
                                "rva": f"0x{site - module_base:X}",
                            })

                    if (
                        params.include_indirect_rip
                        and opcode == 0xFF
                        and offset + 6 <= len(data)
                        and data[offset + 1] == 0x15
                    ):
                        disp = struct.unpack_from("<i", data, offset + 2)[0]
                        next_ip = site + 6
                        slot = next_ip + disp
                        try:
                            ptr_data = _read_bytes(handle, slot, 8)
                            target = struct.unpack("<Q", ptr_data)[0]
                        except Exception:
                            target = None
                        if target in target_set:
                            seen_sites.add(site)
                            counts[f"0x{target:X}"] += 1
                            results.append({
                                "kind": "call_rip_indirect",
                                "call_site": f"0x{site:X}",
                                "call_site_int": site,
                                "target": f"0x{target:X}",
                                "target_int": target,
                                "target_inputs": resolved_targets[target],
                                "next_ip": f"0x{next_ip:X}",
                                "pointer_slot": f"0x{slot:X}",
                                "disp32": disp,
                                "disp32_hex": f"0x{disp & 0xFFFFFFFF:X}",
                                "bytes": " ".join(f"{b:02X}" for b in data[offset:offset + 6]),
                                "module": module["name"],
                                "section": region.get("name"),
                                "rva": f"0x{site - module_base:X}",
                            })

                    if len(results) >= params.max_results:
                        break

                cursor += min(chunk_size, region_size - cursor)
            if len(results) >= params.max_results:
                break

        results.sort(key=lambda item: item["call_site_int"])
        return json.dumps({
            "pid": params.pid,
            "module": {
                "name": module["name"],
                "base": module["base_hex"],
                "size": module["size_hex"],
            },
            "targets": [
                {"target": f"0x{target:X}", "inputs": inputs, "count": counts[f"0x{target:X}"]}
                for target, inputs in sorted(resolved_targets.items())
            ],
            "scan_regions": [
                {
                    "name": region.get("name"),
                    "base": region.get("base_hex", f"0x{int(region['base']):X}"),
                    "size": region.get("size_hex", f"0x{int(region['size']):X}"),
                    "rva": region.get("rva_hex"),
                    "protect": region.get("protect"),
                    "source_base": region.get("source_base"),
                    "source_size": region.get("source_size"),
                }
                for region in scan_regions
            ],
            "bytes_scanned": bytes_scanned,
            "bytes_scanned_mb": round(bytes_scanned / 1048576, 2),
            "read_errors": read_errors,
            "read_error_details": read_error_details,
            "result_count": len(results),
            "truncated": len(results) >= params.max_results,
            "results": results,
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return f"Error encontrando callers: {e}"
