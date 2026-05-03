"""Structured memory, pointer-chain, batch-read, and write tools."""

from ..runtime import *

# ---- Tool: Escribir memoria ----

class WriteMemoryInput(BaseModel):
    """Input para escribir en memoria."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    address: str = Field(..., description="Dirección de memoria en hex (0x...) o decimal")
    data: str = Field(..., description="Datos a escribir en hex (bytes separados por espacio o sin separador). Ej: 'B0 01 90 90' o 'B0019090'")
    vprotect: bool = Field(default=True, description="Si True, intenta VirtualProtectEx si el write falla (para regiones protegidas)")

@mcp.tool(
    name="mem_write",
    annotations={
        "title": "Escribir memoria",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_write(params: WriteMemoryInput) -> str:
    """Escribe bytes en la memoria de un proceso.

    Acepta datos en formato hex: 'B0 01 90 90' o 'B0019090'.
    Si vprotect=True, intenta cambiar la protección de la página antes de escribir.
    Útil para patchear funciones (ej: cambiar 'xor eax,eax;ret' a 'mov al,1;ret').
    """
    try:
        # Parse hex data
        hex_str = params.data.replace(" ", "").replace("\t", "").replace("\n", "")
        if len(hex_str) % 2 != 0:
            return f"Error: cadena hex de longitud impar ({len(hex_str)} chars)"
        data = bytes.fromhex(hex_str)

        addr = _parse_address_expression(params.address, params.pid)
        # Open with write access
        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            False, params.pid
        )
        if not handle:
            err = ctypes.get_last_error()
            return f"Error: no se pudo abrir proceso con acceso de escritura (error {err})"

        written = _write_bytes(handle, addr, data, try_vprotect=params.vprotect)
        kernel32.CloseHandle(handle)

        result = {
            "address": f"0x{addr:X}",
            "bytes_written": written,
            "data_hex": " ".join(f"{b:02X}" for b in data),
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error escribiendo memoria: {e}"


# ---- Tool: Leer estructura (múltiples campos) ----

class StructField(BaseModel):
    """Definición de un campo en una estructura."""
    name: str = Field(..., description="Nombre del campo")
    offset: str = Field(..., description="Offset desde la base en hex (0x...) o decimal")
    type: str = Field(
        default="u32",
        description="Tipo: u8, i8, u16, i16, u32, i32, u64, i64, f32, f64, ptr32, ptr64, utf8, utf16, bytes"
    )
    size: int = Field(
        default=0,
        description="Tamaño en bytes (solo necesario para tipos utf8, utf16, bytes). 0=autodetectar",
        ge=0, le=1024,
    )

class ReadStructInput(BaseModel):
    """Input para leer una estructura."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    base_address: str = Field(..., description="Dirección base de la estructura")
    fields: List[StructField] = Field(
        ...,
        description="Lista de campos a leer",
        min_length=1, max_length=50,
    )

@mcp.tool(
    name="mem_read_struct",
    annotations={
        "title": "Leer estructura de datos",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_read_struct(params: ReadStructInput) -> str:
    """Lee múltiples campos de una estructura de memoria de una sola vez.

    Muy útil cuando ya conoces (o sospechas) la disposición de una estructura.
    Ej: leer Unit struct con campos type(+0x00), txtfileno(+0x04), unit_id(+0x08),
    mode(+0x0C), pUnitData(+0x10), act_ptr(+0x20), path_ptr(+0x38), etc.

    Tipos soportados: u8, i8, u16, i16, u32, i32, u64, i64, f32, f64,
    ptr32, ptr64, utf8, utf16, bytes.
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
        base = _parse_address_expression(params.base_address, params.pid)
        handle = _get_handle(params.pid)
        results = {}

        for field in params.fields:
            offset = _parse_address(field.offset)
            addr = base + offset
            ftype = field.type.lower()

            try:
                if ftype in TYPE_SIZES:
                    sz = TYPE_SIZES[ftype]
                    data = _read_bytes(handle, addr, sz)
                    val = struct.unpack(TYPE_FORMATS[ftype], data)[0]
                    if "ptr" in ftype:
                        results[field.name] = f"0x{val:X}"
                    elif ftype == "f32":
                        results[field.name] = round(val, 6)
                    elif ftype == "f64":
                        results[field.name] = round(val, 10)
                    else:
                        results[field.name] = val

                elif ftype == "utf8":
                    sz = field.size if field.size > 0 else 64
                    data = _read_bytes(handle, addr, sz)
                    null_idx = data.find(b"\x00")
                    txt = data[:null_idx] if null_idx >= 0 else data
                    results[field.name] = txt.decode("utf-8", errors="replace")

                elif ftype == "utf16":
                    sz = field.size if field.size > 0 else 128
                    data = _read_bytes(handle, addr, sz)
                    txt = data.decode("utf-16-le", errors="replace")
                    null_idx = txt.find("\x00")
                    results[field.name] = txt[:null_idx] if null_idx >= 0 else txt

                elif ftype == "bytes":
                    sz = field.size if field.size > 0 else 16
                    data = _read_bytes(handle, addr, sz)
                    results[field.name] = " ".join(f"{b:02X}" for b in data)

                else:
                    results[field.name] = f"[tipo desconocido: {ftype}]"

            except Exception as e:
                results[field.name] = f"[error: {e}]"

        return json.dumps({
            "base": f"0x{base:X}",
            "fields": results,
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return f"Error leyendo estructura: {e}"


# ---- Tool: Seguir cadena de punteros ----

class FollowPointersInput(BaseModel):
    """Input para seguir una cadena de punteros."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    base_address: str = Field(
        ...,
        description="Dirección base inicial (puede ser un RVA, se suma a module_base si se proporciona)"
    )
    offsets: List[str] = Field(
        ...,
        description="Lista de offsets para derreferenciar. Ej: ['0x20', '0x70', '0x860'] para Unit→Act→ActMisc→seed",
        min_length=1, max_length=20,
    )
    module_base: Optional[str] = Field(
        default=None,
        description="Base del módulo (si base_address es un RVA). Ej: '0x7FF6A0000000'"
    )
    read_size_at_end: int = Field(
        default=256,
        description="Bytes a leer en la dirección final (para inspeccionar la estructura destino)",
        ge=1, le=4096,
    )

@mcp.tool(
    name="mem_follow_pointers",
    annotations={
        "title": "Seguir cadena de punteros",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def mem_follow_pointers(params: FollowPointersInput) -> str:
    """Sigue una cadena de punteros derrefenciando en cada paso.

    Patron fundamental en reverse engineering de estructuras dinamicas.
    Ej: Root object -> +0x20 -> Context -> +0x70 -> Metadata -> +0x860 -> value

    Cada paso: lee un puntero de 8 bytes (x64) en [current + offset],
    el valor leído se convierte en la nueva dirección base.
    Al final, lee `read_size_at_end` bytes en la dirección resultante.

    Muestra cada paso intermedio con la dirección calculada y el puntero leído.
    """
    try:
        handle = _get_handle(params.pid)

        current = _parse_address_expression(params.base_address, params.pid)
        if params.module_base:
            current += _parse_address(params.module_base)

        chain_log = []
        chain_log.append({"step": "base", "address": f"0x{current:X}"})

        for i, off_str in enumerate(params.offsets):
            offset = _parse_address(off_str)
            read_addr = current + offset

            try:
                data = _read_bytes(handle, read_addr, 8)
                ptr_value = struct.unpack("<Q", data)[0]

                chain_log.append({
                    "step": i + 1,
                    "deref_at": f"0x{read_addr:X} (0x{current:X} + 0x{offset:X})",
                    "value_read": f"0x{ptr_value:X}",
                })

                # El último offset no se dereferencia como puntero (es el valor final)
                if i < len(params.offsets) - 1:
                    if ptr_value == 0:
                        chain_log.append({"error": f"NULL pointer en paso {i + 1}!"})
                        return json.dumps({"chain": chain_log, "final_address": None}, indent=2)
                    current = ptr_value
                else:
                    # Último paso: current + offset es la dirección final
                    final_addr = read_addr

            except Exception as e:
                chain_log.append({"error": f"Fallo en paso {i + 1}: {e}"})
                return json.dumps({"chain": chain_log, "final_address": None}, indent=2)

        # Leer datos en la dirección final
        final_addr = current + _parse_address(params.offsets[-1])
        try:
            final_data = _read_bytes(handle, final_addr, params.read_size_at_end)
            return json.dumps({
                "chain": chain_log,
                "final_address": f"0x{final_addr:X}",
                "hex_dump": _format_hex_dump(final_data, final_addr),
                "interpreted": _interpret_bytes(final_data, final_addr),
            }, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({
                "chain": chain_log,
                "final_address": f"0x{final_addr:X}",
                "read_error": str(e),
            }, indent=2)

    except Exception as e:
        return f"Error siguiendo punteros: {e}"


# ---- Tool: Lectura batch tipada ----

class WatchItem(BaseModel):
    """Una lectura tipada para mem_watch_batch."""
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., description="Nombre logico del valor")
    address: str = Field(..., description="Direccion absoluta o expresion tipo modulo.exe+0xRVA")
    type: str = Field(default="u32", description="Tipo: u8/i8/u16/i16/u32/i32/u64/i64/f32/f64/ptr64/utf8/utf16/bytes")
    size: int = Field(default=0, description="Tamano para utf8/utf16/bytes. 0 usa default", ge=0, le=4096)
    pointer_offsets: List[str] = Field(
        default_factory=list,
        description="Cadena estilo Cheat Engine. Se derreferencian todos los offsets salvo el ultimo.",
        max_length=20,
    )
    pointer_type: str = Field(default="ptr64", description="ptr64 o ptr32")


class WatchBatchInput(BaseModel):
    """Input para leer varias direcciones tipadas de una vez."""
    model_config = ConfigDict(str_strip_whitespace=True)

    pid: int = Field(..., description="PID del proceso", ge=1)
    items: List[WatchItem] = Field(..., description="Lecturas a realizar", min_length=1, max_length=100)
    include_pointer_log: bool = Field(default=False, description="Incluye pasos de resolucion de punteros")


@mcp.tool(
    name="mem_watch_batch",
    annotations={
        "title": "Leer batch tipado",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def mem_watch_batch(params: WatchBatchInput) -> str:
    """Lee muchas direcciones tipadas en una sola llamada MCP.

    Pensado para agentes: agrupa lecturas repetidas de estado, resuelve expresiones
    tipo modulo+offset y cadenas de punteros, y devuelve JSON compacto por item.
    """
    try:
        handle = _get_handle(params.pid)
        results = []
        for item in params.items:
            record: Dict[str, Any] = {"name": item.name}
            try:
                base = _parse_address_expression(item.address, params.pid)
                final_address, pointer_log = _resolve_pointer_offsets(
                    handle,
                    base,
                    item.pointer_offsets,
                    pointer_type=item.pointer_type.lower(),
                )
                record["address"] = f"0x{final_address:X}"
                record["type"] = item.type.lower()
                record["value"] = _read_typed_value(handle, final_address, item.type, item.size)
                if params.include_pointer_log:
                    record["pointer_log"] = pointer_log
            except Exception as e:
                record["error"] = str(e)
            results.append(record)

        return json.dumps({"pid": params.pid, "count": len(results), "items": results}, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error en lectura batch: {e}"
