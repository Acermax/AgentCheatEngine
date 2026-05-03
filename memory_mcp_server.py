#!/usr/bin/env python3
"""
MCP Server para lectura de memoria de procesos Windows.

Diseñado para exploración y reverse engineering de estructuras de datos
en procesos propios, laboratorios o apps con autorizacion. Usa Windows API (ReadProcessMemory,
VirtualQueryEx, etc.) via ctypes.

Requiere: Python 3.10+, mcp[cli], pydantic, psutil
Ejecutar como administrador para acceso completo a procesos.
"""

import ctypes
import ctypes.wintypes as wt
import json
import struct
import re
import sys
import os
import logging
import time
import uuid
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
from dataclasses import dataclass

import psutil
from pydantic import BaseModel, Field, ConfigDict
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging (stderr, nunca stdout — stdio transport)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[memory_mcp] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("memory_mcp")

# ---------------------------------------------------------------------------
# Windows API constants & types
# ---------------------------------------------------------------------------
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ALL_ACCESS = 0x001FFFFF
ERROR_PARTIAL_COPY = 299
DEFAULT_PAGE_SIZE = 0x1000

MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000

PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000

READABLE_PROTECTIONS = (
    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

# ctypes handles
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlbcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]

# Function prototypes
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]

kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]

kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]

kernel32.Module32First.restype = wt.BOOL
kernel32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]

kernel32.Module32Next.restype = wt.BOOL
kernel32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]

kernel32.WriteProcessMemory.restype = wt.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.VirtualProtectEx.restype = wt.BOOL
kernel32.VirtualProtectEx.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD),
]


# ---------------------------------------------------------------------------
# Low-level memory helpers
# ---------------------------------------------------------------------------

def _open_process(pid: int, access: int = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) -> wt.HANDLE:
    """Abre un handle al proceso. Caller debe cerrar con CloseHandle."""
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        raise PermissionError(
            f"No se pudo abrir el proceso PID {pid} (error {err}). "
            "¿Estás ejecutando como administrador?"
        )
    return handle


def _read_bytes(handle: wt.HANDLE, address: int, size: int) -> bytes:
    """Lee `size` bytes de `address` en el proceso."""
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read))
    if not ok:
        err = ctypes.get_last_error()
        raise MemoryError(f"ReadProcessMemory falló en 0x{address:X} size={size} (error {err})")
    return buf.raw[: bytes_read.value]


def _read_bytes_best_effort(handle: wt.HANDLE, address: int, size: int) -> Dict[str, Any]:
    """Lee memoria por paginas y devuelve datos parciales si una pagina falla."""
    chunks: List[bytes] = []
    segments: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    current = address
    remaining = size

    while remaining > 0:
        page_left = DEFAULT_PAGE_SIZE - (current & (DEFAULT_PAGE_SIZE - 1))
        request_size = min(remaining, page_left)
        buf = ctypes.create_string_buffer(request_size)
        bytes_read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(current),
            buf,
            request_size,
            ctypes.byref(bytes_read),
        )
        read_count = int(bytes_read.value)
        if ok or read_count > 0:
            if read_count > 0:
                chunks.append(buf.raw[:read_count])
                segments.append({
                    "address": f"0x{current:X}",
                    "size": read_count,
                    "requested": request_size,
                    "partial": (not ok) or read_count != request_size,
                })
                current += read_count
                remaining -= read_count
            if not ok or read_count != request_size:
                err = ctypes.get_last_error()
                errors.append({
                    "address": f"0x{current:X}",
                    "requested": request_size - read_count,
                    "error": err,
                    "error_name": "ERROR_PARTIAL_COPY" if err == ERROR_PARTIAL_COPY else None,
                })
                break
            continue

        err = ctypes.get_last_error()
        errors.append({
            "address": f"0x{current:X}",
            "requested": request_size,
            "error": err,
            "error_name": "ERROR_PARTIAL_COPY" if err == ERROR_PARTIAL_COPY else None,
        })
        break

    data = b"".join(chunks)
    return {
        "data": data,
        "bytes_read": len(data),
        "complete": len(data) == size,
        "segments": segments,
        "errors": errors,
    }


def _write_bytes(handle: wt.HANDLE, address: int, data: bytes, try_vprotect: bool = True) -> int:
    """Escribe bytes en `address` del proceso. Retorna bytes escritos."""
    size = len(data)
    buf = ctypes.create_string_buffer(data)
    buf_ptr = ctypes.cast(buf, ctypes.c_void_p)
    bytes_written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(handle, ctypes.c_void_p(address), buf_ptr, size, ctypes.byref(bytes_written))
    if not ok and try_vprotect:
        # Intenta cambiar proteccion y reintentar (usa pagina completa de 4096)
        old_protect = wt.DWORD(0)
        vp_ok = kernel32.VirtualProtectEx(
            handle, ctypes.c_void_p(address), 4096,
            PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
        )
        if not vp_ok:
            vp_err = ctypes.get_last_error()
            logger.debug(f"VirtualProtectEx failed at 0x{address:X} (error {vp_err})")
        if vp_ok:
            ok = kernel32.WriteProcessMemory(
                handle, ctypes.c_void_p(address), buf_ptr, size, ctypes.byref(bytes_written)
            )
    if not ok:
        err = ctypes.get_last_error()
        raise MemoryError(f"WriteProcessMemory falló en 0x{address:X} size={size} (error {err})")
    return bytes_written.value


def _get_modules(pid: int) -> List[Dict[str, Any]]:
    """Retorna lista de módulos cargados en el proceso."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == wt.HANDLE(-1).value or snap == 0xFFFFFFFF or snap == -1:
        raise OSError(f"CreateToolhelp32Snapshot falló para PID {pid}. ¿Ejecutando como admin?")

    modules = []
    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)

    try:
        if kernel32.Module32First(snap, ctypes.byref(me32)):
            while True:
                base = ctypes.cast(me32.modBaseAddr, ctypes.c_void_p).value or 0
                modules.append({
                    "name": me32.szModule.decode("utf-8", errors="replace"),
                    "base": base,
                    "base_hex": f"0x{base:X}",
                    "size": me32.modBaseSize,
                    "size_hex": f"0x{me32.modBaseSize:X}",
                    "path": me32.szExePath.decode("utf-8", errors="replace"),
                })
                if not kernel32.Module32Next(snap, ctypes.byref(me32)):
                    break
    finally:
        kernel32.CloseHandle(snap)

    return modules


def _find_module(pid: int, module_name: Optional[str] = None, address: Optional[int] = None) -> Dict[str, Any]:
    """Encuentra un modulo por nombre parcial o por direccion contenida."""
    modules = _get_modules(pid)
    if module_name:
        needle = module_name.lower()
        for module in modules:
            if needle == module["name"].lower() or needle == os.path.basename(module.get("path", "")).lower():
                return module
        for module in modules:
            if needle in module["name"].lower():
                return module
        raise ValueError(f"Modulo no encontrado: {module_name}")

    if address is not None:
        for module in modules:
            base = int(module["base"])
            size = int(module["size"])
            if base <= address < base + size:
                return module
        raise ValueError(f"No hay modulo que contenga 0x{address:X}")

    raise ValueError("Se requiere module_name o address")


def _module_code_sections(handle: wt.HANDLE, module: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Lee headers PE remotos y devuelve secciones ejecutables/de codigo."""
    base = int(module["base"])
    module_size = int(module["size"])
    header = _read_bytes(handle, base, min(0x1000, module_size))
    if len(header) < 0x40 or header[:2] != b"MZ":
        raise ValueError(f"Modulo sin cabecera MZ valida: {module.get('name')}")

    pe_off = struct.unpack_from("<I", header, 0x3C)[0]
    needed = pe_off + 0x18
    if needed > len(header):
        header = _read_bytes(handle, base, min(max(needed, 0x1000), module_size))
    if header[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError(f"Modulo sin firma PE valida: {module.get('name')}")

    number_of_sections = struct.unpack_from("<H", header, pe_off + 6)[0]
    size_of_optional_header = struct.unpack_from("<H", header, pe_off + 20)[0]
    section_table = pe_off + 24 + size_of_optional_header
    total_needed = section_table + number_of_sections * 40
    if total_needed > len(header):
        header = _read_bytes(handle, base, min(max(total_needed, 0x1000), module_size))

    sections = []
    for index in range(number_of_sections):
        off = section_table + index * 40
        raw_name = header[off:off + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", header, off + 8)[0]
        virtual_address = struct.unpack_from("<I", header, off + 12)[0]
        raw_size = struct.unpack_from("<I", header, off + 16)[0]
        characteristics = struct.unpack_from("<I", header, off + 36)[0]
        size = max(virtual_size, raw_size)
        if size <= 0:
            continue
        size = min(size, max(0, module_size - virtual_address))
        executable = bool(characteristics & IMAGE_SCN_MEM_EXECUTE)
        code = bool(characteristics & IMAGE_SCN_CNT_CODE)
        sections.append({
            "name": name,
            "base": base + virtual_address,
            "base_hex": f"0x{base + virtual_address:X}",
            "rva": virtual_address,
            "rva_hex": f"0x{virtual_address:X}",
            "size": size,
            "size_hex": f"0x{size:X}",
            "characteristics": f"0x{characteristics:X}",
            "executable": executable,
            "code": code,
        })
    return [section for section in sections if section["executable"] or section["code"]]


def _module_executable_regions(handle: wt.HANDLE, module: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fallback: regiones VirtualQueryEx ejecutables dentro de un modulo."""
    base = int(module["base"])
    end = base + int(module["size"])
    regions = []
    for region in _memory_regions(handle, readable_only=True):
        rbase = int(region["base"])
        rsize = int(region["size"])
        if rbase + rsize <= base or rbase >= end:
            continue
        if "E" not in str(region.get("protect", "")):
            continue
        start = max(base, rbase)
        stop = min(end, rbase + rsize)
        if stop > start:
            regions.append({
                "name": region.get("protect", "exec"),
                "base": start,
                "base_hex": f"0x{start:X}",
                "rva": start - base,
                "rva_hex": f"0x{start - base:X}",
                "size": stop - start,
                "size_hex": f"0x{stop - start:X}",
                "executable": True,
                "code": False,
            })
    return regions


def _protection_str(protect: int) -> str:
    """Convierte flags de protección a string legible."""
    flags = []
    if protect & PAGE_EXECUTE_READWRITE:
        flags.append("ERW")
    elif protect & PAGE_EXECUTE_READ:
        flags.append("ER")
    elif protect & PAGE_EXECUTE_WRITECOPY:
        flags.append("EWC")
    elif protect & PAGE_EXECUTE:
        flags.append("E")
    elif protect & PAGE_READWRITE:
        flags.append("RW")
    elif protect & PAGE_READONLY:
        flags.append("R")
    elif protect & PAGE_WRITECOPY:
        flags.append("WC")
    elif protect & PAGE_NOACCESS:
        flags.append("NA")
    if protect & PAGE_GUARD:
        flags.append("GUARD")
    return "|".join(flags) if flags else f"0x{protect:X}"


def _memory_regions(handle: wt.HANDLE, readable_only: bool = True) -> List[Dict[str, Any]]:
    """Enumera regiones de memoria del proceso."""
    regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while True:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
        if result == 0:
            break

        if mbi.State == MEM_COMMIT:
            is_readable = bool(mbi.Protect & READABLE_PROTECTIONS) and not (mbi.Protect & PAGE_GUARD)
            if not readable_only or is_readable:
                regions.append({
                    "base": mbi.BaseAddress,
                    "base_hex": f"0x{mbi.BaseAddress:X}",
                    "size": mbi.RegionSize,
                    "size_hex": f"0x{mbi.RegionSize:X}",
                    "protect": _protection_str(mbi.Protect),
                    "readable": is_readable,
                })

        address = (mbi.BaseAddress or 0) + mbi.RegionSize
        if address >= 0x7FFFFFFFFFFF:  # límite usermode x64
            break

    return regions


def _format_hex_dump(data: bytes, base_addr: int, bytes_per_line: int = 16) -> str:
    """Formatea bytes como hex dump clásico con ASCII."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        addr = base_addr + i
        lines.append(f"0x{addr:012X}  {hex_part:<{bytes_per_line * 3}}  {ascii_part}")
    return "\n".join(lines)


def _interpret_bytes(data: bytes, base_addr: int) -> Dict[str, Any]:
    """Interpreta bytes como distintos tipos de datos comunes."""
    result = {}
    if len(data) >= 1:
        result["u8"] = struct.unpack_from("<B", data)[0]
        result["i8"] = struct.unpack_from("<b", data)[0]
    if len(data) >= 2:
        result["u16"] = struct.unpack_from("<H", data)[0]
        result["i16"] = struct.unpack_from("<h", data)[0]
    if len(data) >= 4:
        result["u32"] = struct.unpack_from("<I", data)[0]
        result["i32"] = struct.unpack_from("<i", data)[0]
        result["f32"] = round(struct.unpack_from("<f", data)[0], 6)
        result["ptr32"] = f"0x{struct.unpack_from('<I', data)[0]:08X}"
    if len(data) >= 8:
        result["u64"] = struct.unpack_from("<Q", data)[0]
        result["i64"] = struct.unpack_from("<q", data)[0]
        result["f64"] = round(struct.unpack_from("<d", data)[0], 6)
        result["ptr64"] = f"0x{struct.unpack_from('<Q', data)[0]:016X}"

    # Intentar leer como string UTF-8 y UTF-16
    try:
        null_idx = data.index(0)
        if null_idx > 0:
            result["string_utf8"] = data[:null_idx].decode("utf-8", errors="replace")
    except ValueError:
        result["string_utf8"] = data.decode("utf-8", errors="replace")

    try:
        txt16 = data.decode("utf-16-le", errors="replace")
        null_idx = txt16.find("\x00")
        if null_idx > 0:
            result["string_utf16"] = txt16[:null_idx]
    except Exception:
        pass

    return result


def _parse_address(addr_str: str) -> int:
    """Parsea una direccion numerica en formato decimal o hexadecimal."""
    value = str(addr_str).strip().replace("_", "")
    if not value:
        raise ValueError("Direccion vacia")
    if value.lower().startswith(("+0x", "-0x", "0x")):
        return int(value, 16)
    body = value[1:] if value[:1] in ("+", "-") else value
    if any(c in body.upper() for c in "ABCDEF"):
        return int(value, 16)
    return int(value, 10)


def _resolve_address_atom(atom: str, pid: Optional[int] = None) -> int:
    """Resuelve un atomo de direccion: numero o nombre de modulo."""
    atom = atom.strip()
    try:
        return _parse_address(atom)
    except ValueError:
        pass

    if pid is None:
        raise ValueError(f"'{atom}' no es una direccion numerica y no hay PID para resolver modulos")

    needle = atom.lower()
    modules = _get_modules(pid)
    for module in modules:
        name = module["name"].lower()
        path_name = os.path.basename(module.get("path", "")).lower()
        if needle == name or needle == path_name:
            return int(module["base"])
    for module in modules:
        if needle in module["name"].lower():
            return int(module["base"])
    raise ValueError(f"Modulo no encontrado en PID {pid}: {atom}")


def _parse_address_expression(expr: str, pid: Optional[int] = None) -> int:
    """
    Resuelve direcciones numericas y expresiones simples:
      0x7FF600001000
      140000000
      DemoApp.exe+0x39310D8
      DemoApp.exe+0x414F6D0+0x4
      kernel32.dll-0x20
    """
    text = str(expr).strip()
    try:
        return _parse_address(text)
    except ValueError:
        pass

    terms: List[Tuple[str, int]] = []
    base_text = text
    term_re = re.compile(r"^(.+)([+-])\s*((?:0x[0-9A-Fa-f]+)|(?:\d+))\s*$")
    while True:
        match = term_re.match(base_text)
        if not match:
            break
        base_text = match.group(1).strip()
        terms.append((match.group(2), _parse_address(match.group(3).strip())))

    base = _resolve_address_atom(base_text, pid)
    for sign, offset in reversed(terms):
        base = base + offset if sign == "+" else base - offset
    return base


NUMERIC_TYPE_FORMATS: Dict[str, Tuple[str, int]] = {
    "u8": ("<B", 1), "i8": ("<b", 1),
    "u16": ("<H", 2), "i16": ("<h", 2),
    "u32": ("<I", 4), "i32": ("<i", 4), "f32": ("<f", 4), "ptr32": ("<I", 4),
    "u64": ("<Q", 8), "i64": ("<q", 8), "f64": ("<d", 8), "ptr64": ("<Q", 8),
}


def _read_typed_value(handle: wt.HANDLE, address: int, value_type: str, size: int = 0) -> Any:
    """Lee e interpreta un valor tipado desde memoria."""
    vtype = value_type.lower()
    if vtype in NUMERIC_TYPE_FORMATS:
        fmt, type_size = NUMERIC_TYPE_FORMATS[vtype]
        raw = _read_bytes(handle, address, type_size)
        value = struct.unpack(fmt, raw)[0]
        if vtype.startswith("ptr"):
            return f"0x{value:X}"
        if vtype in ("f32", "f64"):
            return round(float(value), 8)
        return value
    if vtype == "utf8":
        raw = _read_bytes(handle, address, size or 64)
        end = raw.find(b"\x00")
        return raw[:end if end >= 0 else len(raw)].decode("utf-8", errors="replace")
    if vtype == "utf16":
        raw = _read_bytes(handle, address, size or 128)
        text = raw.decode("utf-16-le", errors="replace")
        end = text.find("\x00")
        return text[:end] if end >= 0 else text
    if vtype == "bytes":
        raw = _read_bytes(handle, address, size or 16)
        return " ".join(f"{b:02X}" for b in raw)
    raise ValueError(f"Tipo no soportado: {value_type}")


def _read_numeric_value(handle: wt.HANDLE, address: int, value_type: str) -> Any:
    """Lee un valor numerico crudo, sin formatear punteros como string."""
    vtype = value_type.lower()
    if vtype not in NUMERIC_TYPE_FORMATS:
        raise ValueError(f"Tipo numerico no soportado: {value_type}")
    fmt, type_size = NUMERIC_TYPE_FORMATS[vtype]
    raw = _read_bytes(handle, address, type_size)
    return struct.unpack(fmt, raw)[0]


def _coerce_scan_value(value: str, value_type: str) -> Any:
    """Convierte un valor textual al tipo numerico usado por los escaneos."""
    vtype = value_type.lower()
    if vtype not in NUMERIC_TYPE_FORMATS:
        raise ValueError(f"Tipo numerico no soportado: {value_type}")
    if vtype.startswith("f"):
        return float(value)
    return int(str(value), 0)


def _numeric_equal(left: Any, right: Any, value_type: str, tolerance: float = 0.0) -> bool:
    if value_type.lower().startswith("f"):
        return abs(float(left) - float(right)) <= tolerance
    return int(left) == int(right)


def _resolve_pointer_offsets(
    handle: wt.HANDLE,
    base_address: int,
    offsets: List[str],
    pointer_type: str = "ptr64",
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Resuelve una cadena estilo Cheat Engine.
    Todos los offsets salvo el ultimo se derreferencian; el ultimo define la direccion final.
    """
    current = base_address
    log: List[Dict[str, Any]] = [{"step": "base", "address": f"0x{current:X}"}]
    if not offsets:
        return current, log

    ptr_fmt, ptr_size = NUMERIC_TYPE_FORMATS[pointer_type]
    for idx, off_text in enumerate(offsets):
        offset = _parse_address(off_text)
        target = current + offset
        if idx == len(offsets) - 1:
            log.append({"step": idx + 1, "final_address": f"0x{target:X}", "offset": f"0x{offset:X}"})
            return target, log
        raw = _read_bytes(handle, target, ptr_size)
        current = struct.unpack(ptr_fmt, raw)[0]
        log.append({
            "step": idx + 1,
            "deref_at": f"0x{target:X}",
            "offset": f"0x{offset:X}",
            "value_read": f"0x{current:X}",
        })
        if current == 0:
            raise MemoryError(f"NULL pointer en paso {idx + 1}")

    return current, log


def _parse_pattern(pattern_str: str) -> Tuple[bytes, bytes]:
    """
    Parsea un AOB pattern como 'A1 ?? B2 4? ?F DD' a (bytes, mask).

    Wildcards:
    - ?? o ? = byte completo variable
    - 4? = nibble alto fijo, nibble bajo variable
    - ?F = nibble alto variable, nibble bajo fijo

    Retorna (pattern_bytes, mask_bytes), donde la mascara indica que bits
    deben compararse.
    """
    tokens = pattern_str.strip().split()
    if not tokens:
        raise ValueError("Patron AOB vacio")

    pattern = bytearray()
    mask = bytearray()
    for t in tokens:
        if t == "??" or t == "?":
            pattern.append(0)
            mask.append(0)
        elif re.fullmatch(r"[0-9A-Fa-f]\?", t):
            pattern.append(int(t[0], 16) << 4)
            mask.append(0xF0)
        elif re.fullmatch(r"\?[0-9A-Fa-f]", t):
            pattern.append(int(t[1], 16))
            mask.append(0x0F)
        else:
            if "?" in t:
                raise ValueError(
                    f"Wildcard AOB invalido en token {t!r}. Usa bytes hex, '?', '??', '4?' o '?F'."
                )
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", t):
                raise ValueError(f"Token AOB invalido {t!r}. Usa bytes hex de 2 digitos, '?', '??', '4?' o '?F'.")
            pattern.append(int(t, 16))
            mask.append(0xFF)
    return bytes(pattern), bytes(mask)


def _aob_search(data: bytes, pattern: bytes, mask: bytes, max_results: Optional[int] = None) -> List[int]:
    """Busca un pattern AOB con wildcards en data. Retorna offsets."""
    results = []
    plen = len(pattern)
    if plen == 0 or plen > len(data):
        return results

    if all(m == 0xFF for m in mask):
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx < 0:
                break
            results.append(idx)
            if max_results is not None and len(results) >= max_results:
                break
            offset = idx + 1
        return results

    for i in range(len(data) - plen + 1):
        found = True
        for j in range(plen):
            if mask[j] != 0 and (data[i + j] & mask[j]) != pattern[j]:
                found = False
                break
        if found:
            results.append(i)
            if max_results is not None and len(results) >= max_results:
                break
    return results


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP("memory_mcp")

# Cache de handles abiertos (PID → handle)
_open_handles: Dict[int, wt.HANDLE] = {}
_scan_sessions: Dict[str, Dict[str, Any]] = {}
_file_jobs: Dict[str, Dict[str, Any]] = {}
MAX_SCAN_CANDIDATES = 200_000
DEFAULT_SCAN_CHUNK_SIZE = 8 * 1024 * 1024
DEFAULT_MAX_SCAN_MB = 256
DEFAULT_MAX_TOOL_SECONDS = 30
DEFAULT_JOB_MAX_SCAN_MB = 8192
SCAN_JOBS_DIR = Path(__file__).resolve().parent / "artifacts" / "scan_jobs"


def _get_handle(pid: int) -> wt.HANDLE:
    """Obtiene o abre un handle al proceso."""
    if pid in _open_handles:
        return _open_handles[pid]
    h = _open_process(pid)
    _open_handles[pid] = h
    return h


def _scan_regions(
    pid: int,
    handle: wt.HANDLE,
    module_name: Optional[str] = None,
    region_start: Optional[str] = None,
    region_end: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Construye la lista de regiones legibles que participaran en un escaneo."""
    regions = []

    if module_name:
        matches = [m for m in _get_modules(pid) if module_name.lower() in m["name"].lower()]
        if not matches:
            raise ValueError(f"Modulo no encontrado: {module_name}")

        readable_regions = _memory_regions(handle, readable_only=True)
        requested_start = _parse_address_expression(region_start, pid) if region_start else None
        requested_end = _parse_address_expression(region_end, pid) if region_end else None

        for module in matches:
            module_base = int(module["base"])
            module_end = module_base + int(module["size"])
            start = max(module_base, requested_start) if requested_start is not None else module_base
            end = min(module_end, requested_end) if requested_end is not None else module_end
            if end <= start:
                continue

            for region in readable_regions:
                base = int(region["base"])
                size = int(region["size"])
                if base + size <= start or base >= end:
                    continue
                clipped_start = max(base, start)
                clipped_end = min(base + size, end)
                if clipped_end > clipped_start:
                    regions.append({
                        "base": clipped_start,
                        "size": clipped_end - clipped_start,
                        "source": module["name"],
                        "module": module["name"],
                        "module_base": module.get("base_hex", f"0x{module_base:X}"),
                        "module_rva": f"0x{clipped_start - module_base:X}",
                        "protect": region.get("protect", "memory"),
                    })
        return regions

    start = _parse_address_expression(region_start, pid) if region_start else 0
    end = _parse_address_expression(region_end, pid) if region_end else 0x7FFFFFFFFFFF
    for region in _memory_regions(handle, readable_only=True):
        base = int(region["base"])
        size = int(region["size"])
        if base + size <= start or base >= end:
            continue
        clipped_start = max(base, start)
        clipped_end = min(base + size, end)
        if clipped_end > clipped_start:
            regions.append({
                "base": clipped_start,
                "size": clipped_end - clipped_start,
                "source": region.get("protect", "memory"),
            })
    return regions


def _initial_scan_match(value: Any, value_type: str, scan_mode: str, target: Any, lower: Any, upper: Any, tolerance: float) -> bool:
    if scan_mode == "unknown":
        return True
    if scan_mode == "exact":
        return _numeric_equal(value, target, value_type, tolerance)
    if scan_mode == "range":
        return lower <= value <= upper
    raise ValueError(f"scan_mode no soportado: {scan_mode}")


def _next_scan_match(current: Any, previous: Any, value_type: str, op: str, target: Any, lower: Any, upper: Any, tolerance: float) -> bool:
    op = op.lower()
    if op in ("eq", "eq_value"):
        return _numeric_equal(current, target, value_type, tolerance)
    if op in ("ne", "ne_value"):
        return not _numeric_equal(current, target, value_type, tolerance)
    if op in ("lt", "lt_value"):
        return current < target
    if op in ("le", "le_value"):
        return current <= target
    if op in ("gt", "gt_value"):
        return current > target
    if op in ("ge", "ge_value"):
        return current >= target
    if op == "between":
        return lower <= current <= upper
    if op == "not_between":
        return not (lower <= current <= upper)
    if op in ("changed", "ne_prev"):
        return not _numeric_equal(current, previous, value_type, tolerance)
    if op in ("unchanged", "eq_prev"):
        return _numeric_equal(current, previous, value_type, tolerance)
    if op in ("increased", "gt_prev"):
        return current > previous
    if op in ("decreased", "lt_prev"):
        return current < previous
    raise ValueError(f"op no soportado: {op}")


def _scan_numeric_candidates(
    handle: wt.HANDLE,
    regions: List[Dict[str, Any]],
    value_type: str,
    scan_mode: str,
    target: Any,
    lower: Any,
    upper: Any,
    tolerance: float,
    alignment: int,
    chunk_size: int,
    max_candidates: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Escanea regiones y devuelve candidatos con valor inicial/anterior."""
    vtype = value_type.lower()
    fmt, type_size = NUMERIC_TYPE_FORMATS[vtype]
    step = alignment or type_size
    candidates: List[Dict[str, Any]] = []
    stats = {"regions_seen": len(regions), "regions_read": 0, "bytes_scanned": 0, "read_errors": 0, "truncated": False}

    for region in regions:
        region_base = int(region["base"])
        region_size = int(region["size"])
        cursor = 0
        while cursor < region_size:
            read_size = min(chunk_size, region_size - cursor)
            read_addr = region_base + cursor
            try:
                data = _read_bytes(handle, read_addr, read_size)
                stats["regions_read"] += 1
                stats["bytes_scanned"] += len(data)
            except Exception:
                stats["read_errors"] += 1
                cursor += read_size
                continue

            max_offset = len(data) - type_size
            for offset in range(0, max_offset + 1, step):
                try:
                    value = struct.unpack_from(fmt, data, offset)[0]
                except struct.error:
                    continue
                if _initial_scan_match(value, vtype, scan_mode, target, lower, upper, tolerance):
                    address = read_addr + offset
                    candidates.append({"address": address, "initial": value, "previous": value})
                    if len(candidates) >= max_candidates:
                        stats["truncated"] = True
                        return candidates, stats
            cursor += read_size

    return candidates, stats


def _regions_total_bytes(regions: List[Dict[str, Any]]) -> int:
    return sum(int(region["size"]) for region in regions)


def _too_expensive_scan_response(
    operation: str,
    regions: List[Dict[str, Any]],
    max_scan_mb: int,
    hint: str,
) -> Optional[str]:
    total_bytes = _regions_total_bytes(regions)
    total_mb = total_bytes / 1048576
    if total_mb <= max_scan_mb:
        return None
    return json.dumps({
        "error": "scan_too_broad",
        "operation": operation,
        "estimated_scan_mb": round(total_mb, 1),
        "max_scan_mb": max_scan_mb,
        "region_count": len(regions),
        "hint": hint,
        "examples": [
            {"module_name": "DemoApp.exe"},
            {"region_start": "DemoApp.exe+0x1000", "region_end": "DemoApp.exe+0x200000"},
            {"max_scan_mb": int(total_mb) + 1},
        ],
    }, indent=2, ensure_ascii=False)


def _job_paths(job_id: str) -> Dict[str, Path]:
    if not re.match(r"^[a-f0-9]{12}$", job_id):
        raise ValueError(f"job_id invalido: {job_id}")
    job_dir = SCAN_JOBS_DIR / job_id
    return {
        "dir": job_dir,
        "status": job_dir / "status.json",
        "results": job_dir / "results.jsonl",
        "meta": job_dir / "meta.json",
        "cancel": job_dir / "cancel.flag",
    }


def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    last_error: Optional[Exception] = None
    for _ in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.05)
    try:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.unlink(missing_ok=True)
    except Exception:
        if last_error:
            raise last_error
        raise


def _read_json_file(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _aob_scan_file_worker(
    job_id: str,
    pid: int,
    pattern_text: str,
    pattern: bytes,
    mask: bytes,
    regions: List[Dict[str, Any]],
    max_results: int,
    context_bytes: int,
) -> None:
    paths = _job_paths(job_id)
    cancel_event = _file_jobs.get(job_id, {}).get("cancel_event")
    started = time.time()
    status: Dict[str, Any] = {
        "job_id": job_id,
        "operation": "mem_aob_scan_file",
        "state": "running",
        "pid": pid,
        "pattern": pattern_text,
        "region_count": len(regions),
        "estimated_scan_mb": round(_regions_total_bytes(regions) / 1048576, 1),
        "regions_done": 0,
        "bytes_scanned": 0,
        "bytes_scanned_mb": 0.0,
        "results_found": 0,
        "read_errors": 0,
        "started_at": started,
        "updated_at": started,
        "results_path": str(paths["results"]),
        "status_path": str(paths["status"]),
    }
    _write_json_atomic(paths["status"], status)

    handle = None
    try:
        handle = _open_process(pid)
        paths["results"].parent.mkdir(parents=True, exist_ok=True)
        with paths["results"].open("w", encoding="utf-8") as out:
            for index, region in enumerate(regions):
                if (cancel_event is not None and cancel_event.is_set()) or paths["cancel"].exists():
                    status["state"] = "cancelled"
                    break
                if status["results_found"] >= max_results:
                    status["state"] = "completed"
                    break

                base = int(region["base"])
                size = int(region["size"])
                try:
                    data = _read_bytes(handle, base, size)
                except Exception as exc:
                    status["read_errors"] += 1
                    status["last_error"] = str(exc)
                    status["regions_done"] = index + 1
                    status["updated_at"] = time.time()
                    _write_json_atomic(paths["status"], status)
                    continue

                remaining = max_results - int(status["results_found"])
                offsets = _aob_search(data, pattern, mask, max_results=remaining)
                for off in offsets:
                    addr = base + off
                    context = data[off:off + max(len(pattern) + context_bytes, len(pattern))]
                    out.write(json.dumps({
                        "address": f"0x{addr:X}",
                        "address_int": addr,
                        "region_base": f"0x{base:X}",
                        "offset_in_region": f"0x{off:X}",
                        "context": " ".join(f"{b:02X}" for b in context),
                    }, ensure_ascii=False) + "\n")
                out.flush()

                status["results_found"] += len(offsets)
                status["bytes_scanned"] += len(data)
                status["bytes_scanned_mb"] = round(status["bytes_scanned"] / 1048576, 1)
                status["regions_done"] = index + 1
                status["updated_at"] = time.time()
                _write_json_atomic(paths["status"], status)

            if status["state"] == "running":
                status["state"] = "completed"
    except Exception as exc:
        status["state"] = "failed"
        status["error"] = str(exc)
    finally:
        if handle:
            kernel32.CloseHandle(handle)
        status["finished_at"] = time.time()
        status["elapsed_sec"] = round(status["finished_at"] - started, 3)
        status["updated_at"] = status["finished_at"]
        _write_json_atomic(paths["status"], status)
        if job_id in _file_jobs:
            _file_jobs[job_id]["state"] = status["state"]


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
            scan_regions = [{
                "name": "manual",
                "base": start,
                "base_hex": f"0x{start:X}",
                "rva": start - module_base,
                "rva_hex": f"0x{start - module_base:X}",
                "size": end - start,
                "size_hex": f"0x{end - start:X}",
            }]
        else:
            try:
                sections = _module_code_sections(handle, module)
            except Exception:
                sections = _module_executable_regions(handle, module)
            wanted_sections = {name.lower() for name in params.section_names}
            scan_regions = [
                section for section in sections
                if not wanted_sections or section["name"].lower() in wanted_sections
            ]
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
                except Exception:
                    read_errors += 1
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
                }
                for region in scan_regions
            ],
            "bytes_scanned_mb": round(bytes_scanned / 1048576, 2),
            "read_errors": read_errors,
            "result_count": len(results),
            "truncated": len(results) >= params.max_results,
            "results": results,
        }, indent=2, ensure_ascii=False)

    except Exception as e:
        return f"Error encontrando callers: {e}"


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
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
