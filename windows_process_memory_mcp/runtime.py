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

THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040

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
TH32CS_SNAPTHREAD = 0x00000004

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_CONTROL_INTEGER = CONTEXT_CONTROL | CONTEXT_INTEGER

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
DEBUG_TIMEOUT_MS = 100
ERROR_SEM_TIMEOUT = 121

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

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

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri", wt.LONG),
        ("tpDeltaPri", wt.LONG),
        ("dwFlags", wt.DWORD),
    ]

class M128A(ctypes.Structure):
    _fields_ = [
        ("Low", ctypes.c_ulonglong),
        ("High", ctypes.c_longlong),
    ]

class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wt.WORD),
        ("StatusWord", wt.WORD),
        ("TagWord", wt.BYTE),
        ("Reserved1", wt.BYTE),
        ("ErrorOpcode", wt.WORD),
        ("ErrorOffset", wt.DWORD),
        ("ErrorSelector", wt.WORD),
        ("Reserved2", wt.WORD),
        ("DataOffset", wt.DWORD),
        ("DataSelector", wt.WORD),
        ("Reserved3", wt.WORD),
        ("MxCsr", wt.DWORD),
        ("MxCsr_Mask", wt.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", wt.BYTE * 96),
    ]

class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wt.DWORD),
        ("MxCsr", wt.DWORD),
        ("SegCs", wt.WORD),
        ("SegDs", wt.WORD),
        ("SegEs", wt.WORD),
        ("SegFs", wt.WORD),
        ("SegGs", wt.WORD),
        ("SegSs", wt.WORD),
        ("EFlags", wt.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]

class EXCEPTION_RECORD64(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wt.DWORD),
        ("ExceptionFlags", wt.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wt.DWORD),
        ("ExceptionInformation", ctypes.c_ulonglong * 15),
    ]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD64),
        ("dwFirstChance", wt.DWORD),
    ]

class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wt.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]

class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wt.HANDLE),
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wt.DWORD),
        ("nDebugInfoSize", wt.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wt.WORD),
    ]

class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wt.DWORD)]

class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wt.DWORD)]

class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wt.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wt.DWORD),
        ("nDebugInfoSize", wt.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wt.WORD),
    ]

class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]

class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", ctypes.c_void_p),
        ("fUnicode", wt.WORD),
        ("nDebugStringLength", wt.WORD),
    ]

class RIP_INFO(ctypes.Structure):
    _fields_ = [
        ("dwError", wt.DWORD),
        ("dwType", wt.DWORD),
    ]

class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wt.DWORD),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]

# Function prototypes
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

kernel32.OpenThread.restype = wt.HANDLE
kernel32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

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

kernel32.Thread32First.restype = wt.BOOL
kernel32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]

kernel32.Thread32Next.restype = wt.BOOL
kernel32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]

kernel32.SuspendThread.restype = wt.DWORD
kernel32.SuspendThread.argtypes = [wt.HANDLE]

kernel32.ResumeThread.restype = wt.DWORD
kernel32.ResumeThread.argtypes = [wt.HANDLE]

kernel32.GetThreadContext.restype = wt.BOOL
kernel32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT64)]

kernel32.SetThreadContext.restype = wt.BOOL
kernel32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT64)]

kernel32.GetCurrentThreadId.restype = wt.DWORD
kernel32.GetCurrentThreadId.argtypes = []

kernel32.DebugActiveProcess.restype = wt.BOOL
kernel32.DebugActiveProcess.argtypes = [wt.DWORD]

kernel32.DebugActiveProcessStop.restype = wt.BOOL
kernel32.DebugActiveProcessStop.argtypes = [wt.DWORD]

kernel32.DebugSetProcessKillOnExit.restype = wt.BOOL
kernel32.DebugSetProcessKillOnExit.argtypes = [wt.BOOL]

kernel32.WaitForDebugEvent.restype = wt.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wt.DWORD]

kernel32.ContinueDebugEvent.restype = wt.BOOL
kernel32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]

kernel32.FlushInstructionCache.restype = wt.BOOL
kernel32.FlushInstructionCache.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t]

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


def _get_threads(pid: int) -> List[Dict[str, Any]]:
    """Retorna threads pertenecientes al proceso."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == wt.HANDLE(-1).value or snap == 0xFFFFFFFF or snap == -1:
        raise OSError(f"CreateToolhelp32Snapshot fallo al enumerar threads para PID {pid}")

    threads = []
    te32 = THREADENTRY32()
    te32.dwSize = ctypes.sizeof(THREADENTRY32)

    try:
        if kernel32.Thread32First(snap, ctypes.byref(te32)):
            while True:
                if int(te32.th32OwnerProcessID) == pid:
                    threads.append({
                        "thread_id": int(te32.th32ThreadID),
                        "owner_pid": int(te32.th32OwnerProcessID),
                        "base_priority": int(te32.tpBasePri),
                        "delta_priority": int(te32.tpDeltaPri),
                        "flags": int(te32.dwFlags),
                    })
                if not kernel32.Thread32Next(snap, ctypes.byref(te32)):
                    break
    finally:
        kernel32.CloseHandle(snap)

    return threads


def _open_thread(thread_id: int, access: int = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION) -> wt.HANDLE:
    handle = kernel32.OpenThread(access, False, thread_id)
    if not handle:
        err = ctypes.get_last_error()
        raise PermissionError(f"No se pudo abrir thread {thread_id} (error {err})")
    return handle


def _get_thread_context64(thread_handle: wt.HANDLE) -> CONTEXT64:
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_CONTROL_INTEGER
    ok = kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx))
    if not ok:
        err = ctypes.get_last_error()
        raise OSError(f"GetThreadContext fallo (error {err})")
    return ctx


def _set_thread_context64(thread_handle: wt.HANDLE, ctx: CONTEXT64) -> None:
    ok = kernel32.SetThreadContext(thread_handle, ctypes.byref(ctx))
    if not ok:
        err = ctypes.get_last_error()
        raise OSError(f"SetThreadContext fallo (error {err})")


def _flush_instruction_cache(process_handle: wt.HANDLE, address: int, size: int = 1) -> None:
    kernel32.FlushInstructionCache(process_handle, ctypes.c_void_p(address), size)


def _debug_event_code_name(code: int) -> str:
    return {
        EXCEPTION_DEBUG_EVENT: "EXCEPTION_DEBUG_EVENT",
        CREATE_THREAD_DEBUG_EVENT: "CREATE_THREAD_DEBUG_EVENT",
        CREATE_PROCESS_DEBUG_EVENT: "CREATE_PROCESS_DEBUG_EVENT",
        EXIT_THREAD_DEBUG_EVENT: "EXIT_THREAD_DEBUG_EVENT",
        EXIT_PROCESS_DEBUG_EVENT: "EXIT_PROCESS_DEBUG_EVENT",
        LOAD_DLL_DEBUG_EVENT: "LOAD_DLL_DEBUG_EVENT",
        UNLOAD_DLL_DEBUG_EVENT: "UNLOAD_DLL_DEBUG_EVENT",
        OUTPUT_DEBUG_STRING_EVENT: "OUTPUT_DEBUG_STRING_EVENT",
        RIP_EVENT: "RIP_EVENT",
    }.get(code, f"UNKNOWN_{code}")


def _exception_code_name(code: int) -> str:
    return {
        EXCEPTION_BREAKPOINT: "EXCEPTION_BREAKPOINT",
        EXCEPTION_SINGLE_STEP: "EXCEPTION_SINGLE_STEP",
    }.get(code, f"0x{code:X}")


def _debug_continue_status(value: str) -> int:
    text = str(value or "AUTO").upper()
    if text == "AUTO":
        return -1
    if text in ("DBG_CONTINUE", "CONTINUE", "HANDLED"):
        return DBG_CONTINUE
    if text in ("DBG_EXCEPTION_NOT_HANDLED", "NOT_HANDLED"):
        return DBG_EXCEPTION_NOT_HANDLED
    return int(text, 0)


def _debug_continue_status_name(status: int) -> str:
    if status == DBG_CONTINUE:
        return "DBG_CONTINUE"
    if status == DBG_EXCEPTION_NOT_HANDLED:
        return "DBG_EXCEPTION_NOT_HANDLED"
    if status == -1:
        return "auto"
    return f"0x{status:X}"


def _debug_auto_continue_status(event_record: Dict[str, Any]) -> int:
    if event_record.get("event_code") != EXCEPTION_DEBUG_EVENT:
        return DBG_CONTINUE
    if event_record.get("breakpoint_id"):
        return DBG_CONTINUE
    exc = event_record.get("exception", {})
    if exc.get("first_chance"):
        return DBG_EXCEPTION_NOT_HANDLED
    return DBG_EXCEPTION_NOT_HANDLED


def _debug_is_second_chance_exception(event_record: Dict[str, Any]) -> bool:
    if event_record.get("event_code") != EXCEPTION_DEBUG_EVENT:
        return False
    if event_record.get("breakpoint_id"):
        return False
    exc = event_record.get("exception", {})
    return bool(exc) and not bool(exc.get("first_chance"))


def _debug_second_chance_guard_response(
    session_id: str,
    state: str,
    pending: Dict[str, Any],
    action: str,
    status: int,
) -> str:
    return json.dumps({
        "error": "pending_second_chance_exception",
        "session_id": session_id,
        "state": state,
        "action": action,
        "continued": False,
        "detached": False,
        "pending_event": pending,
        "continue_status": _debug_continue_status_name(status),
        "risk": (
            "Este evento es una excepcion second-chance ajena. "
            "DBG_EXCEPTION_NOT_HANDLED puede terminar el proceso; DBG_CONTINUE "
            "puede reejecutar la instruccion que fallo y dejar el proceso en bucle, "
            "colgado o crasheado si no se corrige RIP/memoria/contexto."
        ),
        "agent_instruction": (
            "No continues ni hagas detach automaticamente. Inspecciona el evento "
            "y pide confirmacion humana. Solo fuerza la operacion con "
            "allow_second_chance_continue=true si aceptas el riesgo para el proceso objetivo."
        ),
    }, indent=2, ensure_ascii=False)


def _debug_write_byte(session: Dict[str, Any], address: int, value: int) -> None:
    _write_bytes(session["process_handle"], address, bytes([value & 0xFF]), try_vprotect=True)
    _flush_instruction_cache(session["process_handle"], address, 1)


def _debug_restore_breakpoint(session: Dict[str, Any], breakpoint_id: str) -> None:
    bp = session["breakpoints"].get(breakpoint_id)
    if not bp or not bp.get("enabled"):
        return
    _debug_write_byte(session, int(bp["address"]), int(bp["original_byte"]))
    bp["enabled"] = False


def _debug_enable_breakpoint(session: Dict[str, Any], breakpoint_id: str) -> None:
    bp = session["breakpoints"].get(breakpoint_id)
    if not bp or bp.get("enabled"):
        return
    _debug_write_byte(session, int(bp["address"]), 0xCC)
    bp["enabled"] = True


def _debug_restore_all_breakpoints(session: Dict[str, Any]) -> None:
    for breakpoint_id in list(session.get("breakpoints", {}).keys()):
        try:
            _debug_restore_breakpoint(session, breakpoint_id)
        except Exception as exc:
            session.setdefault("cleanup_errors", []).append({
                "breakpoint_id": breakpoint_id,
                "error": str(exc),
            })


def _debug_find_breakpoint(session: Dict[str, Any], exception_address: int, thread_id: int) -> Tuple[Optional[str], Optional[int]]:
    candidates = [exception_address, exception_address - 1]
    try:
        th = _open_thread(thread_id, THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION)
        try:
            ctx = _get_thread_context64(th)
            candidates.append(int(ctx.Rip) - 1)
            candidates.append(int(ctx.Rip))
        finally:
            kernel32.CloseHandle(th)
    except Exception:
        pass

    for breakpoint_id, bp in session.get("breakpoints", {}).items():
        if not bp.get("enabled"):
            continue
        bp_addr = int(bp["address"])
        if bp_addr in candidates:
            return breakpoint_id, bp_addr
    return None, None


def _debug_close_event_handles(event: DEBUG_EVENT) -> None:
    code = int(event.dwDebugEventCode)
    handles: List[int] = []
    if code == CREATE_PROCESS_DEBUG_EVENT:
        info = event.u.CreateProcessInfo
        handles.extend([int(info.hFile or 0), int(info.hProcess or 0), int(info.hThread or 0)])
    elif code == CREATE_THREAD_DEBUG_EVENT:
        handles.append(int(event.u.CreateThread.hThread or 0))
    elif code == LOAD_DLL_DEBUG_EVENT:
        handles.append(int(event.u.LoadDll.hFile or 0))
    for handle in handles:
        if handle:
            kernel32.CloseHandle(wt.HANDLE(handle))


def _debug_build_event_record(session: Dict[str, Any], event: DEBUG_EVENT) -> Dict[str, Any]:
    event_id = session["next_event_id"]
    session["next_event_id"] += 1
    code = int(event.dwDebugEventCode)
    record: Dict[str, Any] = {
        "event_id": event_id,
        "session_id": session["session_id"],
        "pid": int(event.dwProcessId),
        "thread_id": int(event.dwThreadId),
        "event_code": code,
        "event": _debug_event_code_name(code),
        "time": time.time(),
    }

    if code == EXCEPTION_DEBUG_EVENT:
        exc = event.u.Exception
        exc_record = exc.ExceptionRecord
        exc_code = int(exc_record.ExceptionCode)
        exc_addr = int(exc_record.ExceptionAddress or 0)
        record["exception"] = {
            "code": f"0x{exc_code:X}",
            "name": _exception_code_name(exc_code),
            "first_chance": bool(exc.dwFirstChance),
            "address": f"0x{exc_addr:X}",
            "address_int": exc_addr,
        }
        if exc_code == EXCEPTION_BREAKPOINT:
            breakpoint_id, breakpoint_addr = _debug_find_breakpoint(session, exc_addr, int(event.dwThreadId))
            if breakpoint_id:
                record["breakpoint_id"] = breakpoint_id
                record["breakpoint_address"] = f"0x{breakpoint_addr:X}"
                record["kind"] = "software_breakpoint"
        elif exc_code == EXCEPTION_SINGLE_STEP:
            record["kind"] = "single_step"
    elif code == CREATE_PROCESS_DEBUG_EVENT:
        info = event.u.CreateProcessInfo
        record["create_process"] = {
            "base": f"0x{int(info.lpBaseOfImage or 0):X}",
            "start_address": f"0x{int(info.lpStartAddress or 0):X}",
            "thread_local_base": f"0x{int(info.lpThreadLocalBase or 0):X}",
        }
    elif code == CREATE_THREAD_DEBUG_EVENT:
        info = event.u.CreateThread
        record["create_thread"] = {
            "start_address": f"0x{int(info.lpStartAddress or 0):X}",
            "thread_local_base": f"0x{int(info.lpThreadLocalBase or 0):X}",
        }
    elif code == EXIT_THREAD_DEBUG_EVENT:
        record["exit_thread"] = {"exit_code": int(event.u.ExitThread.dwExitCode)}
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        record["exit_process"] = {"exit_code": int(event.u.ExitProcess.dwExitCode)}
    elif code == LOAD_DLL_DEBUG_EVENT:
        record["load_dll"] = {"base": f"0x{int(event.u.LoadDll.lpBaseOfDll or 0):X}"}
    elif code == UNLOAD_DLL_DEBUG_EVENT:
        record["unload_dll"] = {"base": f"0x{int(event.u.UnloadDll.lpBaseOfDll or 0):X}"}
    elif code == OUTPUT_DEBUG_STRING_EVENT:
        info = event.u.DebugString
        record["debug_string"] = {
            "address": f"0x{int(info.lpDebugStringData or 0):X}",
            "unicode": bool(info.fUnicode),
            "length": int(info.nDebugStringLength),
        }
    elif code == RIP_EVENT:
        record["rip_info"] = {
            "error": int(event.u.RipInfo.dwError),
            "type": int(event.u.RipInfo.dwType),
        }
    return record


def _debug_should_auto_continue(session: Dict[str, Any], record: Dict[str, Any]) -> Optional[int]:
    code = int(record["event_code"])
    if code != EXCEPTION_DEBUG_EVENT:
        return DBG_CONTINUE

    exc = record.get("exception", {})
    exc_name = exc.get("name")
    if exc_name == "EXCEPTION_SINGLE_STEP":
        pending = session.get("single_step_reinsert")
        if pending and int(pending.get("thread_id", 0)) == int(record["thread_id"]):
            try:
                _debug_enable_breakpoint(session, pending["breakpoint_id"])
            finally:
                session["single_step_reinsert"] = None
            return DBG_CONTINUE

    if exc_name == "EXCEPTION_BREAKPOINT":
        if record.get("breakpoint_id"):
            return None
        if not session.get("initial_breakpoint_seen"):
            session["initial_breakpoint_seen"] = True
            return DBG_CONTINUE
        if session.get("auto_continue_initial_events") and not session.get("breakpoints"):
            return DBG_CONTINUE

    if session.get("auto_continue_first_chance_exceptions") and record.get("exception", {}).get("first_chance"):
        return DBG_EXCEPTION_NOT_HANDLED

    return None


def _debug_prepare_continue(session: Dict[str, Any], event_record: Dict[str, Any], requested_status: int) -> int:
    breakpoint_id = event_record.get("breakpoint_id")
    if breakpoint_id:
        bp = session["breakpoints"].get(breakpoint_id)
        if bp:
            thread_handle = _open_thread(
                int(event_record["thread_id"]),
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
            )
            try:
                ctx = _get_thread_context64(thread_handle)
                bp_addr = int(bp["address"])
                if int(ctx.Rip) in (bp_addr + 1, bp_addr):
                    ctx.Rip = bp_addr
                ctx.EFlags = int(ctx.EFlags) | 0x100
                _debug_restore_breakpoint(session, breakpoint_id)
                _set_thread_context64(thread_handle, ctx)
                session["single_step_reinsert"] = {
                    "breakpoint_id": breakpoint_id,
                    "thread_id": int(event_record["thread_id"]),
                    "address": bp_addr,
                }
            finally:
                kernel32.CloseHandle(thread_handle)
        return DBG_CONTINUE
    return requested_status


def _debug_prepare_detach_continue(session: Dict[str, Any], event_record: Dict[str, Any], requested_status: int) -> int:
    breakpoint_id = event_record.get("breakpoint_id")
    if breakpoint_id:
        bp = session["breakpoints"].get(breakpoint_id)
        if bp:
            thread_handle = _open_thread(
                int(event_record["thread_id"]),
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
            )
            try:
                ctx = _get_thread_context64(thread_handle)
                bp_addr = int(bp["address"])
                if int(ctx.Rip) in (bp_addr + 1, bp_addr):
                    ctx.Rip = bp_addr
                ctx.EFlags = int(ctx.EFlags) & ~0x100
                _debug_restore_breakpoint(session, breakpoint_id)
                _set_thread_context64(thread_handle, ctx)
            finally:
                kernel32.CloseHandle(thread_handle)
        return DBG_CONTINUE

    _debug_restore_all_breakpoints(session)
    return requested_status


def _debug_session_worker(session: Dict[str, Any]) -> None:
    pid = int(session["pid"])
    attached = False
    try:
        process_handle = _open_process(
            pid,
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        )
        session["process_handle"] = process_handle

        if not kernel32.DebugActiveProcess(pid):
            err = ctypes.get_last_error()
            raise PermissionError(f"DebugActiveProcess fallo para PID {pid} (error {err})")
        attached = True
        session["state"] = "attached"
        kernel32.DebugSetProcessKillOnExit(False)
        session["attached_event"].set()

        while True:
            if session.get("stop_requested"):
                break

            event = DEBUG_EVENT()
            ok = kernel32.WaitForDebugEvent(ctypes.byref(event), DEBUG_TIMEOUT_MS)
            if not ok:
                err = ctypes.get_last_error()
                if err in (0, ERROR_SEM_TIMEOUT):
                    continue
                session.setdefault("worker_errors", []).append(f"WaitForDebugEvent error {err}")
                continue

            record = _debug_build_event_record(session, event)
            auto_status = _debug_should_auto_continue(session, record)
            if auto_status is not None:
                record["auto_continued"] = True
                session["history"].append(record)
                if len(session["history"]) > session["event_history_limit"]:
                    session["history"] = session["history"][-session["event_history_limit"]:]
                _debug_close_event_handles(event)
                kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, auto_status)
                continue

            with session["condition"]:
                session["pending_event"] = record
                session["events"].append(record)
                session["history"].append(record)
                if len(session["history"]) > session["event_history_limit"]:
                    session["history"] = session["history"][-session["event_history_limit"]:]
                session["condition"].notify_all()
                while session.get("continue_command") is None and not session.get("stop_requested"):
                    session["condition"].wait(0.1)
                command = session.get("continue_command")
                session["continue_command"] = None

            if session.get("stop_requested") or (command and command.get("action") == "detach"):
                requested_status = int(command.get("status", _debug_auto_continue_status(record))) if command else _debug_auto_continue_status(record)
                status = _debug_prepare_detach_continue(session, record, requested_status)
                _debug_close_event_handles(event)
                kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status)
                break

            status = _debug_prepare_continue(session, record, int(command.get("status", DBG_CONTINUE)) if command else DBG_CONTINUE)
            _debug_close_event_handles(event)
            kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status)
            with session["condition"]:
                session["pending_event"] = None
                session["condition"].notify_all()

        _debug_restore_all_breakpoints(session)
        if attached:
            kernel32.DebugActiveProcessStop(pid)
        session["state"] = "detached"
    except Exception as exc:
        session["state"] = "failed"
        session["error"] = str(exc)
        session["attached_event"].set()
    finally:
        handle = session.get("process_handle")
        if handle:
            kernel32.CloseHandle(handle)
            session["process_handle"] = None
        with session["condition"]:
            session["condition"].notify_all()


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


def _clip_ranges_to_readable_regions(
    handle: wt.HANDLE,
    ranges: List[Dict[str, Any]],
    module: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Recorta rangos logicos contra regiones legibles de VirtualQueryEx."""
    readable_regions = _memory_regions(handle, readable_only=True)
    module_base = int(module["base"]) if module else 0
    clipped: List[Dict[str, Any]] = []

    for source in ranges:
        source_base = int(source["base"])
        source_size = int(source["size"])
        source_end = source_base + source_size
        for region in readable_regions:
            region_base = int(region["base"])
            region_size = int(region["size"])
            region_end = region_base + region_size
            if region_end <= source_base or region_base >= source_end:
                continue

            start = max(source_base, region_base)
            end = min(source_end, region_end)
            if end <= start:
                continue

            item = dict(source)
            item.update({
                "base": start,
                "base_hex": f"0x{start:X}",
                "size": end - start,
                "size_hex": f"0x{end - start:X}",
                "rva": start - module_base if module else source.get("rva", start - source_base),
                "rva_hex": f"0x{start - module_base:X}" if module else f"0x{start - source_base:X}",
                "source_base": source.get("base_hex", f"0x{source_base:X}"),
                "source_size": source.get("size_hex", f"0x{source_size:X}"),
                "protect": region.get("protect", "memory"),
            })
            clipped.append(item)

    clipped.sort(key=lambda item: int(item["base"]))
    return clipped


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


def _memory_region_at(handle: wt.HANDLE, address: int) -> Optional[Dict[str, Any]]:
    """Devuelve la region VirtualQueryEx que contiene address."""
    mbi = MEMORY_BASIC_INFORMATION()
    result = kernel32.VirtualQueryEx(
        handle,
        ctypes.c_void_p(address),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi),
    )
    if result == 0:
        return None

    is_readable = bool(mbi.Protect & READABLE_PROTECTIONS) and not (mbi.Protect & PAGE_GUARD)
    return {
        "base": f"0x{int(mbi.BaseAddress or 0):X}",
        "allocation_base": f"0x{int(mbi.AllocationBase or 0):X}",
        "size": int(mbi.RegionSize),
        "size_hex": f"0x{int(mbi.RegionSize):X}",
        "state": f"0x{int(mbi.State):X}",
        "protect": _protection_str(int(mbi.Protect)),
        "type": f"0x{int(mbi.Type):X}",
        "readable": is_readable,
    }


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
_debug_sessions: Dict[str, Dict[str, Any]] = {}
_debug_sessions_lock = threading.RLock()
MAX_SCAN_CANDIDATES = 200_000
DEFAULT_SCAN_CHUNK_SIZE = 8 * 1024 * 1024
DEFAULT_MAX_SCAN_MB = 256
DEFAULT_MAX_TOOL_SECONDS = 30
DEFAULT_JOB_MAX_SCAN_MB = 8192
SCAN_JOBS_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "scan_jobs"


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




# Tool modules intentionally import private helpers from this runtime module.
__all__ = [name for name in globals() if not (name.startswith("__") and name.endswith("__"))]
