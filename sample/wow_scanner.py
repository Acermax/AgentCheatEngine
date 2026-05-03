"""
WoWScan - Scanner de memoria minimalista estilo CheatEngine.

Solo lectura via ReadProcessMemory. Sin DLLs, sin hooks, sin inyeccion.
GUI Tkinter (libreria estandar, sin dependencias externas).
Ventana siempre encima + hotkeys globales para usar mientras juegas.

USO BASICO (flujo CheatEngine):
    1. Abrir Wow.exe del combo
    2. Tipo: f32 (HP en WoW retail moderno suele ser float)
    3. Escribir tu HP actual en "Valor" -> click "FIRST SCAN"
    4. Recibir un golpe en el juego
    5. Apretar F8 (hotkey global "menor") sin salir del juego
    6. Repetir 4-5 hasta tener pocos candidatos (1-3)
    7. La direccion que queda es la del HP del player

HOTKEYS GLOBALES (funcionan sin foco en la app):
    Ctrl+Shift+F8  -> Decreased (HP bajo - recibiste daño)
    Ctrl+Shift+F9  -> Unchanged (mismo valor)
    Ctrl+Shift+F10 -> Increased (HP subio - regeneraste/curaste)
    Ctrl+Shift+F11 -> Refresh values

Requiere Python 3.8+ en Windows. Tkinter incluido.
"""

import ctypes
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import threading
import time
import tkinter as tk
from ctypes import wintypes
from tkinter import messagebox, simpledialog, ttk

WATCHES_FILE = os.path.expanduser('~/.wow_scanner_watches.json')
STRING_DTYPE = 'string (utf-8)'
DEFAULT_STRING_PREVIEW_BYTES = 128
DEFAULT_STRING_WATCH_BYTES = 64
MAX_STRING_WATCH_BYTES = 4096
SNAPSHOT_BLOCK_SIZE = 8 * 1024 * 1024
RESULTS_PAGE_SIZE = 500
RANGE_VALUE_RE = re.compile(
    r'^\s*([+-]?(?:0[xX][0-9A-Fa-f]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?))\s*-\s*'
    r'([+-]?(?:0[xX][0-9A-Fa-f]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?))\s*$'
)
WATCH_EXPR_RE = re.compile(
    r'^\s*([A-Za-z0-9_.-]+)\s*([+-])\s*(0[xX][0-9A-Fa-f]+|\d+)\s*$'
)
OFFSET_SPLIT_RE = re.compile(r'[\s,;]+')
DEREF_TOKENS = {'deref', 'read', 'readptr', 'read_ptr', 'ptr', '*'}

# ============================================================
# Win32 API
# ============================================================

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

# Hotkeys
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
WM_HOTKEY = 0x0312

VK_F8 = 0x77
VK_F9 = 0x78
VK_F10 = 0x79
VK_F11 = 0x7A
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class MBI(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('__align', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ('hwnd', wintypes.HWND),
        ('message', wintypes.UINT),
        ('wParam', wintypes.WPARAM),
        ('lParam', wintypes.LPARAM),
        ('time', wintypes.DWORD),
        ('pt_x', wintypes.LONG),
        ('pt_y', wintypes.LONG),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', ctypes.c_wchar * 256),
        ('szExePath', ctypes.c_wchar * MAX_PATH),
    ]


# Function prototypes (importante para 64-bit correctness)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MBI), ctypes.c_size_t
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL

psapi.EnumProcesses.argtypes = [
    ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
psapi.EnumProcesses.restype = wintypes.BOOL

user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
user32.RegisterHotKey.restype = wintypes.BOOL
user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = wintypes.BOOL


def is_readable(protect):
    """True si la proteccion permite lectura."""
    if protect == 0 or protect == PAGE_NOACCESS:
        return False
    if protect & PAGE_GUARD:
        return False
    # PAGE_READONLY=2, PAGE_READWRITE=4, PAGE_WRITECOPY=8,
    # PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40, PAGE_EXECUTE_WRITECOPY=0x80
    return protect & 0xEE != 0


def list_processes():
    arr = (wintypes.DWORD * 4096)()
    cb = wintypes.DWORD(0)
    if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(cb)):
        return []
    count = cb.value // ctypes.sizeof(wintypes.DWORD)
    result = []
    for i in range(count):
        pid = arr[i]
        if pid == 0:
            continue
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            continue
        try:
            buf = ctypes.create_unicode_buffer(260)
            sz = wintypes.DWORD(260)
            if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
                full = buf.value
                short = full.rsplit('\\', 1)[-1]
                result.append((pid, short, full))
        finally:
            kernel32.CloseHandle(h)
    return result


# ============================================================
# Scanner core
# ============================================================

DTYPES = {
    'byte (u8)':    ('<B', 1),
    'flag (bool)':  ('<?', 1),
    'i32 (int)':    ('<i', 4),
    'u32 (uint)':   ('<I', 4),
    'f32 (float)':  ('<f', 4),
    'i64 (long)':   ('<q', 8),
    'u64 (ulong)':  ('<Q', 8),
    'f64 (double)': ('<d', 8),
    STRING_DTYPE:   (None, None),
}

DTYPE_CAST_CODES = {
    '<B': 'B',
    '<i': 'i',
    '<I': 'I',
    '<f': 'f',
    '<q': 'q',
    '<Q': 'Q',
    '<d': 'd',
}


def dtype_is_string(dtype):
    return dtype == STRING_DTYPE


def dtype_is_flag(dtype):
    return dtype == 'flag (bool)'


def format_signed_hex(value):
    value = int(value)
    if value < 0:
        return f'-0x{abs(value):X}'
    return f'+0x{value:X}'


class NumericCandidateFile:
    """Store numericos en disco para scans masivos."""

    def __init__(self, fmt):
        self.fmt = fmt
        self.value_fmt = fmt[1:] if fmt.startswith('<') else fmt
        self.record_struct = struct.Struct(f'<Q{self.value_fmt}')
        self.record_size = self.record_struct.size
        fd, self.path = tempfile.mkstemp(prefix='wowscan_candidates_', suffix='.bin')
        os.close(fd)
        self._writer = open(self.path, 'wb')
        self.count = 0

    def append(self, addr, value):
        self._writer.write(self.record_struct.pack(addr, value))
        self.count += 1

    def finalize(self):
        if self._writer:
            self._writer.flush()
            self._writer.close()
            self._writer = None

    def close(self):
        self.finalize()
        try:
            os.remove(self.path)
        except OSError:
            pass

    def __len__(self):
        return self.count

    def __iter__(self):
        yield from self.iter_records()

    def iter_records(self):
        self.finalize()
        block_size = self.record_size * 4096
        with open(self.path, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                for off in range(0, len(data), self.record_size):
                    end = off + self.record_size
                    if end > len(data):
                        break
                    yield self.record_struct.unpack_from(data, off)

    def get_page(self, offset, limit):
        if offset < 0:
            offset = 0
        if limit <= 0 or offset >= self.count:
            return []

        self.finalize()
        with open(self.path, 'rb') as f:
            f.seek(offset * self.record_size)
            data = f.read(limit * self.record_size)

        page = []
        for off in range(0, len(data), self.record_size):
            end = off + self.record_size
            if end > len(data):
                break
            page.append(self.record_struct.unpack_from(data, off))
        return page


class Scanner:
    def __init__(self):
        self.handle = None
        self.pid = None
        self.proc_name = None
        self.module_bases = {}
        # candidates: lista de (addr, current_value)
        self.candidates = []
        self.dtype = 'i32 (int)'
        # Si True, exige alineamiento natural al tamano del tipo (mas rapido).
        # Si False, escanea byte a byte (mas lento pero encuentra structs packed).
        self.aligned = False
        # Filtro opcional de rango (para acotar a heap del juego)
        self.addr_min = 0
        self.addr_max = 0x7FFFFFFFFFFF
        self.snapshot_dir = None
        self.snapshot_regions = []
        self.snapshot_dtype = None
        self.snapshot_aligned = False
        self.last_scan_truncated = False
        self.last_scan_truncated_reason = ''

    def _reset_scan_flags(self):
        self.last_scan_truncated = False
        self.last_scan_truncated_reason = ''

    def clear_snapshot(self):
        snap_dir = self.snapshot_dir
        self.snapshot_dir = None
        self.snapshot_regions = []
        self.snapshot_dtype = None
        self.snapshot_aligned = False
        if snap_dir:
            shutil.rmtree(snap_dir, ignore_errors=True)

    def has_snapshot(self):
        return bool(self.snapshot_regions)

    def snapshot_matches_current_config(self):
        return (
            self.has_snapshot()
            and self.snapshot_dtype == self.dtype
            and self.snapshot_aligned == self.aligned
        )

    def clear_candidates(self):
        old = self.candidates
        self.candidates = []
        if isinstance(old, NumericCandidateFile):
            old.close()

    def set_candidates(self, candidates):
        old = self.candidates
        self.candidates = candidates
        if isinstance(old, NumericCandidateFile) and old is not candidates:
            old.close()

    def get_candidate_page(self, offset, limit):
        if isinstance(self.candidates, NumericCandidateFile):
            return self.candidates.get_page(offset, limit)
        return list(self.candidates[offset:offset + limit])

    def open(self, pid):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None
        self.clear_snapshot()
        self.clear_candidates()
        h = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not h:
            err = ctypes.get_last_error()
            raise OSError(f'OpenProcess fallo (error {err}). '
                          f'Necesitas ejecutar como administrador?')
        self.handle = h
        self.pid = pid
        self.module_bases = self._enum_modules()
        self.clear_candidates()

    def close(self):
        self.clear_snapshot()
        self.clear_candidates()
        self.module_bases = {}
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def parse_value(self, txt):
        if dtype_is_string(self.dtype):
            if txt == '':
                raise ValueError('Escribe un string no vacio')
            return txt
        if dtype_is_flag(self.dtype):
            raw = txt.strip().lower()
            if raw in {'1', 'true', 't', 'yes', 'y', 'on'}:
                return True
            if raw in {'0', 'false', 'f', 'no', 'n', 'off'}:
                return False
            raise ValueError('Para flag usa 0/1, true/false, on/off')
        fmt, size = DTYPES[self.dtype]
        txt = txt.strip()
        if 'f' in fmt or 'd' in fmt:
            return float(txt)
        if txt.lower().startswith('0x'):
            return int(txt, 16)
        return int(txt)

    def _encode_string(self, value):
        if not isinstance(value, str):
            value = str(value)
        raw = value.encode('utf-8')
        if not raw:
            raise ValueError('El string no puede estar vacio')
        return raw

    def _read_string_exact(self, addr, byte_len):
        if byte_len <= 0:
            return ''
        data = self.read(addr, byte_len)
        if not data or len(data) < byte_len:
            return None
        return data[:byte_len].decode('utf-8', errors='replace')

    def _read_string_preview(self, addr, byte_len=None):
        size = byte_len if byte_len is not None else DEFAULT_STRING_PREVIEW_BYTES
        size = max(size, 1)
        data = self.read(addr, size)
        if not data:
            return None
        nul = data.find(b'\x00')
        raw = data if nul < 0 else data[:nul]
        return raw.decode('utf-8', errors='replace')

    def enum_regions(self):
        addr = self.addr_min
        max_addr = self.addr_max
        regs = []
        while addr < max_addr:
            mbi = MBI()
            ok = kernel32.VirtualQueryEx(
                self.handle, ctypes.c_void_p(addr),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not ok:
                # Saltar al siguiente bloque grande
                addr += 0x1000
                continue
            base = mbi.BaseAddress if mbi.BaseAddress else 0
            size = mbi.RegionSize
            if size == 0:
                break
            if (mbi.State == MEM_COMMIT
                    and is_readable(mbi.Protect)
                    and base >= self.addr_min
                    and base < self.addr_max):
                regs.append((base, size))
            addr = base + size
        return regs

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)
        )
        if ok and n.value > 0:
            return buf.raw[:n.value]
        return None

    def read_ptr(self, addr):
        data = self.read(addr, 8)
        if not data or len(data) < 8:
            return None
        return struct.unpack('<Q', data[:8])[0]

    def _enum_modules(self):
        modules = {}
        if not self.pid:
            return modules

        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid
        )
        if snap == INVALID_HANDLE_VALUE:
            return modules

        try:
            me = MODULEENTRY32W()
            me.dwSize = ctypes.sizeof(MODULEENTRY32W)
            ok = kernel32.Module32FirstW(snap, ctypes.byref(me))
            while ok:
                name = me.szModule
                base = ctypes.addressof(me.modBaseAddr.contents) if me.modBaseAddr else 0
                if name and base:
                    modules[name.lower()] = base
                ok = kernel32.Module32NextW(snap, ctypes.byref(me))
        finally:
            kernel32.CloseHandle(snap)
        return modules

    def resolve_address_expr(self, expr):
        txt = expr.strip()
        if not txt:
            raise ValueError('Direccion vacia')

        if txt.lower().startswith('0x'):
            return int(txt, 16)
        if txt.isdigit():
            return int(txt)

        match = WATCH_EXPR_RE.match(txt)
        if not match:
            raise ValueError('Formato invalido. Usa 0x..., decimal o Modulo+0xOFFSET')

        mod_name, sign, off_txt = match.groups()
        module_base = self.module_bases.get(mod_name.lower())
        if module_base is None:
            raise ValueError(f'Modulo no encontrado: {mod_name}')

        offset = int(off_txt, 0)
        if sign == '-':
            return module_base - offset
        return module_base + offset

    def parse_watch_path_steps(self, raw_text):
        steps = []
        txt = raw_text.strip()
        if not txt:
            return steps

        lines = []
        for raw_line in txt.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            parts = [part.strip() for part in raw_line.split(',') if part.strip()]
            if parts:
                lines.extend(parts)

        for token in lines:
            normalized = token.lower().replace(' ', '').replace('-', '')
            if normalized in DEREF_TOKENS:
                steps.append({'op': 'deref'})
                continue

            try:
                value = int(token, 0)
            except ValueError as e:
                raise ValueError(
                    f'Paso invalido: {token}. Usa offsets como +0x10/-0x8 o "deref"'
                ) from e
            steps.append({'op': 'add', 'value': value})

        return steps

    def parse_legacy_watch_offsets(self, raw_text):
        txt = raw_text.strip()
        if not txt:
            return []
        try:
            return [
                int(part, 0)
                for part in OFFSET_SPLIT_RE.split(txt.replace('\n', ' '))
                if part
            ]
        except ValueError as e:
            raise ValueError('Offsets invalidos') from e

    def watch_text_uses_deref(self, raw_text):
        txt = raw_text.strip()
        if not txt:
            return False

        for raw_line in txt.splitlines():
            parts = [part.strip() for part in raw_line.split(',') if part.strip()]
            for token in parts:
                normalized = token.lower().replace(' ', '').replace('-', '')
                if normalized in DEREF_TOKENS:
                    return True
        return False

    def format_watch_path_steps(self, watch):
        path_steps = watch.get('path_steps')
        if path_steps:
            lines = []
            for step in path_steps:
                if step.get('op') == 'deref':
                    lines.append('deref')
                elif step.get('op') == 'add':
                    lines.append(format_signed_hex(step.get('value', 0)))
            return '\n'.join(lines)

        offsets = watch.get('offsets') or []
        if not offsets:
            return ''
        return '\n'.join(f'0x{int(off):X}' for off in offsets)

    def resolve_watch_address(self, watch):
        if 'addr_expr' not in watch and 'offsets' not in watch and 'path_steps' not in watch:
            return watch.get('addr')

        base_expr = watch.get('addr_expr')
        if not base_expr:
            return watch.get('addr')

        addr = self.resolve_address_expr(base_expr)
        path_steps = watch.get('path_steps')
        if path_steps:
            cur = addr
            for step in path_steps:
                op = step.get('op')
                if op == 'deref':
                    cur = self.read_ptr(cur)
                    if cur is None:
                        return None
                elif op == 'add':
                    cur += int(step.get('value', 0))
                else:
                    return None
            return cur

        offsets = watch.get('offsets') or []
        if not offsets:
            return addr

        if isinstance(offsets, str):
            offsets = [int(part, 0) for part in OFFSET_SPLIT_RE.split(offsets) if part]

        cur = self.read_ptr(addr)
        if cur is None:
            return None

        for off in offsets[:-1]:
            next_addr = cur + int(off)
            cur = self.read_ptr(next_addr)
            if cur is None:
                return None

        return cur + int(offsets[-1])

    def snapshot_scan(self, progress_cb=None, stop_flag=None):
        if dtype_is_string(self.dtype):
            raise ValueError('Snapshot inicial sin valor no esta soportado para strings')

        self.clear_snapshot()
        self.clear_candidates()
        self._reset_scan_flags()

        regs = self.enum_regions()
        total = sum(r[1] for r in regs)
        scanned = 0
        regions = []
        snap_dir = tempfile.mkdtemp(prefix='wowscan_snapshot_')

        try:
            for i, (base, region_size) in enumerate(regs):
                if stop_flag and stop_flag():
                    break
                data = self.read(base, region_size)
                scanned += region_size
                if progress_cb and (i % 20 == 0):
                    progress_cb(scanned, total, len(regions))
                if not data:
                    continue
                path = os.path.join(snap_dir, f'{len(regions):06d}.bin')
                with open(path, 'wb') as f:
                    f.write(data)
                regions.append({
                    'base': base,
                    'size': len(data),
                    'path': path,
                })

            if not regions:
                raise ValueError('No se pudo crear el snapshot de ninguna region legible')

            self.snapshot_dir = snap_dir
            self.snapshot_regions = regions
            self.snapshot_dtype = self.dtype
            self.snapshot_aligned = self.aligned
            if progress_cb:
                progress_cb(total, total, len(regions))
            return len(regions)
        except Exception:
            shutil.rmtree(snap_dir, ignore_errors=True)
            raise

    def scan_from_snapshot(self, op, progress_cb=None, stop_flag=None):
        if dtype_is_string(self.dtype):
            raise ValueError('Snapshot inicial sin valor solo esta soportado para tipos numericos')
        if op not in {'eq', 'ne', 'lt', 'gt'}:
            raise ValueError('El snapshot inicial solo soporta = prev, != prev, MENOR y MAYOR')
        if not self.snapshot_matches_current_config():
            raise ValueError('El snapshot actual no coincide con el tipo/alineacion seleccionados')

        self._reset_scan_flags()

        fmt, size = DTYPES[self.dtype]
        cast_code = DTYPE_CAST_CODES.get(fmt)
        step = size if self.aligned else 1
        store = NumericCandidateFile(fmt)
        total = sum(meta['size'] for meta in self.snapshot_regions)
        scanned = 0

        for region_idx, meta in enumerate(self.snapshot_regions):
            if stop_flag and stop_flag():
                break

            base = meta['base']
            region_size = meta['size']

            with open(meta['path'], 'rb') as f:
                offset = 0
                while offset < region_size:
                    if stop_flag and stop_flag():
                        break

                    advance = min(SNAPSHOT_BLOCK_SIZE, region_size - offset)
                    read_size = min(advance + size - 1, region_size - offset)
                    f.seek(offset)
                    prev_chunk = f.read(read_size)
                    cur_chunk = self.read(base + offset, read_size)

                    scanned += advance
                    if progress_cb and (region_idx % 8 == 0):
                        progress_cb(scanned, total, len(store))

                    offset += advance

                    if not cur_chunk:
                        continue

                    limit = min(len(prev_chunk), len(cur_chunk))
                    window_limit = limit - size + 1
                    if window_limit <= 0:
                        continue

                    scan_stop = window_limit
                    if advance < region_size:
                        scan_stop = min(scan_stop, advance)
                    if scan_stop <= 0:
                        continue

                    compare_len = scan_stop + size - 1
                    prev_view = prev_chunk[:compare_len]
                    cur_view = cur_chunk[:compare_len]

                    if op in {'ne', 'lt', 'gt'} and prev_view == cur_view:
                        continue

                    block_base = base + offset - advance

                    if self.aligned and cast_code and scan_stop % size == 0:
                        prev_vals = memoryview(prev_view[:scan_stop]).cast(cast_code)
                        cur_vals = memoryview(cur_view[:scan_stop]).cast(cast_code)

                        for idx, (prev_val, cur_val) in enumerate(zip(prev_vals, cur_vals)):
                            keep = False
                            if op == 'eq':
                                keep = cur_val == prev_val
                            elif op == 'ne':
                                keep = cur_val != prev_val
                            elif op == 'lt':
                                keep = cur_val < prev_val
                            elif op == 'gt':
                                keep = cur_val > prev_val

                            if keep:
                                store.append(block_base + idx * size, cur_val)
                        continue

                    for off in range(0, scan_stop, step):
                        try:
                            prev_val = struct.unpack(fmt, prev_chunk[off:off + size])[0]
                            cur_val = struct.unpack(fmt, cur_chunk[off:off + size])[0]
                        except struct.error:
                            continue

                        keep = False
                        if op == 'eq':
                            keep = cur_val == prev_val
                        elif op == 'ne':
                            keep = cur_val != prev_val
                        elif op == 'lt':
                            keep = cur_val < prev_val
                        elif op == 'gt':
                            keep = cur_val > prev_val

                        if keep:
                            store.append(block_base + off, cur_val)

        if progress_cb:
            progress_cb(total, total, len(store))
        if len(store) == 0:
            store.close()
            self.set_candidates([])
            return 0
        store.finalize()
        self.set_candidates(store)
        return len(store)

    def first_scan(self, value, progress_cb=None, stop_flag=None):
        self._reset_scan_flags()
        if dtype_is_string(self.dtype):
            pat = self._encode_string(value)
            size = len(pat)
        else:
            fmt, size = DTYPES[self.dtype]
            try:
                pat = struct.pack(fmt, value)
            except struct.error as e:
                raise ValueError(f'No se puede empaquetar {value} como {self.dtype}: {e}')

        hits = []
        regs = self.enum_regions()
        total = sum(r[1] for r in regs)
        scanned = 0
        for i, (base, region_size) in enumerate(regs):
            if stop_flag and stop_flag():
                break
            data = self.read(base, region_size)
            scanned += region_size
            if progress_cb and (i % 20 == 0):
                progress_cb(scanned, total, len(hits))
            if not data:
                continue
            off = 0
            while True:
                idx = data.find(pat, off)
                if idx < 0:
                    break
                if dtype_is_string(self.dtype) or (not self.aligned) or (base + idx) % size == 0:
                    hits.append((base + idx, value))
                off = idx + 1
        if progress_cb:
            progress_cb(total, total, len(hits))
        self.set_candidates(hits)
        return len(hits)

    def first_scan_range(self, vmin, vmax, progress_cb=None, stop_flag=None):
        """Escanea todos los valores del tipo actual cuyo valor este en [vmin, vmax].
        Util para coords / valores que driftan continuamente."""
        self._reset_scan_flags()
        if dtype_is_string(self.dtype):
            raise ValueError('RANGE no esta disponible para strings')
        fmt, size = DTYPES[self.dtype]
        step = 1 if not self.aligned else size

        hits = []
        regs = self.enum_regions()
        total = sum(r[1] for r in regs)
        scanned = 0
        for i, (base, region_size) in enumerate(regs):
            if stop_flag and stop_flag():
                break
            data = self.read(base, region_size)
            scanned += region_size
            if progress_cb and (i % 20 == 0):
                progress_cb(scanned, total, len(hits))
            if not data:
                continue
            n = len(data)
            for off in range(0, n - size + 1, step):
                try:
                    v = struct.unpack(fmt, data[off:off + size])[0]
                except struct.error:
                    continue
                # Filtra NaN
                if v != v:
                    continue
                if vmin <= v <= vmax:
                    hits.append((base + off, v))
                    # Cap de seguridad para evitar saturar memoria
                    if len(hits) > 5_000_000:
                        self.set_candidates(hits)
                        if progress_cb:
                            progress_cb(total, total, len(hits))
                        return len(hits)
        if progress_cb:
            progress_cb(total, total, len(hits))
        self.set_candidates(hits)
        return len(hits)

    def next_scan(self, op, value=None):
        """
        op:
            'eq_val' = igual a `value`
            'ne_val' = distinto a `value`
            'lt_val' = menor que `value`
            'gt_val' = mayor que `value`
            'eq'     = sin cambios respecto al snapshot anterior
            'ne'     = cambio cualquiera
            'lt'     = decreased (menor que el snapshot)
            'gt'     = increased (mayor que el snapshot)
        """
        self._reset_scan_flags()
        if dtype_is_string(self.dtype):
            if op not in {'eq_val', 'ne_val', 'eq', 'ne'}:
                raise ValueError('Los strings solo soportan = valor, != valor, = prev y != prev')

            target_len = None
            if op in {'eq_val', 'ne_val'}:
                target_len = len(self._encode_string(value))

            new = []
            for addr, prev in self.candidates:
                if target_len is not None:
                    cur = self._read_string_exact(addr, target_len)
                else:
                    prev_len = len(self._encode_string(prev))
                    cur = self._read_string_exact(addr, prev_len)
                if cur is None:
                    continue

                keep = False
                if op == 'eq_val':
                    keep = cur == value
                elif op == 'ne_val':
                    keep = cur != value
                elif op == 'eq':
                    keep = cur == prev
                elif op == 'ne':
                    keep = cur != prev
                if keep:
                    new.append((addr, cur))
            self.set_candidates(new)
            return len(new)

        fmt, size = DTYPES[self.dtype]
        source = self.candidates
        use_file_store = isinstance(source, NumericCandidateFile)
        new = NumericCandidateFile(fmt) if use_file_store else []
        for addr, prev in source:
            data = self.read(addr, size)
            if not data or len(data) < size:
                continue
            try:
                cur = struct.unpack(fmt, data[:size])[0]
            except struct.error:
                continue

            keep = False
            if op == 'eq_val':
                keep = cur == value
            elif op == 'ne_val':
                keep = cur != value
            elif op == 'lt_val':
                keep = cur < value
            elif op == 'gt_val':
                keep = cur > value
            elif op == 'eq':
                keep = cur == prev
            elif op == 'ne':
                keep = cur != prev
            elif op == 'lt':
                keep = cur < prev
            elif op == 'gt':
                keep = cur > prev
            if keep:
                if use_file_store:
                    new.append(addr, cur)
                else:
                    new.append((addr, cur))
        if use_file_store:
            if len(new) == 0:
                new.close()
                self.set_candidates([])
                return 0
            new.finalize()
        self.set_candidates(new)
        return len(new)

    def refresh_values(self):
        if dtype_is_string(self.dtype):
            new = []
            for addr, prev in self.candidates:
                preview_len = max(
                    len(self._encode_string(prev)),
                    DEFAULT_STRING_PREVIEW_BYTES,
                )
                cur = self._read_string_preview(addr, preview_len)
                new.append((addr, prev if cur is None else cur))
            self.set_candidates(new)
            return

        fmt, size = DTYPES[self.dtype]
        source = self.candidates
        use_file_store = isinstance(source, NumericCandidateFile)
        new = NumericCandidateFile(fmt) if use_file_store else []
        for addr, prev in source:
            data = self.read(addr, size)
            if data and len(data) >= size:
                try:
                    cur = struct.unpack(fmt, data[:size])[0]
                    if use_file_store:
                        new.append(addr, cur)
                    else:
                        new.append((addr, cur))
                    continue
                except struct.error:
                    pass
            if use_file_store:
                new.append(addr, prev)
            else:
                new.append((addr, prev))
        if use_file_store:
            if len(new) == 0:
                new.close()
                self.set_candidates([])
                return
            new.finalize()
        self.set_candidates(new)


# ============================================================
# Hotkeys globales (thread aparte con message loop)
# ============================================================

class HotkeyListener(threading.Thread):
    """Registra hotkeys globales con RegisterHotKey y envia callbacks."""

    def __init__(self, callback):
        super().__init__(daemon=True)
        self.callback = callback
        self.bindings = []
        self._stop = False

    def add(self, hk_id, modifiers, vk):
        self.bindings.append((hk_id, modifiers, vk))

    def run(self):
        registered = []
        for hk_id, mods, vk in self.bindings:
            if user32.RegisterHotKey(None, hk_id, mods, vk):
                registered.append(hk_id)
            else:
                err = ctypes.get_last_error()
                print(f'[!] No se pudo registrar hotkey id={hk_id} (err {err})',
                      file=sys.stderr)

        msg = MSG()
        try:
            while not self._stop:
                ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if ret <= 0:
                    break
                if msg.message == WM_HOTKEY:
                    try:
                        self.callback(msg.wParam)
                    except Exception as e:
                        print(f'[!] Error en hotkey callback: {e}', file=sys.stderr)
        finally:
            for hk_id in registered:
                user32.UnregisterHotKey(None, hk_id)


# ============================================================
# GUI
# ============================================================

HK_DECREASED = 1
HK_UNCHANGED = 2
HK_INCREASED = 3
HK_REFRESH = 4


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('WoWScan')
        self.attributes('-topmost', True)
        self.geometry('480x980')
        self.minsize(440, 800)

        self.scanner = Scanner()
        self.scanning = False
        self._proc_list = []
        self.results_page = 0
        # watches: lista de dicts {addr, dtype, label}
        self.watches = []
        self._load_watches()

        self._build_ui()
        self._setup_hotkeys()
        self.refresh_processes()
        self._refresh_watches_loop()
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # --------- UI ---------
    def _build_ui(self):
        pad = {'padx': 6, 'pady': 4}

        # Proceso
        frm_proc = ttk.LabelFrame(self, text='Proceso')
        frm_proc.pack(fill='x', **pad)
        self.proc_var = tk.StringVar()
        self.proc_combo = ttk.Combobox(
            frm_proc, textvariable=self.proc_var, state='readonly', width=36
        )
        self.proc_combo.pack(side='left', fill='x', expand=True, padx=4, pady=4)
        ttk.Button(frm_proc, text='Refrescar', width=10,
                   command=self.refresh_processes).pack(side='left', padx=2)
        ttk.Button(frm_proc, text='Abrir',
                   command=self.open_process).pack(side='left', padx=2)

        self.lbl_status = ttk.Label(self, text='Sin proceso abierto', foreground='gray')
        self.lbl_status.pack(**pad)

        # Tipo de dato
        frm_type = ttk.LabelFrame(self, text='Tipo de dato')
        frm_type.pack(fill='x', **pad)
        self.dtype_var = tk.StringVar(value='f32 (float)')
        for i, dt in enumerate(DTYPES):
            ttk.Radiobutton(
                frm_type, text=dt, variable=self.dtype_var, value=dt
            ).grid(row=i // 3, column=i % 3, sticky='w', padx=4, pady=2)

        # Valor
        frm_val = ttk.LabelFrame(self, text='Valor')
        frm_val.pack(fill='x', **pad)
        self.val_entry = ttk.Entry(frm_val, font=('Consolas', 14))
        self.val_entry.pack(fill='x', padx=4, pady=4)
        self.val_entry.bind('<Return>', self._on_enter)
        ttk.Label(
            frm_val,
            text='Deja el campo vacio para snapshot inicial, o escribe min-max para un range scan',
            foreground='#444'
        ).pack(anchor='w', padx=4)
        self.aligned_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frm_val,
            text='Fast scan (alineado al tipo) - desmarca si no encuentras structs packed',
            variable=self.aligned_var
        ).pack(anchor='w', padx=4, pady=2)

        # Botones de accion
        frm_btn = ttk.Frame(self)
        frm_btn.pack(fill='x', **pad)

        ttk.Button(frm_btn, text='FIRST SCAN / SNAPSHOT', command=self.first_scan
                   ).grid(row=0, column=0, columnspan=3, sticky='ew', padx=2, pady=2)
        ttk.Button(frm_btn, text='NEW SCAN', command=self.new_scan
                   ).grid(row=0, column=3, sticky='ew', padx=2, pady=2)

        # Comparaciones contra valor del campo
        ttk.Button(frm_btn, text='= valor',
                   command=lambda: self.next_scan('eq_val')
                   ).grid(row=1, column=0, sticky='ew', padx=2, pady=2)
        ttk.Button(frm_btn, text='!= valor',
                   command=lambda: self.next_scan('ne_val')
                   ).grid(row=1, column=1, sticky='ew', padx=2, pady=2)
        ttk.Button(frm_btn, text='< valor',
                   command=lambda: self.next_scan('lt_val')
                   ).grid(row=1, column=2, sticky='ew', padx=2, pady=2)
        ttk.Button(frm_btn, text='> valor',
                   command=lambda: self.next_scan('gt_val')
                   ).grid(row=1, column=3, sticky='ew', padx=2, pady=2)

        # Comparaciones contra snapshot anterior (lo importante)
        b1 = ttk.Button(frm_btn, text='= prev (F9)',
                        command=lambda: self.next_scan('eq'))
        b1.grid(row=2, column=0, sticky='ew', padx=2, pady=2)
        ttk.Button(frm_btn, text='!= prev',
                   command=lambda: self.next_scan('ne')
                   ).grid(row=2, column=1, sticky='ew', padx=2, pady=2)
        b3 = ttk.Button(frm_btn, text='MENOR (F8)',
                        command=lambda: self.next_scan('lt'))
        b3.grid(row=2, column=2, sticky='ew', padx=2, pady=2)
        b4 = ttk.Button(frm_btn, text='MAYOR (F10)',
                        command=lambda: self.next_scan('gt'))
        b4.grid(row=2, column=3, sticky='ew', padx=2, pady=2)

        for c in range(4):
            frm_btn.columnconfigure(c, weight=1)

        # Conteo
        self.lbl_count = ttk.Label(self, text='Sin candidatos',
                                   font=('Segoe UI', 12, 'bold'))
        self.lbl_count.pack(**pad)

        self.progress = ttk.Progressbar(self, mode='determinate')
        self.progress.pack(fill='x', padx=6)

        # Lista de candidatos
        frm_list = ttk.LabelFrame(self, text='Candidatos')
        frm_list.pack(fill='both', expand=True, **pad)

        cols = ('addr', 'value')
        self.tree = ttk.Treeview(
            frm_list, columns=cols, show='headings', height=12, selectmode='extended'
        )
        self.tree.heading('addr', text='Direccion')
        self.tree.heading('value', text='Valor actual')
        self.tree.column('addr', width=200, anchor='w')
        self.tree.column('value', width=140, anchor='e')
        self.tree.pack(side='left', fill='both', expand=True)
        sb = ttk.Scrollbar(frm_list, orient='vertical', command=self.tree.yview)
        sb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=sb.set)

        frm_list_nav = ttk.Frame(self)
        frm_list_nav.pack(fill='x', **pad)
        self.btn_prev_page = ttk.Button(
            frm_list_nav, text='< Prev',
            command=lambda: self._change_results_page(-1)
        )
        self.btn_prev_page.pack(side='left', padx=2)
        self.btn_next_page = ttk.Button(
            frm_list_nav, text='Next >',
            command=lambda: self._change_results_page(1)
        )
        self.btn_next_page.pack(side='left', padx=2)
        self.lbl_results_page = ttk.Label(frm_list_nav, text='Sin resultados')
        self.lbl_results_page.pack(side='left', padx=8)

        # Bottom
        frm_bot = ttk.Frame(self)
        frm_bot.pack(fill='x', **pad)
        ttk.Button(frm_bot, text='Refrescar valores (F11)',
                   command=self.refresh_values).pack(side='left', padx=2)
        ttk.Button(frm_bot, text='Copiar direccion',
                   command=self.copy_addr).pack(side='left', padx=2)
        ttk.Button(frm_bot, text='Quitar candidatos',
                   command=self.remove_selected_candidates).pack(side='left', padx=2)
        ttk.Button(frm_bot, text='-> Watch',
                   command=self.add_candidate_to_watch).pack(side='left', padx=2)

        # ============ WATCHES ============
        frm_watch = ttk.LabelFrame(self, text='Watches (refresh auto)')
        frm_watch.pack(fill='both', expand=True, **pad)

        wcols = ('addr', 'dtype', 'label', 'value')
        self.watch_tree = ttk.Treeview(
            frm_watch, columns=wcols, show='headings', height=8
        )
        self.watch_tree.heading('addr', text='Direccion')
        self.watch_tree.heading('dtype', text='Tipo')
        self.watch_tree.heading('label', text='Etiqueta')
        self.watch_tree.heading('value', text='Valor')
        self.watch_tree.column('addr', width=140, anchor='w')
        self.watch_tree.column('dtype', width=70, anchor='w')
        self.watch_tree.column('label', width=110, anchor='w')
        self.watch_tree.column('value', width=90, anchor='e')
        self.watch_tree.pack(side='left', fill='both', expand=True)
        wsb = ttk.Scrollbar(frm_watch, orient='vertical',
                            command=self.watch_tree.yview)
        wsb.pack(side='right', fill='y')
        self.watch_tree.configure(yscrollcommand=wsb.set)

        frm_wbtn = ttk.Frame(self)
        frm_wbtn.pack(fill='x', **pad)
        ttk.Button(frm_wbtn, text='Add manual',
                   command=self.add_watch_manual).pack(side='left', padx=2)
        ttk.Button(frm_wbtn, text='Copiar direccion',
                   command=self.copy_watch_addr).pack(side='left', padx=2)
        ttk.Button(frm_wbtn, text='Editar',
                   command=self.edit_watch).pack(side='left', padx=2)
        ttk.Button(frm_wbtn, text='Quitar',
                   command=self.remove_watch).pack(side='left', padx=2)
        ttk.Button(frm_wbtn, text='Quitar todos',
                   command=self.clear_watches).pack(side='left', padx=2)

        self.lbl_hk = ttk.Label(
            self,
            text='Hotkeys globales: Ctrl+Shift+ F8=menor F9=igual F10=mayor F11=refresh',
            foreground='#444', font=('Segoe UI', 8)
        )
        self.lbl_hk.pack(**pad)

    def _scan_note(self):
        if self.scanner.last_scan_truncated:
            return f' - truncado ({self.scanner.last_scan_truncated_reason})'
        return ''

    def _change_results_page(self, delta):
        total = len(self.scanner.candidates)
        if total <= 0:
            return
        max_page = max(0, (total - 1) // RESULTS_PAGE_SIZE)
        self.results_page = max(0, min(max_page, self.results_page + delta))
        self._update_results()

    def _reset_results_page(self):
        self.results_page = 0

    def _parse_inline_range(self, txt):
        if dtype_is_string(self.scanner.dtype) or dtype_is_flag(self.scanner.dtype):
            return None

        match = RANGE_VALUE_RE.match(txt.strip())
        if not match:
            return None

        a_txt, b_txt = match.groups()
        try:
            if self.scanner.dtype in {'f32 (float)', 'f64 (double)'}:
                vmin = float(a_txt)
                vmax = float(b_txt)
            else:
                vmin = int(a_txt, 0)
                vmax = int(b_txt, 0)
        except ValueError as e:
            raise ValueError(f'Rango invalido: {e}') from e

        if vmin > vmax:
            vmin, vmax = vmax, vmin
        return vmin, vmax

    def _start_first_scan_range(self, vmin, vmax):
        def task():
            t0 = time.time()

            def progress(scanned, total, hits):
                pct = (scanned / total * 100) if total else 0
                self.after(0, lambda: self.progress.configure(value=pct))
                self.after(0, lambda: self.lbl_count.configure(
                    text=f'Range scan... {hits} hits ({scanned // (1024 * 1024)} MB)'
                ))

            self.scanner.first_scan_range(vmin, vmax, progress_cb=progress)
            elapsed = time.time() - t0
            self.after(0, lambda: self.progress.configure(value=100))
            self.after(0, lambda: self._update_results(reset_page=True))
            self.after(0, lambda: self.lbl_count.configure(
                text=f'{len(self.scanner.candidates)} candidatos ({elapsed:.1f}s){self._scan_note()}'
            ))

        self._start_thread(task)

    def _setup_hotkeys(self):
        listener = HotkeyListener(self._on_global_hotkey)
        listener.add(HK_DECREASED, MOD_CONTROL | MOD_SHIFT, VK_F8)
        listener.add(HK_UNCHANGED, MOD_CONTROL | MOD_SHIFT, VK_F9)
        listener.add(HK_INCREASED, MOD_CONTROL | MOD_SHIFT, VK_F10)
        listener.add(HK_REFRESH, MOD_CONTROL | MOD_SHIFT, VK_F11)
        listener.start()

    def _on_global_hotkey(self, hk_id):
        # Llamado desde el thread del listener: re-enviar al main thread
        if hk_id == HK_DECREASED:
            self.after(0, lambda: self.next_scan('lt'))
        elif hk_id == HK_UNCHANGED:
            self.after(0, lambda: self.next_scan('eq'))
        elif hk_id == HK_INCREASED:
            self.after(0, lambda: self.next_scan('gt'))
        elif hk_id == HK_REFRESH:
            self.after(0, self.refresh_values)

    def _on_enter(self, _evt):
        if not self.scanner.candidates:
            self.first_scan()
        else:
            self.next_scan('eq_val')

    # --------- Procesos ---------
    def refresh_processes(self):
        try:
            procs = list_processes()
        except Exception as e:
            messagebox.showerror('Error', f'No pude listar procesos: {e}')
            return
        procs.sort(key=lambda p: (0 if 'wow' in p[1].lower() else 1, p[1].lower()))
        self._proc_list = procs
        self.proc_combo['values'] = [
            f'{p[1]}  (PID {p[0]})' for p in procs
        ]
        if procs:
            self.proc_combo.current(0)

    def open_process(self):
        idx = self.proc_combo.current()
        if idx < 0:
            return
        pid, name, _full = self._proc_list[idx]
        try:
            self.scanner.open(pid)
            self.scanner.proc_name = name
            self.lbl_status.config(
                text=f'Abierto: {name} (PID {pid})', foreground='green'
            )
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.lbl_status.config(text=f'Fallo: {e}', foreground='red')

    # --------- Helpers ---------
    def _ensure_open(self):
        if not self.scanner.handle:
            messagebox.showwarning('Sin proceso', 'Abre un proceso primero')
            return False
        return True

    def _start_thread(self, target):
        if self.scanning:
            return
        self.scanning = True

        def run():
            try:
                target()
            except Exception as e:
                self.after(0, lambda: messagebox.showerror('Error', str(e)))
            finally:
                self.scanning = False
        threading.Thread(target=run, daemon=True).start()

    # --------- Scans ---------
    def first_scan(self):
        if not self._ensure_open():
            return
        self.scanner.dtype = self.dtype_var.get()
        self.scanner.aligned = self.aligned_var.get()
        raw_value = self.val_entry.get()
        if not raw_value.strip():
            if dtype_is_string(self.scanner.dtype):
                messagebox.showinfo(
                    'No soportado',
                    'El snapshot inicial sin valor solo esta soportado para tipos numericos'
                )
                return

            def task():
                t0 = time.time()

                def progress(scanned, total, saved_regions):
                    pct = (scanned / total * 100) if total else 0
                    self.after(0, lambda: self.progress.configure(value=pct))
                    self.after(0, lambda: self.lbl_count.configure(
                        text=f'Snapshot... {saved_regions} regiones ({scanned // (1024 * 1024)} MB)'
                    ))

                self.scanner.snapshot_scan(progress_cb=progress)
                elapsed = time.time() - t0
                snap_mb = sum(meta['size'] for meta in self.scanner.snapshot_regions) / (1024 * 1024)
                self.after(0, lambda: self.progress.configure(value=100))
                self.after(0, lambda: self._update_results(reset_page=True))
                self.after(0, lambda: self.lbl_count.configure(
                    text=(
                        f'Snapshot listo: {len(self.scanner.snapshot_regions)} regiones, '
                        f'{snap_mb:.1f} MB ({elapsed:.1f}s). '
                        f'Usa = prev / != prev / MENOR / MAYOR'
                    )
                ))

            self._start_thread(task)
            return

        try:
            range_values = self._parse_inline_range(raw_value)
        except Exception as e:
            messagebox.showerror('Rango invalido', str(e))
            return
        if range_values is not None:
            self._start_first_scan_range(*range_values)
            return

        try:
            value = self.scanner.parse_value(raw_value)
        except Exception as e:
            messagebox.showerror('Valor invalido', str(e))
            return

        def task():
            t0 = time.time()

            def progress(scanned, total, hits):
                pct = (scanned / total * 100) if total else 0
                self.after(0, lambda: self.progress.configure(value=pct))
                self.after(0, lambda: self.lbl_count.configure(
                    text=f'Escaneando... {hits} hits ({scanned // (1024 * 1024)} MB)'
                ))

            self.scanner.first_scan(value, progress_cb=progress)
            elapsed = time.time() - t0
            self.after(0, lambda: self.progress.configure(value=100))
            self.after(0, lambda: self._update_results(reset_page=True))
            self.after(0, lambda: self.lbl_count.configure(
                text=f'{len(self.scanner.candidates)} candidatos ({elapsed:.1f}s){self._scan_note()}'
            ))

        self._start_thread(task)

    def first_scan_range(self):
        if not self._ensure_open():
            return
        self.scanner.dtype = self.dtype_var.get()
        if dtype_is_string(self.scanner.dtype) or dtype_is_flag(self.scanner.dtype):
            messagebox.showinfo(
                'No soportado',
                'RANGE solo esta disponible para tipos numericos no-flag'
            )
            return
        self.scanner.aligned = self.aligned_var.get()
        txt = self.val_entry.get().strip()
        try:
            range_values = self._parse_inline_range(txt)
        except Exception as e:
            messagebox.showerror('Rango invalido', str(e))
            return
        if range_values is None:
            messagebox.showerror(
                'Formato invalido',
                'Para rango escribe min-max  (ej: -330--320)'
            )
            return
        self._start_first_scan_range(*range_values)

    def new_scan(self):
        self.scanner.clear_candidates()
        self.scanner.clear_snapshot()
        self.scanner._reset_scan_flags()
        self.progress.configure(value=0)
        self.lbl_count.configure(text='Sin candidatos')
        self._update_results(reset_page=True)

    def next_scan(self, op):
        if not self._ensure_open():
            return
        if not self.scanner.candidates:
            if self.scanner.has_snapshot():
                if op not in {'eq', 'ne', 'lt', 'gt'}:
                    messagebox.showinfo(
                        'Snapshot activo',
                        'Tras un snapshot inicial sin valor, usa primero = prev, != prev, MENOR o MAYOR'
                    )
                    return
                if not self.scanner.snapshot_matches_current_config():
                    messagebox.showerror(
                        'Snapshot incompatible',
                        'El snapshot guardado no coincide con el tipo o la alineacion actuales'
                    )
                    return

                def task():
                    t0 = time.time()

                    def progress(scanned, total, hits):
                        pct = (scanned / total * 100) if total else 0
                        self.after(0, lambda: self.progress.configure(value=pct))
                        self.after(0, lambda: self.lbl_count.configure(
                            text=f'Comparando snapshot... {hits} hits ({scanned // (1024 * 1024)} MB)'
                        ))

                    self.scanner.scan_from_snapshot(op, progress_cb=progress)
                    elapsed = time.time() - t0
                    self.after(0, lambda: self.progress.configure(value=100))
                    self.after(0, lambda: self._update_results(reset_page=True))
                    self.after(0, lambda: self.lbl_count.configure(
                        text=f'{len(self.scanner.candidates)} candidatos ({elapsed:.2f}s){self._scan_note()}'
                    ))

                self._start_thread(task)
                return

            messagebox.showinfo('Sin candidatos', 'Haz un First Scan primero')
            return
        if dtype_is_string(self.scanner.dtype) and op in {'lt_val', 'gt_val', 'lt', 'gt'}:
            messagebox.showinfo(
                'No soportado',
                'Los strings solo soportan = valor, != valor, = prev y != prev'
            )
            return
        value = None
        if op.endswith('_val'):
            try:
                value = self.scanner.parse_value(self.val_entry.get())
            except Exception as e:
                messagebox.showerror('Valor invalido', str(e))
                return

        def task():
            t0 = time.time()
            self.scanner.next_scan(op, value)
            elapsed = time.time() - t0
            self.after(0, lambda: self._update_results(reset_page=True))
            self.after(0, lambda: self.lbl_count.configure(
                text=f'{len(self.scanner.candidates)} candidatos ({elapsed:.2f}s){self._scan_note()}'
            ))

        self._start_thread(task)

    def refresh_values(self):
        if not self._ensure_open():
            return
        if not self.scanner.candidates:
            return
        self.scanner.refresh_values()
        self._update_results()

    def _update_results(self, reset_page=False):
        if reset_page:
            self._reset_results_page()

        self.tree.delete(*self.tree.get_children())
        total = len(self.scanner.candidates)
        if total <= 0:
            self.lbl_results_page.config(text='Sin resultados')
            self.btn_prev_page.state(['disabled'])
            self.btn_next_page.state(['disabled'])
            return

        max_page = max(0, (total - 1) // RESULTS_PAGE_SIZE)
        if self.results_page > max_page:
            self.results_page = max_page

        start = self.results_page * RESULTS_PAGE_SIZE
        page = self.scanner.get_candidate_page(start, RESULTS_PAGE_SIZE)
        for addr, val in page:
            if isinstance(val, float):
                val_str = f'{val:.4f}'
            else:
                val_str = str(val)
            self.tree.insert('', 'end', values=(f'0x{addr:X}', val_str))

        end = start + len(page)
        self.lbl_results_page.config(
            text=f'Mostrando {start + 1}-{end} de {total}'
        )

        if self.results_page <= 0:
            self.btn_prev_page.state(['disabled'])
        else:
            self.btn_prev_page.state(['!disabled'])

        if self.results_page >= max_page:
            self.btn_next_page.state(['disabled'])
        else:
            self.btn_next_page.state(['!disabled'])

    def copy_addr(self):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        addr = item['values'][0]
        self.clipboard_clear()
        self.clipboard_append(str(addr))
        self.lbl_status.config(text=f'Copiado: {addr}')

    def remove_selected_candidates(self):
        sel = self.tree.selection()
        if not sel:
            return

        remove_addrs = set()
        for iid in sel:
            item = self.tree.item(iid)
            values = item.get('values', [])
            if not values:
                continue
            addr_str = str(values[0])
            if not addr_str.startswith('0x'):
                continue
            try:
                remove_addrs.add(int(addr_str, 16))
            except ValueError:
                continue

        if not remove_addrs:
            return

        source = self.scanner.candidates
        if isinstance(source, NumericCandidateFile):
            fmt = DTYPES[self.scanner.dtype][0]
            new_store = NumericCandidateFile(fmt)
            kept = 0
            for addr, val in source:
                if addr in remove_addrs:
                    continue
                new_store.append(addr, val)
                kept += 1
            if kept == 0:
                new_store.close()
                self.scanner.set_candidates([])
            else:
                new_store.finalize()
                self.scanner.set_candidates(new_store)
        else:
            self.scanner.set_candidates([
                (addr, val) for addr, val in source if addr not in remove_addrs
            ])

        self._update_results()
        self.lbl_count.configure(text=f'{len(self.scanner.candidates)} candidatos')
        self.lbl_status.config(text=f'Quitados {len(remove_addrs)} candidatos')

    def copy_watch_addr(self):
        sel = self.watch_tree.selection()
        if not sel:
            return
        item = self.watch_tree.item(sel[0])
        values = item.get('values', [])
        if not values:
            return
        addr = str(values[0])
        self.clipboard_clear()
        self.clipboard_append(addr)
        self.lbl_status.config(text=f'Copiado watch: {addr}')

    # --------- Watches ---------
    def _load_watches(self):
        try:
            if os.path.exists(WATCHES_FILE):
                with open(WATCHES_FILE, 'r', encoding='utf-8') as f:
                    self.watches = json.load(f)
        except Exception as e:
            print(f'[!] No pude cargar watches: {e}', file=sys.stderr)
            self.watches = []

    def _save_watches(self):
        try:
            with open(WATCHES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.watches, f, indent=2)
        except Exception as e:
            print(f'[!] No pude guardar watches: {e}', file=sys.stderr)

    def _on_close(self):
        self._save_watches()
        try:
            self.scanner.close()
        except Exception:
            pass
        self.destroy()

    def _read_watch_value(self, w):
        if not self.scanner.handle:
            return None, None
        resolved_addr = self.scanner.resolve_watch_address(w)
        if resolved_addr is None:
            return None, None
        if dtype_is_string(w['dtype']):
            size = int(w.get('size') or DEFAULT_STRING_WATCH_BYTES)
            return resolved_addr, self.scanner._read_string_preview(resolved_addr, size)
        fmt, size = DTYPES.get(w['dtype'], ('<f', 4))
        data = self.scanner.read(resolved_addr, size)
        if not data or len(data) < size:
            return resolved_addr, None
        try:
            return resolved_addr, struct.unpack(fmt, data[:size])[0]
        except struct.error:
            return resolved_addr, None

    def _refresh_watches_loop(self):
        selected = tuple(self.watch_tree.selection())
        focus = self.watch_tree.focus()
        current_items = set(self.watch_tree.get_children())
        wanted_items = set()

        for i, w in enumerate(self.watches):
            iid = str(i)
            wanted_items.add(iid)
            resolved_addr, val = self._read_watch_value(w)
            dtype_label = w['dtype'].split()[0]
            if dtype_is_string(w['dtype']):
                dtype_label = f'str[{int(w.get("size") or DEFAULT_STRING_WATCH_BYTES)}]'

            if resolved_addr is None:
                addr_label = w.get('addr_expr') or (
                    f'0x{w["addr"]:X}' if 'addr' in w else '???'
                )
            else:
                addr_label = f'0x{resolved_addr:X}'
            if val is None:
                val_str = '???'
            elif isinstance(val, float):
                val_str = f'{val:.4f}'
            else:
                val_str = str(val)

            values = (
                addr_label,
                dtype_label,
                w.get('label', ''),
                val_str,
            )

            if iid in current_items:
                self.watch_tree.item(iid, values=values)
                self.watch_tree.move(iid, '', i)
            else:
                self.watch_tree.insert('', 'end', iid=iid, values=values)

        stale_items = current_items - wanted_items
        if stale_items:
            self.watch_tree.delete(*stale_items)

        kept_selection = [iid for iid in selected if self.watch_tree.exists(iid)]
        if kept_selection:
            self.watch_tree.selection_set(kept_selection)
        if focus and self.watch_tree.exists(focus):
            self.watch_tree.focus(focus)
        self.after(200, self._refresh_watches_loop)

    def add_candidate_to_watch(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Sin seleccion',
                                'Selecciona un candidato en la lista de arriba')
            return
        item = self.tree.item(sel[0])
        addr_str = str(item['values'][0])
        if not addr_str.startswith('0x'):
            return
        try:
            addr = int(addr_str, 16)
        except ValueError:
            return
        label = simpledialog.askstring(
            'Etiqueta', 'Nombre para el watch:', parent=self
        ) or ''
        watch_dtype = self.scanner.dtype
        watch = {
            'addr': addr,
            'dtype': watch_dtype,
            'label': label,
        }
        if dtype_is_string(watch_dtype):
            current_value = str(item['values'][1]) if len(item['values']) > 1 else ''
            watch['size'] = max(len(current_value.encode('utf-8')), DEFAULT_STRING_WATCH_BYTES)
        self.watches.append(watch)
        self._save_watches()

    def add_watch_manual(self):
        dlg = WatchDialog(self, title='Nuevo watch')
        if dlg.result:
            self.watches.append(dlg.result)
            self._save_watches()

    def edit_watch(self):
        sel = self.watch_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        dlg = WatchDialog(self, title='Editar watch', initial=self.watches[idx])
        if dlg.result:
            self.watches[idx] = dlg.result
            self._save_watches()

    def remove_watch(self):
        sel = self.watch_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        del self.watches[idx]
        self._save_watches()

    def clear_watches(self):
        if not self.watches:
            return
        if messagebox.askyesno('Confirmar', f'Borrar {len(self.watches)} watches?'):
            self.watches = []
            self._save_watches()


class WatchDialog(tk.Toplevel):
    """Dialog para crear/editar un watch."""

    def __init__(self, parent, title='Watch', initial=None):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)
        self.attributes('-topmost', True)
        self.result = None
        self.parent = parent

        initial = initial or {}
        init_addr = initial.get('addr_expr')
        if not init_addr and 'addr' in initial:
            init_addr = f'0x{initial["addr"]:X}'
        init_dtype = initial.get('dtype', 'f32 (float)')
        init_label = initial.get('label', '')
        init_size = str(initial.get('size', ''))
        init_offsets = parent.scanner.format_watch_path_steps(initial)

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text='Direccion base (0x..., decimal o Wow.exe+0x...):').grid(
            row=0, column=0, sticky='w', pady=2
        )
        self.addr_var = tk.StringVar(value=init_addr)
        ttk.Entry(frm, textvariable=self.addr_var, width=30,
                  font=('Consolas', 11)).grid(row=1, column=0, sticky='ew', pady=2)

        ttk.Label(frm, text='Pasos de cadena (uno por linea: deref, +0x10, -0x8):').grid(
            row=2, column=0, sticky='w', pady=(8, 2)
        )
        self.offsets_txt = tk.Text(frm, width=30, height=4, font=('Consolas', 10))
        self.offsets_txt.grid(row=3, column=0, sticky='ew', pady=2)
        if init_offsets:
            self.offsets_txt.insert('1.0', init_offsets)
        ttk.Label(
            frm,
            text='Ejemplo: deref / +0x60 / deref / +0x28 / +0x19E0 / -0xA8',
            foreground='#444'
        ).grid(row=4, column=0, sticky='w', pady=(0, 4))

        ttk.Label(frm, text='Tipo:').grid(row=5, column=0, sticky='w', pady=(8, 2))
        self.dtype_var = tk.StringVar(value=init_dtype)
        ttk.Combobox(frm, textvariable=self.dtype_var,
                     values=list(DTYPES.keys()), state='readonly').grid(
            row=6, column=0, sticky='ew', pady=2
        )

        ttk.Label(frm, text='Bytes a leer (solo string, opcional):').grid(
            row=7, column=0, sticky='w', pady=(8, 2)
        )
        self.size_var = tk.StringVar(value=init_size)
        ttk.Entry(frm, textvariable=self.size_var, width=30).grid(
            row=8, column=0, sticky='ew', pady=2
        )

        ttk.Label(frm, text='Etiqueta:').grid(row=9, column=0, sticky='w', pady=(8, 2))
        self.label_var = tk.StringVar(value=init_label)
        ttk.Entry(frm, textvariable=self.label_var, width=30).grid(
            row=10, column=0, sticky='ew', pady=2
        )

        btns = ttk.Frame(frm)
        btns.grid(row=11, column=0, sticky='e', pady=(10, 0))
        ttk.Button(btns, text='OK', command=self._ok).pack(side='left', padx=4)
        ttk.Button(btns, text='Cancel', command=self.destroy).pack(side='left')

        self.offsets_txt.bind('<Return>', self._on_offsets_return)
        self.offsets_txt.bind('<KP_Enter>', self._on_offsets_return)
        self.bind('<Return>', self._on_return_key)
        self.bind('<KP_Enter>', self._on_return_key)
        self.bind('<Escape>', lambda e: self.destroy())
        self.grab_set()
        self.wait_window()

    def _on_offsets_return(self, _evt):
        self.offsets_txt.insert('insert', '\n')
        return 'break'

    def _on_return_key(self, _evt):
        if self.focus_get() == self.offsets_txt:
            return 'break'
        self._ok()
        return 'break'

    def _ok(self):
        addr_txt = self.addr_var.get().strip()
        offsets_raw = self.offsets_txt.get('1.0', 'end').strip()
        try:
            base_addr = self.parent.scanner.resolve_address_expr(addr_txt)
        except ValueError:
            messagebox.showerror(
                'Error',
                'Direccion invalida. Usa 0x..., decimal o Modulo+0xOFFSET',
                parent=self
            )
            return

        uses_deref = self.parent.scanner.watch_text_uses_deref(offsets_raw)
        path_steps = []
        legacy_offsets = []
        try:
            if uses_deref:
                path_steps = self.parent.scanner.parse_watch_path_steps(offsets_raw)
            else:
                legacy_offsets = self.parent.scanner.parse_legacy_watch_offsets(offsets_raw)
        except ValueError as e:
            messagebox.showerror('Error', str(e), parent=self)
            return
        dtype = self.dtype_var.get()
        if dtype not in DTYPES:
            messagebox.showerror('Error', 'Tipo invalido', parent=self)
            return
        result = {
            'dtype': dtype,
            'label': self.label_var.get().strip(),
        }
        if uses_deref:
            result['addr_expr'] = addr_txt
            result['path_steps'] = path_steps
            result['addr'] = base_addr
        elif legacy_offsets or WATCH_EXPR_RE.match(addr_txt) or not addr_txt.lower().startswith('0x'):
            result['addr_expr'] = addr_txt
            result['offsets'] = legacy_offsets
            result['addr'] = base_addr
        else:
            result['addr'] = base_addr
        if dtype_is_string(dtype):
            size_txt = self.size_var.get().strip()
            if size_txt:
                try:
                    size = int(size_txt)
                except ValueError:
                    messagebox.showerror('Error', 'Bytes invalidos', parent=self)
                    return
            else:
                size = DEFAULT_STRING_WATCH_BYTES
            if size < 1 or size > MAX_STRING_WATCH_BYTES:
                messagebox.showerror(
                    'Error',
                    f'Los bytes deben estar entre 1 y {MAX_STRING_WATCH_BYTES}',
                    parent=self
                )
                return
            result['size'] = size
        self.result = result
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == '__main__':
    main()
