#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ELF 打包器：凸包模式（UPX 风格）
- 使用单一 PT_LOAD 凸包覆盖所有原始段
- 彻底解决虚拟地址空隙问题
- Stub 直接在凸包内恢复数据
- 保持原始虚拟地址和符号完全有效
"""

import argparse
import json
import os
import random
import subprocess
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path

import lief

# ================= Magic values (must match delete.c) =================
MAGIC64_OEP       = 0x1111111122222222
MAGIC64_TEXT_ADDR = 0x3333333344444444
MAGIC64_TEXT_SIZE = 0x5555555566666666
MAGIC64_VOFFSET   = 0x7777777788888888
MAGIC64_TEXT_OFF  = 0x99999999AAAABBBB
MAGIC64_RETAIN_INTERVAL = 0xAAAAAAAA11111111
MAGIC64_DELETE_SIZE     = 0xBBBBBBBB22222222
MAGIC64_TOTAL_BLOCKS    = 0xCCCCCCCC33333333
MAGIC64_CONVEX_MIN_VADDR = 0xEEEEEEEE66666666

MAGIC32_OEP       = 0x22222222
MAGIC32_TEXT_ADDR = 0x44444444
MAGIC32_TEXT_SIZE = 0x66666666
MAGIC32_VOFFSET   = 0x88888888
MAGIC32_TEXT_OFF  = 0xAAAABBBB
MAGIC32_RETAIN_INTERVAL = 0x11111111
MAGIC32_DELETE_SIZE     = 0x55555555
MAGIC32_TOTAL_BLOCKS    = 0x77777777
MAGIC32_CONVEX_MIN_VADDR = 0xEEEE6666

TARGET_FILE = "target.elf"
OUTPUT_FILE = "target_packed.elf"
TEMP_FILE = "packed_temp.elf"

ARCH_I386 = 3
ARCH_ARM = 40
ARCH_X86_64 = 62
ARCH_AARCH64 = 183
ARCH_MIPS = 8
ARCH_PPC = 20
ARCH_SPARC = 2
ARCH_M68K = 4
ARCH_SH = 42
ARCH_OR1K = 92
ARCH_ARC = 93
ARCH_XTENSA = 94
ARCH_NIOS2 = 113

ARCH_SPECS = {
    "x86_64": {
        "machine": ARCH_X86_64,
        "bits": 64,
        "stub_name": "stub_delete_x86_64.so",
        "legacy_stub_names": ["stub_delete64.so"],
        "default_cc": "gcc",
        "cflags": ["-m64", "-mno-sse"],
    },
    "i386": {
        "machine": ARCH_I386,
        "bits": 32,
        "stub_name": "stub_delete_i386.so",
        "legacy_stub_names": ["stub_delete32.so"],
        "default_cc": "gcc",
        "cflags": ["-m32"],
    },
    "arm": {
        "machine": ARCH_ARM,
        "bits": 32,
        "stub_name": "stub_delete_arm.so",
        "legacy_stub_names": [],
        "default_cc": "arm-linux-gnueabihf-gcc",
        "cflags": ["-fomit-frame-pointer"],
    },
    "aarch64": {
        "machine": ARCH_AARCH64,
        "bits": 64,
        "stub_name": "stub_delete_aarch64.so",
        "legacy_stub_names": [],
        "default_cc": "aarch64-linux-gnu-gcc",
        "cflags": [],
    },
    # inject_tmp 默认 delete.c 目前覆盖:
    # x86_64/i386/arm/aarch64/mips/ppc/sh/m68k
    # 其余架构默认走外部/预编译 stub（或 --stub-source 自定义源码）。
    "mips": {
        "machine": ARCH_MIPS,
        "bits": 32,
        "stub_name": "stub_delete_mips.so",
        "legacy_stub_names": [],
        "default_cc": "mips-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": True,
    },
    "ppc": {
        "machine": ARCH_PPC,
        "bits": 32,
        "stub_name": "stub_delete_ppc.so",
        "legacy_stub_names": ["stub_delete_powerpc.so"],
        "default_cc": "powerpc-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": True,
    },
    "sparc": {
        "machine": ARCH_SPARC,
        "bits": 32,
        "stub_name": "stub_delete_sparc.so",
        "legacy_stub_names": [],
        "default_cc": "sparc-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": False,
    },
    "m68k": {
        "machine": ARCH_M68K,
        "bits": 32,
        "stub_name": "stub_delete_m68k.so",
        "legacy_stub_names": [],
        "default_cc": "m68k-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": True,
    },
    "sh": {
        "machine": ARCH_SH,
        "bits": 32,
        "stub_name": "stub_delete_sh.so",
        "legacy_stub_names": ["stub_delete_sh4.so"],
        "default_cc": "sh4-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": True,
    },
    "or1k": {
        "machine": ARCH_OR1K,
        "bits": 32,
        "stub_name": "stub_delete_or1k.so",
        "legacy_stub_names": ["stub_delete_openrisc.so"],
        "default_cc": "or1k-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": False,
    },
    "arc": {
        "machine": ARCH_ARC,
        "bits": 32,
        "stub_name": "stub_delete_arc.so",
        "legacy_stub_names": ["stub_delete_arcompact.so"],
        "default_cc": "arc-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": False,
    },
    "xtensa": {
        "machine": ARCH_XTENSA,
        "bits": 32,
        "stub_name": "stub_delete_xtensa.so",
        "legacy_stub_names": [],
        "default_cc": "xtensa-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": False,
    },
    "nios2": {
        "machine": ARCH_NIOS2,
        "bits": 32,
        "stub_name": "stub_delete_nios2.so",
        "legacy_stub_names": [],
        "default_cc": "nios2-linux-gnu-gcc",
        "cflags": [],
        "auto_build_supported": False,
    },
}

SUPPORTED_MACHINE_TO_ARCH = {
    int(spec["machine"]): key for key, spec in ARCH_SPECS.items()
}

MACHINE_ALIASES = {
    "x86_64": ARCH_X86_64,
    "amd64": ARCH_X86_64,
    "i386": ARCH_I386,
    "x86": ARCH_I386,
    "arm": ARCH_ARM,
    "arm32": ARCH_ARM,
    "aarch64": ARCH_AARCH64,
    "arm64": ARCH_AARCH64,
    "mips": ARCH_MIPS,
    "ppc": ARCH_PPC,
    "powerpc": ARCH_PPC,
    "sparc": ARCH_SPARC,
    "m68k": ARCH_M68K,
    "sh": ARCH_SH,
    "superh": ARCH_SH,
    "or1k": ARCH_OR1K,
    "openrisc": ARCH_OR1K,
    "arc": ARCH_ARC,
    "arcompact": ARCH_ARC,
    "xtensa": ARCH_XTENSA,
    "nios2": ARCH_NIOS2,
}

MAGIC_MAP_64 = {
    'OEP_ADDR': MAGIC64_OEP,
    'TEXT_ADDR': MAGIC64_TEXT_ADDR,
    'TEXT_SIZE': MAGIC64_TEXT_SIZE,
    'TEXT_OFFSET': MAGIC64_TEXT_OFF,
    'STUB_VOFFSET': MAGIC64_VOFFSET,
    'RETAIN_INTERVAL': MAGIC64_RETAIN_INTERVAL,
    'DELETE_SIZE': MAGIC64_DELETE_SIZE,
    'TOTAL_BLOCKS': MAGIC64_TOTAL_BLOCKS,
    'CONVEX_MIN_VADDR': MAGIC64_CONVEX_MIN_VADDR,
    'HEADER_VADDR':     0x1A1A1A1A2A2A2A2A,
    'HEADER_OFFSET':    0x2B2B2B2B3B3B3B3B,
    'HEADER_SIZE':      0x3C3C3C3C4C4C4C4C,
    'HEADER_RETAIN':    0x4D4D4D4D5D5D5D5D,
    'HEADER_DELETE':    0x5E5E5E5E6E6E6E6E,
    'HEADER_BLOCKS':    0x6F6F6F6F7F7F7F7F,
    'REGION_OFFSETS':   0xDDDDDDDD55555555,
    'PROTECTED_COUNT':  0xFFFFFFFF22222222,
    'PROTECTED_ADDRS':  0xAAAAAAAA66666666,
    'PROTECTED_SIZES':  0xBBBBBBBB77777777,
    'PROTECTED_OFFSETS':0xCCCCCCCC88888888,
}

MAGIC_MAP_32 = {
    'OEP_ADDR': MAGIC32_OEP,
    'TEXT_ADDR': MAGIC32_TEXT_ADDR,
    'TEXT_SIZE': MAGIC32_TEXT_SIZE,
    'TEXT_OFFSET': MAGIC32_TEXT_OFF,
    'STUB_VOFFSET': MAGIC32_VOFFSET,
    'RETAIN_INTERVAL': MAGIC32_RETAIN_INTERVAL,
    'DELETE_SIZE': MAGIC32_DELETE_SIZE,
    'TOTAL_BLOCKS': MAGIC32_TOTAL_BLOCKS,
    'CONVEX_MIN_VADDR': MAGIC32_CONVEX_MIN_VADDR,
    'HEADER_VADDR':     0x1A2A1A2A,
    'HEADER_OFFSET':    0x2B3B2B3B,
    'HEADER_SIZE':      0x3C4C3C4C,
    'HEADER_RETAIN':    0x4D5D4D5D,
    'HEADER_DELETE':    0x5E6E5E6E,
    'HEADER_BLOCKS':    0x6F7F6F7F,
    'REGION_OFFSETS':   0xDDDD5555,
    'PROTECTED_COUNT':  0xFF222222,
    'PROTECTED_ADDRS':  0xAA666666,
    'PROTECTED_SIZES':  0xBB777777,
    'PROTECTED_OFFSETS':0xCC888888,
}

AUTO_BLOCK_CANDIDATES = (8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512)
AUTO_INSERT_CANDIDATES = (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)
STUB_MAX_REGIONS = 64

STUB_PATCH_SYMBOLS = (
    'OEP_ADDR', 'STUB_VOFFSET', 'REGION_COUNT',
    'REGION_ADDRS', 'REGION_SIZES', 'REGION_RETAINS', 'REGION_DELETES', 'REGION_BLOCKS',
    'CONVEX_MIN_VADDR',
    'HEADER_VADDR', 'HEADER_OFFSET', 'HEADER_SIZE', 'HEADER_RETAIN', 'HEADER_DELETE', 'HEADER_BLOCKS',
    'REGION_OFFSETS',
    'PROTECTED_COUNT', 'PROTECTED_ADDRS', 'PROTECTED_SIZES', 'PROTECTED_OFFSETS',
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 基础辅助函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def is_elf64(binary):
    cls = binary.header.identity_class
    if hasattr(lief.ELF, "CLASS"):
        return cls == lief.ELF.CLASS.ELF64
    if hasattr(lief.ELF, "ELF_CLASS"):
        return cls == lief.ELF.ELF_CLASS.CLASS64
    try:
        return int(cls) == 2
    except Exception:
        return False


def detect_target_arch(binary) -> str:
    machine = int(binary.header.machine_type)
    arch_key, _ = resolve_arch_from_machine(machine)
    if arch_key is not None:
        return arch_key
    name = getattr(binary.header.machine_type, "name", str(binary.header.machine_type))
    raise RuntimeError(f"[-] 暂不支持的 ELF 架构: machine={machine} ({name})")


def parse_machine_arg(machine_arg: str) -> int | None:
    raw = (machine_arg or "").strip()
    if not raw:
        return None
    key = raw.lower().replace("-", "_")
    if key in MACHINE_ALIASES:
        return int(MACHINE_ALIASES[key])
    try:
        return int(raw, 0)
    except Exception as e:
        raise RuntimeError(f"[-] 无法解析 --machine: {machine_arg}") from e


def resolve_arch_from_machine(machine: int | None) -> tuple[str | None, dict | None]:
    if machine is None:
        return None, None
    arch_key = SUPPORTED_MACHINE_TO_ARCH.get(int(machine))
    if arch_key is None:
        return None, None
    return arch_key, ARCH_SPECS[arch_key]


def seg_has_exec(seg) -> bool:
    try:
        return (seg.flags & lief.ELF.Segment.FLAGS.X) != 0
    except TypeError:
        return (int(seg.flags) & int(lief.ELF.Segment.FLAGS.X)) != 0


def seg_has_write(seg) -> bool:
    try:
        return (seg.flags & lief.ELF.Segment.FLAGS.W) != 0
    except TypeError:
        return (int(seg.flags) & int(lief.ELF.Segment.FLAGS.W)) != 0


def sec_has_alloc(sec) -> bool:
    try:
        return (sec.flags & lief.ELF.Section.FLAGS.ALLOC) != 0
    except TypeError:
        return (int(sec.flags) & int(lief.ELF.Section.FLAGS.ALLOC)) != 0


def sec_has_execinstr(sec) -> bool:
    try:
        return (sec.flags & lief.ELF.Section.FLAGS.EXECINSTR) != 0
    except TypeError:
        return (int(sec.flags) & int(lief.ELF.Section.FLAGS.EXECINSTR)) != 0


def nop_bytes(arch: str, count: int) -> bytes:
    arch = arch.lower()
    if 'aarch64' in arch or 'arm64' in arch:
        nop_insn = b'\x1f\x20\x03\xd5'
        return nop_insn * (count // 4) + nop_insn[:count % 4]
    if 'x86' in arch or 'amd64' in arch or 'i386' in arch:
        return b'\x90' * count
    if 'arm' in arch:
        nop_insn = b'\x00\x00\xa0\xe1'
        return nop_insn * (count // 4) + nop_insn[:count % 4]
    return b'\x00' * count


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def get_stub_blob(stub_binary):
    load_segments = [seg for seg in stub_binary.segments if seg.type == lief.ELF.Segment.TYPE.LOAD]
    if not load_segments:
        raise RuntimeError("[-] Error: No LOAD segments found in stub")

    min_va = min(seg.virtual_address for seg in load_segments)
    max_va = max(seg.virtual_address + seg.physical_size for seg in load_segments)
    blob_size = max_va - min_va

    blob = bytearray(blob_size)
    for seg in load_segments:
        offset = seg.virtual_address - min_va
        content = bytes(seg.content)
        blob[offset:offset + len(content)] = content

    entry_offset = stub_binary.header.entrypoint - min_va
    return blob, entry_offset, min_va


def get_stub_symbol_offsets(stub_binary, min_va: int, symbol_names: tuple[str, ...]) -> dict[str, int]:
    offsets: dict[str, int] = {}
    for name in symbol_names:
        value = None
        for sym in stub_binary.symbols:
            if sym.name == name:
                value = int(sym.value)
                break
        if value is None:
            raise RuntimeError(f"[-] Stub symbol not found: {name}")
        offsets[name] = value - min_va
    return offsets


def resolve_stub_source(base_dir: Path, arch_key: str, override_source: str = "") -> Path:
    if override_source:
        candidate = Path(override_source)
        if not candidate.is_absolute():
            candidate = (base_dir / candidate).resolve()
        if candidate.exists():
            return candidate
        raise RuntimeError(f'[-] 指定的 stub 源码不存在: {candidate}')

    candidates = [
        base_dir / f"stubs/delete_{arch_key}.c",
        base_dir / f"delete_{arch_key}.c",
        base_dir / f"delete.{arch_key}.c",
        base_dir / "delete.c",
    ]
    for p in candidates:
        if p.exists():
            return p
    raise RuntimeError(f'[-] 缺少 stub 源码（已尝试: {[str(x) for x in candidates]}）')


def build_delete_stub(base_dir: Path, arch_key: str, compiler: str, force: bool,
                      source_override: str = "", timeout_sec: int = 120) -> Path:
    spec = ARCH_SPECS[arch_key]
    if not bool(spec.get("auto_build_supported", True)) and not source_override:
        raise RuntimeError(
            f'[-] 架构 {arch_key} 当前不支持基于默认 delete.c 自动构建 stub。'
            f'请提供 --stub-path，或使用 --stub-source 指向该架构的自定义源码。'
        )
    stub_path = base_dir / spec["stub_name"]
    if stub_path.exists() and not force:
        return stub_path

    delete_c = resolve_stub_source(base_dir, arch_key, source_override)

    cmd = [
        compiler,
        "-O0",
        "-fPIC",
        "-shared",
        "-nostdlib",
        "-fvisibility=hidden",
        "-fno-stack-protector",
        "-e",
        "_start",
    ]
    cmd.extend(spec["cflags"])
    cmd.extend(["-o", str(stub_path), str(delete_c)])
    print(f'    [build] {" ".join(cmd)}')

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=max(1, int(timeout_sec)),
        )
    except FileNotFoundError as e:
        raise RuntimeError(f'[-] 构建 stub 失败：未找到编译器 {compiler}') from e
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "").strip() if isinstance(e.stdout, str) else ""
        err = (e.stderr or "").strip() if isinstance(e.stderr, str) else ""
        raise RuntimeError(
            f'[-] 构建 stub 超时（>{int(timeout_sec)}s）: {" ".join(cmd)}\n'
            f'    stdout: {out}\n'
            f'    stderr: {err}\n'
            f'    建议：检查交叉编译器/工具链，或使用 --stub-path 指定预编译 stub，'
            f'或通过 --stub-build-timeout 增大超时。'
        ) from e
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
        raise RuntimeError(
            f'[-] 构建 stub 失败: {" ".join(cmd)}\n'
            f'    stdout: {stdout}\n'
            f'    stderr: {stderr}'
        )

    print(f'    已构建 stub: {stub_path}')
    return stub_path


def resolve_existing_stub(base_dir: Path, arch_key: str) -> Path | None:
    spec = ARCH_SPECS[arch_key]
    candidates = [spec["stub_name"]] + spec["legacy_stub_names"]
    for name in candidates:
        p = base_dir / name
        if p.exists():
            return p
    return None


def build_polluted_text(old_text: bytes, block_size: int, insert_size: int, insert_type: str, arch_name: str):
    if insert_type == 'zero':
        fill = b'\x00' * insert_size
    elif insert_type == 'nop':
        fill = nop_bytes(arch_name, insert_size)
    elif insert_type == 'junk':
        fill = os.urandom(insert_size)
    else:
        raise ValueError("insert_type 必须是 zero、nop 或 junk")

    new_content = bytearray()
    pos = 0
    insert_count = 0
    old_size = len(old_text)

    while pos + block_size <= old_size:
        new_content.extend(old_text[pos:pos + block_size])
        new_content.extend(fill)
        insert_count += 1
        pos += block_size

    if pos < old_size:
        new_content.extend(old_text[pos:])

    return bytes(new_content), insert_count


def patch_value(file_path: Path, offset: int, value: int, width: int):
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        if width == 8:
            f.write(struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF))
        elif width == 4:
            f.write(struct.pack('<I', value & 0xFFFFFFFF))
        else:
            raise ValueError('Unsupported patch width')


def read_back_value(file_path: Path, offset: int, width: int) -> int:
    with open(file_path, 'rb') as f:
        f.seek(offset)
        data = f.read(width)
    if width == 8:
        return struct.unpack('<Q', data)[0]
    if width == 4:
        return struct.unpack('<I', data)[0]
    raise ValueError('Unsupported patch width')


def _elf_phdr_layout(file_path: Path, is64: bool) -> tuple[str, int, int, int]:
    """Read ELF header fields needed to walk program headers."""
    with open(file_path, 'rb') as f:
        ident = f.read(16)
        if len(ident) < 16 or ident[:4] != b'\x7fELF':
            raise RuntimeError(f'[-] 非 ELF 文件: {file_path}')
        ei_data = ident[5]
        if ei_data == 1:
            endian = '<'
        elif ei_data == 2:
            endian = '>'
        else:
            raise RuntimeError('[-] 不支持的 ELF 字节序')

        if is64:
            f.seek(0x20)  # e_phoff
            e_phoff = struct.unpack(endian + 'Q', f.read(8))[0]
            f.seek(0x36)  # e_phentsize
            e_phentsize = struct.unpack(endian + 'H', f.read(2))[0]
            e_phnum = struct.unpack(endian + 'H', f.read(2))[0]
        else:
            f.seek(0x1C)  # e_phoff
            e_phoff = struct.unpack(endian + 'I', f.read(4))[0]
            f.seek(0x2A)  # e_phentsize
            e_phentsize = struct.unpack(endian + 'H', f.read(2))[0]
            e_phnum = struct.unpack(endian + 'H', f.read(2))[0]

    return endian, int(e_phoff), int(e_phentsize), int(e_phnum)


def _elf_phdr_layout_from_bytes(data: bytes, is64: bool) -> tuple[str, int, int, int]:
    """Parse ELF program-header layout from in-memory bytes."""
    if len(data) < 16 or data[:4] != b'\x7fELF':
        raise RuntimeError('[-] 非 ELF 文件（内存）')
    ei_data = data[5]
    if ei_data == 1:
        endian = '<'
    elif ei_data == 2:
        endian = '>'
    else:
        raise RuntimeError('[-] 不支持的 ELF 字节序（内存）')
    if is64:
        e_phoff     = struct.unpack_from(endian + 'Q', data, 0x20)[0]
        e_phentsize = struct.unpack_from(endian + 'H', data, 0x36)[0]
        e_phnum     = struct.unpack_from(endian + 'H', data, 0x38)[0]
    else:
        e_phoff     = struct.unpack_from(endian + 'I', data, 0x1C)[0]
        e_phentsize = struct.unpack_from(endian + 'H', data, 0x2A)[0]
        e_phnum     = struct.unpack_from(endian + 'H', data, 0x2C)[0]
    return endian, int(e_phoff), int(e_phentsize), int(e_phnum)


# Architectures that have mmap(MAP_FIXED|MAP_ANONYMOUS) support in the stub.
# Track A: recover via disk read + mmap_fixed; PT_LOAD is nullified.
# Track B (others): recover in-place from already-mapped polluted data; PT_LOAD kept.
_MMAP_ARCH_KEYS: frozenset[str] = frozenset({'x86_64', 'i386', 'arm', 'aarch64'})


def _arch_supports_mmap(arch_key: str | None) -> bool:
    return arch_key in _MMAP_ARCH_KEYS


def _apply_inplace_insertions(
        file_bytes: bytes,
        is64: bool,
        recoverable_segs: list[dict],
        block_size: int,
        insert_size: int,
        insert_type: str,
        arch_name: str,
) -> tuple[bytes, list[dict]]:
    """
    Apply insertion-pollution in-place to each recoverable PT_LOAD segment.

    For each segment the original file data is replaced with the polluted
    (block-inserted) version.  Zero padding is appended when needed so that
    the next PT_LOAD's alignment invariant  p_offset ≡ p_vaddr (mod p_align)
    is preserved.  All later segment p_offsets and e_shoff are updated
    accordingly.

    Returns:
        (modified_bytes, recoverable_infos)

    Each entry in recoverable_infos has:
        vaddr         – original virtual address of the segment
        size          – original file size (before insertion)
        file_offset   – file offset of the polluted data in modified_bytes
        block_size, insert_size, blocks
    """
    if not recoverable_segs:
        return file_bytes, []

    endian, e_phoff, e_phentsize, e_phnum = _elf_phdr_layout_from_bytes(file_bytes, is64)
    width = 8 if is64 else 4

    off_p_type   = 0
    off_p_offset = 8  if is64 else 4
    off_p_vaddr  = 16 if is64 else 8
    off_p_filesz = 32 if is64 else 16
    off_p_memsz  = 40 if is64 else 20
    off_p_align  = 48 if is64 else 28
    off_e_shoff  = 0x28 if is64 else 0x20

    data = bytearray(file_bytes)

    wfmt = endian + ('Q' if is64 else 'I')

    def read_word(buf: bytearray, off: int) -> int:
        return struct.unpack_from(wfmt, buf, off)[0]

    def write_word(buf: bytearray, off: int, val: int) -> None:
        struct.pack_into(wfmt, buf, off, val)

    def ph_off(ph_idx: int, field_off: int) -> int:
        return e_phoff + ph_idx * e_phentsize + field_off

    def get_ph(buf: bytearray, ph_idx: int, field_off: int) -> int:
        return read_word(buf, ph_off(ph_idx, field_off))

    def set_ph(buf: bytearray, ph_idx: int, field_off: int, val: int) -> None:
        write_word(buf, ph_off(ph_idx, field_off), val)

    sorted_segs = sorted(recoverable_segs, key=lambda s: s['file_offset'])
    recoverable_infos: list[dict] = []
    cumulative_delta = 0

    for seg in sorted_segs:
        orig_file_offset = int(seg['file_offset'])
        orig_file_size   = int(seg['file_size'])
        vaddr            = int(seg['vaddr'])

        current_offset = orig_file_offset + cumulative_delta

        seg_data = bytes(data[current_offset:current_offset + orig_file_size])
        polluted, blocks = build_polluted_text(
            seg_data, block_size, insert_size, insert_type, arch_name)
        polluted_size = len(polluted)
        expansion = polluted_size - orig_file_size

        # Find the next PT_LOAD in file-offset order to compute alignment padding.
        after_orig = current_offset + orig_file_size
        next_off: int | None = None
        next_align: int | None = None
        next_vaddr: int | None = None
        for i in range(e_phnum):
            p_type = struct.unpack_from(endian + 'I', data, ph_off(i, off_p_type))[0]
            if p_type != 1:  # PT_LOAD only
                continue
            p_o = get_ph(data, i, off_p_offset)
            if p_o >= after_orig:
                if next_off is None or p_o < next_off:
                    next_off   = p_o
                    next_align = get_ph(data, i, off_p_align)
                    next_vaddr = get_ph(data, i, off_p_vaddr)

        # Compute zero-padding so next PT_LOAD alignment is maintained.
        padding = 0
        if next_off is not None and next_align and next_align > 1:
            new_next = next_off + expansion
            needed   = int(next_vaddr) % next_align
            current  = new_next % next_align
            if current != needed:
                pad = needed - current
                if pad <= 0:
                    pad += next_align
                padding = int(pad)

        total_expansion = expansion + padding

        # Replace original segment data with polluted + padding in the buffer.
        new_data = bytearray()
        new_data.extend(data[:current_offset])
        new_data.extend(polluted)
        new_data.extend(b'\x00' * padding)
        new_data.extend(data[current_offset + orig_file_size:])
        data = new_data

        # Shift p_offset for all segments whose data starts after this segment.
        for i in range(e_phnum):
            p_o = get_ph(data, i, off_p_offset)
            if p_o >= after_orig:
                set_ph(data, i, off_p_offset, p_o + total_expansion)

        # Update p_filesz / p_memsz for the current recoverable segment.
        for i in range(e_phnum):
            p_o = get_ph(data, i, off_p_offset)
            p_v = get_ph(data, i, off_p_vaddr)
            if p_o == current_offset and p_v == vaddr:
                set_ph(data, i, off_p_filesz, polluted_size)
                p_msz = get_ph(data, i, off_p_memsz)
                if p_msz < polluted_size:
                    set_ph(data, i, off_p_memsz, polluted_size)
                break

        # Update section-header offset if it follows the modified region.
        e_shoff_val = read_word(data, off_e_shoff)
        if e_shoff_val >= after_orig:
            write_word(data, off_e_shoff, e_shoff_val + total_expansion)

        recoverable_infos.append({
            'vaddr':       vaddr,
            'size':        orig_file_size,
            'file_offset': current_offset,
            'block_size':  block_size,
            'insert_size': insert_size,
            'blocks':      blocks,
        })
        cumulative_delta += total_expansion

    return bytes(data), recoverable_infos


def _nullify_recoverable_ptloads(
        output_file: Path,
        is64: bool,
        recoverable_infos: list[dict],
        vaddr_shift: int,
        strip_plaintext: bool,
        prune_bytes: bool,
        prune_pages: bool,
) -> tuple[int, int, str]:
    """
    Rewrite output ELF program headers: convert recoverable PT_LOAD to PT_NULL.

    This keeps immutable PT_LOAD segments mapped by loader, while recoverable
    regions are restored by stub at runtime (UPX-like behavior).
    """
    if not recoverable_infos:
        return 0, 0, 'none'

    targets = {
        (int(r['vaddr']) + int(vaddr_shift), int(r['size']))
        for r in recoverable_infos
    }

    endian, e_phoff, e_phentsize, e_phnum = _elf_phdr_layout(output_file, is64)
    expected_phentsize = 56 if is64 else 32
    if e_phentsize < expected_phentsize:
        raise RuntimeError(f'[-] 异常 Program Header 大小: {e_phentsize}')

    with open(output_file, 'rb') as f:
        data = bytearray(f.read())

    file_size = len(data)
    nulled = 0
    changed_bytes = 0
    target_ph_indices: set[int] = set()
    remove_ranges: list[tuple[int, int]] = []
    all_ph: list[dict] = []

    def _read_u(ph: bytes, off: int, width: int) -> int:
        if width == 8:
            return struct.unpack_from(endian + 'Q', ph, off)[0]
        return struct.unpack_from(endian + 'I', ph, off)[0]

    off_p_type = 0
    off_p_offset = 8 if is64 else 4
    off_p_vaddr = 16 if is64 else 8
    off_p_filesz = 32 if is64 else 16
    off_p_memsz = 40 if is64 else 20
    off_p_align = 48 if is64 else 28
    width = 8 if is64 else 4

    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        ph = bytes(data[ph_off:ph_off + e_phentsize])
        if len(ph) < e_phentsize:
            raise RuntimeError('[-] Program Header 读取失败')

        p_type = struct.unpack_from(endian + 'I', ph, off_p_type)[0]
        p_offset = _read_u(ph, off_p_offset, width)
        p_vaddr = _read_u(ph, off_p_vaddr, width)
        p_filesz = _read_u(ph, off_p_filesz, width)
        p_memsz = _read_u(ph, off_p_memsz, width)
        p_align = _read_u(ph, off_p_align, width)

        all_ph.append({
            'index': i,
            'ph_off': ph_off,
            'type': int(p_type),
            'offset': int(p_offset),
            'vaddr': int(p_vaddr),
            'filesz': int(p_filesz),
            'memsz': int(p_memsz),
            'align': int(p_align),
        })

    for ph in all_ph:
        if ph['type'] != 1:  # PT_LOAD
            continue
        for tvaddr, tsize in targets:
            if ph['vaddr'] != int(tvaddr):
                continue
            if ph['filesz'] < int(tsize) or ph['memsz'] < int(tsize):
                continue
            target_ph_indices.add(ph['index'])
            if strip_plaintext and ph['filesz'] > 0:
                start = ph['offset']
                end = ph['offset'] + ph['filesz']
                if start < 0 or end > file_size or end < start:
                    raise RuntimeError(f'[-] 待裁剪范围越界: idx={ph["index"]} off={start} size={ph["filesz"]}')
                remove_ranges.append((start, end))
            break

    # PT_NULL + zero sizes/offset for recoverable PT_LOAD
    for ph in all_ph:
        if ph['index'] not in target_ph_indices:
            continue
        ph_off = ph['ph_off']
        data[ph_off:ph_off + 4] = struct.pack(endian + 'I', 0)  # PT_NULL
        data[ph_off + off_p_offset:ph_off + off_p_offset + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
        data[ph_off + off_p_filesz:ph_off + off_p_filesz + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
        data[ph_off + off_p_memsz:ph_off + off_p_memsz + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
        nulled += 1

    mode = 'none'
    if strip_plaintext and remove_ranges:
        droppable_non_load_types = {
            4,           # PT_NOTE
            0x6474E550,  # PT_GNU_EH_FRAME
            0x6474E553,  # PT_GNU_PROPERTY
        }

        def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
            if not ranges:
                return []
            ranges = sorted(ranges)
            merged_out: list[tuple[int, int]] = []
            for start, end in ranges:
                if end <= start:
                    continue
                if not merged_out or start > merged_out[-1][1]:
                    merged_out.append((start, end))
                else:
                    merged_out[-1] = (merged_out[-1][0], max(merged_out[-1][1], end))
            return merged_out

        def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
            return max(a0, b0) < min(a1, b1)

        def overlap_len(start: int, end: int, ranges: list[tuple[int, int]]) -> int:
            total = 0
            for a, b in ranges:
                if b <= start:
                    continue
                if a >= end:
                    break
                total += max(0, min(end, b) - max(start, a))
            return total

        def subtract_ranges(
                ranges: list[tuple[int, int]],
                cuts: list[tuple[int, int]]
        ) -> list[tuple[int, int]]:
            src = merge_ranges(ranges)
            sub = merge_ranges(cuts)
            if not src:
                return []
            if not sub:
                return src

            out: list[tuple[int, int]] = []
            for start, end in src:
                cur = start
                for c0, c1 in sub:
                    if c1 <= cur:
                        continue
                    if c0 >= end:
                        break
                    if c0 > cur:
                        out.append((cur, min(c0, end)))
                    if c1 >= end:
                        cur = end
                        break
                    cur = max(cur, c1)
                if cur < end:
                    out.append((cur, end))
            return merge_ranges(out)

        def removed_before(pos: int, ranges: list[tuple[int, int]]) -> int:
            s = 0
            for a, b in ranges:
                if b <= pos:
                    s += (b - a)
                else:
                    break
            return s

        def inside_removed(pos: int, ranges: list[tuple[int, int]]) -> bool:
            for a, b in ranges:
                if a <= pos < b:
                    return True
                if pos < a:
                    return False
            return False

        def apply_prune_ranges(prune_ranges: list[tuple[int, int]]) -> int:
            nonlocal data
            chunks: list[bytes] = []
            cur = 0
            for start, end in prune_ranges:
                if cur < start:
                    chunks.append(bytes(data[cur:start]))
                cur = end
            if cur < len(data):
                chunks.append(bytes(data[cur:]))
            data = bytearray(b''.join(chunks))
            return sum((b - a) for a, b in prune_ranges)

        def drop_section_headers() -> None:
            if is64:
                data[0x28:0x30] = struct.pack(endian + 'Q', 0)
                data[0x3A:0x3C] = struct.pack(endian + 'H', 0)
                data[0x3C:0x3E] = struct.pack(endian + 'H', 0)
                data[0x3E:0x40] = struct.pack(endian + 'H', 0)
            else:
                data[0x20:0x24] = struct.pack(endian + 'I', 0)
                data[0x2E:0x30] = struct.pack(endian + 'H', 0)
                data[0x30:0x32] = struct.pack(endian + 'H', 0)
                data[0x32:0x34] = struct.pack(endian + 'H', 0)

        merged = merge_ranges(remove_ranges)

        if prune_bytes:
            e_ph_end = e_phoff + e_phnum * e_phentsize
            critical_ranges = [(0, max(0x40, e_ph_end))]
            droppable_candidates: list[dict] = []
            for ph in all_ph:
                if ph['index'] in target_ph_indices:
                    continue
                if ph['filesz'] <= 0 or ph['offset'] <= 0:
                    continue
                if ph['type'] in droppable_non_load_types:
                    droppable_candidates.append(ph)
                    continue
                critical_ranges.append((ph['offset'], ph['offset'] + ph['filesz']))

            prune_ranges = subtract_ranges(merged, critical_ranges)

            partial_droppable_ranges: list[tuple[int, int]] = []
            droppable_drop_indices: set[int] = set()
            for ph in droppable_candidates:
                s = ph['offset']
                e = ph['offset'] + ph['filesz']
                ov = overlap_len(s, e, prune_ranges)
                if ov <= 0:
                    continue
                if ov == ph['filesz']:
                    droppable_drop_indices.add(ph['index'])
                else:
                    partial_droppable_ranges.append((s, e))

            if partial_droppable_ranges:
                prune_ranges = subtract_ranges(prune_ranges, partial_droppable_ranges)

            confirmed_droppable: set[int] = set()
            for ph in droppable_candidates:
                if ph['index'] not in droppable_drop_indices:
                    continue
                s = ph['offset']
                e = ph['offset'] + ph['filesz']
                if overlap_len(s, e, prune_ranges) == ph['filesz']:
                    confirmed_droppable.add(ph['index'])

            byte_prune_ok = bool(prune_ranges)
            if byte_prune_ok:
                for ph in all_ph:
                    if ph['index'] in target_ph_indices or ph['index'] in confirmed_droppable:
                        continue
                    if ph['offset'] <= 0 or ph['filesz'] <= 0:
                        continue

                    seg_start = ph['offset']
                    seg_end = ph['offset'] + ph['filesz']
                    if overlap_len(seg_start, seg_end, prune_ranges) > 0:
                        byte_prune_ok = False
                        break

                    if ph['type'] == 1:  # PT_LOAD
                        if inside_removed(seg_start, prune_ranges):
                            byte_prune_ok = False
                            break
                        new_off = seg_start - removed_before(seg_start, prune_ranges)
                        align = ph['align'] if ph['align'] > 1 else 1
                        if (new_off % align) != (ph['vaddr'] % align):
                            byte_prune_ok = False
                            break

            if byte_prune_ok:
                for ph in all_ph:
                    if ph['index'] not in confirmed_droppable:
                        continue
                    ph_off = ph['ph_off']
                    data[ph_off:ph_off + 4] = struct.pack(endian + 'I', 0)
                    data[ph_off + off_p_offset:ph_off + off_p_offset + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
                    data[ph_off + off_p_filesz:ph_off + off_p_filesz + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
                    data[ph_off + off_p_memsz:ph_off + off_p_memsz + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)

                for ph in all_ph:
                    if ph['index'] in target_ph_indices or ph['index'] in confirmed_droppable:
                        continue
                    if ph['offset'] <= 0:
                        continue
                    new_off = ph['offset'] - removed_before(ph['offset'], prune_ranges)
                    if new_off == ph['offset']:
                        continue
                    ph_off = ph['ph_off']
                    data[ph_off + off_p_offset:ph_off + off_p_offset + width] = \
                        struct.pack(endian + ('Q' if is64 else 'I'), new_off)

                drop_section_headers()
                changed_bytes = apply_prune_ranges(prune_ranges)
                mode = 'byte-prune'

        if mode == 'none' and prune_pages:
            page = 0x1000

            # Candidate prune pages: pages touched by recoverable plaintext ranges.
            candidate_pages: list[tuple[int, int]] = []
            for start, end in merged:
                p0 = (start // page) * page
                p1 = ((end + page - 1) // page) * page
                for p in range(p0, p1, page):
                    candidate_pages.append((p, p + page))

            # Keep unique, sorted pages.
            candidate_pages = sorted(set(candidate_pages))

            # critical file ranges that cannot be pruned
            e_ph_end = e_phoff + e_phnum * e_phentsize
            critical_ranges = [(0, max(0x40, e_ph_end))]
            for ph in all_ph:
                if ph['index'] in target_ph_indices:
                    continue
                if ph['filesz'] <= 0 or ph['offset'] <= 0:
                    continue
                if ph['type'] in droppable_non_load_types:
                    continue
                critical_ranges.append((ph['offset'], ph['offset'] + ph['filesz']))

            safe_pages: list[tuple[int, int]] = []
            for a, b in candidate_pages:
                if a < 0 or b > file_size:
                    continue
                if any(overlaps(a, b, c0, c1) for c0, c1 in critical_ranges):
                    continue
                safe_pages.append((a, b))

            # merge contiguous safe pages
            prune_ranges = merge_ranges(safe_pages)

            if prune_ranges:
                # for remaining PT_LOAD, ensure new offset keeps congruence
                for ph in all_ph:
                    if ph['index'] in target_ph_indices or ph['type'] != 1:
                        continue
                    if ph['filesz'] <= 0:
                        continue
                    if inside_removed(ph['offset'], prune_ranges):
                        raise RuntimeError(
                            f'[-] 页级裁剪冲突：保留 PT_LOAD idx={ph["index"]} 起始偏移落入裁剪页'
                        )
                    new_off = ph['offset'] - removed_before(ph['offset'], prune_ranges)
                    align = ph['align'] if ph['align'] > 1 else 1
                    if (new_off % align) != (ph['vaddr'] % align):
                        raise RuntimeError(
                            f'[-] 页级裁剪后对齐失配: idx={ph["index"]} '
                            f'new_off={hex(new_off)} align={hex(align)} vaddr={hex(ph["vaddr"])}'
                        )

                # non-critical non-load segments landing in removed pages -> PT_NULL
                for ph in all_ph:
                    if ph['index'] in target_ph_indices:
                        continue
                    if ph['offset'] <= 0 or ph['filesz'] <= 0:
                        continue
                    if not inside_removed(ph['offset'], prune_ranges):
                        continue
                    if ph['type'] not in droppable_non_load_types:
                        raise RuntimeError(
                            f'[-] 页级裁剪冲突：关键段 idx={ph["index"]} type={hex(ph["type"])} 落入裁剪页'
                        )
                    ph_off = ph['ph_off']
                    data[ph_off:ph_off + 4] = struct.pack(endian + 'I', 0)
                    data[ph_off + off_p_offset:ph_off + off_p_offset + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
                    data[ph_off + off_p_filesz:ph_off + off_p_filesz + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)
                    data[ph_off + off_p_memsz:ph_off + off_p_memsz + width] = struct.pack(endian + ('Q' if is64 else 'I'), 0)

                # rewrite p_offset for remaining entries
                for ph in all_ph:
                    if ph['index'] in target_ph_indices:
                        continue
                    if ph['offset'] <= 0:
                        continue
                    if inside_removed(ph['offset'], prune_ranges):
                        continue
                    new_off = ph['offset'] - removed_before(ph['offset'], prune_ranges)
                    if new_off == ph['offset']:
                        continue
                    ph_off = ph['ph_off']
                    data[ph_off + off_p_offset:ph_off + off_p_offset + width] = \
                        struct.pack(endian + ('Q' if is64 else 'I'), new_off)

                drop_section_headers()
                changed_bytes = apply_prune_ranges(prune_ranges)
                mode = 'prune'

        if mode == 'none':
            # Fallback: overwrite plaintext bytes.
            for start, end in merged:
                length = end - start
                if length <= 0:
                    continue
                data[start:end] = b'\xA5' * length
                changed_bytes += length
            mode = 'wipe'

    with open(output_file, 'wb') as f:
        f.write(data)

    return nulled, changed_bytes, mode


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 凸包相关函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def compute_vaddr_convex_hull(binary: lief.ELF.Binary) -> dict:
    """
    计算包含所有 PT_LOAD 的凸包虚拟地址范围
    """
    load_segments = []
    for idx, seg in enumerate(binary.segments):
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            load_segments.append((idx, seg))
    
    if not load_segments:
        raise RuntimeError("[-] 无法找到任何 PT_LOAD 段")
    
    min_vaddr = min(seg.virtual_address for _, seg in load_segments)
    max_vaddr = max(seg.virtual_address + seg.virtual_size 
                    for _, seg in load_segments)
    
    return {
        'min_vaddr': min_vaddr,
        'max_vaddr': max_vaddr,
        'size': max_vaddr - min_vaddr,
        'segments': load_segments,
        'count': len(load_segments),
    }


# ELF machine type to numeric value
def _elf_machine_value(binary) -> int:
    try:
        return int(binary.header.machine_type)
    except Exception:
        name = str(binary.header.machine_type).lower().replace('-', '_')
        for key, val in MACHINE_ALIASES.items():
            if key in name:
                return val
    return 0


def _elf_flags(binary) -> int:
    try:
        return int(binary.header.processor_flags)
    except Exception:
        return 0


# Protected section names that indicate dynamic linking
_PROTECTED_SECTION_NAMES = frozenset({
    '.dynamic', '.got', '.got.plt',
    '.dynsym', '.dynstr',
    '.gnu.hash', '.gnu.version', '.gnu.version_r',
    '.rela.dyn', '.rela.plt',
    '.interp',
})


def is_segment_protectable(binary: lief.ELF.Binary, seg) -> bool:
    """Return True if the segment must NOT be polluted."""
    # Hard rule: if the first PT_LOAD starts at file offset 0, always keep it.
    # This avoids destroying ELF header / PHDR area on binaries whose first
    # load segment covers the file header region.
    first_load = None
    for cand in binary.segments:
        if cand.type == lief.ELF.Segment.TYPE.LOAD:
            first_load = cand
            break
    if first_load is not None and int(first_load.file_offset) == 0:
        if (
            int(seg.file_offset) == int(first_load.file_offset)
            and int(seg.virtual_address) == int(first_load.virtual_address)
            and int(seg.physical_size) == int(first_load.physical_size)
        ):
            return True

    # Existing rule: keep segments that contain dynamic-linking metadata.
    seg_start = seg.virtual_address
    seg_end = seg.virtual_address + max(seg.virtual_size, seg.physical_size)

    # Check overlap with PT_DYNAMIC
    for other in binary.segments:
        if other.type == lief.ELF.Segment.TYPE.DYNAMIC:
            dyn_start = other.virtual_address
            dyn_end = dyn_start + max(other.virtual_size, other.physical_size)
            if seg_start < dyn_end and seg_end > dyn_start:
                return True

    # Check overlap with protected sections
    for section in binary.sections:
        if section.name not in _PROTECTED_SECTION_NAMES:
            continue
        sec_start = section.virtual_address
        sec_end = sec_start + section.size
        if sec_start < seg_end and sec_end > seg_start and sec_start >= seg_start:
            return True

    return False


# ── ELF construction helpers ─────────────────────────────────────────────────
_ELF_HEADER_OFFSET = 0x1000   # file offset where stub+data begins inside the PT_LOAD


def _build_elf64(entry_va: int, load_va: int, content: bytes,
                 e_machine: int, e_flags: int) -> bytes:
    """Build a minimal ELF64 executable with a single RWX PT_LOAD."""
    ehdr_size  = 64
    phdr_size  = 56
    phdr_off   = ehdr_size
    content_off = _ELF_HEADER_OFFSET   # page-aligned gap for headers

    e_ident = struct.pack('<4sBBBBBxxxxxxx',
                          b'\x7fELF', 2, 1, 1, 0, 0)   # CLASS64 DATA2LSB
    ehdr = e_ident + struct.pack('<HHIQQQIHHHHHH',
        2,           # ET_EXEC
        e_machine,
        1,           # EV_CURRENT
        entry_va,
        phdr_off,
        0,           # no section headers
        e_flags,
        ehdr_size,
        phdr_size,
        1,           # phnum
        64,          # shentsize (conventional)
        0, 0,
    )

    phdr = struct.pack('<IIQQQQQQ',
        1,                    # PT_LOAD
        7,                    # PF_RWX
        content_off,          # p_offset
        load_va,              # p_vaddr
        load_va,              # p_paddr
        len(content),         # p_filesz
        len(content),         # p_memsz
        0x1000,               # p_align
    )

    buf = bytearray(content_off)
    buf[:len(ehdr)] = ehdr
    buf[phdr_off:phdr_off + len(phdr)] = phdr
    buf.extend(content)
    return bytes(buf)


def _build_elf32(entry_va: int, load_va: int, content: bytes,
                 e_machine: int, e_flags: int) -> bytes:
    """Build a minimal ELF32 executable with a single RWX PT_LOAD."""
    ehdr_size  = 52
    phdr_size  = 32
    phdr_off   = ehdr_size
    content_off = _ELF_HEADER_OFFSET

    e_ident = struct.pack('<4sBBBBBxxxxxxx',
                          b'\x7fELF', 1, 1, 1, 0, 0)   # CLASS32 DATA2LSB
    ehdr = e_ident + struct.pack('<HHIIIIIHHHHHH',
        2,           # ET_EXEC
        e_machine,
        1,           # EV_CURRENT
        entry_va,
        phdr_off,
        0,           # no section headers
        e_flags,
        ehdr_size,
        phdr_size,
        1,           # phnum
        40,          # shentsize (conventional)
        0, 0,
    )

    phdr = struct.pack('<IIIIIIII',
        1,                    # PT_LOAD
        content_off,          # p_offset
        load_va,              # p_vaddr
        load_va,              # p_paddr
        len(content),         # p_filesz
        len(content),         # p_memsz
        7,                    # PF_RWX
        0x1000,               # p_align
    )

    buf = bytearray(content_off)
    buf[:len(ehdr)] = ehdr
    buf[phdr_off:phdr_off + len(phdr)] = phdr
    buf.extend(content)
    return bytes(buf)


def build_convex_hull_content(
        binary: lief.ELF.Binary,
        convex_info: dict,
        file_bytes: bytes,
        block_size: int,
        insert_size: int,
        insert_type: str,
        arch_name: str,
) -> tuple[bytes, dict, list[dict], list[dict]]:
    """
    Build the convex-hull data block using sequential (non-sparse) layout.

    Layout inside the returned bytes:
        [polluted ELF header] [polluted PT_LOAD_0] ... [raw protected PT_LOAD_0] ...

    Returns:
        (convex_content, header_info, recoverable_region_infos, protected_region_infos)

    All offsets in the returned dicts are relative to the START of convex_content
    (not including the stub_blob prepended later; adjust in the patcher).
    """
    is64 = is_elf64(binary)
    hdr_size = 64 if is64 else 52

    # ── Pollute and store original ELF header ──────────────────────────
    original_header = file_bytes[:hdr_size]
    polluted_hdr, hdr_blocks = build_polluted_text(
        original_header, block_size, insert_size, insert_type, arch_name)

    content = bytearray(polluted_hdr)
    header_info = {
        'vaddr':    convex_info['min_vaddr'],   # maps to VA min_vaddr at runtime
        'size':     hdr_size,
        'offset_in_content': 0,
        'block_size': block_size,
        'insert_size': insert_size,
        'blocks':   hdr_blocks,
    }

    # ── Classify and process each PT_LOAD ─────────────────────────────
    load_segs = sorted(
        [(seg, seg.file_offset, seg.physical_size)
         for _, seg in convex_info['segments']],
        key=lambda t: t[0].virtual_address
    )

    recoverable_infos: list[dict] = []
    protected_infos:   list[dict] = []

    for seg, foff, fsize in load_segs:
        seg_data = file_bytes[foff:foff + fsize]
        if is_segment_protectable(binary, seg):
            off = len(content)
            content.extend(seg_data)
            protected_infos.append({
                'vaddr':            seg.virtual_address,
                'size':             fsize,
                'offset_in_content': off,
            })
        else:
            polluted, blocks = build_polluted_text(
                seg_data, block_size, insert_size, insert_type, arch_name)
            off = len(content)
            content.extend(polluted)
            recoverable_infos.append({
                'vaddr':            seg.virtual_address,
                'size':             fsize,
                'offset_in_content': off,
                'block_size':       block_size,
                'insert_size':      insert_size,
                'blocks':           blocks,
            })

    return bytes(content), header_info, recoverable_infos, protected_infos



def create_convex_hull_elf(
        source_path: Path,
        binary: lief.ELF.Binary,
        convex_info: dict,
        stub_entry_offset: int,
        stub_blob: bytes,
        is64: bool,
) -> tuple[lief.ELF.Binary, int, int, int]:
    """
    Re-parse *source_path* (which already contains the in-place-polluted PT_LOADs)
    and append a single stub-only PT_LOAD segment.

    Returns:
        (new_binary, convex_va, entry_vaddr, relocated_original_oep)
    """
    new_binary = lief.parse(str(source_path))
    if not new_binary:
        raise RuntimeError(f"[-] 无法重新解析 ELF: {source_path}")

    seg = lief.ELF.Segment()
    seg.type = lief.ELF.Segment.TYPE.LOAD
    seg.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W | lief.ELF.Segment.FLAGS.X
    seg.alignment = 0x1000
    seg.content = list(stub_blob)

    added = new_binary.add(seg)
    convex_va = int(added.virtual_address)
    relocated_original_oep = int(new_binary.header.entrypoint)
    entry_vaddr = convex_va + stub_entry_offset
    new_binary.header.entrypoint = entry_vaddr
    return new_binary, convex_va, entry_vaddr, relocated_original_oep


def _patch_convex_hull_stub(
        _temp_file: Path,
        output_file: Path,
        _temp_bin,
        is64: bool,
        convex_info: dict,
        convex_va: int,
        stub_file_start: int,
        original_oep: int,
        vaddr_shift: int,
        header_info: dict,
        recoverable_infos: list[dict],
        protected_infos: list[dict],
        _stub_blob_size: int,
        stub_symbol_offsets: dict[str, int],
):
    """Patch all stub variables directly into the packed ELF on disk."""
    width = 8 if is64 else 4

    def stub_file_off(symbol: str, idx: int | None = None) -> int:
        if symbol not in stub_symbol_offsets:
            raise RuntimeError(f"[-] Stub 符号未找到: {symbol}")
        off = stub_file_start + stub_symbol_offsets[symbol]
        if idx is not None:
            off += idx * width
        return off

    print('    打补丁...')

    # CONVEX_MIN_VADDR (= convex_va)
    patch_value(output_file, stub_file_off('CONVEX_MIN_VADDR'), convex_va, width)
    print(f'      CONVEX_MIN_VADDR = {hex(convex_va)}')

    # STUB_VOFFSET (symbol VA, not runtime VA)
    voffset_va = convex_va + int(stub_symbol_offsets['STUB_VOFFSET'])
    patch_value(output_file, stub_file_off('STUB_VOFFSET'), voffset_va, width)

    # OEP_ADDR
    patch_value(output_file, stub_file_off('OEP_ADDR'), original_oep, width)
    print(f'      OEP_ADDR = {hex(original_oep)}')
    print(f'      VADDR_SHIFT = {hex(vaddr_shift)}')

    # Keep original headers for dynamic loader; disable runtime header remap.
    patch_value(output_file, stub_file_off('HEADER_VADDR'), 0, width)
    patch_value(output_file, stub_file_off('HEADER_OFFSET'), 0, width)
    patch_value(output_file, stub_file_off('HEADER_SIZE'), 0, width)
    patch_value(output_file, stub_file_off('HEADER_RETAIN'), 0, width)
    patch_value(output_file, stub_file_off('HEADER_DELETE'), 0, width)
    patch_value(output_file, stub_file_off('HEADER_BLOCKS'), 0, width)
    print('      HEADER_* disabled (preserve original ELF header/PT_DYNAMIC layout)')

    # ── Recoverable PT_LOAD regions ───────────────────────────────────
    n_rec = min(len(recoverable_infos), STUB_MAX_REGIONS)
    patch_value(output_file, stub_file_off('REGION_COUNT'), n_rec, width)
    print(f'      REGION_COUNT = {n_rec}')

    for i, r in enumerate(recoverable_infos[:STUB_MAX_REGIONS]):
        patch_value(output_file, stub_file_off('REGION_ADDRS',   i), r['vaddr'] + vaddr_shift,  width)
        patch_value(output_file, stub_file_off('REGION_SIZES',   i), r['size'],   width)
        patch_value(output_file, stub_file_off('REGION_RETAINS', i), r['block_size'], width)
        patch_value(output_file, stub_file_off('REGION_DELETES', i), r['insert_size'], width)
        patch_value(output_file, stub_file_off('REGION_BLOCKS',  i), r['blocks'], width)
        patch_value(output_file, stub_file_off('REGION_OFFSETS', i),
                    r['file_offset'], width)

    # ── Protected (non-pollutable) PT_LOAD regions ───────────────────
    # Do not overwrite loader-relocated data (.got/.dynamic etc.) at runtime.
    n_prot = 0
    patch_value(output_file, stub_file_off('PROTECTED_COUNT'), n_prot, width)
    print(f'      PROTECTED_COUNT = {n_prot}')

    for i in range(STUB_MAX_REGIONS):
        patch_value(output_file, stub_file_off('PROTECTED_ADDRS', i), 0, width)
        patch_value(output_file, stub_file_off('PROTECTED_SIZES', i), 0, width)
        patch_value(output_file, stub_file_off('PROTECTED_OFFSETS', i), 0, width)

    print(f'      填充了 {n_rec} 个可污染段，{n_prot} 个受保护段')


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主打包函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def pack_with_convex_hull(target_file: Path, 
                          output_file: Path,
                          temp_file: Path,
                          block_size: int,
                          insert_size: int,
                          insert_type: str,
                          machine_override: int | None,
                          stub_path_override: str,
                          stub_source_override: str,
                          auto_build_stub: bool,
                          rebuild_stub: bool,
                          stub_compilers: dict[str, str],
                          stub_build_timeout: int) -> tuple[bool, dict]:
    """
    使用凸包方式打包 ELF
    """
    status = {
        'input': str(target_file),
        'output': str(output_file),
        'success': False,
        'error': '',
        'arch': None,
        'is_64bit': None,
        'block_size': int(block_size),
        'insert_size': int(insert_size),
        'insert_type': str(insert_type),
        'machine_override': machine_override,
        'stub_path_override': stub_path_override,
        'stub_source_override': stub_source_override,
        'stub_build_timeout': int(stub_build_timeout),
    }

    def fail(error: str) -> tuple[bool, dict]:
        status['error'] = str(error)
        return False, status

    print(f'[*] 处理文件（凸包模式）: {target_file}')
    
    binary = lief.parse(str(target_file))
    if not binary:
        print('[-] 解析失败，不是有效的 ELF 文件')
        return fail('解析失败，不是有效的 ELF 文件')
    
    machine = int(machine_override) if machine_override is not None else int(binary.header.machine_type)
    arch_key, arch_spec = resolve_arch_from_machine(machine)
    is64 = bool(is_elf64(binary))
    arch_name = arch_key or (
        binary.header.machine_type.name if hasattr(binary.header.machine_type, 'name') else f'machine={machine}'
    )
    status['machine'] = int(machine)
    status['arch'] = arch_key if arch_key is not None else f'machine={machine}'
    status['is_64bit'] = bool(is64)

    if arch_key is not None and arch_spec is not None:
        print(f'   目标架构: {arch_key} ({arch_spec["bits"]}-bit)')
    else:
        print(f'   目标架构: machine={machine} ({64 if is64 else 32}-bit)')
        if not stub_path_override:
            msg = f'[-] 暂不支持的 ELF 架构: machine={machine}（请提供 --stub-path）'
            print(msg)
            return fail(msg)
    print('   打包模式: 凸包（UPX 风格）')
    
    with open(target_file, "rb") as f:
        file_bytes = f.read()
    
    # 计算凸包
    print('   计算虚拟地址凸包...')
    try:
        convex_info = compute_vaddr_convex_hull(binary)
    except Exception as e:
        print(f'[-] {e}')
        return fail(str(e))
    
    print(f'     最小虚拟地址: {hex(convex_info["min_vaddr"])}')
    print(f'     最大虚拟地址: {hex(convex_info["max_vaddr"])}')
    print(f'     凸包大小: {hex(convex_info["size"])} ({convex_info["size"]} 字节)')
    print(f'     包含 PT_LOAD 段数: {convex_info["count"]}')
    status['convex_min_vaddr'] = int(convex_info['min_vaddr'])
    status['convex_max_vaddr'] = int(convex_info['max_vaddr'])
    status['convex_size'] = int(convex_info['size'])
    status['convex_load_count'] = int(convex_info['count'])
    
    # 对可恢复 PT_LOAD 段执行原地插入污染
    print('   原地插入污染...')
    load_segs = sorted(
        [(seg, int(seg.file_offset), int(seg.physical_size))
         for _, seg in convex_info['segments']],
        key=lambda t: t[0].virtual_address,
    )
    rec_segs_input = []
    protected_infos: list[dict] = []
    for seg, foff, fsize in load_segs:
        if is_segment_protectable(binary, seg):
            protected_infos.append({
                'vaddr': int(seg.virtual_address),
                'size':  fsize,
            })
        else:
            rec_segs_input.append({
                'vaddr':       int(seg.virtual_address),
                'file_offset': foff,
                'file_size':   fsize,
            })

    try:
        modified_bytes, recoverable_infos = _apply_inplace_insertions(
            file_bytes, is64, rec_segs_input,
            block_size, insert_size, insert_type, arch_name,
        )
    except Exception as e:
        print(f'[-] {e}')
        return fail(str(e))

    print(f'     可污染段数: {len(recoverable_infos)}, 受保护段数: {len(protected_infos)}')
    status['recoverable_segments'] = int(len(recoverable_infos))
    status['protected_segments'] = int(len(protected_infos))

    # 写修改后的字节到临时文件
    temp_modified_file = Path(str(temp_file) + '.inplace')
    try:
        with open(temp_modified_file, 'wb') as f:
            f.write(modified_bytes)
    except Exception as e:
        print(f'[-] 写临时修改文件失败: {e}')
        return fail(f'写临时修改文件失败: {e}')

    # 记录原始 OEP（用于计算布局重排偏移）
    original_oep_before_layout = int(binary.header.entrypoint)
    status['original_oep_before_layout'] = int(original_oep_before_layout)

    # 构建 Stub
    print('   准备 Stub...')
    base_dir = Path(__file__).parent
    stub_path: Path | None = None
    if stub_path_override:
        stub_path = Path(stub_path_override)
        if not stub_path.is_absolute():
            stub_path = (base_dir / stub_path).resolve()
        if not stub_path.exists():
            msg = f'错误：指定的 --stub-path 不存在: {stub_path}'
            print(f'[-] {msg}')
            return fail(msg)
        if auto_build_stub or rebuild_stub:
            print('   [notice] 已指定 --stub-path，忽略 --auto-build-stub/--rebuild-stub')
    else:
        if arch_key is None or arch_spec is None:
            msg = '错误：未知架构必须显式提供 --stub-path'
            print(f'[-] {msg}')
            return fail(msg)
        stub_path = resolve_existing_stub(base_dir, arch_key)
        if auto_build_stub or rebuild_stub:
            try:
                compiler = stub_compilers.get(arch_key) or arch_spec["default_cc"]
                stub_path = build_delete_stub(
                    base_dir=base_dir,
                    arch_key=arch_key,
                    compiler=compiler,
                    force=rebuild_stub,
                    source_override=stub_source_override,
                    timeout_sec=stub_build_timeout,
                )
            except Exception as e:
                print(str(e))
                return fail(str(e))

        if stub_path is None or not stub_path.exists():
            expected = [arch_spec["stub_name"]] + arch_spec["legacy_stub_names"]
            detail = ''
            if not bool(arch_spec.get("auto_build_supported", True)):
                detail = '（该架构默认仅支持外部 stub；可用 --stub-path 或 --stub-source）'
            msg = f'错误：找不到架构 {arch_key} 对应 stub。候选: {expected}{detail}'
            print(f'[-] {msg}')
            return fail(msg)
    
    print(f'   使用 stub: {stub_path.name}')
    status['stub_path'] = str(stub_path)
    
    # 提取 Stub blob
    print('   注入 Stub...')
    try:
        stub = lief.parse(str(stub_path))
        if not stub:
            msg = f'无法解析 stub 文件 {stub_path}'
            print(f'[-] {msg}')
            return fail(msg)
        
        stub_blob, stub_entry_offset, stub_min_va = get_stub_blob(stub)
        print(f'     Stub 大小: {len(stub_blob)} 字节')
        print(f'     Stub Entry Offset: {hex(stub_entry_offset)}')
        status['stub_size'] = int(len(stub_blob))
        status['stub_entry_offset'] = int(stub_entry_offset)
    except Exception as e:
        print(f'[-] {e}')
        return fail(str(e))
    
    # 创建凸包 ELF（仅含 stub 段）
    print('   创建凸包 ELF...')
    try:
        new_binary, convex_va, entry_vaddr, relocated_oep = create_convex_hull_elf(
            temp_modified_file, binary, convex_info,
            stub_entry_offset, stub_blob, is64
        )
        vaddr_shift = int(relocated_oep) - int(original_oep_before_layout)
        print(f'     原始 OEP（重排后）: {hex(relocated_oep)}')
        print(f'     布局虚拟地址偏移: {hex(vaddr_shift)}')
        stub_symbol_offsets = get_stub_symbol_offsets(stub, stub_min_va, STUB_PATCH_SYMBOLS)
        status['relocated_original_oep'] = int(relocated_oep)
        status['vaddr_shift'] = int(vaddr_shift)
        status['entry_vaddr'] = int(entry_vaddr)
    except Exception as e:
        print(f'[-] {e}')
        return fail(str(e))

    # 写到输出文件（保留原始 PT_DYNAMIC/PT_INTERP 等）
    try:
        new_binary.write(str(output_file))
    except Exception as e:
        print(f'[-] 写输出文件失败: {e}')
        return fail(f'写输出文件失败: {e}')

    # 重新解析输出文件，获取各可恢复段在输出文件中的实际文件偏移。
    # 这些偏移在 Track A 架构中由 stub 用于从磁盘读取污染数据。
    try:
        out_bin_pre = lief.parse(str(output_file))
        if not out_bin_pre:
            msg = '无法解析输出 ELF（预失活）'
            print(f'[-] {msg}')
            return fail(msg)
        for r_info in recoverable_infos:
            target_va = int(r_info['vaddr']) + vaddr_shift
            for seg in out_bin_pre.segments:
                if seg.type != lief.ELF.Segment.TYPE.LOAD:
                    continue
                if int(seg.virtual_address) == target_va:
                    r_info['file_offset'] = int(seg.file_offset)
                    break
    except Exception as e:
        print(f'[-] 解析输出布局（预失活）失败: {e}')
        return fail(f'解析输出布局（预失活）失败: {e}')

    # Track A：将可恢复 PT_LOAD 失活（PT_NULL），原地污染数据留在文件中供 stub 读取。
    # Track B：保留 PT_LOAD，OS 直接加载污染数据，stub 在内存中原地恢复。
    use_mmap_approach = _arch_supports_mmap(arch_key)
    nullify_list = recoverable_infos if use_mmap_approach else []
    nulled = 0
    changed = 0
    mode = 'none'
    try:
        nulled, changed, mode = _nullify_recoverable_ptloads(
            output_file=output_file,
            is64=is64,
            recoverable_infos=nullify_list,
            vaddr_shift=vaddr_shift,
            strip_plaintext=False,  # 污染数据必须保留供 stub 读取/使用
            prune_bytes=False,
            prune_pages=False,
        )
        if use_mmap_approach:
            print(f'   Program Header 重写: PT_NULL 化可恢复 PT_LOAD = {nulled}')
        else:
            print(f'   Program Header 保留: Track B 架构原地恢复，保留 PT_LOAD')
    except Exception as e:
        print(f'[-] 重写 Program Header 失败: {e}')
        return fail(f'重写 Program Header 失败: {e}')
    status['nulled_recoverable_ptloads'] = int(nulled)
    status['plaintext_changed_bytes'] = int(changed)
    status['plaintext_handling_mode'] = 'inplace-disk' if use_mmap_approach else 'inplace-memory'

    # 重新解析，定位新增 stub 段的文件偏移
    try:
        out_bin = lief.parse(str(output_file))
        if not out_bin:
            msg = '无法解析输出 ELF'
            print(f'[-] {msg}')
            return fail(msg)

        stub_seg = None
        for seg in out_bin.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            if int(seg.virtual_address) <= int(entry_vaddr) < int(seg.virtual_address + seg.physical_size):
                stub_seg = seg
                break
        if stub_seg is None:
            msg = '无法在输出 ELF 中定位 stub 段'
            print(f'[-] {msg}')
            return fail(msg)
        stub_file_start = int(stub_seg.file_offset)
        convex_va = int(stub_seg.virtual_address)
    except Exception as e:
        print(f'[-] 解析输出布局失败: {e}')
        return fail(f'解析输出布局失败: {e}')
    
    # 打补丁
    print('   打补丁...')
    # 创建哑 header_info（头部恢复已禁用）
    header_info = {
        'vaddr': 0, 'size': 0, 'offset_in_content': 0,
        'block_size': block_size, 'insert_size': insert_size, 'blocks': 0,
    }
    try:
        _patch_convex_hull_stub(
            temp_file, output_file, None, is64,
            convex_info, convex_va, stub_file_start, relocated_oep, vaddr_shift,
            header_info, recoverable_infos, [],
            len(stub_blob), stub_symbol_offsets
        )
    except Exception as e:
        print(f'[-] 打补丁失败: {e}')
        return fail(f'打补丁失败: {e}')
    
    # 保持可执行权限
    try:
        shutil.copymode(target_file, output_file)
    except Exception:
        pass

    # 清理临时文件
    try:
        temp_modified_file.unlink(missing_ok=True)
    except Exception:
        pass
    
    recoverable_blocks = int(sum(r['blocks'] for r in recoverable_infos))
    total_blocks = recoverable_blocks
    status['header_blocks'] = 0
    status['recoverable_blocks'] = recoverable_blocks
    status['total_blocks'] = total_blocks
    status['obfuscation_inserted_bytes_header'] = 0
    status['obfuscation_inserted_bytes_recoverable'] = recoverable_blocks * int(insert_size)
    status['obfuscation_inserted_bytes_excluding_stub'] = total_blocks * int(insert_size)
    status['convex_va'] = int(convex_va)
    status['stub_file_start'] = int(stub_file_start)
    try:
        status['output_size'] = int(output_file.stat().st_size)
    except Exception:
        pass

    print(f'[+] 已生成: {output_file}')
    print(f'[+] 原地插入模式：stub@{hex(convex_va)}，'
          f'污染 {len(recoverable_infos)} 个可恢复段，{len(protected_infos)} 个受保护段')
    print(f'[+] 原始虚拟地址范围: {hex(convex_info["min_vaddr"])} - {hex(convex_info["max_vaddr"])}')
    print(f'[+] 共污染 {total_blocks} 个块\n')
    status['success'] = True
    return True, status


def _output_name(src: Path, suffix: str) -> str:
    if not suffix:
        return src.name
    if src.suffix:
        return f'{src.stem}{suffix}{src.suffix}'
    return f'{src.name}{suffix}'


def _iter_files(input_path: Path, recursive: bool):
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        if recursive:
            return [p for p in input_path.rglob('*') if p.is_file()]
        return [p for p in input_path.iterdir() if p.is_file()]
    return []


def _write_status_json(status_json_path: Path, args, results: list[dict], ok: int, skipped: int, total: int):
    payload = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'tool': 'inject_tmp/packer.py',
        'summary': {
            'success': int(ok),
            'skipped': int(skipped),
            'total': int(total),
        },
        'config': {
            k: v for k, v in vars(args).items()
            if k != 'status_json'
        },
        'results': results,
    }
    status_json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(status_json_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f'[+] 状态报告已写入: {status_json_path}')


def main():
    parser = argparse.ArgumentParser(
        description='ELF 打包器：凸包模式（UPX 风格），解决虚拟地址空隙问题')
    
    parser.add_argument('--input', default='', help='输入文件或目录')
    parser.add_argument('--output-dir', default='', help='输出目录')
    parser.add_argument('--recursive', action='store_true', help='递归处理子目录')
    parser.add_argument('--num-files', type=int, default=0,
                        help='当 --input 为目录时，随机处理文件并在成功数量达到该值后停止；<=0 表示处理全部')
    parser.add_argument('--suffix', default='_packed', help='输出文件名后缀')
    parser.add_argument('--overwrite', action='store_true', help='覆盖已存在文件')
    parser.add_argument('--block-size', type=int, default=32, help='原始块大小（字节）')
    parser.add_argument('--insert-size', type=int, default=64, help='插入块大小（字节）')
    parser.add_argument('--insert-type', choices=['zero', 'nop', 'junk'], default='nop', help='插入内容类型（zero=全零, nop=NOP指令, junk=随机字节）')
    parser.add_argument('--machine', default='',
                        help='覆盖目标 e_machine（如 x86_64/i386/arm/aarch64/mips/ppc/sparc/sh/m68k/or1k/arc/xtensa/nios2，或数值如 62）')
    parser.add_argument('--stub-path', default='',
                        help='外部 stub 路径；可用于非内建架构')
    parser.add_argument('--stub-source', default='',
                        help='自动构建 stub 时使用的源文件（相对路径相对于 inject_tmp 目录）')
    parser.add_argument('--auto-build-stub', action='store_true', help='自动构建 stub')
    parser.add_argument('--rebuild-stub', action='store_true', help='强制重建 stub')
    parser.add_argument('--stub-cc-x86-64', default=ARCH_SPECS["x86_64"]["default_cc"], help='x86_64 stub 编译器')
    parser.add_argument('--stub-cc-i386', default=ARCH_SPECS["i386"]["default_cc"], help='i386 stub 编译器')
    parser.add_argument('--stub-cc-arm', default=ARCH_SPECS["arm"]["default_cc"], help='ARM32 stub 编译器')
    parser.add_argument('--stub-cc-aarch64', default=ARCH_SPECS["aarch64"]["default_cc"], help='AArch64 stub 编译器')
    parser.add_argument('--stub-cc-mips', default=ARCH_SPECS["mips"]["default_cc"], help='MIPS stub 编译器')
    parser.add_argument('--stub-cc-ppc', default=ARCH_SPECS["ppc"]["default_cc"], help='PowerPC stub 编译器')
    parser.add_argument('--stub-cc-sh', default=ARCH_SPECS["sh"]["default_cc"], help='SuperH stub 编译器')
    parser.add_argument('--stub-cc-m68k', default=ARCH_SPECS["m68k"]["default_cc"], help='M68K stub 编译器')
    parser.add_argument('--stub-build-timeout', type=int, default=120,
                        help='自动构建 stub 的超时时间（秒）')
    # backward-compatible aliases
    parser.add_argument('--stub-cc64', default='', help=argparse.SUPPRESS)
    parser.add_argument('--stub-cc32', default='', help=argparse.SUPPRESS)
    parser.add_argument('--status-json', default='',
                        help='将处理状态写入 JSON 文件（包含每个文件的统计信息）')
    
    args = parser.parse_args()
    
    try:
        machine_override = parse_machine_arg(args.machine)
    except Exception as e:
        print(str(e))
        return
    if machine_override is not None and args.machine:
        print(f'   [config] machine override: {args.machine} -> {machine_override}')
    stub_compilers = {
        "x86_64": args.stub_cc_x86_64 or args.stub_cc64 or ARCH_SPECS["x86_64"]["default_cc"],
        "i386": args.stub_cc_i386 or args.stub_cc32 or ARCH_SPECS["i386"]["default_cc"],
        "arm": args.stub_cc_arm or ARCH_SPECS["arm"]["default_cc"],
        "aarch64": args.stub_cc_aarch64 or ARCH_SPECS["aarch64"]["default_cc"],
        "mips": args.stub_cc_mips or ARCH_SPECS["mips"]["default_cc"],
        "ppc": args.stub_cc_ppc or ARCH_SPECS["ppc"]["default_cc"],
        "sh": args.stub_cc_sh or ARCH_SPECS["sh"]["default_cc"],
        "m68k": args.stub_cc_m68k or ARCH_SPECS["m68k"]["default_cc"],
    }
    status_path = Path(args.status_json) if args.status_json else None
    
    if not args.input:
        # 默认模式
        target_file = Path(TARGET_FILE)
        output_file = Path(OUTPUT_FILE)
        temp_file = Path(TEMP_FILE)

        ok, rec = pack_with_convex_hull(
            target_file, output_file, temp_file,
            args.block_size, args.insert_size, args.insert_type,
            machine_override,
            args.stub_path,
            args.stub_source,
            args.auto_build_stub, args.rebuild_stub,
            stub_compilers, args.stub_build_timeout
        )
        
        if temp_file.exists():
            temp_file.unlink()
        if status_path is not None:
            _write_status_json(status_path, args, [rec], 1 if ok else 0, 0 if ok else 1, 1)
        return
    
    if args.num_files < 0:
        print('[-] Error: --num-files 不能为负数。')
        return

    # 处理多个文件
    input_path = Path(args.input)
    if not input_path.exists():
        print(f'[-] 输入路径不存在: {input_path}')
        return
    
    if not args.output_dir:
        print('[-] 错误：使用 --input 时必须指定 --output-dir')
        return
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    files = _iter_files(input_path, args.recursive)
    if not files:
        print('[-] 未找到任何文件')
        return

    target_success = args.num_files if input_path.is_dir() and args.num_files > 0 else 0
    if input_path.is_file() and args.num_files > 0:
        print('[notice] --num-files 仅在目录输入时生效；当前为单文件输入，已忽略。')
    if target_success > 0:
        random.shuffle(files)
        print(f'[*] 随机处理模式已启用：目标成功数量={target_success}，候选文件={len(files)}')
    
    ok = skipped = 0
    results: list[dict] = []
    for p in files:
        if target_success > 0 and ok >= target_success:
            print(f'[*] 已达到目标成功数量 {target_success}，提前停止。')
            break
        out_name = _output_name(p, args.suffix)
        out_path = output_dir / out_name
        
        if out_path.exists() and not args.overwrite:
            print(f'[跳过] {out_path} 已存在')
            skipped += 1
            results.append({
                'input': str(p),
                'output': str(out_path),
                'success': False,
                'skipped': True,
                'error': '输出文件已存在且未启用 --overwrite',
            })
            continue
        
        temp_path = output_dir / (out_name + '.tmp.convex.elf')
        
        try:
            succ, rec = pack_with_convex_hull(
                p, out_path, temp_path,
                args.block_size, args.insert_size, args.insert_type,
                machine_override,
                args.stub_path,
                args.stub_source,
                args.auto_build_stub, args.rebuild_stub,
                stub_compilers, args.stub_build_timeout
            )
            results.append(rec)
            if succ:
                ok += 1
            else:
                skipped += 1
        except Exception as e:
            skipped += 1
            results.append({
                'input': str(p),
                'output': str(out_path),
                'success': False,
                'error': f'未捕获异常: {e}',
            })
        finally:
            if temp_path.exists():
                temp_path.unlink()
    
    attempted = len(results)
    if target_success > 0 and ok < target_success:
        print(f'[!] 候选文件已遍历完，未达到目标成功数量 {target_success}（实际成功 {ok}）')
    print(f'\n完成: 成功 {ok}, 跳过 {skipped}, 已处理 {attempted}, 候选总数 {len(files)}')
    if status_path is not None:
        _write_status_json(status_path, args, results, ok, skipped, attempted)


if __name__ == '__main__':
    main()
