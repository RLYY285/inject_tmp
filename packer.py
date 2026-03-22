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
import subprocess
import shutil
import struct
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
    for arch_key, spec in ARCH_SPECS.items():
        if machine == spec["machine"]:
            return arch_key
    name = getattr(binary.header.machine_type, "name", str(binary.header.machine_type))
    raise RuntimeError(f"[-] 暂不支持的 ELF 架构: machine={machine} ({name})")


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


def build_delete_stub(base_dir: Path, arch_key: str, compiler: str, force: bool) -> Path:
    spec = ARCH_SPECS[arch_key]
    stub_path = base_dir / spec["stub_name"]
    if stub_path.exists() and not force:
        return stub_path

    delete_c = base_dir / "delete.c"
    if not delete_c.exists():
        raise RuntimeError(f'[-] 缺少 stub 源码: {delete_c}')

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

    proc = subprocess.run(cmd, capture_output=True, text=True)
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
    else:
        raise ValueError("insert_type 必须是 zero 或 nop")

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


def _nullify_recoverable_ptloads(
        output_file: Path,
        is64: bool,
        recoverable_infos: list[dict],
        vaddr_shift: int,
) -> int:
    """
    Rewrite output ELF program headers: convert recoverable PT_LOAD to PT_NULL.

    This keeps immutable PT_LOAD segments mapped by loader, while recoverable
    regions are restored by stub at runtime (UPX-like behavior).
    """
    if not recoverable_infos:
        return 0

    # Match by vaddr only; p_filesz may be 0 when original data was cleared.
    target_vaddrs = {int(r['vaddr']) + int(vaddr_shift) for r in recoverable_infos}

    endian, e_phoff, e_phentsize, e_phnum = _elf_phdr_layout(output_file, is64)
    removed = 0

    with open(output_file, 'r+b') as f:
        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            f.seek(ph_off)
            ph = f.read(e_phentsize)
            if len(ph) < e_phentsize:
                raise RuntimeError('[-] Program Header 读取失败')

            p_type = struct.unpack_from(endian + 'I', ph, 0)[0]
            if p_type != 1:  # PT_LOAD
                continue

            if is64:
                p_vaddr = struct.unpack_from(endian + 'Q', ph, 16)[0]
            else:
                p_vaddr = struct.unpack_from(endian + 'I', ph, 8)[0]

            if int(p_vaddr) in target_vaddrs:
                # p_type -> PT_NULL
                f.seek(ph_off)
                f.write(struct.pack(endian + 'I', 0))
                removed += 1

    return removed


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
        name = str(binary.header.machine_type).lower()
        for key, val in (('x86_64', 62), ('i386', 3), ('aarch64', 183), ('arm', 40)):
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
    """Return True if the segment must NOT be polluted (contains dynamic linking info)."""
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
        convex_content: bytes,
        stub_entry_offset: int,
        stub_blob: bytes,
        is64: bool,
        recoverable_infos: list[dict] | None = None,
) -> tuple[lief.ELF.Binary, int, int, int]:
    """
    Preserve the original ELF program-header layout (incl. PT_INTERP/PT_DYNAMIC)
    and add one extra convex PT_LOAD that stores:
        [stub_blob][convex_content]

    When recoverable_infos is provided, the content of those PT_LOAD segments is
    cleared before writing so that the original plaintext data is not duplicated
    in the output file (the stub restores it at runtime from convex_content).

    Returns:
        (new_binary, convex_va, entry_vaddr, relocated_original_oep)
    """
    # Re-parse to get a writable copy
    new_binary = lief.parse(str(source_path))
    if not new_binary:
        raise RuntimeError(f"[-] 无法重新解析 ELF: {source_path}")

    # Remove original data for recoverable segments so the output file does not
    # contain a redundant plaintext copy.  The stub will restore these regions
    # at runtime from the polluted convex_content.
    if recoverable_infos:
        recoverable_vaddrs = {int(r['vaddr']) for r in recoverable_infos}
        for seg in new_binary.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            if int(seg.virtual_address) in recoverable_vaddrs:
                # Clear the segment's file content (sets p_filesz → 0 in the
                # output).  The segment header (vaddr, memsz, flags) is kept so
                # the stub can still locate and restore the region.  LIEF will
                # not write any bytes for this segment, reducing file size.
                seg.content = []

    combined = stub_blob + convex_content

    # Add convex storage segment; keep original PT_LOAD/PT_DYNAMIC/PT_INTERP intact.
    seg = lief.ELF.Segment()
    seg.type = lief.ELF.Segment.TYPE.LOAD
    seg.flags = lief.ELF.Segment.FLAGS.R | lief.ELF.Segment.FLAGS.W | lief.ELF.Segment.FLAGS.X
    seg.alignment = 0x1000
    seg.content = combined

    added = new_binary.add(seg)
    convex_va = int(added.virtual_address)
    # LIEF may relocate existing segments/entrypoint after adding a segment.
    # Capture the post-layout original OEP before switching entry to stub.
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
        stub_blob_size: int,
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

    def content_va_off(offset_in_content: int) -> int:
        """Byte offset from CONVEX_MIN_VADDR to convex_content[offset]."""
        return stub_blob_size + offset_in_content

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
                    content_va_off(r['offset_in_content']), width)

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
                          auto_build_stub: bool,
                          rebuild_stub: bool,
                          stub_compilers: dict[str, str],
                          verify_recovery: bool) -> bool:
    """
    使用凸包方式打包 ELF
    """
    print(f'[*] 处理文件（凸包模式）: {target_file}')
    
    binary = lief.parse(str(target_file))
    if not binary:
        print('[-] 解析失败，不是有效的 ELF 文件')
        return False
    
    try:
        arch_key = detect_target_arch(binary)
    except Exception as e:
        print(str(e))
        return False
    
    arch_spec = ARCH_SPECS[arch_key]
    is64 = arch_spec["bits"] == 64
    arch_name = binary.header.machine_type.name if hasattr(binary.header.machine_type, 'name') else ''
    
    print(f'   目标架构: {arch_key} ({arch_spec["bits"]}-bit)')
    print('   打包模式: 凸包（UPX 风格）')
    
    with open(target_file, "rb") as f:
        file_bytes = f.read()
    
    # 计算凸包
    print('   计算虚拟地址凸包...')
    try:
        convex_info = compute_vaddr_convex_hull(binary)
    except Exception as e:
        print(f'[-] {e}')
        return False
    
    print(f'     最小虚拟地址: {hex(convex_info["min_vaddr"])}')
    print(f'     最大虚拟地址: {hex(convex_info["max_vaddr"])}')
    print(f'     凸包大小: {hex(convex_info["size"])} ({convex_info["size"]} 字节)')
    print(f'     包含 PT_LOAD 段数: {convex_info["count"]}')
    
    # 构建凸包内容
    print('   构建污染数据...')
    try:
        convex_content, header_info, recoverable_infos, protected_infos = \
            build_convex_hull_content(
                binary, convex_info, file_bytes,
                block_size, insert_size, insert_type, arch_name
            )
    except Exception as e:
        print(f'[-] {e}')
        return False

    print(f'     凸包内容大小: {len(convex_content)} 字节')
    print(f'     可污染段数: {len(recoverable_infos)}, 受保护段数: {len(protected_infos)}')

    # 记录原始 OEP（用于计算布局重排偏移）
    original_oep_before_layout = int(binary.header.entrypoint)

    # 构建 Stub
    print('   准备 Stub...')
    base_dir = Path(__file__).parent
    stub_path = resolve_existing_stub(base_dir, arch_key)
    
    if auto_build_stub or rebuild_stub:
        try:
            compiler = stub_compilers.get(arch_key) or arch_spec["default_cc"]
            stub_path = build_delete_stub(
                base_dir=base_dir,
                arch_key=arch_key,
                compiler=compiler,
                force=rebuild_stub,
            )
        except Exception as e:
            print(str(e))
            return False
    
    if stub_path is None or not stub_path.exists():
        expected = [arch_spec["stub_name"]] + arch_spec["legacy_stub_names"]
        print(f'[-] 错误：找不到架构 {arch_key} 对应 stub。候选: {expected}')
        return False
    
    print(f'   使用 stub: {stub_path.name}')
    
    # 提取 Stub blob
    print('   注入 Stub...')
    try:
        stub = lief.parse(str(stub_path))
        if not stub:
            print(f'[-] 无法解析 stub 文件 {stub_path}')
            return False
        
        stub_blob, stub_entry_offset, stub_min_va = get_stub_blob(stub)
        print(f'     Stub 大小: {len(stub_blob)} 字节')
        print(f'     Stub Entry Offset: {hex(stub_entry_offset)}')
    except Exception as e:
        print(f'[-] {e}')
        return False
    
    # 创建凸包 ELF
    print('   创建凸包 ELF...')
    try:
        new_binary, convex_va, entry_vaddr, relocated_oep = create_convex_hull_elf(
            target_file, binary, convex_info, convex_content,
            stub_entry_offset, stub_blob, is64,
            recoverable_infos,
        )
        vaddr_shift = int(relocated_oep) - int(original_oep_before_layout)
        print(f'     原始 OEP（重排后）: {hex(relocated_oep)}')
        print(f'     布局虚拟地址偏移: {hex(vaddr_shift)}')
        stub_symbol_offsets = get_stub_symbol_offsets(stub, stub_min_va, STUB_PATCH_SYMBOLS)
    except Exception as e:
        print(f'[-] {e}')
        return False

    # 写到输出文件（保留原始 PT_DYNAMIC/PT_INTERP 等）
    try:
        new_binary.write(str(output_file))
    except Exception as e:
        print(f'[-] 写输出文件失败: {e}')
        return False

    # 头部重建语义：
    # - 保留不可改 PT_LOAD
    # - 将可恢复 PT_LOAD 失活（PT_NULL）
    # - 运行时由 stub 从 convex 段恢复并 map 回目标虚拟地址
    try:
        nulled = _nullify_recoverable_ptloads(
            output_file=output_file,
            is64=is64,
            recoverable_infos=recoverable_infos,
            vaddr_shift=vaddr_shift,
        )
        print(f'   Program Header 重写: PT_NULL 化可恢复 PT_LOAD = {nulled}')
    except Exception as e:
        print(f'[-] 重写 Program Header 失败: {e}')
        return False

    # 重新解析，定位新增 stub 段的文件偏移
    try:
        out_bin = lief.parse(str(output_file))
        if not out_bin:
            print('[-] 无法解析输出 ELF')
            return False

        stub_seg = None
        for seg in out_bin.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            if int(seg.virtual_address) <= int(entry_vaddr) < int(seg.virtual_address + seg.physical_size):
                stub_seg = seg
                break
        if stub_seg is None:
            print('[-] 无法在输出 ELF 中定位 stub 段')
            return False
        stub_file_start = int(stub_seg.file_offset)
        convex_va = int(stub_seg.virtual_address)
    except Exception as e:
        print(f'[-] 解析输出布局失败: {e}')
        return False
    
    # 打补丁
    print('   打补丁...')
    try:
        _patch_convex_hull_stub(
            temp_file, output_file, None, is64,
            convex_info, convex_va, stub_file_start, relocated_oep, vaddr_shift,
            header_info, recoverable_infos, protected_infos,
            len(stub_blob), stub_symbol_offsets
        )
    except Exception as e:
        print(f'[-] 打补丁失败: {e}')
        return False
    
    # 保持可执行权限
    try:
        shutil.copymode(target_file, output_file)
    except Exception:
        pass
    
    total_blocks = (header_info['blocks'] +
                    sum(r['blocks'] for r in recoverable_infos))
    print(f'[+] 已生成: {output_file}')
    print(f'[+] 凸包模式：stub@{hex(convex_va)}，'
          f'覆盖 {convex_info["count"]} 个原始段')
    print(f'[+] 原始虚拟地址范围: {hex(convex_info["min_vaddr"])} - {hex(convex_info["max_vaddr"])}')
    print(f'[+] 共污染 {total_blocks} 个块，受保护段 {len(protected_infos)} 个\n')
    
    return True


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


def main():
    parser = argparse.ArgumentParser(
        description='ELF 打包器：凸包模式（UPX 风格），解决虚拟地址空隙问题')
    
    parser.add_argument('--input', default='', help='输入文件或目录')
    parser.add_argument('--output-dir', default='', help='输出目录')
    parser.add_argument('--recursive', action='store_true', help='递归处理子目录')
    parser.add_argument('--suffix', default='_packed', help='输出文件名后缀')
    parser.add_argument('--overwrite', action='store_true', help='覆盖已存在文件')
    parser.add_argument('--block-size', type=int, default=32, help='原始块大小（字节）')
    parser.add_argument('--insert-size', type=int, default=64, help='插入块大小（字节）')
    parser.add_argument('--insert-type', choices=['zero', 'nop'], default='nop', help='插入内容类型')
    parser.add_argument('--auto-build-stub', action='store_true', help='自动构建 stub')
    parser.add_argument('--rebuild-stub', action='store_true', help='强制重建 stub')
    parser.add_argument('--stub-cc-x86-64', default=ARCH_SPECS["x86_64"]["default_cc"], help='x86_64 stub 编译器')
    parser.add_argument('--stub-cc-i386', default=ARCH_SPECS["i386"]["default_cc"], help='i386 stub 编译器')
    parser.add_argument('--stub-cc-arm', default=ARCH_SPECS["arm"]["default_cc"], help='ARM32 stub 编译器')
    parser.add_argument('--stub-cc-aarch64', default=ARCH_SPECS["aarch64"]["default_cc"], help='AArch64 stub 编译器')
    parser.add_argument('--no-verify-recovery', action='store_true', help='关闭恢复一致性校验')
    
    args = parser.parse_args()
    
    verify_recovery = not args.no_verify_recovery
    stub_compilers = {
        "x86_64": args.stub_cc_x86_64,
        "i386": args.stub_cc_i386,
        "arm": args.stub_cc_arm,
        "aarch64": args.stub_cc_aarch64,
    }
    
    if not args.input:
        # 默认模式
        target_file = Path(TARGET_FILE)
        output_file = Path(OUTPUT_FILE)
        temp_file = Path(TEMP_FILE)
        
        pack_with_convex_hull(
            target_file, output_file, temp_file,
            args.block_size, args.insert_size, args.insert_type,
            args.auto_build_stub, args.rebuild_stub,
            stub_compilers, verify_recovery
        )
        
        if temp_file.exists():
            temp_file.unlink()
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
    
    ok = skipped = 0
    for p in files:
        out_name = _output_name(p, args.suffix)
        out_path = output_dir / out_name
        
        if out_path.exists() and not args.overwrite:
            print(f'[跳过] {out_path} 已存在')
            skipped += 1
            continue
        
        temp_path = output_dir / (out_name + '.tmp.convex.elf')
        
        try:
            if pack_with_convex_hull(
                p, out_path, temp_path,
                args.block_size, args.insert_size, args.insert_type,
                args.auto_build_stub, args.rebuild_stub,
                stub_compilers, verify_recovery
            ):
                ok += 1
            else:
                skipped += 1
        finally:
            if temp_path.exists():
                temp_path.unlink()
    
    print(f'\n完成: 成功 {ok}, 跳过 {skipped}, 总计 {len(files)}')


if __name__ == '__main__':
    main()
