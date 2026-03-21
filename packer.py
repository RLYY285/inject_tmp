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
MAGIC64_OEP              = 0x1111111122222222
MAGIC64_VOFFSET          = 0x7777777788888888
MAGIC64_REGION_COUNT     = 0xEEEEEEEE44444444
MAGIC64_REGION_ADDR      = 0x3333333344444444
MAGIC64_REGION_SIZE      = 0x5555555566666666
MAGIC64_RETAIN_INTERVAL  = 0xAAAAAAAA11111111
MAGIC64_DELETE_SIZE      = 0xBBBBBBBB22222222
MAGIC64_TOTAL_BLOCKS     = 0xCCCCCCCC33333333
MAGIC64_CONVEX_MIN_VADDR = 0xEEEEEEEE66666666

MAGIC32_OEP              = 0x22222222
MAGIC32_VOFFSET          = 0x88888888
MAGIC32_REGION_COUNT     = 0xEEEE4444
MAGIC32_REGION_ADDR      = 0x44444444
MAGIC32_REGION_SIZE      = 0x66666666
MAGIC32_RETAIN_INTERVAL  = 0x11111111
MAGIC32_DELETE_SIZE      = 0x55555555
MAGIC32_TOTAL_BLOCKS     = 0x77777777
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
    'OEP_ADDR':        MAGIC64_OEP,
    'STUB_VOFFSET':    MAGIC64_VOFFSET,
    'REGION_COUNT':    MAGIC64_REGION_COUNT,
    'REGION_ADDR':     MAGIC64_REGION_ADDR,
    'REGION_SIZE':     MAGIC64_REGION_SIZE,
    'RETAIN_INTERVAL': MAGIC64_RETAIN_INTERVAL,
    'DELETE_SIZE':     MAGIC64_DELETE_SIZE,
    'TOTAL_BLOCKS':    MAGIC64_TOTAL_BLOCKS,
    'CONVEX_MIN_VADDR': MAGIC64_CONVEX_MIN_VADDR,
}

MAGIC_MAP_32 = {
    'OEP_ADDR':        MAGIC32_OEP,
    'STUB_VOFFSET':    MAGIC32_VOFFSET,
    'REGION_COUNT':    MAGIC32_REGION_COUNT,
    'REGION_ADDR':     MAGIC32_REGION_ADDR,
    'REGION_SIZE':     MAGIC32_REGION_SIZE,
    'RETAIN_INTERVAL': MAGIC32_RETAIN_INTERVAL,
    'DELETE_SIZE':     MAGIC32_DELETE_SIZE,
    'TOTAL_BLOCKS':    MAGIC32_TOTAL_BLOCKS,
    'CONVEX_MIN_VADDR': MAGIC32_CONVEX_MIN_VADDR,
}

AUTO_BLOCK_CANDIDATES = (8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512)
AUTO_INSERT_CANDIDATES = (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)
STUB_MAX_REGIONS = 64

STUB_PATCH_SYMBOLS = (
    "OEP_ADDR",
    "STUB_VOFFSET",
    "REGION_COUNT",
    "REGION_ADDRS",
    "REGION_SIZES",
    "REGION_RETAINS",
    "REGION_DELETES",
    "REGION_BLOCKS",
    "CONVEX_MIN_VADDR",
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


def build_convex_hull_content(binary: lief.ELF.Binary, 
                               convex_info: dict,
                               file_bytes: bytes,
                               block_size: int,
                               insert_size: int,
                               insert_type: str,
                               arch_name: str) -> tuple[bytes, dict]:
    """
    构建凸包内容：污染后的原始 PT_LOAD 数据（按虚拟地址偏移放置）

    布局：每个原始 LOAD 段的污染数据写入其相对于 min_vaddr 的偏移处。
    若污染后的数据超出当前段在虚拟地址空间中的范围，将使段间产生重叠，
    函数会检测并报告此情况。

    返回：(凸包内容, 段信息映射)
    """
    convex_content = bytearray()
    min_vaddr = convex_info['min_vaddr']

    # 记录每个段的信息
    segment_info = {}

    # 对每个原始 PT_LOAD，按虚拟地址顺序处理
    segments_sorted = sorted(convex_info['segments'],
                             key=lambda x: x[1].virtual_address)

    for list_pos, (seg_idx, seg) in enumerate(segments_sorted):
        # 计算这个段在凸包内的偏移
        seg_offset_in_convex = seg.virtual_address - min_vaddr

        # 提取原始数据
        seg_file_start = seg.file_offset
        seg_file_end = seg_file_start + seg.physical_size
        original_data = file_bytes[seg_file_start:seg_file_end]

        # 污染数据
        polluted_data, total_blocks = build_polluted_text(
            original_data,
            block_size,
            insert_size,
            insert_type,
            arch_name
        )

        polluted_size = len(polluted_data)

        # 检查污染数据是否溢出到下一个段的虚拟地址空间
        if list_pos + 1 < len(segments_sorted):
            next_seg = segments_sorted[list_pos + 1][1]
            next_offset = next_seg.virtual_address - min_vaddr
            if seg_offset_in_convex + polluted_size > next_offset:
                overflow = seg_offset_in_convex + polluted_size - next_offset
                raise RuntimeError(
                    f"[-] 段 {list_pos} (vaddr={hex(seg.virtual_address)}) 的污染数据"
                    f"超出其虚拟地址范围 {overflow} 字节，"
                    f"与段 {list_pos + 1} (vaddr={hex(next_seg.virtual_address)}) 重叠。"
                    f"请减小 --insert-size 或增大 --block-size。"
                )

        # 确保凸包内容足够大
        needed_size = seg_offset_in_convex + polluted_size
        if len(convex_content) < needed_size:
            convex_content.extend(b'\x00' * (needed_size - len(convex_content)))

        # 写入污染数据
        convex_content[seg_offset_in_convex:needed_size] = polluted_data

        # 记录段信息（含验证所需的原始数据元数据）
        segment_info[seg_idx] = {
            'vaddr': seg.virtual_address,
            'size': seg.physical_size,
            'polluted_size': polluted_size,
            'blocks': total_blocks,
            'block_size': block_size,
            'insert_size': insert_size,
            # 验证用元数据
            '_orig_file_start': seg_file_start,
            '_polluted_data': bytes(polluted_data),
        }

    return bytes(convex_content), segment_info


def write_convex_elf(output_path: Path,
                     combined_content: bytearray,
                     convex_vaddr: int,
                     convex_virtual_size: int,
                     stub_entry_vaddr: int,
                     is64: bool) -> None:
    """
    手动构建并写出凸包 ELF 文件。

    避免使用 LIEF 写出 ELF（LIEF 在某些二进制文件上无法正确重定位 PHT），
    直接构造 ELF 头 + 单个 PT_LOAD 程序头 + 内容。

    布局（文件）：
      [ELF header][PT_LOAD phdr][pad to PAGE_SIZE][combined_content]
    """
    PAGE_SIZE = 0x1000

    if is64:
        ELF_HDR_SIZE  = 64
        PHDR_ENT_SIZE = 56
        e_machine     = 62    # EM_X86_64
        e_class       = 2     # ELFCLASS64
        elf_fmt       = '<4sBBBBBxxxxxxx'   # e_ident (16 bytes)
        ehdr_fmt      = '<HHIQQQIHHHHHH'     # remaining ELF header fields
        phdr_fmt      = '<IIQQQQQQ'          # 64-bit phdr
        e_type        = 2     # ET_EXEC (non-PIE default)
    else:
        ELF_HDR_SIZE  = 52
        PHDR_ENT_SIZE = 32
        e_machine     = 3     # EM_386
        e_class       = 1     # ELFCLASS32
        elf_fmt       = '<4sBBBBBxxxxxxx'
        ehdr_fmt      = '<HHIIIIIHHHHHH'
        phdr_fmt      = '<IIIIIIII'
        e_type        = 2

    e_phoff   = ELF_HDR_SIZE
    e_phnum   = 1
    # Content starts at the first page after the header + single phdr
    hdr_total = ELF_HDR_SIZE + PHDR_ENT_SIZE
    content_file_offset = align_up(hdr_total, PAGE_SIZE)
    header_pad = content_file_offset - hdr_total

    p_type  = 1          # PT_LOAD
    p_flags = 7          # R | W | X
    p_offset = content_file_offset
    p_vaddr  = convex_vaddr
    p_paddr  = convex_vaddr
    p_filesz = len(combined_content)
    p_memsz  = convex_virtual_size
    p_align  = PAGE_SIZE

    # Build ELF ident (16 bytes)
    # Fields: EI_CLASS, EI_DATA (1=ELFDATA2LSB), EI_VERSION (1=current), EI_OSABI (0=SysV), EI_ABIVERSION (0)
    elf_ident = struct.pack(elf_fmt, b'\x7fELF', e_class, 1, 1, 0, 0)  # 16 bytes

    if is64:
        ehdr_body = struct.pack(ehdr_fmt,
            e_type, e_machine, 1,           # type, machine, version
            stub_entry_vaddr,               # e_entry
            e_phoff, 0, 0,                  # e_phoff, e_shoff, e_flags
            ELF_HDR_SIZE,                   # e_ehsize
            PHDR_ENT_SIZE, e_phnum,         # e_phentsize, e_phnum
            0, 0, 0,                        # e_shentsize, e_shnum, e_shstrndx
        )
        phdr_data = struct.pack(phdr_fmt,
            p_type, p_flags,
            p_offset, p_vaddr, p_paddr,
            p_filesz, p_memsz, p_align,
        )
    else:
        ehdr_body = struct.pack(ehdr_fmt,
            e_type, e_machine, 1,
            stub_entry_vaddr & 0xFFFFFFFF,
            e_phoff, 0, 0,
            ELF_HDR_SIZE,
            PHDR_ENT_SIZE, e_phnum,
            0, 0, 0,
        )
        phdr_data = struct.pack(phdr_fmt,
            p_type, p_offset,
            p_vaddr & 0xFFFFFFFF, p_paddr & 0xFFFFFFFF,
            p_filesz & 0xFFFFFFFF, p_memsz & 0xFFFFFFFF,
            p_flags, p_align & 0xFFFFFFFF,
        )

    out = elf_ident + ehdr_body + phdr_data + bytes(header_pad) + bytes(combined_content)
    output_path.write_bytes(out)


def create_convex_hull_elf(source_path: Path,
                           binary: lief.ELF.Binary,
                           convex_info: dict,
                           convex_content: bytes,
                           stub_entry_offset: int,
                           stub_blob: bytes,
                           is64: bool,
                           temp_file: Path) -> tuple[int, int, int, int]:
    """
    创建凸包 ELF 并写入 temp_file。

    布局分两种情况：
      - 标准布局（非 PIE / min_vaddr >= stub_pad）：
          [Stub | Pad] | [原始 LOAD 数据（按原始虚拟地址偏移）]
          凸包起始地址 = min_vaddr - stub_pad，原始段地址不变
      - 后置布局（PIE / min_vaddr < stub_pad）：
          [原始 LOAD 数据（按原始虚拟地址偏移）] | [Pad] | [Stub]
          凸包起始地址 = min_vaddr，Stub 追加于原始数据之后

    使用 write_convex_elf 手动构建 ELF，确保虚拟地址精确（避免 LIEF 重定位问题）。

    返回: (stub_pad, stub_offset_in_combined, convex_vaddr, content_file_offset)
      - stub_pad:              Stub 占用的页对齐字节数
      - stub_offset_in_combined: Stub blob 在 combined_content 中的字节偏移
      - convex_vaddr:          凸包 PT_LOAD 的起始虚拟地址
      - content_file_offset:   combined_content 在输出文件中的字节偏移
    """
    PAGE_SIZE = 0x1000

    stub_pad = align_up(len(stub_blob), PAGE_SIZE)
    min_vaddr = convex_info['min_vaddr']

    if min_vaddr >= stub_pad:
        # 标准布局：Stub 在原始数据之前
        convex_vaddr = min_vaddr - stub_pad
        stub_padding = bytes(stub_pad - len(stub_blob))
        combined_content = (bytearray(stub_blob) + bytearray(stub_padding) +
                            bytearray(convex_content))
        convex_virtual_size = stub_pad + max(convex_info['size'], len(convex_content))
        stub_offset_in_combined = 0
    else:
        # 后置布局（PIE / min_vaddr 过小）：Stub 追加于原始数据之后
        convex_vaddr = min_vaddr
        data_aligned = align_up(len(convex_content), PAGE_SIZE)
        data_padding = bytes(data_aligned - len(convex_content))
        stub_padding = bytes(stub_pad - len(stub_blob))
        combined_content = (bytearray(convex_content) + bytearray(data_padding) +
                            bytearray(stub_blob) + bytearray(stub_padding))
        convex_virtual_size = data_aligned + stub_pad
        stub_offset_in_combined = data_aligned

    stub_entry_vaddr = convex_vaddr + stub_offset_in_combined + stub_entry_offset

    # 使用手动构建函数写出文件，确保虚拟地址精确
    write_convex_elf(
        temp_file,
        combined_content,
        convex_vaddr,
        convex_virtual_size,
        stub_entry_vaddr,
        is64,
    )

    # content_file_offset: combined_content 在文件中的偏移
    ELF_HDR_SIZE  = 64 if is64 else 52
    PHDR_ENT_SIZE = 56 if is64 else 32
    content_file_offset = align_up(ELF_HDR_SIZE + PHDR_ENT_SIZE, PAGE_SIZE)

    return stub_pad, stub_offset_in_combined, convex_vaddr, content_file_offset




def _patch_convex_hull_stub(output_file: Path,
                           is64: bool,
                           convex_info: dict,
                           segment_info: dict,
                           stub_symbol_offsets: dict[str, int],
                           original_oep: int,
                           stub_pad: int,
                           stub_offset_in_combined: int,
                           content_file_offset: int):
    """
    在凸包 ELF 中打补丁

    参数：
      original_oep:          原始 ELF 的入口点虚拟地址（运行时恢复后的跳转目标）
      stub_pad:              Stub 在凸包中占用的页对齐字节数
      stub_offset_in_combined: Stub blob 在组合内容（combined_content）中的字节偏移
      content_file_offset:   combined_content 在输出文件中的字节偏移
    """
    width = 8 if is64 else 4

    # stub 在文件中的起始偏移 = combined_content 的文件偏移 + stub 在 combined 中的偏移
    stub_file_start = content_file_offset + stub_offset_in_combined

    def stub_file_off(symbol: str, idx: int | None = None) -> int:
        if symbol not in stub_symbol_offsets:
            raise RuntimeError(f"[-] Stub 符号未找到: {symbol}")
        off = stub_file_start + stub_symbol_offsets[symbol]
        if idx is not None:
            off += idx * width
        return off

    # 打补丁
    print('    打补丁...')

    try:
        # CONVEX_MIN_VADDR：原始段的最小虚拟地址（原始数据起始位置）
        patch_value(output_file, stub_file_off("CONVEX_MIN_VADDR"),
                    convex_info['min_vaddr'], width)
        print(f'      CONVEX_MIN_VADDR = {hex(convex_info["min_vaddr"])}')

        # OEP_ADDR：原始 ELF 入口点（恢复后跳转的目标地址）
        patch_value(output_file, stub_file_off("OEP_ADDR"),
                    original_oep, width)
        print(f'      OEP_ADDR = {hex(original_oep)}')

        # STUB_VOFFSET：stub 在凸包中的偏移（即 stub_pad）
        patch_value(output_file, stub_file_off("STUB_VOFFSET"),
                    stub_pad, width)
        print(f'      STUB_VOFFSET = {hex(stub_pad)}')

        # REGION_COUNT
        patch_value(output_file, stub_file_off("REGION_COUNT"),
                    len(segment_info), width)
        print(f'      REGION_COUNT = {len(segment_info)}')

        # 填充每个段的信息（按虚拟地址排序，与恢复顺序一致）
        for i, (seg_idx, info) in enumerate(sorted(segment_info.items())):
            if i >= STUB_MAX_REGIONS:
                break

            # REGION_ADDRS[i]：段的原始虚拟地址
            patch_value(output_file, stub_file_off("REGION_ADDRS", i),
                        info['vaddr'], width)

            # REGION_SIZES[i]：污染后的大小（compact_in_place 需要处理的缓冲区大小）
            # 必须使用 polluted_size 而非原始 size：C 代码会验证
            # blocks * (retain + del) <= region_size，使用原始 size 会导致该检查失败（返回 -7）
            patch_value(output_file, stub_file_off("REGION_SIZES", i),
                        info['polluted_size'], width)

            # REGION_RETAINS[i] = block_size（每次保留的字节数）
            patch_value(output_file, stub_file_off("REGION_RETAINS", i),
                        info['block_size'], width)

            # REGION_DELETES[i] = insert_size（每次删除的字节数）
            patch_value(output_file, stub_file_off("REGION_DELETES", i),
                        info['insert_size'], width)

            # REGION_BLOCKS[i]：插入块的总数
            patch_value(output_file, stub_file_off("REGION_BLOCKS", i),
                        info['blocks'], width)

        print(f'      填充了 {min(len(segment_info), STUB_MAX_REGIONS)} 个段信息')

    except Exception as e:
        raise RuntimeError(f"[-] 打补丁失败: {e}")


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

    original_oep = binary.header.entrypoint
    print(f'     最小虚拟地址: {hex(convex_info["min_vaddr"])}')
    print(f'     最大虚拟地址: {hex(convex_info["max_vaddr"])}')
    print(f'     凸包大小: {hex(convex_info["size"])} ({convex_info["size"]} 字节)')
    print(f'     包含 PT_LOAD 段数: {convex_info["count"]}')
    print(f'     原始入口点 (OEP): {hex(original_oep)}')
    
    # 构建凸包内容
    print('   构建污染数据...')
    try:
        convex_content, segment_info = build_convex_hull_content(
            binary, convex_info, file_bytes,
            block_size, insert_size, insert_type, arch_name
        )
    except Exception as e:
        print(f'[-] {e}')
        return False
    
    print(f'     凸包内容大小: {len(convex_content)} 字节')
    
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
    
    # 创建凸包 ELF（写入临时文件）
    print('   创建凸包 ELF...')
    try:
        stub_symbol_offsets = get_stub_symbol_offsets(stub, stub_min_va, STUB_PATCH_SYMBOLS)
        stub_pad, stub_offset_in_combined, convex_vaddr, content_file_offset = create_convex_hull_elf(
            target_file, binary, convex_info, convex_content,
            stub_entry_offset, stub_blob, is64, temp_file
        )
        print(f'     凸包起始虚拟地址: {hex(convex_vaddr)} (stub_pad={hex(stub_pad)}, '
              f'stub_offset={hex(stub_offset_in_combined)})')
    except Exception as e:
        print(f'[-] {e}')
        return False

    # 打补丁（从临时文件复制到输出文件，然后打补丁）
    print('   打补丁...')
    try:
        shutil.copy(str(temp_file), str(output_file))
        _patch_convex_hull_stub(
            output_file, is64,
            convex_info, segment_info, stub_symbol_offsets,
            original_oep, stub_pad, stub_offset_in_combined, content_file_offset
        )
    except Exception as e:
        print(f'[-] 打补丁失败: {e}')
        return False

    # 保持可执行权限
    try:
        shutil.copymode(target_file, output_file)
    except Exception:
        pass

    # 恢复一致性验证（可选）
    if verify_recovery:
        _verify_recovery(file_bytes, segment_info)

    print(f'[+] 已生成: {output_file}')
    print(f'[+] 凸包模式：单一 PT_LOAD，覆盖 {convex_info["count"]} 个原始段')
    print(f'[+] 凸包起始地址: {hex(convex_vaddr)}, 原始数据起始: {hex(convex_info["min_vaddr"])}')
    print(f'[+] 虚拟地址范围: {hex(convex_info["min_vaddr"])} - {hex(convex_info["max_vaddr"])}')
    print(f'[+] 共污染 {sum(info["blocks"] for info in segment_info.values())} 个块\n')

    return True


def _compact_in_place_py(data: bytearray, retain: int, delete: int, blocks: int) -> bytearray:
    """
    Python 实现的 compact_in_place，用于恢复验证。
    与 delete.c 中的 compact_in_place 逻辑保持一致。
    """
    region_size = len(data)
    result = bytearray()
    pos = 0

    for _ in range(blocks):
        if pos >= region_size:
            break
        retain_len = min(retain, region_size - pos)
        result.extend(data[pos:pos + retain_len])
        pos += retain_len
        del_len = min(delete, region_size - pos)
        pos += del_len

    if pos < region_size:
        result.extend(data[pos:])

    return result


def _verify_recovery(file_bytes: bytes, segment_info: dict) -> None:
    """
    恢复一致性验证：对每个段的污染数据执行 Python 侧 compact_in_place，
    比较恢复结果与原始数据是否一致。
    """
    print('   [验证] 恢复一致性校验...')
    all_ok = True
    for seg_idx, info in sorted(segment_info.items()):
        orig_start = info.get('_orig_file_start')
        orig_size  = info.get('size', 0)
        poll_data  = info.get('_polluted_data')

        if poll_data is None or orig_start is None:
            # 元数据未记录，跳过
            continue

        original_data = file_bytes[orig_start:orig_start + orig_size]
        recovered = _compact_in_place_py(
            bytearray(poll_data),
            info['block_size'],
            info['insert_size'],
            info['blocks'],
        )

        if bytes(recovered[:orig_size]) != original_data:
            print(f'     [!] 段 {seg_idx} (vaddr={hex(info["vaddr"])}) '
                  f'恢复结果与原始数据不一致！')
            all_ok = False
        else:
            print(f'     [✓] 段 {seg_idx} (vaddr={hex(info["vaddr"])}) 恢复验证通过')

    if all_ok:
        print('   [验证] 全部段恢复验证通过 ✓')


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
