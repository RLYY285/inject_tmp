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
    构建凸包内容：污染后的原始 PT_LOAD 数据（连续存放）
    
    返回：(凸包内容, 段信息映射)
    """
    convex_content = bytearray()
    min_vaddr = convex_info['min_vaddr']
    
    # 记录每个段的信息
    segment_info = {}
    
    # 对每个原始 PT_LOAD，按虚拟地址顺序处理
    segments_sorted = sorted(convex_info['segments'], 
                             key=lambda x: x[1].virtual_address)
    
    for seg_idx, seg in segments_sorted:
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
        
        # 确保凸包内容足够大
        needed_size = seg_offset_in_convex + len(polluted_data)
        if len(convex_content) < needed_size:
            convex_content.extend(b'\x00' * (needed_size - len(convex_content)))
        
        # 写入污染数据
        convex_content[seg_offset_in_convex:needed_size] = polluted_data
        
        # 记录段信息
        segment_info[seg_idx] = {
            'vaddr': seg.virtual_address,
            'size': seg.physical_size,
            'polluted_size': len(polluted_data),
            'blocks': total_blocks,
            'block_size': block_size,
            'insert_size': insert_size,
        }
    
    return bytes(convex_content), segment_info


def create_convex_hull_elf(source_path: Path,
                           binary: lief.ELF.Binary,
                           convex_info: dict,
                           convex_content: bytes,
                           stub_entry_offset: int,
                           stub_blob: bytes,
                           is64: bool) -> lief.ELF.Binary:
    """
    创建凸包 ELF：
    1. 克隆原始 ELF
    2. 移除所有原始 PT_LOAD
    3. 创建单一凸包 PT_LOAD
    4. 保留其他段（PT_DYNAMIC, PT_INTERP 等）
    5. 更新 entrypoint
    """
    # LIEF Binary 对象不可 deepcopy（内部不可 pickle），改为重新 parse 一份独立对象
    new_binary = lief.parse(str(source_path))
    if not new_binary:
        raise RuntimeError(f"[-] 无法重新解析 ELF: {source_path}")
    
    # 移除所有原始 PT_LOAD 段
    new_binary.remove(lief.ELF.Segment.TYPE.LOAD)
    
    # 创建凸包 PT_LOAD
    convex_seg = lief.ELF.Segment()
    convex_seg.type = lief.ELF.Segment.TYPE.LOAD
    convex_seg.flags = (lief.ELF.Segment.FLAGS.R | 
                        lief.ELF.Segment.FLAGS.W | 
                        lief.ELF.Segment.FLAGS.X)
    convex_seg.virtual_address = convex_info['min_vaddr']
    convex_seg.physical_address = convex_info['min_vaddr']
    convex_seg.virtual_size = convex_info['size']
    
    # 内容 = Stub + 污染数据
    combined_content = stub_blob + convex_content
    convex_seg.physical_size = len(combined_content)
    convex_seg.alignment = 0x1000
    convex_seg.content = combined_content
    
    # 添加凸包段
    new_binary.add(convex_seg)
    
    # 更新 entrypoint
    stub_vaddr = convex_info['min_vaddr'] + stub_entry_offset
    new_binary.header.entrypoint = stub_vaddr
    
    return new_binary


def _patch_convex_hull_stub(temp_file: Path,
                           output_file: Path,
                           temp_bin: lief.ELF.Binary,
                           is64: bool,
                           convex_info: dict,
                           segment_info: dict,
                           stub_symbol_offsets: dict[str, int]):
    """
    在凸包 ELF 中打补丁
    """
    width = 8 if is64 else 4
    
    # 找到凸包 PT_LOAD（应该是第一个 LOAD 段）
    convex_seg = None
    for seg in temp_bin.segments:
        if (seg.type == lief.ELF.Segment.TYPE.LOAD and
            seg.virtual_address == convex_info['min_vaddr']):
            convex_seg = seg
            break
    
    if not convex_seg:
        raise RuntimeError("[-] 无法找到凸包 PT_LOAD")
    
    stub_file_start = int(convex_seg.file_offset)
    
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
        # CONVEX_MIN_VADDR
        patch_value(output_file, stub_file_off("CONVEX_MIN_VADDR"), 
                    convex_info['min_vaddr'], width)
        print(f'      CONVEX_MIN_VADDR = {hex(convex_info["min_vaddr"])}')
        
        # OEP_ADDR
        patch_value(output_file, stub_file_off("OEP_ADDR"), 
                    convex_info['min_vaddr'], width)
        print(f'      OEP_ADDR = {hex(convex_info["min_vaddr"])}')
        
        # REGION_COUNT
        patch_value(output_file, stub_file_off("REGION_COUNT"), 
                    len(segment_info), width)
        print(f'      REGION_COUNT = {len(segment_info)}')
        
        # 填充每个段的信息
        for i, (seg_idx, info) in enumerate(sorted(segment_info.items())):
            if i >= STUB_MAX_REGIONS:
                break
            
            # REGION_ADDRS[i]
            patch_value(output_file, stub_file_off("REGION_ADDRS", i),
                        info['vaddr'], width)
            
            # REGION_SIZES[i]
            patch_value(output_file, stub_file_off("REGION_SIZES", i),
                        info['size'], width)
            
            # REGION_RETAINS[i] = block_size
            patch_value(output_file, stub_file_off("REGION_RETAINS", i),
                        info['block_size'], width)
            
            # REGION_DELETES[i] = insert_size
            patch_value(output_file, stub_file_off("REGION_DELETES", i),
                        info['insert_size'], width)
            
            # REGION_BLOCKS[i]
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
    
    print(f'     最小虚拟地址: {hex(convex_info["min_vaddr"])}')
    print(f'     最大虚拟地址: {hex(convex_info["max_vaddr"])}')
    print(f'     凸包大小: {hex(convex_info["size"])} ({convex_info["size"]} 字节)')
    print(f'     包含 PT_LOAD 段数: {convex_info["count"]}')
    
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
    
    # 创建凸包 ELF
    print('   创建凸包 ELF...')
    try:
        new_binary = create_convex_hull_elf(
            target_file, binary, convex_info, convex_content,
            stub_entry_offset, stub_blob, is64
        )
    except Exception as e:
        print(f'[-] {e}')
        return False
    
    # 写到临时文件
    try:
        new_binary.write(str(temp_file))
    except Exception as e:
        print(f'[-] 写临时文件失败: {e}')
        return False
    
    # 解析临时文件
    try:
        temp_bin = lief.parse(str(temp_file))
        if not temp_bin:
            print('[-] 无法解析临时 ELF')
            return False
        
        stub_symbol_offsets = get_stub_symbol_offsets(stub, stub_min_va, STUB_PATCH_SYMBOLS)
    except Exception as e:
        print(f'[-] {e}')
        return False
    
    # 打补丁
    print('   打补丁...')
    try:
        shutil.copy(str(temp_file), str(output_file))
        _patch_convex_hull_stub(
            temp_file, output_file, temp_bin, is64, 
            convex_info, segment_info, stub_symbol_offsets
        )
    except Exception as e:
        print(f'[-] 打补丁失败: {e}')
        return False
    
    # 保持可执行权限
    try:
        shutil.copymode(target_file, output_file)
    except Exception:
        pass
    
    print(f'[+] 已生成: {output_file}')
    print(f'[+] 凸包模式：单一 PT_LOAD，覆盖 {convex_info["count"]} 个原始段')
    print(f'[+] 虚拟地址范围: {hex(convex_info["min_vaddr"])} - {hex(convex_info["max_vaddr"])}')
    print(f'[+] 共污染 {sum(info["blocks"] for info in segment_info.values())} 个块\n')
    
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
