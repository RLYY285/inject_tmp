# inject_tmp 使用说明（凸包模式 / UPX 风格）

本文档对应 `modify_tools/inject_tmp/packer.py` 的当前实现。

## 1. 功能概览

`inject_tmp` 采用“凸包段 + 运行时恢复”方案：

1. 保留动态链接初始化所需信息（`PT_INTERP` / `PT_DYNAMIC` 相关）。
2. 新增一个 `PT_LOAD(RWX)` 作为 stub+数据凸包段。
3. 将可恢复的原始 `PT_LOAD` 在程序头中改为 `PT_NULL`（首次加载不映射）。
4. 默认覆写原可恢复段在文件中的明文字节（当前实现为 `0xA5`），避免明文保留。
5. 运行时由 stub 从凸包段读取污染数据，在临时区恢复后 `MAP_FIXED` 回目标虚拟地址，再跳回 OEP。

这套逻辑不再依赖“扩展段不能跨下一个 `PT_LOAD` 虚拟地址”的旧限制。

## 2. 当前处理流程

对每个输入 ELF：

1. 解析 ELF，收集全部 `PT_LOAD`，计算虚拟地址凸包范围。
2. 将段分为两类：
   - 可恢复段：执行“按块插入污染”（保留块 + 插入块）。
   - 保护段：动态链接关键元数据相关段（`.dynamic/.got/.dyn*/.rela*` 等），不污染。
3. 生成 `convex_content`（存放污染副本）。
4. 新增 stub `PT_LOAD`，入口改到 stub。
5. 重写 Program Header：将可恢复段对应的 `PT_LOAD` 改为 `PT_NULL`。
6. 默认覆写可恢复段原始文件字节，去除明文映像（可通过参数关闭）。
7. 给 stub 打补丁（`OEP_ADDR`、`REGION_*`、`CONVEX_MIN_VADDR`、偏移信息等）。
8. 运行时 stub 执行恢复并跳转原入口。

## 3. 插入策略说明（重要）

当前算法是“整块触发”：

- `total_blocks = segment_size // block_size`
- `inserted_bytes = total_blocks * insert_size`

只有凑满一个完整 `block_size` 才会插入一次。  
若段大小小于 `block_size`，该段 `total_blocks=0`，不会插入任何字节。

这就是日志里出现“`共污染 0 个块`”的原因。

## 4. 命令行参数

常用参数：

- `--input`：输入文件或目录。
- `--output-dir`：输出目录（使用 `--input` 时必填）。
- `--recursive`：递归处理目录。
- `--suffix`：输出文件后缀，默认 `_packed`。
- `--overwrite`：覆盖已存在输出。
- `--block-size`：保留块大小（默认 `32`）。
- `--insert-size`：每块后插入长度（默认 `64`）。
- `--insert-type`：插入内容类型，`zero` 或 `nop`。
- `--keep-recoverable-plaintext`：保留原可恢复段明文字节（默认会覆写去明文）。
- `--prune-recoverable-pages`：启用页级裁剪（按 `0x1000` 页重排）；无法安全裁剪时回退为明文覆写。
- `--auto-build-stub`：自动构建 stub（不存在时建议开）。
- `--rebuild-stub`：强制重建 stub。
- `--stub-cc-x86-64/--stub-cc-i386/--stub-cc-arm/--stub-cc-aarch64`：指定各架构编译器。

支持架构：`x86_64`、`i386`、`arm`、`aarch64`。

## 5. 使用示例

单文件：

```bash
python3 packer.py \
  --input ../inject/hello \
  --output-dir out/ \
  --block-size 32 \
  --insert-size 512 \
  --insert-type zero \
  --rebuild-stub
```

目录批量：

```bash
python3 packer.py \
  --input ../inject/samples \
  --output-dir out/ \
  --recursive \
  --overwrite
```

## 6. 日志解读

常见字段含义：

- `可污染段数 / 受保护段数`：分类结果。
- `Program Header 重写: PT_NULL 化可恢复 PT_LOAD = N`：
  已把 N 个可恢复段从首次加载映射中移除。
- `明文覆写: 覆写可恢复段原始字节 = N 字节`：
  已去除原可恢复段的文件明文数据。
- `页级裁剪: 裁剪可恢复段相关页面 = N 字节`：
  已按页重排并物理移除可恢复段相关页面数据。
- `REGION_COUNT = N`：stub 运行时将恢复 N 个段。
- `共污染 X 个块`：实际发生插入污染的块数（由段大小和 `block-size` 决定）。

## 7. 注意事项

1. 若 `block-size` 过大，可能出现 `共污染 0 个块`，但流程仍会成功。
2. `hello` 这类小样本建议用较小 `block-size`（如 `32/64/128`）。
3. 输出文件属于“运行时恢复”模型，静态字节布局与原始文件不同。
4. 页级裁剪需要满足装载对齐约束；实现会自动做安全检查，不满足时回退为覆写模式。
