// delete.c - 凸包模式（UPX 风格）
// 支持 x86_64, i386, aarch64, arm

#include <stdint.h>

#if defined(__x86_64__)
#define ARCH_X64 1
#elif defined(__i386__)
#define ARCH_X86 1
#elif defined(__aarch64__)
#define ARCH_AARCH64 1
#elif defined(__arm__)
#define ARCH_ARM 1
#else
#error "Unsupported architecture for delete.c"
#endif

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 1. 凸包模式常量定义
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#define STUB_TEXT_SYM __attribute__((section(".text"))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
#define STUB_MAX_REGIONS 64

#if defined(ARCH_X64) || defined(ARCH_AARCH64)
#define MAGIC_OEP              0x1111111122222222ULL
#define MAGIC_VOFFSET          0x7777777788888888ULL
#define MAGIC_REGION_COUNT     0xEEEEEEEE44444444ULL
#define MAGIC_REGION_ADDR      0x3333333344444444ULL
#define MAGIC_REGION_SIZE      0x5555555566666666ULL
#define MAGIC_REGION_RETAIN    0xAAAAAAAA11111111ULL
#define MAGIC_REGION_DELETE    0xBBBBBBBB22222222ULL
#define MAGIC_REGION_BLOCKS    0xCCCCCCCC33333333ULL
#define MAGIC_CONVEX_MIN_VADDR 0xEEEEEEEE66666666ULL

typedef uint64_t uaddr_t;

STUB_TEXT_SYM volatile uint64_t OEP_ADDR         = MAGIC_OEP;
STUB_TEXT_SYM volatile uint64_t STUB_VOFFSET     = MAGIC_VOFFSET;
STUB_TEXT_SYM volatile uint64_t REGION_COUNT     = MAGIC_REGION_COUNT;
STUB_TEXT_SYM volatile uint64_t CONVEX_MIN_VADDR = MAGIC_CONVEX_MIN_VADDR;
STUB_TEXT_SYM volatile uint64_t REGION_ADDRS[STUB_MAX_REGIONS]   = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_ADDR };
STUB_TEXT_SYM volatile uint64_t REGION_SIZES[STUB_MAX_REGIONS]   = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_SIZE };
STUB_TEXT_SYM volatile uint64_t REGION_RETAINS[STUB_MAX_REGIONS] = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_RETAIN };
STUB_TEXT_SYM volatile uint64_t REGION_DELETES[STUB_MAX_REGIONS] = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_DELETE };
STUB_TEXT_SYM volatile uint64_t REGION_BLOCKS[STUB_MAX_REGIONS]  = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_BLOCKS };
#else
#define MAGIC_OEP              0x22222222U
#define MAGIC_VOFFSET          0x88888888U
#define MAGIC_REGION_COUNT     0xEEEE4444U
#define MAGIC_REGION_ADDR      0x44444444U
#define MAGIC_REGION_SIZE      0x66666666U
#define MAGIC_REGION_RETAIN    0x11111111U
#define MAGIC_REGION_DELETE    0x55555555U
#define MAGIC_REGION_BLOCKS    0x77777777U
#define MAGIC_CONVEX_MIN_VADDR 0xEEEE6666U

typedef uint32_t uaddr_t;

STUB_TEXT_SYM volatile uint32_t OEP_ADDR         = MAGIC_OEP;
STUB_TEXT_SYM volatile uint32_t STUB_VOFFSET     = MAGIC_VOFFSET;
STUB_TEXT_SYM volatile uint32_t REGION_COUNT     = MAGIC_REGION_COUNT;
STUB_TEXT_SYM volatile uint32_t CONVEX_MIN_VADDR = MAGIC_CONVEX_MIN_VADDR;
STUB_TEXT_SYM volatile uint32_t REGION_ADDRS[STUB_MAX_REGIONS]   = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_ADDR };
STUB_TEXT_SYM volatile uint32_t REGION_SIZES[STUB_MAX_REGIONS]   = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_SIZE };
STUB_TEXT_SYM volatile uint32_t REGION_RETAINS[STUB_MAX_REGIONS] = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_RETAIN };
STUB_TEXT_SYM volatile uint32_t REGION_DELETES[STUB_MAX_REGIONS] = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_DELETE };
STUB_TEXT_SYM volatile uint32_t REGION_BLOCKS[STUB_MAX_REGIONS]  = { [0 ... STUB_MAX_REGIONS - 1] = MAGIC_REGION_BLOCKS };
#endif

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 2. 保存的寄存器和栈
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#define STUB_STACK_SIZE 0x4000
#define STUB_DATA_SECTION ".text"

#if defined(ARCH_X64)
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint64_t SAVED_RSP = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint64_t SAVED_RDX = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
static uint8_t STUB_STACK[STUB_STACK_SIZE];
#elif defined(ARCH_X86)
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint32_t SAVED_ESP = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint32_t SAVED_EDX = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
static uint8_t STUB_STACK[STUB_STACK_SIZE];
#elif defined(ARCH_AARCH64)
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint64_t SAVED_SP = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint64_t SAVED_X0 = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint64_t SAVED_X1 = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint64_t SAVED_X2 = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
static uint8_t STUB_STACK[STUB_STACK_SIZE];
#elif defined(ARCH_ARM)
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint32_t SAVED_SP = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint32_t SAVED_R0 = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint32_t SAVED_R1 = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
volatile uint32_t SAVED_R2 = 0;
__attribute__((section(STUB_DATA_SECTION))) __attribute__((visibility("hidden"))) __attribute__((aligned(16)))
static uint8_t STUB_STACK[STUB_STACK_SIZE];
#endif

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 3. 系统调用号
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#if defined(ARCH_X64)
#define SYS_MPROTECT 10
#define SYS_EXIT     60
#elif defined(ARCH_AARCH64)
#define SYS_MPROTECT 226
#define SYS_EXIT     93
#else
#define SYS_MPROTECT 125
#define SYS_EXIT     1
#endif

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 4. 系统调用包装
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#if defined(ARCH_X64)
static inline long my_syscall1(long n, long a1) {
    unsigned long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}
static inline long my_syscall3(long n, long a1, long a2, long a3) {
    unsigned long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}
#elif defined(ARCH_X86)
static inline long my_syscall1(long n, long a1) {
    long ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(n), "b"(a1) : "memory");
    return ret;
}
static inline long my_syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(n), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
#elif defined(ARCH_AARCH64)
static inline long my_syscall1(long n, long a1) {
    register long x0 __asm__("x0") = a1;
    register long x8 __asm__("x8") = n;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}
static inline long my_syscall3(long n, long a1, long a2, long a3) {
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x8 __asm__("x8") = n;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
    return x0;
}
#elif defined(ARCH_ARM)
static inline long my_syscall1(long n, long a1) {
    long ret;
    __asm__ volatile (
        "mov r7, %1\n\t"
        "mov r0, %2\n\t"
        "svc 0\n\t"
        "mov %0, r0\n\t"
        : "=r"(ret)
        : "r"(n), "r"(a1)
        : "r0", "r7", "memory", "cc", "lr"
    );
    return ret;
}
static inline long my_syscall3(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile (
        "mov r7, %1\n\t"
        "mov r0, %2\n\t"
        "mov r1, %3\n\t"
        "mov r2, %4\n\t"
        "svc 0\n\t"
        "mov %0, r0\n\t"
        : "=r"(ret)
        : "r"(n), "r"(a1), "r"(a2), "r"(a3)
        : "r0", "r1", "r2", "r7", "memory", "cc", "lr"
    );
    return ret;
}
#endif

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 5. 内存操作和辅助函数
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

static inline void memcpy_safe(uint8_t *dst, const uint8_t *src, uaddr_t len) {
    uaddr_t i;
    for (i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

static inline int add_overflow_uaddr(uaddr_t a, uaddr_t b, uaddr_t *out) {
    *out = a + b;
    return *out < a;
}

static inline int mul_overflow_uaddr(uaddr_t a, uaddr_t b, uaddr_t *out) {
    if (a == 0 || b == 0) {
        *out = 0;
        return 0;
    }
    *out = a * b;
    return (*out / a) != b;
}

static inline void fail_exit(int code) {
    my_syscall1(SYS_EXIT, code);
    for (;;) { }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 6. 删块恢复函数
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * compact_in_place: 原地删块恢复
 * 
 * 参数：
 *   src_addr: 污染数据地址（源）
 *   dst_addr: 恢复数据地址（目标，通常与 src_addr 相同）
 *   region_size: 区域大小
 *   retain_interval: 保留块大小
 *   delete_size: 删除块大小
 *   total_blocks: 块数
 *   oep_in_src: OEP 在源地址内的偏移（-1 表示不在此区域）
 *   out_new_oep: 输出新 OEP（指针）
 */
static int compact_in_place(
    uint8_t *src_addr,
    uint8_t *dst_addr,
    uaddr_t region_size,
    uaddr_t retain_interval,
    uaddr_t delete_size,
    uaddr_t total_blocks,
    uaddr_t oep_in_src,
    uaddr_t *out_new_oep
)
{
    uaddr_t block_len;
    uaddr_t processed_len;
    uaddr_t pos = 0;
    uaddr_t dest = 0;
    uaddr_t new_oep_off = 0;
    int oep_found = 0;
    uaddr_t blk;

    if (!src_addr || !dst_addr || !region_size || !out_new_oep) return -1;
    if (!retain_interval) return -2;

    if (add_overflow_uaddr(retain_interval, delete_size, &block_len)) return -5;
    if (mul_overflow_uaddr(total_blocks, block_len, &processed_len)) return -6;
    if (processed_len > region_size) return -7;

    // 删块逻辑
    for (blk = 0; blk < total_blocks; blk++) {
        uaddr_t retain_len = retain_interval;
        uaddr_t del_len = delete_size;

        if (pos > region_size) return -11;

        // 计算实际保留��度
        if (pos + retain_len > region_size) {
            retain_len = region_size - pos;
        }

        // 处理保留部分
        if (retain_len > 0) {
            // 检查 OEP 是否在这个块中
            if (oep_in_src != (uaddr_t)-1 && !oep_found) {
                if (oep_in_src >= pos && oep_in_src < pos + retain_len) {
                    new_oep_off = dest + (oep_in_src - pos);
                    oep_found = 1;
                }
            }

            // 复制保留部分
            if (src_addr != dst_addr || src_addr + pos != dst_addr + dest) {
                memcpy_safe(dst_addr + dest, src_addr + pos, retain_len);
            }

            dest += retain_len;
            pos += retain_len;
        }

        if (pos > region_size) break;

        // 计算实际删除长度
        if (pos + del_len > region_size) {
            del_len = region_size - pos;
        }

        // 跳过删除部分
        pos += del_len;
    }

    // 处理剩余数据
    if (pos < region_size) {
        uaddr_t remaining_len = region_size - pos;

        if (oep_in_src != (uaddr_t)-1 && !oep_found) {
            if (oep_in_src >= pos && oep_in_src < region_size) {
                new_oep_off = dest + (oep_in_src - pos);
                oep_found = 1;
            }
        }

        if (src_addr != dst_addr || src_addr + pos != dst_addr + dest) {
            memcpy_safe(dst_addr + dest, src_addr + pos, remaining_len);
        }
        dest += remaining_len;
    }

    // OEP 计算
    if (oep_in_src != (uaddr_t)-1) {
        if (!oep_found) return -16;
        *out_new_oep = (uaddr_t)(uintptr_t)dst_addr + new_oep_off;
    } else {
        *out_new_oep = 0;
    }

    return 0;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 7. 凸包模式 Stub（简化版）
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#if defined(ARCH_X64)

static __attribute__((noinline)) void stub_main(void) {
    uaddr_t convex_base = CONVEX_MIN_VADDR;
    uaddr_t new_oep = OEP_ADDR;
    uaddr_t count = REGION_COUNT;
    uaddr_t i;
    int rc;

    if (count > STUB_MAX_REGIONS) count = STUB_MAX_REGIONS;

    // 直接在凸包内恢复数据（所有地址都有效）
    for (i = 0; i < count; i++) {
        uaddr_t region_vaddr = REGION_ADDRS[i];
        uaddr_t region_size = REGION_SIZES[i];
        uaddr_t retain = REGION_RETAINS[i];
        uaddr_t del = REGION_DELETES[i];
        uaddr_t blocks = REGION_BLOCKS[i];

        if (!region_size || !retain) continue;

        // 使目标地址可写
        my_syscall3(
            SYS_MPROTECT,
            (long)(region_vaddr & ~0xfffUL),
            (long)(((region_size + 0xfff) & ~0xfffUL)),
            7  // PROT_READ|PROT_WRITE|PROT_EXEC
        );

        // 直接原地恢复
        uaddr_t oep_offset = (uaddr_t)-1;
        if (new_oep >= region_vaddr && new_oep < region_vaddr + region_size) {
            oep_offset = new_oep - region_vaddr;
        }

        rc = compact_in_place(
            (uint8_t *)region_vaddr,
            (uint8_t *)region_vaddr,
            region_size,
            retain,
            del,
            blocks,
            oep_offset,
            &new_oep
        );

        if (rc != 0) fail_exit(1);
    }

    // 跳转到恢复后的 OEP
    __asm__ volatile (
        "mov %0, %%rdx\n\t"
        "mov %1, %%rsp\n\t"
        "jmp *%%rax\n\t"
        :
        : "m"(SAVED_RDX), "m"(SAVED_RSP), "a"(new_oep)
        : "rdx", "memory"
    );

    fail_exit(0);
}

__attribute__((naked)) void _start(void) {
    __asm__ volatile (
        "mov %rsp, SAVED_RSP(%rip)\n\t"
        "mov %rdx, SAVED_RDX(%rip)\n\t"
        "lea STUB_STACK(%rip), %rsp\n\t"
        "add $0x4000, %rsp\n\t"
        "and $-16, %rsp\n\t"
        "call stub_main\n\t"
        "ud2\n\t"
    );
}

#elif defined(ARCH_X86)

#define OFF(sym) ((uintptr_t)(&(sym)) - (uintptr_t)(&__stub_base))
__asm__(".text\n.global __stub_base\n__stub_base:\n");
extern uint8_t __stub_base;

static inline uint8_t *get_stub_base(void) {
    uint8_t *base;
    __asm__ volatile (
        "call 1f\n"
        "1: pop %0\n"
        "leal __stub_base-1b(%0), %0\n"
        : "=r"(base)
    );
    return base;
}

static __attribute__((noinline)) void stub_main(uint8_t *stub_base) {
    volatile uint32_t *oep_ptr      = (volatile uint32_t*)(stub_base + OFF(OEP_ADDR));
    volatile uint32_t *region_count_p = (volatile uint32_t*)(stub_base + OFF(REGION_COUNT));
    volatile uint32_t *region_addrs_p = (volatile uint32_t*)(stub_base + OFF(REGION_ADDRS));
    volatile uint32_t *region_sizes_p = (volatile uint32_t*)(stub_base + OFF(REGION_SIZES));
    volatile uint32_t *region_retain_p = (volatile uint32_t*)(stub_base + OFF(REGION_RETAINS));
    volatile uint32_t *region_delete_p = (volatile uint32_t*)(stub_base + OFF(REGION_DELETES));
    volatile uint32_t *region_blocks_p = (volatile uint32_t*)(stub_base + OFF(REGION_BLOCKS));
    volatile uint32_t *saved_esp_p  = (volatile uint32_t*)(stub_base + OFF(SAVED_ESP));
    volatile uint32_t *saved_edx_p  = (volatile uint32_t*)(stub_base + OFF(SAVED_EDX));

    uint32_t new_oep = *oep_ptr;
    uint32_t count = *region_count_p;
    uint32_t i;
    int rc;

    if (count > STUB_MAX_REGIONS) count = STUB_MAX_REGIONS;

    for (i = 0; i < count; i++) {
        uint32_t region_vaddr = region_addrs_p[i];
        uint32_t region_size = region_sizes_p[i];
        uint32_t retain = region_retain_p[i];
        uint32_t del = region_delete_p[i];
        uint32_t blocks = region_blocks_p[i];

        if (!region_size || !retain) continue;

        my_syscall3(
            SYS_MPROTECT,
            (long)(region_vaddr & ~0xfffL),
            (long)(((region_size + 0xfff) & ~0xfffL)),
            7
        );

        uint32_t oep_offset = (uint32_t)-1;
        if (new_oep >= region_vaddr && new_oep < region_vaddr + region_size) {
            oep_offset = new_oep - region_vaddr;
        }

        rc = compact_in_place(
            (uint8_t *)region_vaddr,
            (uint8_t *)region_vaddr,
            region_size,
            retain,
            del,
            blocks,
            oep_offset,
            (uaddr_t *)&new_oep
        );

        if (rc != 0) fail_exit(1);
    }

    __asm__ volatile (
        "movl %0, %%edx\n\t"
        "movl %1, %%esp\n\t"
        "jmp *%%eax\n\t"
        :
        : "m"(*saved_edx_p), "m"(*saved_esp_p), "a"(new_oep)
        : "edx", "memory"
    );

    fail_exit(0);
}

void _start(void) {
    uint8_t *base = get_stub_base();
    volatile uint32_t *saved_esp_p = (volatile uint32_t*)(base + OFF(SAVED_ESP));
    volatile uint32_t *saved_edx_p = (volatile uint32_t*)(base + OFF(SAVED_EDX));
    uint8_t *stack_base = base + OFF(STUB_STACK);
    uint32_t new_sp = (uint32_t)(uintptr_t)(stack_base + STUB_STACK_SIZE);

    __asm__ volatile ("movl %%esp, %0" : "=m"(*saved_esp_p));
    __asm__ volatile ("movl %%edx, %0" : "=m"(*saved_edx_p));
    __asm__ volatile (
        "movl %0, %%esp\n\t"
        "andl $-16, %%esp\n\t"
        :
        : "r"(new_sp)
    );

    stub_main(base);
    __asm__ volatile ("ud2\n\t");
}

#elif defined(ARCH_AARCH64)

static __attribute__((noinline)) void stub_main(void) {
    uaddr_t new_oep = OEP_ADDR;
    uaddr_t count = REGION_COUNT;
    uaddr_t i;
    int rc;

    if (count > STUB_MAX_REGIONS) count = STUB_MAX_REGIONS;

    for (i = 0; i < count; i++) {
        uaddr_t region_vaddr = REGION_ADDRS[i];
        uaddr_t region_size = REGION_SIZES[i];
        uaddr_t retain = REGION_RETAINS[i];
        uaddr_t del = REGION_DELETES[i];
        uaddr_t blocks = REGION_BLOCKS[i];

        if (!region_size || !retain) continue;

        my_syscall3(
            SYS_MPROTECT,
            (long)(region_vaddr & ~0xfffL),
            (long)(((region_size + 0xfff) & ~0xfffL)),
            7
        );

        uaddr_t oep_offset = (uaddr_t)-1;
        if (new_oep >= region_vaddr && new_oep < region_vaddr + region_size) {
            oep_offset = new_oep - region_vaddr;
        }

        rc = compact_in_place(
            (uint8_t *)region_vaddr,
            (uint8_t *)region_vaddr,
            region_size,
            retain,
            del,
            blocks,
            oep_offset,
            &new_oep
        );

        if (rc != 0) fail_exit(1);
    }

    __asm__ volatile (
        "mov x0, %0\n\t"
        "mov x1, %1\n\t"
        "mov x2, %2\n\t"
        "mov sp, %3\n\t"
        "br %4\n\t"
        :
        : "r"(SAVED_X0), "r"(SAVED_X1), "r"(SAVED_X2), "r"(SAVED_SP), "r"(new_oep)
        : "x0", "x1", "x2", "memory"
    );

    fail_exit(0);
}

__attribute__((naked)) void _start(void) {
    __asm__ volatile (
        "mov x9, sp\n\t"
        "adrp x10, SAVED_SP\n\t"
        "add x10, x10, :lo12:SAVED_SP\n\t"
        "str x9, [x10]\n\t"

        "adrp x10, SAVED_X0\n\t"
        "add x10, x10, :lo12:SAVED_X0\n\t"
        "str x0, [x10]\n\t"

        "adrp x10, SAVED_X1\n\t"
        "add x10, x10, :lo12:SAVED_X1\n\t"
        "str x1, [x10]\n\t"

        "adrp x10, SAVED_X2\n\t"
        "add x10, x10, :lo12:SAVED_X2\n\t"
        "str x2, [x10]\n\t"

        "adrp x11, STUB_STACK\n\t"
        "add x11, x11, :lo12:STUB_STACK\n\t"
        "add x11, x11, #0x4000\n\t"
        "and x11, x11, #-16\n\t"
        "mov sp, x11\n\t"

        "bl stub_main\n\t"
        "brk #0\n\t"
    );
}

#elif defined(ARCH_ARM)

static __attribute__((noinline)) void stub_main(void) {
    uaddr_t new_oep = OEP_ADDR;
    uaddr_t count = REGION_COUNT;
    uaddr_t i;
    int rc;

    if (count > STUB_MAX_REGIONS) count = STUB_MAX_REGIONS;

    for (i = 0; i < count; i++) {
        uaddr_t region_vaddr = REGION_ADDRS[i];
        uaddr_t region_size = REGION_SIZES[i];
        uaddr_t retain = REGION_RETAINS[i];
        uaddr_t del = REGION_DELETES[i];
        uaddr_t blocks = REGION_BLOCKS[i];

        if (!region_size || !retain) continue;

        my_syscall3(
            SYS_MPROTECT,
            (long)(region_vaddr & ~0xfffL),
            (long)(((region_size + 0xfff) & ~0xfffL)),
            7
        );

        uaddr_t oep_offset = (uaddr_t)-1;
        if (new_oep >= region_vaddr && new_oep < region_vaddr + region_size) {
            oep_offset = new_oep - region_vaddr;
        }

        rc = compact_in_place(
            (uint8_t *)region_vaddr,
            (uint8_t *)region_vaddr,
            region_size,
            retain,
            del,
            blocks,
            oep_offset,
            (uaddr_t *)&new_oep
        );

        if (rc != 0) fail_exit(1);
    }

    __asm__ volatile (
        "mov r0, %0\n\t"
        "mov r1, %1\n\t"
        "mov r2, %2\n\t"
        "mov sp, %3\n\t"
        "bx %4\n\t"
        :
        : "r"(SAVED_R0), "r"(SAVED_R1), "r"(SAVED_R2), "r"(SAVED_SP), "r"(new_oep)
        : "r0", "r1", "r2", "memory"
    );

    fail_exit(0);
}

__attribute__((naked)) void _start(void) {
    __asm__ volatile (
        "mov r4, sp\n\t"
        "ldr r5, =SAVED_SP\n\t"
        "str r4, [r5]\n\t"

        "ldr r5, =SAVED_R0\n\t"
        "str r0, [r5]\n\t"
        "ldr r5, =SAVED_R1\n\t"
        "str r1, [r5]\n\t"
        "ldr r5, =SAVED_R2\n\t"
        "str r2, [r5]\n\t"

        "ldr r6, =STUB_STACK\n\t"
        "add r6, r6, #0x4000\n\t"
        "bic r6, r6, #0xf\n\t"
        "mov sp, r6\n\t"

        "bl stub_main\n\t"
        "udf #0\n\t"
    );
}

#endif

/* vim:set ts=4 sw=4 et: */