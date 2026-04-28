/*
 * agent-unlink.c -- frida agent self-unlink from linker tables.
 *
 * 同时摘 r_debug.r_map (双链表) + solist (单链表) 两条链表, 让风控
 * 走 dl_iterate_phdr / r_debug.r_map / link_map 任意路径都看不到 agent.
 *
 * 实现策略:
 *   1) r_debug.r_map 摘链 -- 通过主程序 PT_DYNAMIC 的 DT_DEBUG entry 拿
 *      到 _r_debug 地址, 不需要 linker 私有符号. 这一步在所有设备通用.
 *
 *   2) solist 摘链 -- 需要 linker 私有静态符号 __dl__ZL6solist /
 *      __dl__ZL6sonext / __dl__ZL12r_debug_tail. 这些是 STB_LOCAL 符号,
 *      不在 .dynsym, 必须读 .symtab 才能得到. 由于 SELinux 限制 +
 *      .symtab 不在 PT_LOAD 内 (内存里读不到), 我们采用 **静态硬编码**
 *      的策略:
 *        - 编译期通过 readelf 解析目标设备的 linker64 拿到偏移
 *        - 用 .note.gnu.build-id 做运行时校验 (那个 note 在 PT_LOAD 内,
 *          可以从内存映射里读出来)
 *        - build-id 匹配则用硬编码偏移; 不匹配则跳过 solist 摘链, 仅做
 *          r_debug.r_map 摘链 (退化方案)
 *
 *   3) 调用时机: 通过导出函数 xiam_unlink_self() 由外部 (frida_agent_main
 *      入口或 RPC) 触发, 不挂在 .init_array. 因为 init_array 在 dlopen
 *      内部跑, g_dl_mutex 持有, RELRO 还在 RW 切换窗口, 改链会破坏
 *      linker finalize 流程, 已实测会导致注入器 dlsym 失败.
 *
 * 设备适配: 改用 readelf -s linker64 找 __dl__ZL6solist 等的 st_value,
 *   再 readelf -n linker64 抄 build-id, 更新下面 LINKER_PROFILES[] 即可.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <link.h>
#include <elf.h>
#include <glib.h>
#include <android/log.h>

/* 统一 frida 这边的 logcat tag 为 "xiam"; 模块前缀加 [unlink] 区分 */
#define TAG "xiam"
#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  TAG, "[unlink] " fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  TAG, "[unlink] " fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, TAG, "[unlink] " fmt, ##__VA_ARGS__)

/* ============================================================
 * 设备 linker64 静态符号偏移表
 * 编译期生成, 用 build-id 做运行时校验.
 *
 * 当前已支持设备:
 *   HUAWEI MNA-L29 (Mate 9, Android 12)
 *     /apex/com.android.runtime/bin/linker64
 *     build-id: 92f8e83b3f3e2690de1efbc419b1e22e
 * ============================================================ */
struct xu_linker_profile {
  uint8_t   build_id[16];        /* GNU build-id (前 16 字节) */
  uint32_t  off_solist;          /* __dl__ZL6solist        offset */
  uint32_t  off_sonext;          /* __dl__ZL6sonext        offset */
  uint32_t  off_r_debug_tail;    /* __dl__ZL12r_debug_tail offset */
  const char *desc;
};

static const struct xu_linker_profile LINKER_PROFILES[] = {
  {
    /* HUAWEI MNA-L29 / Android 12 / EMUI 12.0 GKI 5.10 */
    { 0x92,0xf8,0xe8,0x3b,0x3f,0x3e,0x26,0x90,
      0xde,0x1e,0xfb,0xc4,0x19,0xb1,0xe2,0x2e },
    /* off_solist        */ 0x1371a0,
    /* off_sonext        */ 0x137198,
    /* off_r_debug_tail  */ 0x1364d0,
    "HUAWEI Mate 9 / Android 12 (build-id 92f8e83b...)",
  },
  {
    /* d76b1349aab3530eead4ecb6a2843336 */
    { 0xd7,0x6b,0x13,0x49,0xaa,0xb3,0x53,0x0e,
      0xea,0xd4,0xec,0xb6,0xa2,0x84,0x33,0x36 },
    /* off_solist        */ 0x133220,
    /* off_sonext        */ 0x133218,
    /* off_r_debug_tail  */ 0x1325a0,
    "Android device (build-id d76b1349...)",
  },
};

/* _r_debug 在 linker ELF 内的 vaddr 偏移 (build-id 内固定).
 * 用法: 拿到 DT_DEBUG 给的 r_debug 真实地址后, 反推真正的 linker_base:
 *   linker_base = r_debug_addr - XU_OFF_R_DEBUG
 * 这是必要的, 因为 /proc/self/maps 第一条匹配 "linker64" 的可能是
 * KPM (text_shadow / hide_proc) 复制的 shadow 副本, 不是真 linker. */
static const uint32_t XU_OFF_R_DEBUG = 0x133530;
#define LINKER_PROFILES_N (sizeof(LINKER_PROFILES) / sizeof(LINKER_PROFILES[0]))

/* ============================================================
 * bionic soinfo 结构最小裁剪 (LP64 + Android 11+ 字段顺序)
 *   字段相对稳定, 改名/重排概率低
 * ============================================================ */
struct xu_soinfo_min {
  /* +0x00 */ const ElfW(Phdr) *phdr;
  /* +0x08 */ size_t            phnum;
  /* +0x10 */ ElfW(Addr)        base;
  /* +0x18 */ size_t            size;
  /* +0x20 */ ElfW(Dyn)        *dynamic;
  /* +0x28 */ struct xu_soinfo_min *next;
};

/* ============================================================ */

static long xu_page_size(void) {
  static long ps = 0;
  if (ps == 0) ps = sysconf(_SC_PAGESIZE);
  return ps;
}

static int xu_write_ptr(void *target, void *val) {
  long ps = xu_page_size();
  uintptr_t page = (uintptr_t)target & ~(ps - 1);
  if (mprotect((void *)page, ps, PROT_READ | PROT_WRITE) != 0) {
    LOGW("mprotect RW @page=0x%lx failed: %s", (unsigned long)page, strerror(errno));
    return -1;
  }
  *(void **)target = val;
  return 0;
}

/* ============================================================
 * Step 1: 通过 DT_DEBUG 找 r_debug
 * ============================================================ */
struct xu_dtdbg_ctx { uintptr_t r_debug; };

static int xu_dtdbg_cb(struct dl_phdr_info *info, size_t size, void *data) {
  struct xu_dtdbg_ctx *ctx = data;
  if (ctx->r_debug) return 1;
  if (!info->dlpi_phdr || info->dlpi_phnum == 0) return 0;
  /* 防御: dlpi_addr 太小说明是 vdso/伪模块或 dlpi_addr 已被 unmap, 跳过 */
  if ((uintptr_t)info->dlpi_addr < 0x10000) return 0;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_DYNAMIC) continue;
    uintptr_t dyn_addr = (uintptr_t)info->dlpi_addr + ph->p_vaddr;
    if (dyn_addr < 0x10000) continue;
    ElfW(Dyn) *dyn = (ElfW(Dyn) *)dyn_addr;
    for (int k = 0; k < 8192; k++) {
      if (dyn[k].d_tag == DT_NULL) break;
      if (dyn[k].d_tag == DT_DEBUG && dyn[k].d_un.d_ptr != 0) {
        ctx->r_debug = (uintptr_t)dyn[k].d_un.d_ptr;
        return 1;
      }
    }
  }
  return 0;
}

static struct r_debug *xu_find_r_debug(void) {
  struct xu_dtdbg_ctx ctx = { 0 };
  dl_iterate_phdr(xu_dtdbg_cb, &ctx);
  return (struct r_debug *)ctx.r_debug;
}

/* ============================================================
 * Step 1.0: 解析 linker64 ELF .symtab 拿任意私有符号地址 (通杀方案).
 *
 * untrusted_app 域 SELinux 标准策略允许 read system_linker_exec, 所以
 * 直接 open + mmap. 万一被定制 ROM 拒掉, fallback 到 /proc/self/map_files/
 * (走进程自己的 inode 引用绕开路径权限).
 *
 * 找到 .symtab 后扫所有符号, 名字匹配即返回 st_value (相对 linker_base 偏移).
 * 这样 _solist / _sonext / _r_debug_tail / 任何其他 linker 私有符号都能拿到,
 * 不需要 build-id 表, 不需要硬编码偏移.
 * ============================================================ */
struct xu_linker_elf {
  void  *map;       /* mmap 的文件起始地址 */
  size_t size;      /* mmap 大小 */
  ElfW(Sym)  *symtab;
  size_t      symtab_count;
  const char *strtab;
};

static int xu_open_linker_elf(const char *linker_path, struct xu_linker_elf *out) {
  memset(out, 0, sizeof(*out));

  int fd = open(linker_path, O_RDONLY);
  if (fd < 0) {
    /* fallback: 通过 /proc/self/map_files/<base>-<end> 拿同一 inode 的 fd */
    LOGW("open(%s) failed: %s, trying /proc/self/map_files fallback",
         linker_path, strerror(errno));
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
      unsigned long s, e;
      char perm[5] = {0};
      if (sscanf(line, "%lx-%lx %4s", &s, &e, perm) < 3) continue;
      if (perm[0] != 'r' || perm[1] != '-') continue;
      if (!strstr(line, "linker64")) continue;
      char map_path[64];
      snprintf(map_path, sizeof(map_path), "/proc/self/map_files/%lx-%lx", s, e);
      fd = open(map_path, O_RDONLY);
      if (fd >= 0) { LOGI("opened linker via %s", map_path); break; }
    }
    fclose(fp);
    if (fd < 0) { LOGW("map_files fallback also failed"); return -1; }
  }

  struct stat st;
  if (fstat(fd, &st) != 0) { close(fd); return -1; }
  void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) { LOGW("mmap linker64 failed"); return -1; }

  ElfW(Ehdr) *eh = (ElfW(Ehdr) *)map;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
    munmap(map, st.st_size);
    return -1;
  }

  /* 扫 section headers 找 .symtab + .strtab */
  ElfW(Shdr) *sh = (ElfW(Shdr) *)((char *)map + eh->e_shoff);
  ElfW(Shdr) *shstr = &sh[eh->e_shstrndx];
  const char *shnames = (const char *)map + shstr->sh_offset;
  ElfW(Shdr) *sym_sh = NULL, *str_sh = NULL;
  for (int i = 0; i < eh->e_shnum; i++) {
    if (sh[i].sh_type == SHT_SYMTAB && strcmp(&shnames[sh[i].sh_name], ".symtab") == 0)
      sym_sh = &sh[i];
    else if (sh[i].sh_type == SHT_STRTAB && strcmp(&shnames[sh[i].sh_name], ".strtab") == 0)
      str_sh = &sh[i];
  }
  if (!sym_sh || !str_sh) {
    LOGW("linker .symtab/.strtab missing (stripped?)");
    munmap(map, st.st_size);
    return -1;
  }

  out->map = map;
  out->size = st.st_size;
  out->symtab = (ElfW(Sym) *)((char *)map + sym_sh->sh_offset);
  out->symtab_count = sym_sh->sh_size / sizeof(ElfW(Sym));
  out->strtab = (const char *)map + str_sh->sh_offset;
  LOGI("linker symtab loaded: %zu symbols", out->symtab_count);
  return 0;
}

static void xu_close_linker_elf(struct xu_linker_elf *e) {
  if (e && e->map) {
    munmap(e->map, e->size);
    memset(e, 0, sizeof(*e));
  }
}

/* 在 .symtab 里找符号, 返回 st_value (= 相对 linker_base 偏移). 找不到返回 0. */
static uintptr_t xu_lookup_symbol(struct xu_linker_elf *e, const char *name) {
  if (!e || !e->symtab) return 0;
  for (size_t i = 0; i < e->symtab_count; i++) {
    if (e->symtab[i].st_value == 0) continue;
    const char *sym_name = e->strtab + e->symtab[i].st_name;
    if (strcmp(sym_name, name) == 0) return (uintptr_t)e->symtab[i].st_value;
  }
  return 0;
}

/* ============================================================
 * Step 1.5: 维护 maps 表用于 safe_read 验证地址
 * ============================================================ */
#define XU_MAX_MAPS 8192
struct xu_map_entry {
  uintptr_t start;
  uintptr_t end;
  int       readable;  /* r 或 rw */
};
static struct xu_map_entry g_maps[XU_MAX_MAPS];
static int                 g_maps_count = 0;

static void xu_load_maps(void) {
  g_maps_count = 0;
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return;
  char line[512];
  while (g_maps_count < XU_MAX_MAPS && fgets(line, sizeof(line), fp)) {
    unsigned long s, e;
    char perm[5] = {0};
    if (sscanf(line, "%lx-%lx %4s", &s, &e, perm) < 3) continue;
    if (perm[0] != 'r') continue;
    g_maps[g_maps_count].start = (uintptr_t)s;
    g_maps[g_maps_count].end   = (uintptr_t)e;
    g_maps[g_maps_count].readable = 1;
    g_maps_count++;
  }
  fclose(fp);
}

static int xu_addr_readable(uintptr_t addr, size_t need) {
  if (addr < 0x10000) return 0;
  for (int i = 0; i < g_maps_count; i++) {
    if (addr >= g_maps[i].start && addr + need <= g_maps[i].end)
      return 1;
  }
  return 0;
}

/* 找出 r_debug 所在 map 区间 (它在 zygote 预分配的匿名 RW 段).
 * 不依赖 g_maps 表 (那个有 8192 条上限可能截断), 直接 scan /proc/self/maps. */
static int xu_find_globals_segment(uintptr_t r_debug_addr,
                                   uintptr_t *out_start, uintptr_t *out_end) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return -1;
  char line[1024];
  int hit = -1;
  while (fgets(line, sizeof(line), fp)) {
    unsigned long s, e;
    char perm[5] = {0};
    if (sscanf(line, "%lx-%lx %4s", &s, &e, perm) < 3) continue;
    if (r_debug_addr < (uintptr_t)s || r_debug_addr >= (uintptr_t)e) continue;
    *out_start = (uintptr_t)s;
    *out_end = (uintptr_t)e;
    /* 同时打印这一行让我们看到 r_debug 落在哪 (匿名段名/路径) */
    LOGI("globals seg line: %.*s", (int)strlen(line) - 1, line);
    hit = 0;
    break;
  }
  fclose(fp);
  return hit;
}

/* 在 [start,end) 范围内扫描 _solist (memory pattern scan).
 *   linker_base   : linker 的加载基址 (验证 candidate->base == linker_base)
 *   start, end    : 扫描范围 (= r_debug 所在 map)
 *   out_solist_var: 输出 solist 变量的地址 (即 &_solist)
 *   out_head      : 输出 solist 链头 soinfo 的地址 (= linker 自己的 soinfo)
 * 找到返回 0, 失败返回 -1. */
static int xu_scan_solist(uintptr_t linker_base,
                          uintptr_t start, uintptr_t end,
                          struct xu_soinfo_min ***out_solist_var,
                          struct xu_soinfo_min  **out_head) {
  *out_solist_var = NULL;
  *out_head = NULL;

  LOGI("scan_solist: range [%lx, %lx) size=%lu",
       start, end, end - start);

  /* 8 字节对齐扫描 */
  for (uintptr_t slot = (start + 7) & ~7UL; slot + 8 <= end; slot += 8) {
    uintptr_t cand = *(uintptr_t *)slot;
    /* 候选必须落在某个可读 map 区间 */
    if (!xu_addr_readable(cand, sizeof(struct xu_soinfo_min))) continue;
    /* 读 cand->base (偏移 0x10) */
    uintptr_t base = ((struct xu_soinfo_min *)cand)->base;
    if (base != linker_base) continue;
    /* 进一步验证: cand->phdr 应该指向某个可读区域 */
    uintptr_t phdr = (uintptr_t)((struct xu_soinfo_min *)cand)->phdr;
    if (!xu_addr_readable(phdr, 32)) continue;

    *out_solist_var = (struct xu_soinfo_min **)slot;
    *out_head = (struct xu_soinfo_min *)cand;
    LOGI("scan_solist: found solist_var @%p, head=%p (linker soinfo, base=%lx)",
         (void *)slot, (void *)cand, base);
    return 0;
  }
  LOGW("scan_solist: no slot found pointing at linker soinfo");
  return -1;
}

/* 在指定区间扫一个值, 改成新值. 用于修正 sonext / r_debug_tail.
 * 返回找到的 slot 数 (理论上应该 1 或 0). */
static int xu_scan_and_fix(uintptr_t start, uintptr_t end,
                           uintptr_t target_value, void *new_value,
                           const char *desc) {
  int n = 0;
  for (uintptr_t slot = (start + 7) & ~7UL; slot + 8 <= end; slot += 8) {
    if (*(uintptr_t *)slot == target_value) {
      xu_write_ptr((void *)slot, new_value);
      LOGI("%s: slot @%p fixed to %p", desc, (void *)slot, new_value);
      n++;
    }
  }
  return n;
}

/* ============================================================
 * Step 2: 拿 linker base + 校验 build-id, 选 profile
 * ============================================================ */
static uintptr_t xu_get_linker_base(char *path_out, size_t path_cap) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return 0;
  char line[512];
  uintptr_t base = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "linker64")) {
      /* 第一行 linker64 一般是 r--p, 这就是 base */
      unsigned long s;
      if (sscanf(line, "%lx-", &s) == 1) {
        base = (uintptr_t)s;
        if (path_out) {
          char *sl = strchr(line, '/');
          if (sl) {
            char *nl = strchr(sl, '\n');
            if (nl) *nl = 0;
            strncpy(path_out, sl, path_cap - 1);
            path_out[path_cap - 1] = 0;
          }
        }
        break;
      }
    }
  }
  fclose(fp);
  return base;
}

/* 在内存里的 linker ELF 上找 .note.gnu.build-id, 取前 16 字节.
 * .note 段总在 PT_LOAD/PT_NOTE 内, 所以从 phdr 表能找到. */
static int xu_read_linker_build_id(uintptr_t base, uint8_t out[16]) {
  ElfW(Ehdr) *eh = (ElfW(Ehdr) *)base;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)(base + eh->e_phoff);
  for (int i = 0; i < eh->e_phnum; i++) {
    if (phdr[i].p_type != PT_NOTE) continue;
    /* 解析 note section 里的所有 note entries */
    uint8_t *p = (uint8_t *)(base + phdr[i].p_vaddr);
    uint8_t *end = p + phdr[i].p_memsz;
    while (p + 12 <= end) {
      uint32_t namesz = *(uint32_t *)(p + 0);
      uint32_t descsz = *(uint32_t *)(p + 4);
      uint32_t type   = *(uint32_t *)(p + 8);
      uint8_t *name = p + 12;
      uint8_t *desc = name + ((namesz + 3) & ~3);
      if (desc + descsz > end) break;
      if (type == NT_GNU_BUILD_ID && namesz == 4 && memcmp(name, "GNU", 4) == 0
          && descsz >= 16) {
        memcpy(out, desc, 16);
        return 0;
      }
      p = desc + ((descsz + 3) & ~3);
    }
  }
  return -1;
}

static const struct xu_linker_profile *xu_match_profile(uintptr_t linker_base) {
  uint8_t bid[16];
  if (xu_read_linker_build_id(linker_base, bid) != 0) {
    LOGW("could not read linker build-id");
    return NULL;
  }
  LOGI("linker build-id: %02x%02x%02x%02x...%02x%02x",
       bid[0], bid[1], bid[2], bid[3], bid[14], bid[15]);
  for (size_t i = 0; i < LINKER_PROFILES_N; i++) {
    if (memcmp(bid, LINKER_PROFILES[i].build_id, 16) == 0) {
      LOGI("profile match: %s", LINKER_PROFILES[i].desc);
      return &LINKER_PROFILES[i];
    }
  }
  LOGW("no matching linker profile, will skip solist unlink");
  return NULL;
}

/* ============================================================
 * Step 3: 摘 solist 单链表 (内存扫描版)
 *   关键: solist 不在 linker 自己的 maps 里, 而在 zygote 给的
 *   匿名 RW 段 (跟 _r_debug 同一段). 用 r_debug 地址定位这段.
 * ============================================================ */
static int xu_unlink_solist_scan(uintptr_t linker_base, ElfW(Addr) self_base,
                                  uintptr_t globals_start, uintptr_t globals_end) {
  struct xu_soinfo_min **solist_var = NULL;
  struct xu_soinfo_min  *head = NULL;
  if (xu_scan_solist(linker_base, globals_start, globals_end, &solist_var, &head) != 0)
    return -1;

  struct xu_soinfo_min *prev = NULL;
  struct xu_soinfo_min *self = head;
  int idx = 0;
  while (self) {
    if (idx > 4096) { LOGW("solist walk too long, abort"); return -1; }
    if (!xu_addr_readable((uintptr_t)self, sizeof(struct xu_soinfo_min))) {
      LOGW("solist node %p not readable, abort", self);
      return -1;
    }
    if (self->base == self_base) break;
    prev = self;
    self = self->next;
    idx++;
  }
  if (!self) { LOGW("self soinfo not found by base=0x%lx", (unsigned long)self_base); return -1; }
  if (!prev) { LOGW("self is solist head, abort"); return -1; }

  LOGI("solist: found self=%p prev=%p next=%p", self, prev, self->next);

  /* 摘单链表 */
  if (xu_write_ptr(&prev->next, self->next) != 0) return -1;
  LOGI("solist: prev->next -> %p", self->next);

  /* 如果 self 是尾节点, sonext 指向 &self->next, 需要改成 &prev->next */
  if (self->next == NULL) {
    xu_scan_and_fix(globals_start, globals_end,
                    (uintptr_t)&self->next, &prev->next, "solist sonext");
  }
  return 0;
}

/* ============================================================
 * Step 4: 摘 r_debug.r_map 双链表
 * ============================================================ */
static int xu_unlink_r_map(struct r_debug *rd, struct link_map *self,
                           uintptr_t linker_base, const struct xu_linker_profile *prof) {
  struct link_map *prev = self->l_prev;
  struct link_map *next = self->l_next;
  if (!prev) { LOGW("self is r_map head, abort"); return -1; }

  LOGI("unlinking r_map: prev=%p (%s), self=%p (%s), next=%p (%s)",
       prev, prev->l_name ? prev->l_name : "(null)",
       self, self->l_name,
       next, next ? (next->l_name ? next->l_name : "(null)") : "(tail)");

  xu_write_ptr(&rd->r_state, (void *)(uintptr_t)RT_DELETE);

  if (xu_write_ptr(&prev->l_next, (void *)next) != 0) return -1;
  if (next && xu_write_ptr(&next->l_prev, (void *)prev) != 0) return -1;

  /* self 是 r_map 链尾: 扫 globals 段找 r_debug_tail (值 == self) 改成 prev.
   * globals_start/end 由调用者传入 (= r_debug 所在 map). */
  (void)linker_base; (void)prof;
  /* (调用者负责扫描和修正, 这里不重复) */

  /* 把 self 自己的 l_next/l_prev 清零, 防止反向缓存回链 */
  xu_write_ptr(&self->l_next, NULL);
  xu_write_ptr(&self->l_prev, NULL);

  xu_write_ptr(&rd->r_state, (void *)(uintptr_t)RT_CONSISTENT);
  return 0;
}

/* ============================================================
 * 主入口
 * ============================================================ */
static int xu_unlink_self(void) {
  LOGI("==== xu_unlink_self begin ====");

  /* (1) 加载 maps 表, 用于 safe-read 验证候选指针 */
  xu_load_maps();
  LOGI("maps loaded: %d entries", g_maps_count);

  /* (2) DT_DEBUG 给真实 r_debug 地址 (这一步永远先做, 不可被 KPM shadow 干扰) */
  struct r_debug *rd = xu_find_r_debug();
  if (!rd) { LOGW("r_debug not found via DT_DEBUG"); return -1; }
  LOGI("r_debug @%p (via DT_DEBUG), r_map=%p, r_state=%d", rd, rd->r_map, rd->r_state);

  /* (3) 从 r_debug 地址向下逐页扫, 找最近的 ELF magic 起始的页 = linker_base.
   *     这种方式不依赖任何硬编码偏移, 不同 Android 版本/OEM 的 linker 都通用.
   *     原理: r_debug 在 linker .data 内, linker base 必然在它前面某个 page 边界,
   *     base 处的 4 字节是 ELFMAG. 扫描上限给个充分的值 (4 MB / 4KB = 1024 页). */
  uintptr_t linker_base = 0;
  long ps = xu_page_size();
  uintptr_t scan = (uintptr_t)rd & ~(ps - 1);
  for (int i = 0; i < 1024; i++) {
    if (xu_addr_readable(scan, 16)
        && memcmp((void *)scan, ELFMAG, SELFMAG) == 0) {
      linker_base = scan;
      break;
    }
    if (scan < (uintptr_t)ps) break;
    scan -= ps;
  }
  if (linker_base == 0) {
    LOGW("linker_base not found by scanning ELFMAG below r_debug, abort");
    return -1;
  }
  uintptr_t r_debug_off = (uintptr_t)rd - linker_base;
  LOGI("linker_base (ELFMAG scan) = 0x%lx, r_debug offset = 0x%lx",
       (unsigned long)linker_base, (unsigned long)r_debug_off);

  /* (4) 优先打开 linker ELF 读 .symtab 拿任意私有符号偏移 (通杀).
   *     失败再退化到 LINKER_PROFILES 表. 找 linker 路径来源:
   *       - /proc/self/maps 里第一条 r--p linker64 行的路径
   *       - 已知 KPM shadow 副本会在第一行先出现, 但路径仍是 apex linker64 的全名,
   *         file inode 一致, open 出来是同一份文件. 所以 grep 第一行 path 即可. */
  struct xu_linker_elf elf = {0};
  char linker_path[256] = "/apex/com.android.runtime/bin/linker64";
  do {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) break;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
      if (!strstr(line, "linker64")) continue;
      char *sl = strchr(line, '/');
      if (sl) {
        char *nl = strchr(sl, '\n');
        if (nl) *nl = 0;
        strncpy(linker_path, sl, sizeof(linker_path) - 1);
        linker_path[sizeof(linker_path) - 1] = 0;
        break;
      }
    }
    fclose(fp);
  } while (0);
  LOGI("linker path resolved: %s", linker_path);

  int has_elf = (xu_open_linker_elf(linker_path, &elf) == 0);
  uintptr_t off_solist        = 0;
  uintptr_t off_sonext         = 0;
  uintptr_t off_r_debug_tail  = 0;
  if (has_elf) {
    off_solist        = xu_lookup_symbol(&elf, "__dl__ZL6solist");
    off_sonext        = xu_lookup_symbol(&elf, "__dl__ZL6sonext");
    off_r_debug_tail  = xu_lookup_symbol(&elf, "__dl__ZL12r_debug_tail");
    LOGI("symtab offsets: solist=0x%lx sonext=0x%lx r_debug_tail=0x%lx",
         (unsigned long)off_solist, (unsigned long)off_sonext,
         (unsigned long)off_r_debug_tail);
  }

  /* build-id 校验仍保留, 作为 .symtab 都拿不到时的最终兜底 */
  const struct xu_linker_profile *prof = xu_match_profile(linker_base);
  if (!has_elf && !prof) LOGW("no .symtab and no matching profile, will skip solist unlink");

  /* 选定使用的偏移: .symtab 优先, profile 兜底 */
  if (off_solist == 0       && prof) off_solist        = prof->off_solist;
  if (off_sonext == 0       && prof) off_sonext        = prof->off_sonext;
  if (off_r_debug_tail == 0 && prof) off_r_debug_tail  = prof->off_r_debug_tail;

  /* (5) 找自己的 link_map */
  struct link_map *self_lm = NULL;
  int idx = 0;
  for (struct link_map *cur = rd->r_map; cur != NULL; cur = cur->l_next) {
    if (idx > 4096) { LOGW("walked too many link_map nodes, abort"); return -1; }
    if (cur->l_name && strstr(cur->l_name, "xiam")) {
      self_lm = cur;
      break;
    }
    idx++;
  }
  if (!self_lm) { LOGW("self link_map not found by name 'xiam'"); return -1; }
  LOGI("self link_map @%p name=%s base=0x%lx",
       self_lm, self_lm->l_name, (unsigned long)self_lm->l_addr);

  /* (6a) 动态摘 solist (优先, 不依赖 profile/build-id):
   *      已知 self_lm 是 self_soinfo 内部 link_map_head 字段, 通过特征
   *      比对 base/dynamic 探测 link_map_head 在 soinfo 内的偏移, 然后
   *      从 head_lm 反推 head_soinfo, 沿 next 链找到 prev, 摘 prev->next. */
  int ret_solist = -1;
  do {
    /* 探测 LINK_MAP_OFFSET. 多重验证防 alignment 巧合命中 (link_map 自身长 40 字节,
     * 它的字段会跟 candidate->base/dynamic 重叠, 单看 base 等值不够安全).
     * 起点 64 = 大于 sizeof(link_map) (40) 向上对齐, 避免落在 self_lm 自身内.
     * 验证项:
     *   1) candidate->base    == self_lm->l_addr
     *   2) candidate->dynamic == self_lm->l_ld
     *   3) candidate->phdr    指向合法可读区域 (soinfo 必有 phdr)
     *   4) candidate->next    要么 NULL, 要么指向合法 soinfo* (base != 0 且可读) */
    int link_map_offset = -1;
    for (int off = 64; off <= 768; off += 8) {
      uintptr_t candidate = (uintptr_t)self_lm - off;
      if (!xu_addr_readable(candidate, sizeof(struct xu_soinfo_min))) continue;
      struct xu_soinfo_min *s = (struct xu_soinfo_min *)candidate;
      if (s->base != self_lm->l_addr) continue;
      if ((uintptr_t)s->dynamic != (uintptr_t)self_lm->l_ld) continue;
      if (!xu_addr_readable((uintptr_t)s->phdr, 32)) continue;
      if (s->next != NULL) {
        if (!xu_addr_readable((uintptr_t)s->next, sizeof(struct xu_soinfo_min))) continue;
        if (s->next->base == 0) continue;
      }
      link_map_offset = off;
      break;
    }
    if (link_map_offset < 0) {
      LOGW("dyn-solist: probe LINK_MAP_OFFSET failed (no candidate matched all 4 checks)");
      break;
    }
    LOGI("dyn-solist: LINK_MAP_OFFSET = 0x%x", link_map_offset);

    struct xu_soinfo_min *self_so =
      (struct xu_soinfo_min *)((uintptr_t)self_lm - link_map_offset);

    struct link_map *head_lm = rd->r_map;
    struct xu_soinfo_min *head_so =
      (struct xu_soinfo_min *)((uintptr_t)head_lm - link_map_offset);
    if (!xu_addr_readable((uintptr_t)head_so, sizeof(struct xu_soinfo_min))
        || head_so->base != head_lm->l_addr) {
      LOGW("dyn-solist: head_soinfo signature mismatch, abort");
      break;
    }

    /* 沿 head_so->next 走, 找 next == self_so 的节点 = prev */
    struct xu_soinfo_min *prev_so = NULL;
    struct xu_soinfo_min *cur = head_so;
    int sidx = 0;
    while (cur) {
      if (sidx > 4096) break;
      if (!xu_addr_readable((uintptr_t)cur, sizeof(struct xu_soinfo_min))) break;
      if (cur->next == self_so) { prev_so = cur; break; }
      cur = cur->next;
      sidx++;
    }
    if (!prev_so) {
      LOGW("dyn-solist: prev_so not found (sidx=%d)", sidx);
      break;
    }
    LOGI("dyn-solist: prev_so=%p, self_so=%p, self_so->next=%p",
         prev_so, self_so, self_so->next);

    /* 摘单链表 */
    if (xu_write_ptr(&prev_so->next, self_so->next) != 0) break;
    LOGI("dyn-solist: unlink ok (sonext/r_debug_tail 未修, self 不在末尾才安全)");
    ret_solist = 0;
  } while (0);

  /* (6b) 静态偏移兜底 (动态版失败 + 有 .symtab 或 profile 偏移才走) */
  if (ret_solist != 0 && off_solist != 0 && off_sonext != 0) {
    LOGI("falling back to static-offset solist unlink (symtab=%d, profile=%d)",
         has_elf, prof != NULL);
    struct xu_soinfo_min **solist_var =
      (struct xu_soinfo_min **)(linker_base + off_solist);
    void **sonext_var =
      (void **)(linker_base + off_sonext);
    LOGI("solist_var @%p, sonext_var @%p", solist_var, sonext_var);

    struct xu_soinfo_min *head = *solist_var;
    if (!xu_addr_readable((uintptr_t)head, sizeof(struct xu_soinfo_min))) {
      LOGW("solist head=%p invalid", head);
    } else {
      LOGI("solist head=%p (->base=0x%lx)", head, (unsigned long)head->base);
      struct xu_soinfo_min *prev_so = NULL;
      struct xu_soinfo_min *self_so = head;
      int sidx = 0;
      while (self_so) {
        if (sidx > 4096) break;
        if (!xu_addr_readable((uintptr_t)self_so, sizeof(struct xu_soinfo_min))) {
          LOGW("solist node %p invalid", self_so);
          self_so = NULL; break;
        }
        if (self_so->base == self_lm->l_addr) break;
        prev_so = self_so;
        self_so = self_so->next;
        sidx++;
      }
      if (self_so && prev_so) {
        LOGI("solist self=%p prev=%p next=%p", self_so, prev_so, self_so->next);
        if (xu_write_ptr(&prev_so->next, self_so->next) == 0) {
          if (self_so->next == NULL) {
            /* tail 情况下 sonext 修复也禁掉 -- 同 r_debug_tail.
             * 之后 linker 新 dlopen 时会把新 soinfo 链到 self_so->next,
             * 但 self_so 已经从 solist 单链表脱钩 (prev_so->next = NULL).
             * 实际效应: 新 SO 只对老 sonext 持有的视角可见, dl_iterate_phdr
             * 走 solist 从 head 开始, 到 prev_so 结束, 看不到新 SO -- 但这
             * 影响的是 xiam-64.so 之后才加载的新 SO, 风控扫此时已存在的
             * agent 还是看不到 (这正是我们要的). */
            LOGW("self is solist tail; sonext intentionally NOT touched "
                 "to keep linker dlopen state intact");
          }
          ret_solist = 0;
        }
      } else {
        LOGW("solist self not found (sidx=%d, prev_so=%p)", sidx, prev_so);
      }
    }
  }
  if (ret_solist != 0) LOGW("solist unlink failed");

  /* (7) 摘 r_debug.r_map */
  struct link_map *prev_lm = self_lm->l_prev;
  struct link_map *next_lm = self_lm->l_next;
  int ret_rmap = xu_unlink_r_map(rd, self_lm, linker_base, prof);
  if (ret_rmap != 0) { LOGW("r_map unlink failed"); return -1; }

  /* (8) tail 情况下的 r_debug_tail 修复 -- 暂时禁用!
   *     即使 *tail==self 验证通过, 写 r_debug_tail 后 agent init 阶段会挂.
   *     猜测: GLib/GIO init 触发新 dlopen, linker 想用 r_debug_tail 挂新节点
   *     但状态被我们改后某条不变量被破坏 (待具体调查).
   *     不修的代价: 之后 dlopen 的新 SO 会被挂到 self 后面 (因为 linker
   *     维护的 tail 还指 self), 但 self 已经从 r_map 双链表摘掉, 形成
   *     "悬挂" 节点. dl_iterate_phdr 走 solist 仍正常; 走 r_debug.r_map 看
   *     不到新加的 SO -- 只对调试器有影响, 对应用层风控无影响.            */
  if (next_lm == NULL) {
    LOGW("self is r_map tail; r_debug_tail intentionally NOT touched "
         "(off=0x%lx) to keep linker dlopen state intact",
         (unsigned long)off_r_debug_tail);
  }

  /* (9) 释放 linker ELF mmap (如果 open 成功的话) */
  xu_close_linker_elf(&elf);

  LOGI("==== xu_unlink_self done: r_map=ok, solist=%s ====",
       (ret_solist == 0) ? "ok" : "failed");
  return 0;
}

__attribute__((visibility("default")))
int xiam_unlink_self(void) {
  int ret = xu_unlink_self();
  if (ret == 0) LOGI("xiam_unlink_self ok");
  else          LOGW("xiam_unlink_self failed ret=%d", ret);
  return ret;
}

/* 用 GLib idle source 在 frida 自己的 main loop 上调度摘链:
 *   ----------------------------------------------------------------
 *   实测 在 _frida_agent_environment_init 阶段直接摘链, 后续 GLib/GIO
 *   init 阶段会再 dlopen 一些 module, linker 此时操作我们改过的链表
 *   导致 "refused to load frida-agent".
 *
 *   挂 g_idle_add 到默认 main context: callback 在 frida_agent_main
 *   起 main loop 后才被调用. 那时所有 init + dlopen 都完成, agent
 *   跟 server 的 socket 也已建好, linker 不再触碰我们要改的链表 ->
 *   摘链 100% 安全. 全程在主进程主线程, 不起新线程.
 *
 *   只跑一次 (摘完返回 G_SOURCE_REMOVE).
 *   ---------------------------------------------------------------- */
static gboolean xu_idle_unlink_cb(gpointer user_data) {
  (void)user_data;
  LOGI("idle unlink: main loop is running, time to unlink");
  (void)xu_unlink_self();
  return G_SOURCE_REMOVE;
}

__attribute__((visibility("default")))
int xiam_unlink_self_delayed(void) {
  guint id = g_idle_add(xu_idle_unlink_cb, NULL);
  LOGI("idle unlink scheduled (source id=%u)", id);
  return 0;
}
