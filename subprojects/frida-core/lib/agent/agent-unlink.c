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
#include <android/log.h>

#define TAG "xiam-unlink"
#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  TAG, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  TAG, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, TAG, fmt, ##__VA_ARGS__)

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

  /* (3) 反推真正的 linker_base.
   *     /proc/self/maps 里第一条匹配 "linker64" 的可能是 KPM (text_shadow)
   *     复制的影子副本, 不是真 linker; 所以不能用 maps 直接拿 base.
   *     真 linker 内部 _r_debug 偏移 0x133530 (build-id 内固定) 反推:
   *       linker_base = r_debug_addr - 0x133530
   *     再用 ELF magic 验证. */
  uintptr_t linker_base = (uintptr_t)rd - XU_OFF_R_DEBUG;
  LOGI("linker_base (from r_debug back-calc) = 0x%lx", (unsigned long)linker_base);
  if (!xu_addr_readable(linker_base, 16)
      || memcmp((void *)linker_base, ELFMAG, SELFMAG) != 0) {
    LOGW("linker_base does not point to ELF magic, abort");
    return -1;
  }

  /* (4) build-id 校验, 选 profile */
  const struct xu_linker_profile *prof = xu_match_profile(linker_base);
  if (!prof) LOGW("no matching linker profile (will skip solist unlink)");

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

  /* (6) 摘 solist 单链表 (有 profile 才做): 静态偏移直接拿 _solist 槽. */
  int ret_solist = -1;
  if (prof) {
    struct xu_soinfo_min **solist_var =
      (struct xu_soinfo_min **)(linker_base + prof->off_solist);
    void **sonext_var =
      (void **)(linker_base + prof->off_sonext);
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
          if (self_so->next == NULL && *sonext_var == (void *)&self_so->next) {
            xu_write_ptr(sonext_var, &prev_so->next);
            LOGI("sonext fixed to &prev->next");
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

  /* (8) 如果 self_lm 是 r_map 链尾且有 profile, 修正 r_debug_tail */
  if (next_lm == NULL && prof && prev_lm) {
    struct link_map **tail_var =
      (struct link_map **)(linker_base + prof->off_r_debug_tail);
    if (xu_addr_readable((uintptr_t)tail_var, 8) && *tail_var == self_lm) {
      xu_write_ptr(tail_var, prev_lm);
      LOGI("r_debug_tail fixed: %p -> %p", self_lm, prev_lm);
    }
  }

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
