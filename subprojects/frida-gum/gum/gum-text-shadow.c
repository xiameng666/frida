/*
 * gum-text-shadow.c - KPM text_shadow 集成
 *
 * 对应 kernel 端 xiaojia-hide/src/text_shadow.c:
 *   prctl(0x45820, func_addr, orig_buf, 0, 0)  → protect
 *   prctl(0x45821, page_addr, 0, 0, 0)         → unprotect
 *   prctl(0x45822, 0, 0, 0, 0)                 → clear all
 *
 * 用户态自维护 shadow pool (大块 mmap + bump allocator), 避免每个保护页
 * 单独 mmap 在 /proc/self/maps 上留下大量碎片匿名段. shadow pool 内部
 * 段也由 hide_proc.c 的 maps 过滤层负责隐藏.
 *
 * 仅在 Android arm64 上生效. 其他平台编译期 stub.
 */

#include "gum-text-shadow.h"

#if defined (HAVE_ANDROID) && defined (HAVE_ARM64)

#include <android/log.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define GUM_TS_LOG_TAG  "xiam"
#define GUM_TS_LOGI(...)  \
    __android_log_print (ANDROID_LOG_INFO,  GUM_TS_LOG_TAG, __VA_ARGS__)
#define GUM_TS_LOGW(...)  \
    __android_log_print (ANDROID_LOG_WARN,  GUM_TS_LOG_TAG, __VA_ARGS__)
#define GUM_TS_LOGE(...)  \
    __android_log_print (ANDROID_LOG_ERROR, GUM_TS_LOG_TAG, __VA_ARGS__)

#define GUM_TS_PROTECT_OPTION    0x45820
#define GUM_TS_UNPROTECT_OPTION  0x45821
#define GUM_TS_CLEAR_ALL_OPTION  0x45822

#define GUM_TS_PAGE_SIZE         4096UL
#define GUM_TS_PAGE_MASK         (~(GUM_TS_PAGE_SIZE - 1))
#define GUM_TS_POOL_CHUNK_PAGES  512
#define GUM_TS_POOL_CHUNK_SIZE   (GUM_TS_PAGE_SIZE * GUM_TS_POOL_CHUNK_PAGES)

typedef struct _GumTsPoolChunk GumTsPoolChunk;

struct _GumTsPoolChunk
{
  guint8 *         base;
  gsize            size;
  gsize            offset;
  GumTsPoolChunk * next;
};

static gboolean         g_initialized = FALSE;
static gboolean         g_available = FALSE;
static GMutex           g_lock;
static GumTsPoolChunk * g_pool_head = NULL;
static GumTsPoolChunk * g_pool_current = NULL;
static GHashTable *     g_saved_pages = NULL;   /* page_va → orig buf */

static gboolean
gum_ts_probe (void)
{
  /*
   * 用 prctl(CLEAR_ALL, 0,0,0,0) 当 sentinel:
   *   KPM 装了 → kernel 走 clear_all_pages(), 返回 0
   *   KPM 没装 → kernel 不识别 option, 返回 -1 errno=EINVAL
   */
  long ret;
  int saved_errno;

  errno = 0;
  ret = syscall (__NR_prctl, GUM_TS_CLEAR_ALL_OPTION,
      (unsigned long) 0, (unsigned long) 0,
      (unsigned long) 0, (unsigned long) 0);
  saved_errno = errno;
  GUM_TS_LOGI ("[text_shadow] probe: prctl(0x%x, 0,0,0,0) = %ld errno=%d",
      GUM_TS_CLEAR_ALL_OPTION, ret, saved_errno);
  if (ret == 0)
    return TRUE;
  return FALSE;
}

static GumTsPoolChunk *
gum_ts_pool_chunk_new (gsize min_size)
{
  GumTsPoolChunk * chunk;
  gsize size;
  void * base;

  size = GUM_TS_POOL_CHUNK_SIZE;
  if (min_size > size)
    size = (min_size + GUM_TS_PAGE_SIZE - 1) & GUM_TS_PAGE_MASK;

  base = mmap (NULL, size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED)
  {
    GUM_TS_LOGE ("[text_shadow] pool: mmap %zu bytes FAILED errno=%d",
        size, errno);
    return NULL;
  }

  chunk = g_slice_new (GumTsPoolChunk);
  chunk->base = (guint8 *) base;
  chunk->size = size;
  chunk->offset = 0;
  chunk->next = NULL;

  GUM_TS_LOGI ("[text_shadow] pool: new chunk base=%p size=0x%zx",
      base, size);
  return chunk;
}

static guint8 *
gum_ts_pool_alloc_page (void)
{
  GumTsPoolChunk * chunk = g_pool_current;
  guint8 * out;

  if (chunk == NULL || chunk->offset + GUM_TS_PAGE_SIZE > chunk->size)
  {
    chunk = gum_ts_pool_chunk_new (GUM_TS_PAGE_SIZE);
    if (chunk == NULL)
      return NULL;

    chunk->next = g_pool_head;
    g_pool_head = chunk;
    g_pool_current = chunk;
  }

  out = chunk->base + chunk->offset;
  chunk->offset += GUM_TS_PAGE_SIZE;
  return out;
}

gboolean
gum_text_shadow_init (void)
{
  g_mutex_lock (&g_lock);

  if (g_initialized)
    goto done;

  g_available = gum_ts_probe ();
  if (g_available)
  {
    g_saved_pages = g_hash_table_new (NULL, NULL);
    GUM_TS_LOGI ("[text_shadow] init: KPM available, ready");
  }
  else
  {
    GUM_TS_LOGI ("[text_shadow] init: KPM not available, all APIs no-op");
  }
  g_initialized = TRUE;

done:
  g_mutex_unlock (&g_lock);
  return g_available;
}

gboolean
gum_text_shadow_is_available (void)
{
  return g_available;
}

gpointer
gum_text_shadow_save_original_page (gconstpointer page)
{
  gpointer page_aligned;
  gpointer existing;
  guint8 * buf;

  if (!g_available)
    return NULL;

  page_aligned =
      (gpointer) ((guintptr) page & GUM_TS_PAGE_MASK);

  g_mutex_lock (&g_lock);

  existing = g_hash_table_lookup (g_saved_pages, page_aligned);
  if (existing != NULL)
  {
    g_mutex_unlock (&g_lock);
    GUM_TS_LOGI ("[text_shadow] save: page=%p (cached, buf=%p)",
        page_aligned, existing);
    return existing;
  }

  buf = gum_ts_pool_alloc_page ();
  if (buf == NULL)
  {
    g_mutex_unlock (&g_lock);
    GUM_TS_LOGE ("[text_shadow] save: page=%p pool_alloc FAILED",
        page_aligned);
    return NULL;
  }

  /*
   * memcpy 之前不应该有任何 Frida 蹦床字节. 调用方 (gum_interceptor) 必须
   * 保证: 进入 transaction_end → 在 mprotect-RWX 之前先调本函数预存所有
   * dirty 页, 然后才让 patch_code_pages 写蹦床.
   */
  memcpy (buf, page_aligned, GUM_TS_PAGE_SIZE);

  g_hash_table_insert (g_saved_pages, page_aligned, buf);

  GUM_TS_LOGI ("[text_shadow] save: page=%p new buf=%p (first 4B=%02x %02x %02x %02x)",
      page_aligned, buf, buf[0], buf[1], buf[2], buf[3]);
  g_mutex_unlock (&g_lock);
  return buf;
}

int
gum_text_shadow_protect (gpointer func_addr)
{
  gpointer page_aligned;
  gpointer orig_buf;
  long ret;
  int saved_errno;

  if (!g_available)
    return -1;

  page_aligned =
      (gpointer) ((guintptr) func_addr & GUM_TS_PAGE_MASK);

  g_mutex_lock (&g_lock);
  orig_buf = g_hash_table_lookup (g_saved_pages, page_aligned);
  g_mutex_unlock (&g_lock);

  if (orig_buf == NULL)
  {
    GUM_TS_LOGE ("[text_shadow] protect: func=%p page=%p MISSING orig_buf",
        func_addr, page_aligned);
    return -1;
  }

  errno = 0;
  ret = syscall (__NR_prctl, GUM_TS_PROTECT_OPTION,
      (unsigned long) func_addr, (unsigned long) orig_buf,
      (unsigned long) 0, (unsigned long) 0);
  saved_errno = errno;
  if (ret == 0)
  {
    GUM_TS_LOGI ("[text_shadow] protect: func=%p page=%p orig=%p ok",
        func_addr, page_aligned, orig_buf);
  }
  else
  {
    GUM_TS_LOGE ("[text_shadow] protect: func=%p page=%p orig=%p FAILED ret=%ld errno=%d",
        func_addr, page_aligned, orig_buf, ret, saved_errno);
  }
  return (int) ret;
}

int
gum_text_shadow_unprotect (gpointer page)
{
  gpointer page_aligned;
  long ret;
  int saved_errno;

  if (!g_available)
    return -1;

  page_aligned =
      (gpointer) ((guintptr) page & GUM_TS_PAGE_MASK);

  errno = 0;
  ret = syscall (__NR_prctl, GUM_TS_UNPROTECT_OPTION,
      (unsigned long) page_aligned, (unsigned long) 0,
      (unsigned long) 0, (unsigned long) 0);
  saved_errno = errno;
  GUM_TS_LOGI ("[text_shadow] unprotect: page=%p ret=%ld errno=%d",
      page_aligned, ret, saved_errno);
  return (int) ret;
}

int
gum_text_shadow_clear_all (void)
{
  long ret;
  int saved_errno;
  if (!g_available)
    return -1;
  errno = 0;
  ret = syscall (__NR_prctl, GUM_TS_CLEAR_ALL_OPTION,
      (unsigned long) 0, (unsigned long) 0,
      (unsigned long) 0, (unsigned long) 0);
  saved_errno = errno;
  GUM_TS_LOGI ("[text_shadow] clear_all: ret=%ld errno=%d", ret, saved_errno);
  return (int) ret;
}

#else  /* not Android arm64: stub */

gboolean
gum_text_shadow_init (void)
{
  return FALSE;
}

gboolean
gum_text_shadow_is_available (void)
{
  return FALSE;
}

gpointer
gum_text_shadow_save_original_page (gconstpointer page)
{
  (void) page;
  return NULL;
}

int
gum_text_shadow_protect (gpointer func_addr)
{
  (void) func_addr;
  return -1;
}

int
gum_text_shadow_unprotect (gpointer page)
{
  (void) page;
  return -1;
}

int
gum_text_shadow_clear_all (void)
{
  return -1;
}

#endif
