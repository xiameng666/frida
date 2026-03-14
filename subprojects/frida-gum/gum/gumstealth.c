/*
 * gumstealth.c - 无痕 hook 支持层 (wxjump KPM 集成)
 *
 * Linux ARM64: 通过 prctl 系统调用与 wxjump KPM 通信
 * 其他平台: 所有函数返回 FALSE (不可用)
 */

#include "gumstealth.h"

#if defined (HAVE_LINUX) && defined (HAVE_ARM64)

#include <sys/prctl.h>
#include <errno.h>

/* 缓存 wxjump KPM 可用性检测结果 */
static volatile gint stealth_checked = 0;
static gboolean stealth_available = FALSE;

gboolean
gum_stealth_is_available (void)
{
  if (g_atomic_int_get (&stealth_checked))
    return stealth_available;

  /*
   * 尝试 QUERY 命令检测 wxjump KPM 是否加载
   * 如果 KPM 已加载且 hook 了 prctl, 会拦截此命令码并返回 0
   * 如果 KPM 未加载, prctl 返回 -1 (EINVAL)
   */
  errno = 0;
  long ret = prctl (GUM_WXJUMP_PRCTL_QUERY, 0, 0, 0, 0);
  stealth_available = (ret == 0 && errno == 0);

  g_atomic_int_set (&stealth_checked, 1);

  return stealth_available;
}

gboolean
gum_stealth_patch (gpointer function_address,
                   const guint8 * code_bytes,
                   gsize code_size)
{
  unsigned long addr;
  unsigned long page_addr;
  size_t offset;
  long ret;

  addr = GPOINTER_TO_SIZE (function_address);
  page_addr = addr & ~((unsigned long) 0xFFF);
  offset = addr & 0xFFF;

  /*
   * prctl(WXJUMP_PATCH, page_addr, buf_ptr, len, offset)
   *
   * wxjump 内核模块会:
   * 1. 为 page_addr 创建 shadow page (如果尚未存在)
   * 2. 将 code_bytes 的内容复制到 shadow page 的 offset 位置
   * 3. 切换 PTE: 执行走 shadow page (--x), 读取走 original page (r--)
   *
   * 注意: code_bytes 必须在用户态可读的内存中 (栈/堆), 不能在 execute-only pool 中
   */
  ret = prctl (GUM_WXJUMP_PRCTL_PATCH,
      page_addr,
      (unsigned long) code_bytes,
      (unsigned long) code_size,
      (unsigned long) offset);

  return (ret == 0);
}

gboolean
gum_stealth_release (gpointer function_address,
                     gsize code_size)
{
  unsigned long addr;
  unsigned long page_addr;
  size_t offset;
  long ret;

  addr = GPOINTER_TO_SIZE (function_address);
  page_addr = addr & ~((unsigned long) 0xFFF);
  offset = addr & 0xFFF;

  /*
   * prctl(WXJUMP_RELEASE, page_addr, len, offset, 0)
   *
   * wxjump 内核模块会:
   * 1. 在 shadow page 上恢复 offset 处的原始字节
   * 2. patch_count--, 如果归零则释放整个 shadow page 并恢复原始 PTE
   */
  ret = prctl (GUM_WXJUMP_PRCTL_RELEASE,
      page_addr,
      (unsigned long) code_size,
      (unsigned long) offset,
      0);

  return (ret == 0);
}

#else /* 非 Linux ARM64 平台 */

gboolean
gum_stealth_is_available (void)
{
  return FALSE;
}

gboolean
gum_stealth_patch (gpointer function_address,
                   const guint8 * code_bytes,
                   gsize code_size)
{
  return FALSE;
}

gboolean
gum_stealth_release (gpointer function_address,
                     gsize code_size)
{
  return FALSE;
}

#endif
