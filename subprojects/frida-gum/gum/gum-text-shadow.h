#ifndef __GUM_TEXT_SHADOW_H__
#define __GUM_TEXT_SHADOW_H__

#include <glib.h>

G_BEGIN_DECLS

/*
 * KPM (KernelPatch Module) text_shadow 集成接口.
 *
 * Android arm64 + xiaojia-hide 内核模块加载时, file-backed .text 页可以
 * 通过 prctl 注册 PTE 双页保护:
 *   - read fault → kernel 切到 alt 页 (干净原件)
 *   - exec fault → kernel 切到 shadow 页 (含 Frida 蹦床)
 *
 * 没装 KPM 的环境, gum_text_shadow_init() 返回 FALSE, 后续 API 全 no-op.
 */

/* 一次性探测 KPM 是否可用. 幂等, 多次调用只探测一次. */
gboolean gum_text_shadow_init (void);

/* 返回 init() 探测结果. 不会触发探测. */
gboolean gum_text_shadow_is_available (void);

/*
 * 保存 page (对齐到 4KB) 的"干净"内容到用户态 shadow pool.
 * 必须在该页被写入任何 Frida 蹦床字节之前调用.
 * 同页第二次调用是 no-op, 直接返回已保存的 buf.
 * 返回 NULL 表示失败 (或 KPM 不可用).
 */
gpointer gum_text_shadow_save_original_page (gconstpointer page);

/*
 * 通知 kernel 保护 func_addr 所在的页.
 *   - func_addr 必须是精确蹦床入口 PC (kernel 用它做 Path B 白名单)
 *   - 页必须先调过 save_original_page
 *   - 同页多函数 attach 自动复用 alt, kernel 内部走 append 分支
 * 返回 0 成功, < 0 失败.
 */
int gum_text_shadow_protect (gpointer func_addr);

/*
 * 卸载 page 的保护. 一般在 detach 时配对调用.
 * 注意: 当前不在 detach 路径自动调用, 进程退出时由 kernel do_group_exit
 * hook 统一清理. 此函数留作未来按需使用.
 */
int gum_text_shadow_unprotect (gpointer page);

/* 清除当前进程所有保护. 一般不调用, 进程退出 kernel 自动处理. */
int gum_text_shadow_clear_all (void);

G_END_DECLS

#endif
