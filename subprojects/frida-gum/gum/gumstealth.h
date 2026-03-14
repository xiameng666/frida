/*
 * gumstealth.h - 无痕 hook 支持层 (wxjump KPM 集成)
 *
 * 通过 KernelPatch 的 wxjump 内核模块实现 shadow page hook:
 * - 执行时命中 shadow page (execute-only) 上的跳转指令
 * - CRC 读取时触发 Data Abort → 切到 original page → 返回未修改的原始字节
 * - 效果: hook 命中零内核异常, CRC 完整性检测完全绕过
 */

#ifndef __GUM_STEALTH_H__
#define __GUM_STEALTH_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

/*
 * wxjump prctl 命令码 (与 KernelPatch/kpms/wxjump 模块对应)
 *
 * PATCH:   prctl(0x57585804, page_addr, buf_ptr, len, offset)
 *          在 shadow page 的 offset 处写入 len 字节跳转指令
 *
 * RELEASE: prctl(0x57585805, page_addr, len, offset, 0)
 *          释放 shadow page 上 offset+len 处的 patch
 *
 * QUERY:   prctl(0x57585806, 0, 0, 0, 0)
 *          查询 wxjump KPM 是否已加载, 返回 0 表示可用
 */
#define GUM_WXJUMP_PRCTL_PATCH   0x57585804
#define GUM_WXJUMP_PRCTL_RELEASE 0x57585805
#define GUM_WXJUMP_PRCTL_QUERY   0x57585806

/*
 * 检测 wxjump KPM 是否可用
 *
 * 通过 prctl(QUERY) 检测, 结果会缓存
 * 仅在 Linux ARM64 上有效, 其他平台始终返回 FALSE
 */
GUM_API gboolean gum_stealth_is_available (void);

/*
 * 通过 wxjump shadow page 写入跳转指令
 *
 * @param function_address  目标函数地址 (将自动计算页地址和偏移)
 * @param code_bytes        跳转指令字节 (MOVZ/MOVK/BR 序列)
 * @param code_size         字节数 (通常 8~16 字节)
 *
 * 返回: TRUE 成功, FALSE 失败 (KPM 未加载或 prctl 失败)
 */
GUM_API gboolean gum_stealth_patch (gpointer function_address,
    const guint8 * code_bytes, gsize code_size);

/*
 * 释放 wxjump shadow page 上的 patch
 *
 * @param function_address  之前 patch 过的目标函数地址
 * @param code_size         当初写入的字节数
 *
 * 返回: TRUE 成功, FALSE 失败
 */
GUM_API gboolean gum_stealth_release (gpointer function_address,
    gsize code_size);

G_END_DECLS

#endif
