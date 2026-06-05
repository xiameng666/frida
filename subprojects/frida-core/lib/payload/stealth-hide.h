#ifndef __FRIDA_STEALTH_HIDE_H__
#define __FRIDA_STEALTH_HIDE_H__

#include <glib.h>

G_BEGIN_DECLS

/*
 * frida_stealth_hide_self_from_linker:
 *
 * Remove the current frida-agent from bionic's solist and r_debug.r_map so
 * that dl_iterate_phdr(), dlopen(RTLD_NOLOAD) and direct link_map traversal
 * can no longer see the agent.
 *
 * Must be called early in create_and_run(), before any background threads are
 * spawned, and after cached_agent_range.base_address has been determined.
 *
 * Android arm64 only; no-op on other platforms.
 *
 * @any_addr_inside_module: any address that lies inside frida-agent.so,
 *                          used to identify the correct soinfo via dladdr().
 */
void frida_stealth_hide_self_from_linker (const void * any_addr_inside_module);

G_END_DECLS

#endif /* __FRIDA_STEALTH_HIDE_H__ */
