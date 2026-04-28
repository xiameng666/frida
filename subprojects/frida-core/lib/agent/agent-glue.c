#include "frida-agent.h"

#include "frida-base.h"
#include "frida-payload.h"

#ifdef HAVE_ANDROID
# include <jni.h>
# if __ANDROID_API__ < __ANDROID_API_L__
#  include <signal.h>
# endif
extern int xiam_unlink_self (void);
extern int xiam_unlink_self_delayed (void);
#endif
#ifdef HAVE_GIOOPENSSL
# include <gioopenssl.h>
#endif

void
_frida_agent_environment_init (void)
{
#ifdef HAVE_MUSL
  static gboolean been_here = FALSE;

  if (been_here)
    return;
  been_here = TRUE;
#endif

#ifdef HAVE_ANDROID
  /* 同步摘链 (此时 g_dl_mutex 已释放, RELRO 稳定) 表面看时机正确, 但实测会
   * 让 agent 后续 GLib/GIO init 阶段的 dlopen 触碰我们改过的链表导致挂掉,
   * 报 "refused to load frida-agent".
   *
   * 改为后台延迟线程: sleep N 秒等 agent 全部 init 完 + 跟 server 建好
   * 通讯后再摘. 此时 linker 不再 dlopen 任何东西, 改链表绝对安全.
   * 需要导出 xiam_unlink_self_delayed (frida-agent-android.version 已加).  */
  (void)xiam_unlink_self_delayed ();
#endif

#ifdef _MSC_VER
  frida_libc_shim_init ();
#endif
  gio_init ();

  g_thread_set_garbage_handler (_frida_agent_on_pending_thread_garbage, NULL);

#ifdef HAVE_GIOOPENSSL
  g_io_module_openssl_register ();
#endif

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
  /*
   * We might be holding the dynamic linker's lock, so force-initialize
   * our bsd_signal() wrapper on this thread.
   */
  bsd_signal (G_MAXINT32, SIG_DFL);
#endif
}

void
_frida_agent_environment_deinit (void)
{
#ifndef HAVE_MUSL
  frida_libc_shim_prepare_to_deinit ();

  gum_shutdown ();
  gio_shutdown ();
  glib_shutdown ();

  gio_deinit ();

  frida_run_atexit_handlers ();

# if defined (_MSC_VER) || defined (HAVE_DARWIN)
  frida_libc_shim_deinit ();
# endif
#endif
}

#ifdef HAVE_ANDROID

jint
JNI_OnLoad (JavaVM * vm, void * reserved)
{
  FridaAgentBridgeState * state = reserved;

  frida_agent_main (state->agent_parameters, &state->unload_policy, state->injector_state);

  return JNI_VERSION_1_6;
}

#endif
