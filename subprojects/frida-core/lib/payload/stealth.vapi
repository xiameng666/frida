[CCode (cheader_filename = "stealth-hide.h")]
namespace Frida.Stealth {
	[CCode (cname = "frida_stealth_hide_self_from_linker")]
	public static void hide_self_from_linker (void * any_addr_inside_module);
}
