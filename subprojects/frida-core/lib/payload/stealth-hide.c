/*
 * stealth-hide.c — Remove frida-agent from bionic solist + r_debug.r_map
 *
 * Ported from frida-server-xiaojia STEALTH_PATCHES.md §3.
 * Android arm64 only. No gum/glib dependency — runs before both are init'd.
 *
 * Key design points:
 *  - Match by soinfo.base (not l_name): agent is loaded via memfd, l_name is
 *    "/proc/self/fd/N", not "frida-agent.so".
 *  - Hold ProtectedDataGuard while modifying linker data structures.
 *  - Use LinkerBlockAllocator::free to return the soinfo block — avoids the
 *    double-free / abort triggered by soinfo_free() which touches other
 *    soinfo dependency chains.
 *  - Decrement g_module_load_counter so anti-cheat counters stay consistent.
 *  - Update r_debug_tail when removing the last link_map node.
 */

#include "stealth-hide.h"

#if defined (HAVE_ANDROID) && defined (HAVE_ARM64)

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── ELF helpers ──────────────────────────────────────────────────────────── */

typedef struct {
  void        * mapping;
  size_t        mapping_size;
  uintptr_t     load_base;   /* runtime base: mapping_start - mapping_offset */
  Elf64_Ehdr  * ehdr;
  Elf64_Shdr  * shdrs;
  const char  * shstrtab;
} FridaElfImg;

static int
frida_elf_img_locate (const char * path, FridaElfImg * img)
{
  char line[512];
  FILE * maps = fopen ("/proc/self/maps", "r");
  if (!maps)
    return -1;

  while (fgets (line, sizeof (line), maps))
    {
      /* Only accept r-xp lines — every loaded ELF has exactly one. */
      if (!strstr (line, "r-xp"))
        continue;
      if (!strstr (line, path))
        continue;

      unsigned long start, end, offset;
      if (sscanf (line, "%lx-%lx r-xp %lx", &start, &end, &offset) == 3)
        {
          img->load_base = start - offset;
          fclose (maps);
          return 0;
        }
    }

  fclose (maps);
  return -1;
}

static int
frida_elf_img_open (const char * path, FridaElfImg * img)
{
  int fd = open (path, O_RDONLY);
  if (fd < 0)
    return -1;

  struct stat st;
  if (fstat (fd, &st) < 0)
    {
      close (fd);
      return -1;
    }

  void * m = mmap (NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close (fd);
  if (m == MAP_FAILED)
    return -1;

  img->mapping      = m;
  img->mapping_size = st.st_size;

  Elf64_Ehdr * ehdr = (Elf64_Ehdr *) m;
  if (memcmp (ehdr->e_ident, ELFMAG, SELFMAG) != 0)
    {
      munmap (m, st.st_size);
      return -1;
    }

  img->ehdr  = ehdr;
  img->shdrs = (Elf64_Shdr *) ((char *) m + ehdr->e_shoff);

  /* shstrtab */
  Elf64_Shdr * shstr_hdr = &img->shdrs[ehdr->e_shstrndx];
  img->shstrtab = (const char *) m + shstr_hdr->sh_offset;

  /* Compute bias from first PT_LOAD: bias = p_vaddr - p_offset (PIE → 0) */
  Elf64_Phdr * phdrs = (Elf64_Phdr *) ((char *) m + ehdr->e_phoff);
  for (int i = 0; i < ehdr->e_phnum; i++)
    {
      if (phdrs[i].p_type == PT_LOAD)
        {
          /* bias absorbed into load_base already; nothing extra needed */
          break;
        }
    }

  return 0;
}

static void
frida_elf_img_close (FridaElfImg * img)
{
  if (img->mapping)
    munmap (img->mapping, img->mapping_size);
  img->mapping = NULL;
}

static uintptr_t
frida_elf_img_find (FridaElfImg * img, const char * sym_name)
{
  Elf64_Shdr * symtab_hdr = NULL;
  Elf64_Shdr * strtab_hdr = NULL;

  for (int i = 0; i < img->ehdr->e_shnum; i++)
    {
      Elf64_Shdr * sh = &img->shdrs[i];
      const char * name = img->shstrtab + sh->sh_name;
      if (sh->sh_type == SHT_SYMTAB && strcmp (name, ".symtab") == 0)
        symtab_hdr = sh;
      else if (sh->sh_type == SHT_STRTAB && strcmp (name, ".strtab") == 0)
        strtab_hdr = sh;
    }

  if (!symtab_hdr || !strtab_hdr)
    return 0;

  Elf64_Sym * syms   = (Elf64_Sym *) ((char *) img->mapping + symtab_hdr->sh_offset);
  const char * strtab = (const char *) img->mapping + strtab_hdr->sh_offset;
  size_t nsyms        = symtab_hdr->sh_size / sizeof (Elf64_Sym);

  for (size_t i = 0; i < nsyms; i++)
    {
      Elf64_Sym * s = &syms[i];
      unsigned char type = ELF64_ST_TYPE (s->st_info);
      if (type != STT_FUNC && type != STT_OBJECT)
        continue;
      if (s->st_size == 0)
        continue;
      if (strcmp (strtab + s->st_name, sym_name) != 0)
        continue;

      uintptr_t addr = img->load_base + s->st_value;
      /* Sanity: within ±32 MiB of load_base */
      if (addr < img->load_base || addr > img->load_base + 32 * 1024 * 1024)
        return 0;
      return addr;
    }

  return 0;
}

/* ── soinfo field offsets (Android 10+ arm64, from linker_soinfo.h) ───────── */

#define SOINFO_BASE_OFF  0x10   /* uintptr_t base */
#define SOINFO_NEXT_OFF  0x28   /* soinfo *      */

/* ── linker symbol addresses ─────────────────────────────────────────────── */

typedef void * soinfo_ptr;

static soinfo_ptr  * g_solist_head    = NULL;  /* __dl__ZL6solist         */
static soinfo_ptr  * g_sonext         = NULL;  /* __dl__ZL6sonext         */
static struct r_debug * g_r_debug     = NULL;  /* __dl__r_debug / _r_debug */
static struct link_map ** g_r_debug_tail = NULL; /* __dl__ZL12r_debug_tail */

/* ProtectedDataGuard ctor/dtor */
typedef void (*pdg_fn_t)(void *);
static pdg_fn_t g_pdg_ctor = NULL;
static pdg_fn_t g_pdg_dtor = NULL;

/* LinkerBlockAllocator::free */
typedef void (*lba_free_fn_t)(void * allocator, void * block);
static lba_free_fn_t  g_lba_free    = NULL;
static void         * g_lba_inst    = NULL;  /* g_soinfo_allocator */

/* load/unload counters */
static uint64_t * g_load_counter   = NULL;
static uint64_t * g_unload_counter = NULL;

static int g_symbols_loaded = 0;

static void __attribute__((noinline))
load_linker_symbols (void)
{
  if (g_symbols_loaded)
    return;
  g_symbols_loaded = 1;

  FridaElfImg img;
  memset (&img, 0, sizeof (img));

  /* Find linker64 path from /proc/self/maps */
  char linker_path[256] = {0};
  {
    char line[512];
    FILE * maps = fopen ("/proc/self/maps", "r");
    if (!maps)
      return;
    while (fgets (line, sizeof (line), maps))
      {
        if (!strstr (line, "r-xp"))
          continue;
        /* Require "linker64" or "/linker" anywhere in the path part */
        if (!strstr (line, "linker64") && !strstr (line, "/linker"))
          continue;
        /* Extract the full path: find first '/' after the permissions field */
        const char * p = strchr (line, '/');
        if (!p)
          continue;
        /* Sanity: the path must actually contain linker64 or /linker */
        if (!strstr (p, "linker64") && !strstr (p, "/linker"))
          continue;
        /* trim newline */
        size_t len = strlen (p);
        if (len > 0 && p[len - 1] == '\n')
          len--;
        if (len >= sizeof (linker_path))
          len = sizeof (linker_path) - 1;
        memcpy (linker_path, p, len);
        linker_path[len] = '\0';
        break;
      }
    fclose (maps);
  }

  if (linker_path[0] == '\0')
    return;

  if (frida_elf_img_locate (linker_path, &img) < 0)
    return;

  if (frida_elf_img_open (linker_path, &img) < 0)
    return;

#define FIND(sym) frida_elf_img_find (&img, (sym))

  uintptr_t addr;

  addr = FIND ("__dl__ZL6solist");
  if (addr) g_solist_head = (soinfo_ptr *) addr;

  addr = FIND ("__dl__r_debug");
  if (!addr) addr = FIND ("_r_debug");
  if (addr) g_r_debug = (struct r_debug *) addr;

  addr = FIND ("__dl__ZL6sonext");
  if (addr) g_sonext = (soinfo_ptr *) addr;

  addr = FIND ("__dl__ZL12r_debug_tail");
  if (addr) g_r_debug_tail = (struct link_map **) addr;

  addr = FIND ("__dl__ZN18ProtectedDataGuardC2Ev");
  if (addr) g_pdg_ctor = (pdg_fn_t) addr;

  addr = FIND ("__dl__ZN18ProtectedDataGuardD2Ev");
  if (addr) g_pdg_dtor = (pdg_fn_t) addr;

  addr = FIND ("__dl__ZN20LinkerBlockAllocator4freeEPv");
  if (addr) g_lba_free = (lba_free_fn_t) addr;

  addr = FIND ("__dl__ZL18g_soinfo_allocator");
  if (addr) g_lba_inst = (void *) addr;

  addr = FIND ("__dl__ZL21g_module_load_counter");
  if (addr) g_load_counter = (uint64_t *) addr;

  addr = FIND ("__dl__ZL23g_module_unload_counter");
  if (addr) g_unload_counter = (uint64_t *) addr;

#undef FIND

  frida_elf_img_close (&img);
}

/* ── ProtectedDataGuard RAII ──────────────────────────────────────────────── */

static char g_pdg_storage[64];   /* sizeof(ProtectedDataGuard) ≪ 64 */

static void
pdg_lock (void)
{
  if (g_pdg_ctor)
    g_pdg_ctor (g_pdg_storage);
}

static void
pdg_unlock (void)
{
  if (g_pdg_dtor)
    g_pdg_dtor (g_pdg_storage);
}

/* ── unlink helpers ───────────────────────────────────────────────────────── */

static inline uintptr_t
soinfo_base (soinfo_ptr so)
{
  return *(uintptr_t *) ((char *) so + SOINFO_BASE_OFF);
}

static inline soinfo_ptr *
soinfo_next_ptr (soinfo_ptr so)
{
  return (soinfo_ptr *) ((char *) so + SOINFO_NEXT_OFF);
}

/*
 * Unlink from r_debug.r_map (ELF standard, walked by GDB and most ABI tools).
 * Must be called under pdg_lock.
 */
static void
unlink_link_map (uintptr_t want_base)
{
  if (!g_r_debug)
    return;

  struct link_map * prev = NULL;
  struct link_map * cur  = g_r_debug->r_map;

  while (cur)
    {
      /*
       * Match by load address. l_addr is the base for shared libs; for the
       * agent loaded via memfd, l_name is "/proc/self/fd/N" — not "frida".
       */
      if ((uintptr_t) cur->l_addr == want_base)
        {
          /* Tell GDB we're modifying the list */
          g_r_debug->r_state = RT_DELETE;

          if (prev)
            prev->l_next = cur->l_next;
          else
            g_r_debug->r_map = cur->l_next;

          if (cur->l_next)
            cur->l_next->l_prev = prev;

          /* Fix tail pointer if we're removing the last node */
          if (!cur->l_next && g_r_debug_tail)
            *g_r_debug_tail = prev;

          /* Isolate the removed node */
          cur->l_next = NULL;
          cur->l_prev = NULL;

          g_r_debug->r_state = RT_CONSISTENT;
          return;
        }

      prev = cur;
      cur  = cur->l_next;
    }
}

/*
 * Unlink from bionic solist (walked by dl_iterate_phdr and dlopen).
 * Must be called under pdg_lock.
 */
static void
unlink_solist (uintptr_t want_base)
{
  if (!g_solist_head)
    return;

  soinfo_ptr prev = NULL;
  soinfo_ptr cur  = *g_solist_head;

  while (cur)
    {
      if (soinfo_base (cur) == want_base)
        {
          soinfo_ptr next = *soinfo_next_ptr (cur);

          if (prev)
            *soinfo_next_ptr (prev) = next;
          else
            *g_solist_head = next;

          /* Update sonext (tail pointer in some bionic versions) */
          if (!next && g_sonext)
            *g_sonext = prev;

          /* Return soinfo block to the allocator to avoid a "hole" */
          if (g_lba_free && g_lba_inst)
            g_lba_free (g_lba_inst, cur);

          return;
        }

      prev = cur;
      cur  = *soinfo_next_ptr (cur);
    }
}

/* ── public API ───────────────────────────────────────────────────────────── */

void
frida_stealth_hide_self_from_linker (const void * any_addr_inside_module)
{
  load_linker_symbols ();

  if (!g_solist_head || !g_r_debug)
    return;   /* Symbol lookup failed; give up silently */

  /*
   * Resolve our own load base via dladdr BEFORE unlinking — dladdr walks
   * the solist internally and will return nothing after we remove ourselves.
   */
  Dl_info info;
  if (dladdr (any_addr_inside_module, &info) == 0)
    return;

  uintptr_t want_base = (uintptr_t) info.dli_fbase;
  if (want_base == 0)
    return;

  pdg_lock ();
  unlink_link_map (want_base);
  unlink_solist   (want_base);
  pdg_unlock ();

  /* Subtract the dlopen +1 so load-counter matches zygote baseline */
  if (g_load_counter && *g_load_counter > 0)
    (*g_load_counter)--;
}

#else /* not (HAVE_ANDROID && HAVE_ARM64) */

void
frida_stealth_hide_self_from_linker (const void * any_addr_inside_module)
{
  (void) any_addr_inside_module;
}

#endif
