# agent-unlink

frida agent 加载到目标 app 后, 把自己从 bionic linker 维护的 `r_debug.r_map`
(双链表) 和 `solist` (单链表) 里摘掉. 摘掉后 `dl_iterate_phdr` /
`r_debug.r_map` / 各种走 link_map 的反检测都看不到 agent.

## 当前实现一句话

1. **找 r_debug**: 主程序 `PT_DYNAMIC` 的 `DT_DEBUG` entry → 真实 `r_debug` 地址.
2. **找 linker_base**: 从 r_debug 地址向下逐页扫 `ELFMAG` → linker 起始页.
3. **拿私有符号偏移 (通杀)**: `open()` + `mmap()` linker ELF 文件, 解析
   `.symtab` 找 `__dl__ZL6solist` / `__dl__ZL6sonext` / `__dl__ZL12r_debug_tail`
   的 `st_value`. SELinux 标准策略允许 `untrusted_app` 读 `system_linker_exec`,
   open 失败时 fallback `/proc/self/map_files/<base>-<end>` 拿同 inode 的 fd.
   这套不再依赖 build-id 表, 跨设备通用.
4. **build-id LINKER_PROFILES 表**: `.symtab` 拿不到时的最终兜底, 只在
   定制 ROM strip 掉 `.symtab` 时才用得上.
5. **摘链时机**: 用 `g_idle_add` 挂到 frida 自己的 main loop, callback 在
   `frida_agent_main` 起 main loop 之后才被调用. 那时 GLib/GIO 全部 init 完成,
   linker 不再操作链表, 摘链 100% 安全. 全程在主线程, 不起新线程.
6. **tail 边界**: self 是 r_map 链尾时, `r_debug_tail` / `sonext` 故意不写
   (实测在某些设备会让 linker 状态机错乱破坏 agent init). 不写的代价仅是
   gdb/lldb 反向遍历 r_map 看不见之后新加载的 SO, 应用层风控走的
   `dl_iterate_phdr` 仍然正常.

## 适配新机型

绝大多数 Android 设备, 由于第 3 步通杀, **不需要任何手动操作**. 直接编译跑.

只有当 `[unlink] linker .symtab/.strtab missing (stripped?)` 出现, 才需要补
`LINKER_PROFILES[]` (静态偏移兜底):

```bash
# 1. 拉 linker
adb shell "su -c 'cp /apex/com.android.runtime/bin/linker64 /data/local/tmp/linker64.bin'"
adb pull /data/local/tmp/linker64.bin /tmp/linker64.bin

# 2. 拿 build-id (16 字节 hex) 和 4 个偏移
TC=/path/to/aarch64-none-elf-readelf
$TC -n /tmp/linker64.bin | grep -A1 build
$TC -s /tmp/linker64.bin | \
  grep -E '__dl__r_debug$|__dl__ZL6solist$|__dl__ZL6sonext$|__dl__ZL12r_debug_tail$'
```

把 build-id 和三个偏移加进 `LINKER_PROFILES[]` (`agent-unlink.c`).

## 排错

logcat 看:

```bash
adb shell "su -c 'logcat -d -s xiam:* 2>&1 | tail -30'"
```

期望日志序列:

```
[unlink] idle unlink scheduled (source id=N)         ← agent_main 注册
... (agent init / GIO / connect 完成)
[unlink] idle unlink: main loop is running, time to unlink
[unlink] ==== xu_unlink_self begin ====
[unlink] r_debug @0x... (via DT_DEBUG)
[unlink] linker_base (ELFMAG scan) = 0x...
[unlink] linker symtab loaded: NNNN symbols          ← .symtab 通杀路径
[unlink] symtab offsets: solist=0x... sonext=0x... r_debug_tail=0x...
[unlink] solist self=... prev=... next=...
[unlink] unlinking r_map: ...
[unlink] ==== xu_unlink_self done: r_map=ok, solist=ok ====
```

常见 LOGW 对应:

| LOGW 信息 | 含义 |
|---|---|
| `linker .symtab/.strtab missing` | linker 被 strip, 走 LINKER_PROFILES 表 |
| `no .symtab and no matching profile` | 既 strip 又没 profile, solist 跳过, 仅摘 r_map |
| `dyn-solist: probe LINK_MAP_OFFSET failed` | 动态探测失败, 走 .symtab/profile 静态偏移 |
| `self is r_map tail; r_debug_tail intentionally NOT touched` | self 在末尾, 故意不修 (避免破坏 linker 状态) |

## 验证

REPL 里:

```js
linkMap()      // 期望 命中 0
dlIter()       // 期望 看不到 xiam-64.so
detect()       // SUMMARY 看 link_map / so 链表都为 0
```

## 关键坑 (历史排查记录)

1. **`/proc/self/maps` 第一条 `linker64` 不一定是真 linker**: KPM
   (xiaojia-hide text_shadow) 会复制 shadow 副本到低地址. 必须用 DT_DEBUG +
   ELFMAG 反推, 别直接信 maps 第一条.
2. **`_r_debug` 偏移因 build 而变**: 不能硬编码全局, 必须 readelf 拿或 ELFMAG 扫.
3. **不能在 `.init_array` (ctor) 里调摘链**: dlopen 内部锁还持有, 改链表会让
   注入器 dlsym 失败 → "refused to load".
4. **不能在 `_frida_agent_environment_init` 同步调**: 表面 dlopen 已返回,
   但 agent 后续 GLib/GIO init 还会再 dlopen, 触碰我们改过的链表导致挂.
   必须延迟到 main loop 跑起来 (用 `g_idle_add`).
5. **tail 情况下别动 `r_debug_tail` / `sonext`**: 即使偏移正确, 写完 linker
   下次 dlopen 走偏. 接受一点边缘代价 (gdb 看不见后续 SO).
6. **`open(/proc/self/map_files/<addr>)` 是 SELinux 兜底**: 万一 untrusted_app
   读 `system_linker_exec` 被自定义策略禁了, 通过进程自己的 inode 引用绕开.
