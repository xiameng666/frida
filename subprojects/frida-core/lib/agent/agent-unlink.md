# agent-unlink 适配新机型指南

`agent-unlink.c` 让 frida agent 自摘出 bionic linker 的 `r_debug.r_map` (link_map
双链表) 与 `solist` (soinfo 单链表), 让风控走 dl_iterate_phdr / r_debug /
gdb-style link_map 任意路径都看不见 agent.

由于 bionic linker 把 `_solist` / `_sonext` / `_r_debug_tail` 这些**私有静态符号
(STB_LOCAL)** 只放在 `.symtab` (运行时不可访问), 我们必须**编译期通过 readelf
拿到偏移**, 用 build-id 做运行时校验, 然后在 agent 里硬编码这套偏移. 换设备/
固件就要补一条 profile.

---

## 一、需要拿到什么

每个 profile 4 个量:

```c
struct xu_linker_profile {
  uint8_t   build_id[16];        /* GNU build-id (前 16 字节) */
  uint32_t  off_solist;          /* __dl__ZL6solist        st_value */
  uint32_t  off_sonext;          /* __dl__ZL6sonext        st_value */
  uint32_t  off_r_debug_tail;    /* __dl__ZL12r_debug_tail st_value */
  const char *desc;
};
```

外加一个全局 **`XU_OFF_R_DEBUG`** (= `__dl__r_debug` 的 st_value), 不同 build
的 linker 这个值通常 _不_ 变 (=`0x133530` for Android 12 5.10 GKI), 但仍要核
对; 如果你的设备不是这个值, 改成 per-profile 字段更稳.

---

## 二、提取偏移的步骤 (新机型必走)

### 1) 从设备拉 linker64 + 校验 build-id

```bash
# 找设备上 linker 实际路径 (Android 11+ 在 apex)
adb shell "su -c 'cat /proc/self/maps | grep linker64 | head -1'"
# 例如:  /apex/com.android.runtime/bin/linker64

adb shell "su -c 'cp /apex/com.android.runtime/bin/linker64 /data/local/tmp/linker64.bin \
                  && chmod 644 /data/local/tmp/linker64.bin'"
adb pull /data/local/tmp/linker64.bin /tmp/linker64.bin

# 拿 GNU build-id
aarch64-none-elf-readelf -n /tmp/linker64.bin | grep -A1 build
# Build ID: 92f8e83b3f3e2690de1efbc419b1e22e   <- 16 字节 hex
```

### 2) 拿 4 个静态符号偏移

```bash
TC=/home/xiam/tools/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-

$TC/readelf -s /tmp/linker64.bin | \
   grep -E '__dl__r_debug$|__dl__ZL6solist$|__dl__ZL6sonext$|__dl__ZL12r_debug_tail$'

#  493: 00000000001364d0   8 OBJECT LOCAL DEFAULT  19 __dl__ZL12r_debug_tail
#  495: 0000000000133530  40 OBJECT LOCAL HIDDEN   18 __dl__r_debug
# 5311: 00000000001371a0   8 OBJECT LOCAL DEFAULT  19 __dl__ZL6solist
# 5313: 0000000000137198   8 OBJECT LOCAL DEFAULT  19 __dl__ZL6sonext
```

第二列就是 st_value (= 运行时相对 linker_base 的偏移).

如果 readelf 找不到这些符号, 说明 linker 被 strip 了 (极少见). 改去
[Android 源码](https://android.googlesource.com/platform/bionic/+/refs/tags/) 翻
对应 GKI 版本的 linker.cpp 估算, 或者放弃 solist 摘链 (退化为只摘 r_map, 仍
可让大多数 link_map 风控盲).

### 3) 把 profile 加进 `LINKER_PROFILES[]`

`subprojects/frida-core/lib/agent/agent-unlink.c`:

```c
static const struct xu_linker_profile LINKER_PROFILES[] = {
  {  /* 老的 */ },
  {
    /* 新机型: HUAWEI YYY / Android 13 EMUI 13 / 描述 */
    { 0xab,0xcd,...,16字节 },        /* 把 build-id 拆 16 个 hex 字节 */
    /* off_solist        */ 0xXXXXXX,
    /* off_sonext        */ 0xXXXXXX,
    /* off_r_debug_tail  */ 0xXXXXXX,
    "新机型描述 (build-id abcd...)",
  },
};
```

---

## 三、踩过的坑 (重要, 不踩同一坑两次)

### 坑 1: 不能用 `/proc/self/maps` 第一条 "linker64" 当 linker_base

如果设备上跑了内核态反检测模块 (例如本仓库配套的 `xiaojia-hide` 的
`text_shadow`), 它会**把 linker 的 r-- 段在低地址再 mmap 一份做 shadow**, 用来
让用户态 hook 看到的字节是干净的. 这时 maps 里会出现 _两份_ linker64, 第一份
是影子副本, 后面没有 r-x/rw-p 段.

**症状**: 用第一条 base 算出 `linker_base + 0x1371a0` 读到的不是 soinfo*, 而
是 linker 内部某个 _函数地址_ (例如 `0x514a0` 是 `ElfReader::xxx` 的 offset).

**正确做法**: **用 DT_DEBUG 反推 linker_base**.

```c
// 主程序 PT_DYNAMIC 的 DT_DEBUG entry 的 d_un.d_ptr = 真实 _r_debug 地址
struct r_debug *rd = xu_find_r_debug();
uintptr_t linker_base = (uintptr_t)rd - XU_OFF_R_DEBUG;   // 0x133530

// 验证: 这个 base 必须指向合法 ELF (e_ident == ELFMAG)
if (memcmp((void*)linker_base, ELFMAG, SELFMAG) != 0) abort;
```

DT_DEBUG 是 ELF ABI 标准, **任何反检测都不会改它** (改了 gdb/lldb/Android
ART 全废), 所以这条永远可信.

### 坑 2: solist 不能在 init_array (.ctor) 阶段调

ctor 在 dlopen 内部跑, 此时:

- `g_dl_mutex` 还被持有
- RELRO 处在 RO -> RW -> RO 的切换窗口
- linker 之后还要做 finalize / 一致性校验

我们改链表 → linker 看 solist 内部计数对不上 → **后续 dlsym
"frida_agent_main" 失败** → 注入器报 "process refused to load frida-agent",
没有 tombstone (因为 dlopen 返回 NULL 不 abort).

**正确做法**: 不挂 ctor, 改成 RPC / `frida_agent_main` 入口显式调用. 此时
dlopen 已经返回, 状态稳定.

### 坑 3: `.symtab` 在内存里读不到, 要从 _文件_ 读

你也许会想: linker 已经映射在进程内存, 我直接读它 ELF 内存找 .symtab 不就好了?

不行. `.symtab` 不在任何 PT_LOAD segment 内 (kernel 加载 ELF 时只看 program
header, .symtab 属于 section header), 所以**只在磁盘文件**, 不在内存映射里.

所以必须**离线** readelf 一次, 编译期硬编码偏移. 这就是为什么有 `LINKER_PROFILES[]`
表.

如果磁盘文件也读不到 (SELinux 限制 app 域 open `/system/bin/linker64`), 还有
两个备选:

- `/proc/self/map_files/<addr>` 用进程自己的 inode 引用绕开路径权限 (复杂度高)
- 让 KPM 通过 ioctl 把 solist 地址传过来 (耦合两侧)

### 坑 4: `_r_debug` / `_solist` 不在 linker 自己的 maps 段里

bionic 把 LOAD 4 (.data + .bss) **可能 mmap 到与 LOAD 1 不连续的高地址**, 这
是 Android 启动时 zygote 给 linker 的特殊 anon 映射. 不要假设 linker maps 是
完全连续的; 始终用 `linker_base + st_value` 计算 (linker_base 由 ELF 加载约定
保证 = LOAD 1 起点).

### 坑 5: build-id 校验只比前后几字节会假阳

记得读完整 16 字节 hex 比较, 不要图方便只比前 4 + 后 2 字节. 不同设备的
linker (即使同 Android 版本) build-id 中间几字节会差.

---

## 四、运行时验证流程

加完 profile, build & push frida-server, 然后:

```bash
frida -H 127.0.0.1:14725 -f com.target.app -l tools/feature-scan.js
```

REPL 里:

```js
linkMap()        // 看到 466 行 [!!] /memfd:xiam-64.so
unlinkSelf()     // 期望返回 0
linkMap()        // 期望命中 0  ← r_map 摘链生效
dlIter()         // 期望看不到 xiam-64.so  ← solist 摘链生效
detect()         // SUMMARY 看 link_map / so 链表都为 0
```

同时抓 logcat:

```bash
adb shell "su -c 'logcat -d -s xiam-unlink:*'"
```

期望看到的关键行 (按顺序):

```
==== xu_unlink_self begin ====
maps loaded: NNNN entries
r_debug @0x... (via DT_DEBUG)
linker_base (from r_debug back-calc) = 0x7f8267d000      ← 反推真 base
linker build-id: 92f8e83b...e22e
profile match: <你的 desc>
self link_map @0x... name=/memfd:xiam-64.so base=0x...
solist_var @0x...   sonext_var @0x...
solist head=0x... (->base=0x7f8267d000)                  ← head->base = linker_base, OK
solist self=... prev=... next=...
solist: prev->next -> ...
unlinking r_map: prev=... self=... next=...
==== xu_unlink_self done: r_map=ok, solist=ok ====
```

任何一行卡住, 看后续 LOGW 信息定位:

| LOGW | 原因 | 处理 |
|---|---|---|
| `r_debug not found via DT_DEBUG` | 主程序 PT_DYNAMIC 没 DT_DEBUG entry | 极少见, app 是非 PIE; 此时只能放弃 |
| `linker_base does not point to ELF magic` | 反推得到的 base 不是 linker | 你的 `XU_OFF_R_DEBUG` 跟当前 build 不符, 检查 readelf 输出 |
| `no matching linker profile` | build-id 没在 LINKER_PROFILES 里 | 走 [二、提取偏移] 流程加一条 |
| `solist head=... invalid` | 偏移读出的不是合法 soinfo* | 你的 `off_solist` 错了, readelf 重核 |
| `solist self not found` | 链表里没 base 匹配 self | self_lm.l_addr 跟 soinfo.base 不一致, 看 logcat 中的具体 base 值 |

---

## 五、调试新机型的"神器组合"

定位偏移除了 readelf 之外, 这几招很顶用:

### A. REPL 访问违例的"地址" → readelf 反查

```
Error: access violation accessing 0x514b0
```

`0x514b0` 拿去 `readelf -s linker64 | awk '$2 == "00000000000514b0" || $2 == "00000000000514a0"'`
立刻看到是不是某个 linker 内部符号. 如果是, 说明你的 base 错了或者 offset 错
读了别的字段.

### B. 完整 maps 上下文 (永远 -A/-B)

```bash
adb shell "su -c 'cat /proc/<pid>/maps'" | grep -A 15 -B 2 linker64
```

千万不要 `grep -m 1`, 否则看不到 KPM 影子副本/真 linker 多份的情况.

### C. xxd 文件 + 内存地址对比

```bash
# 文件中 _r_debug 处的字节
xxd -s 0x132530 -l 40 /tmp/linker64.bin
# 期望: 0100 0000 0000 0000 0000 0000 ... (r_version=1 + zero r_map 等)

# 运行时 linker_base + 0x133530 处读出的值
# 通过 unlinkSelf logcat 输出对比
```

如果文件里是正确字节, 内存里是垃圾, 说明 linker_base 错.

### D. 后台抓 logcat (避免 -d 缓冲过期)

```bash
adb shell "su -c 'logcat -c'"      # 清缓冲
adb shell "su -c 'logcat 2>&1 | grep -i xiam'" &  # 后台实时抓
# 然后跑测试
```

`logcat -d` 在 priority filter 严格的设备上可能丢前面的日志, 实时抓更稳.

---

## 六、长期目标

如果适配工作量太大 (大量机型 / 频繁 OTA 更新), 考虑迁移到:

1. **KPM 暴露 ioctl 返回 solist 地址**: KPM 在内核态有 task->mm 完全访问权,
   可以直接读 linker .symtab 或者跟踪 dlopen 拿到 soinfo 链表头. agent 走
   ioctl 一次拿到, 不再依赖 build-id 表.
2. **KPM 直接做摘链**: 完全不需要 agent 干这事, KPM 在 dlopen 完成后立刻摘.
3. **Pattern scan 而不是固定偏移**: 在 linker rw 段扫"指向 base==linker_base
   的 soinfo*"找 _solist. 之前实测发现这个 rw 段不是 linker 本体而是 zygote
   预分配段, 需要额外定位; 如果可靠, 是不依赖 build-id 的方案.

目前用 LINKER_PROFILES 表是最快出活的折中.
