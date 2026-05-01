# gum-text-shadow: KPM PTE 隐藏集成

把 xiaojia-hide 内核模块 (KPM) 提供的 `text_shadow` PTE 双页隐藏能力
集成到 frida-gum 的 Interceptor 流程, 用户在 JS 端调一次
`Interceptor.enableShadow()` 即可让所有后续 inline hook 对外不可见.

## 背景

Frida 默认 inline hook 在目标函数 (libc/libart 等 file-backed `.text`)
入口写一条 `B`/`LDR+BR` 蹦床, 跳到 frida 自己 mmap 的 trampoline 池.
这条蹦床直接暴露在两个层面:

1. **content** — 读 `libc.so` 的那一页可以扫到 ARM64 跳板字节
2. **VMA perm** — 不还原情况下 `mprotect rwx` 会把 `libc.so` 的
   `r-x` 段撕成多片 (前置 commit `feat(frida-gum): 整段 mprotect RWX 让
   .text 不撕段` 已解决)

`text_shadow` 解决 (1): 每个保护页准备两份物理页, 一份 shadow
(`--x`, 含蹦床) 一份 alt (`r--`, 干净原件), 通过 `do_page_fault` hook
实现 read fault → alt, exec fault → shadow 的 PTE 切换. 详细原理见
xiaojia-hide 仓库 `src/text_shadow.c` 文件头注释.

## 整体流程

```
JS 端                             frida-gum 内部                    KPM 内核侧
─────                             ───────────                       ──────────
Interceptor.enableShadow()
  ↓
gumjs_interceptor_enable_shadow
  ↓                              gum_interceptor_enable_shadow
                                   ↓
                                 gum_text_shadow_init
                                   ↓                               prctl(0x45822, 0)
                                   ←─────────────────────────────  (CLEAR_ALL probe)
                                 → use_shadow=TRUE (探测成功)

Interceptor.attach(open, ...)
  ↓
gumjs_interceptor_attach
  ↓
gum_interceptor_attach
  ↓
... transaction_begin ... 写 listener ... transaction_end
  ↓
                                 transaction_end:
                                   1. 收集 dirty pages
                                   2. ★ shadow_save_original_page  (memcpy 干净页到 pool)
                                   3. gum_memory_patch_code_pages  (mprotect → 写蹦床 → 还原)
                                   4. ★ for func in dirty_funcs:
                                        prctl(0x45820, func, orig)→ protect_page
                                                                    分配 alt + 切 PTE 到 shadow
```

## 三个用户态 API

```js
const ok = Interceptor.enableShadow();   // 探测 KPM 并开启, 返回是否成功
                                         //   - 装了 KPM:  true
                                         //   - 没装 KPM:  false (静默 fallback)
                                         //   - 非 Android arm64: 永远 false

Interceptor.disableShadow();             // 关闭, 不影响已保护的页, 只让后续 attach
                                         //   不再注册 PTE 保护

const v = Interceptor.shadowEnabled;     // 当前状态 (KPM 不可用时永远 false)
```

### 与现有 API 的关系

* 在 `Interceptor.attach()` 之前调 `enableShadow()` —— 当批 attach 的 hook
  全部走 shadow.
* `attach` 之后再调 `enableShadow()` —— 已 attach 的 hook **不会追溯保护**
  (前面的蹦床仍然可读), 只对后续 attach 生效.
* `Interceptor.flush()` 触发的写出仍然走同一个 `transaction_end`,
  shadow 集成对它透明.

## ABI: 与 KPM 端的约定

`text_shadow.c` (内核) 通过 `prctl` 暴露 3 个私有 option:

| option       | arg1                | arg2          | 语义                                          |
|--------------|---------------------|---------------|-----------------------------------------------|
| `0x45820`    | func_addr (蹦床 PC) | original_buf  | 保护 func_addr 所在页, 同页第二次走 append    |
| `0x45821`    | page_addr           | -             | 卸载该页保护                                  |
| `0x45822`    | -                   | -             | 清除当前进程所有保护                          |

* `func_addr` 必须是**精确蹦床入口 PC**, kernel 用它做 Path B 同页自读
  白名单. 传页基址会让函数自 CRC 时拿错字节.
* `original_buf` 必须是 4KB 页对齐的"干净"内容副本 (在写蹦床之前 memcpy
  得到). gum-text-shadow 用一个 mmap 大块 + bump allocator 自维护, 同
  页二次保护复用首次 buf.

KPM 探测使用 `0x45822` (CLEAR_ALL) 作为 sentinel: 装了 KPM 返回 0,
没装返回 -1 (errno=EINVAL).

## 用户态 shadow pool 设计

每个保护页都需要一份"干净"副本传给 kernel. 直觉上每页单独 mmap 4KB
就行, 但这样 `/proc/self/maps` 上会多出大量匿名映射, 自身成为新特征.

实现上用了 **bump allocator + 大块 mmap**:

```
shadow pool:
  chunk0 (2MB)  [page0|page1|page2|...|empty]
  chunk1 (2MB)  [page0|...]              ← chunk 用满后再 mmap 下一块
  ...
  
按 (addr & PAGE_MASK) → buf 缓存, 同页第二次 save 是 no-op.
```

每个 chunk 默认 512 页 (2MB), 实际 frida 项目里同时被 hook 的页一般
< 100, 一个 chunk 够用.

注意 chunk 自身在 `/proc/self/maps` 里也是匿名映射, 但:
1. 集中到大块, 段数固定 (1-2 段), 不像每页单独 mmap 那样数量随保护
   函数数线性增长.
2. xiaojia-hide 的 `hide_proc.c` 已经在 kernel `show_map` hook 里按
   关键字过滤了 `xiam-*` / `frida-agent` / `libGumTrace` 等可疑行,
   但匿名段没法靠名字区分. 当前的 chunk 仍可见. 后续可以给它加上
   `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)` 起一个伪装名字
   (例如 `[anon:libdex2oat-cache]`), 然后让 hide_proc 放行.

## 集成点

唯一的接入点在 `gum_interceptor_transaction_end` (`guminterceptor.c`):

1. **预存原件** (mprotect-RWX 之前) — 必须在写蹦床字节前 memcpy 干净
   页, 否则 alt 页就是脏的.
2. **批量 protect** (mprotect 还原之后) — 此时蹦床字节已写入,
   `prctl(PROTECT)` 通知 kernel 接管 PTE.

`gum_memory_patch_code_pages` 内的整段 mprotect RWX (前置 commit) 与
本改造**正交**, 顺序无冲突: 整段 mprotect 处理 vma perm 层 (libc.so
不撕段), text_shadow 处理 PTE 层 (libc.so 内容不暴露).

## 平台条件编译

`gum-text-shadow.c` 文件头:

```c
#if defined (HAVE_ANDROID) && defined (HAVE_ARM64)
... 真实实现 ...
#else
... stub 全部返回 FALSE/-1, 不做任何系统调用 ...
#endif
```

非 Android arm64 平台编译期就走 stub, 不留 KPM 探测痕迹.
`Interceptor.enableShadow()` 在 iOS/Linux/Windows 永远返回 false.

## 已知 trade-off

1. **detach 不调 unprotect** —— 简化设计, 进程退出时由 kernel 的
   `do_group_exit` hook 统一清理. 中途 detach 后该页仍处于 PTE 保护
   状态, 读取仍然路由到 alt 页 (干净), 执行路由到 shadow 页 (此时已
   无蹦床, 等于干净). 行为正确, 仅泄漏少量 kernel 内存到进程退出.

2. **fork 子进程不自动重注册** —— kernel 端 `do_page_fault_before` 已
   有兜底 (找不到匹配 entry → 把 PTE_USER 加回, 该子进程那一页**暴露
   蹦床但不崩**). zygote → app 模型下, 子进程 tgid 不同, 不会自动
   继承 protect. 后续可在 `pthread_atfork` child handler 里重注册.

3. **smaps `Anonymous` 字段非 0** —— PTE 的 alt 指向 `__get_free_pages`
   分配的 anon page, 走到 alt 状态时 file-backed vma 的
   smaps `Anonymous:` 会显示几 kB. 大多数风控不扫此字段, 已知风险.

4. **pagemap bit 62** —— alt page 是 anon, 在 `/proc/pid/pagemap`
   会被标 anon. 但 pagemap 在 Android 需要 CAP_SYS_ADMIN, 普通 app
   读不到. root 级 forensic 仍然有破绽.

5. **JS API 不能追溯保护** —— `enableShadow()` 之前的 attach 不被
   保护. 文档要求用户把 `enableShadow()` 放脚本第一行.

## 测试

见 `tools/feature-scan.js` 的 `testShadow*` RPC 套件 (待补).
最小验证:

```js
const ok = Interceptor.enableShadow();
if (!ok) throw new Error("KPM not loaded");
const open = Module.findExportByName("libc.so", "open");
Interceptor.attach(open, {});
// 同进程自读: 应该拿到 ELF 原始字节, 不是 B 跳板
const bytes = Memory.readByteArray(open, 4);
console.log(hexdump(bytes));   // 期望: 原始 stp/sub 等指令
```
