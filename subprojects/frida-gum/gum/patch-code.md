# gum_memory_patch_code 整段 mprotect 改动

## 背景

frida 默认的 hook 路径走 `gum_memory_patch_code → gum_memory_patch_code_pages`
做 inline hook：

```
mprotect(target_page, RWX)   per-page, 撕段
write trampoline
(不还原 → 永久 rwxp)
```

后果：
- `/proc/self/maps` 上 libc/libart 的 `.text` 被撕成 `r-x | rwxp | r-x | ...` 多片
- 留下永久 `rwxp` 段，风控强特征

## 为什么单纯 per-page 还原成 r-x 也不够

写过 W 的 page 在 kernel 层会创建 `anon_vma`（COW 副本）。即使 perm 改回
r-x，**vma_merge 在 Linux 5.10 上拒绝合并**：

```c
// mm/mmap.c is_mergeable_anon_vma:
((!a1 || !a2) && (!vma || list_is_singular(&vma->anon_vma_chain)))
   → 1
return a1 == a2;
```

prev 段从来没写过，`anon_vma_chain` 是空 list。`list_is_singular(empty)`
返回 **FALSE**（实现是 `!list_empty && head->next == head->prev`）。
所以拒绝合并 → 段永久撕开。

## 最终方案：整段 mprotect RWX + 按 ELF 原 perm 整段还原

只在 `HAVE_ANDROID` 启用，对 file-backed `PT_LOAD+PF_X` 段：

```c
1. dl_iterate_phdr 找 page 所在 PT_LOAD+PF_X 段, 同时记录
   ELF p_flags 推算的原始 GumPageProtection (一般 R+X = 0x05)

2. mprotect(整段, RWX)
   - vma 整段同 perm 改, kernel 不 split (vma_merge 不需要触发)
   - 保留 X: 别的线程在该段执行不会因 NX 触发 instruction fetch fault

3. apply 写跳板 (在已经 RW 的页上直接 memcpy)
   - 写入触发 COW 但只创建 1 份 anon_vma, 整段共享, 不撕

4. mprotect(整段, ELF 原 perm)
   - 整段同 perm 改, 仍是 1 个 vma
   - vma 永远没分裂过, 不需要合并什么
```

anon page (gum 自己 trampoline 池) 不在任何 PT_LOAD 段, 走 per-page
mprotect RWX → 写 → 还原 RX. 这些 anon 段在 maps 里本来就独立 (例如
`[anon:xiam-gum]`), 撕不撕都不影响系统库的 `.text` 视图.

## 效果

`/proc/self/maps` libc.so 段:

| 改前 (per-page mprotect) | 改后 (整段 mprotect) |
|---|---|
| 16+ 段 r-x/rwxp 交错 | **4 段 (跟干净进程一致)** |
| 永久 rwxp 4-7 个 | **0** |

`/proc/self/smaps` 唯一可观察的痕迹: `.text` 段的 `Anonymous: N kB`
(N = 写过的 page 数 × 4KB). 正常 .text 段是 0. 大多数风控不扫这个字段.

要彻底连 Anonymous 都为 0, 需要走 `/proc/self/mem` pwrite 或 KPM
wxshadow 路径 (完全不动 PTE, 不创建 anon_vma).

## 关键代码位置

- `subprojects/frida-gum/gum/gummemory.c::gum_memory_patch_code_pages`
  - `#ifdef HAVE_ANDROID` 路径走整段 mprotect
  - `gum_find_text_segment` 用 `dl_iterate_phdr` 找 PT_LOAD+PF_X
  - `GumTextSegment` 缓存 `start/end/orig_prot` 三个字段

## 调试

崩点定位：

```bash
adb shell "su -c 'logcat -d -s xiam:* 2>&1 | grep gum-patch | tail -20'"
```

期望看到的 LOGW (有问题时):

| 日志 | 含义 |
|---|---|
| `mprotect RWX seg FAILED` | 整段 mprotect 失败, 可能 SCTLR.WXN 启用拒 RWX |
| `mprotect RWX anon FAILED` | anon page mprotect 失败, 一般是地址越界 |
| `mprotect restore seg FAILED` | 还原原 perm 失败 |
| `mprotect restore anon FAILED` | anon page 还原失败 |

## 历史踩坑记录

1. **per-page mprotect RW (无 X)** → 别的线程在 .text 内执行时 NX fault SIGSEGV
2. **per-page mprotect RWX 不还原** → 永久 rwxp 段
3. **per-page mprotect RWX → 还原 RX** → 撕段 (vma_merge anon_vma 不一致)
4. **整段 mprotect RW (无 X)** → 别的线程 instruction fetch fault, frida-server 启动崩
5. **整段 mprotect RWX → 整段还原 ELF 原 perm** → ✓ 通过
