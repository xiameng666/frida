# Progress

## 2026-03-14
- **原因**: 为 Frida gum interceptor 新增无痕 hook 能力，配合 KernelPatch wxjump KPM 的 shadow page 机制绕过 CRC 完整性检测
- **修改**:
  - `gum/guminterceptor.h` — 新增 `GUM_ATTACH_FLAGS_STEALTH = (1 << 2)` 标志
  - `gum/guminterceptor-priv.h` — `GumFunctionContext` 新增 `guint8 stealth` 字段
  - `gum/guminterceptor.c` — attach 时传播 stealth flag；`gum_interceptor_transaction_end` 中 stealth hooks 绕过 `gum_memory_patch_code_pages` 直接调用 backend；`gum_apply_updates` 跳过已处理的 stealth hooks
  - `gum/backend-arm64/guminterceptor-arm64.c` — `activate_trampoline` 新增 stealth 路径：构造 LDR+BR 跳转到栈 buffer 后通过 `gum_stealth_patch()` 写入 shadow page；`deactivate_trampoline` 新增 stealth 路径：调用 `gum_stealth_release()`
  - `gum/gumstealth.h` (新增) — stealth API 头文件，定义 prctl 命令码 (PATCH/RELEASE/QUERY) 和 3 个函数声明
  - `gum/gumstealth.c` (新增) — Linux ARM64 通过 `prctl()` 与 wxjump KPM 通信；其他平台 stub 返回 FALSE
  - `gum/meson.build` — 将 gumstealth.h/.c 加入编译列表
- **时间**: 2026-03-14 16:30
