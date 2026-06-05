// feature-scan.js — 极简重写 (脚本不装任何 hook, 不做任何自动操作)
//
// REPL 函数:
//   maps()        过滤 frida/xiam 痕迹的 /proc/self/maps
//   mapsRaw()     全量 /proc/self/maps
//   cmdline()     /proc/self/cmdline
//   linkMap()     遍历 r_debug.r_map, 只打 xiam/memfd/frida 命中行
//   unlinkProbe() 探测断链计划 (dry-run, 默认匹配 'xiam')
//   unlinkDo()    真断链 (单向 forward, 2 个写)

const PROC_SELF = '/proc/self';

// procfs 文件 size=0, File.readBytes() 一次 short-read 就 EOF, 拿不到内容.
// 用 read syscall 循环读到 EOF.
const _open  = new NativeFunction(Module.getGlobalExportByName('open'),  'int',  ['pointer', 'int']);
const _read  = new NativeFunction(Module.getGlobalExportByName('read'),  'long', ['int', 'pointer', 'ulong']);
const _close = new NativeFunction(Module.getGlobalExportByName('close'), 'int',  ['int']);

function _slurp(path) {
    const fd = _open(Memory.allocUtf8String(path), 0);
    if (fd < 0) return '';
    const sz = 8192;
    const buf = Memory.alloc(sz);
    let out = '';
    while (true) {
        const n = _read(fd, buf, sz).valueOf();
        if (n <= 0) break;
        const u8 = new Uint8Array(buf.readByteArray(n));
        let s = '';
        for (let i = 0; i < n; i++) s += String.fromCharCode(u8[i]);
        out += s;
    }
    _close(fd);
    return out;
}

// ── 1) maps ─────────────────────────────────────────────────────────────────
function maps() {
    const txt = _slurp(PROC_SELF + '/maps');
    const re = /(libc\.so|libart\.so|libandroid_runtime\.so|\/linker(64)?\b|xiam|memfd:|frida)/i;
    const lines = txt.split('\n').filter(l => re.test(l));
    console.log('=== /proc/self/maps  filter=[libc|libart|libandroid_runtime|linker|xiam|memfd|frida] ===');
    console.log(lines.join('\n'));
    console.log(`---- ${lines.length} lines (total ${txt.split('\n').length}) ----`);
}

function mapsRaw() {
    console.log(_slurp(PROC_SELF + '/maps'));
}

// ── 2) cmdline ──────────────────────────────────────────────────────────────
function cmdline() {
    const s = _slurp(PROC_SELF + '/cmdline').replace(/\0/g, ' ').trim();
    console.log('cmdline:', s);
}

// ── 3) linkMap: 走 r_debug.r_map, 只打可疑 ──────────────────────────────────
function _findRDebugViaDtDebug() {
    const exe = Process.enumerateModules()[0];
    const phoff   = exe.base.add(0x20).readU64();
    const phentsz = exe.base.add(0x36).readU16();
    const phnum   = exe.base.add(0x38).readU16();
    const phdrs   = exe.base.add(parseInt(phoff.toString()));
    for (let i = 0; i < phnum; i++) {
        const ph = phdrs.add(i * phentsz);
        if (ph.readU32() !== 2) continue;   // PT_DYNAMIC
        const dynVA = ph.add(16).readU64();
        const dyn = exe.base.add(parseInt(dynVA.toString()));
        for (let j = 0; j < 4096; j++) {
            const e = dyn.add(j * 16);
            const tag = parseInt(e.readU64().toString());
            if (tag === 0) return null;
            if (tag === 21) {   // DT_DEBUG
                return e.add(8).readPointer();
            }
        }
        return null;
    }
    return null;
}

// 双向遍历 r_debug.r_map:
//   forward 走 l_next (+0x18), reverse 走 l_prev (+0x20).
//   forward / reverse 差集 = "半摘节点" (单向 forward unlink 漏洞).
function linkMap() {
    const rd = _findRDebugViaDtDebug();
    if (!rd || rd.isNull()) { console.log('r_debug not found'); return null; }
    console.log('r_debug @', rd);

    const fwd = new Set();
    const fwdHits = [];
    let lm = rd.add(8).readPointer();
    let tail = lm;
    let i = 0;
    while (!lm.isNull() && i < 4096) {
        fwd.add(lm.toString());
        let n = '';
        try { n = lm.add(8).readPointer().readCString() || ''; } catch (_) {}
        if (/xiam|memfd:|frida/i.test(n)) fwdHits.push(`fwd[${i}] ${lm} "${n}"`);
        tail = lm;
        lm = lm.add(0x18).readPointer();
        i++;
    }

    const revHits = [];
    const hidden = [];
    let cur = tail;
    let j = 0;
    while (!cur.isNull() && j < 4096) {
        let n = '';
        try { n = cur.add(8).readPointer().readCString() || ''; } catch (_) {}
        if (!fwd.has(cur.toString())) {
            const t = /xiam|memfd:|frida/i.test(n) ? '!! ' : '   ';
            hidden.push(`${t}rev[${j}] ${cur} "${n}"`);
        }
        if (/xiam|memfd:|frida/i.test(n)) revHits.push(`rev[${j}] ${cur} "${n}"`);
        cur = cur.add(0x20).readPointer();
        j++;
    }

    console.log(`forward: ${i} 节点, xiam/frida 命中 ${fwdHits.length}`);
    fwdHits.forEach(s => console.log('  ' + s));
    console.log(`reverse: ${j} 节点, xiam/frida 命中 ${revHits.length}`);
    revHits.forEach(s => console.log('  ' + s));
    if (hidden.length) {
        console.log(`!! 半摘 ${hidden.length} 个 (forward 看不到 / reverse 还在) — 单向 unlink 漏洞:`);
        hidden.forEach(s => console.log('   ' + s));
    } else if (fwdHits.length === 0 && revHits.length === 0) {
        console.log(`✓ forward / reverse 都无 xiam/frida — r_map 视角干净`);
    } else {
        console.log(`  forward / reverse 集合一致 (无半摘), 但仍命中 xiam — 未 removeSoList`);
    }
    return { fwd: i, rev: j, hidden: hidden.length, hits: fwdHits.length };
}

// ── 4) unlinkProbe / unlinkDo ───────────────────────────────────────────────
//   AOSP arm64 标准偏移: soinfo.next=0x28, soinfo.link_map_head=0xd0
//   单向摘: prev_so.next = self.next  +  prev_so.l_next = next_so + 0xd0
function _solistHead() {
    const linker = Process.getModuleByName('linker64') || Process.getModuleByName('linker');
    const sym = linker.enumerateSymbols().find(s => s.name.indexOf('_ZL6solist') !== -1);
    if (!sym) throw new Error('linker .symtab 没有 __dl__ZL6solist');
    return sym.address.readPointer();
}

// 走 solist 单链表 (bionic 私有, dl_iterate_phdr 走的就是这条)
//   每个 soinfo: l_name 在 +0xd0+8 (link_map_head.l_name)
//   只打 xiam/memfd/frida 命中
function soList() {
    let head;
    try { head = _solistHead(); }
    catch (e) { console.log('soList: ' + e.message); return 0; }
    let cur = head;
    let idx = 0, hits = 0;
    while (!cur.isNull() && idx < 4096) {
        let name = '';
        try { name = cur.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
        if (/xiam|memfd:|frida/i.test(name)) {
            console.log(`!! [${idx}] so=${cur} l_addr=${cur.add(0xd0).readPointer()}  "${name}"`);
            hits++;
        }
        cur = cur.add(0x28).readPointer();
        idx++;
    }
    console.log(`---- 总 ${idx}, 命中 ${hits} ----`);
    return hits;
}

function _walkSolist(filterRe) {
    const head = _solistHead();
    let prev = head, cur = head.add(0x28).readPointer(), idx = 1;
    while (!cur.isNull() && idx < 4096) {
        let name = '';
        try { name = cur.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
        if (filterRe.test(name)) {
            return { prev, self: cur, next: cur.add(0x28).readPointer(), name, idx };
        }
        prev = cur;
        cur = cur.add(0x28).readPointer();
        idx++;
    }
    return null;
}

// removeSoList: 把 soName 匹配的 soinfo 从所有 SO 索引摘掉:
//   W1: solist:    prev.next   = self.next
//   W2: r_map fwd: prev.l_next = next_lm       (link_map.l_next)
//   W3: r_map rev: next.l_prev = prev_lm       (link_map.l_prev, self 是 tail 时跳过)
//   W4: ns:        prev_entry.next = next_entry  /  或 head_ = next_entry (self 是 head 时)
//   W5: ns:        tail_ = prev_entry            (self 是 tail 时)
function removeSoList(soName) {
    soName = soName || 'xiam';
    const r = _walkSolist(new RegExp(soName, 'i'));
    if (!r) { console.log(`"${soName}" 不在 solist 上`); return false; }

    const writes = [
        { a: r.prev.add(0x28), v: r.next,                                            desc: 'solist:    prev.next   = self.next' },
        { a: r.prev.add(0xe8), v: r.next.isNull() ? ptr(0) : r.next.add(0xd0),       desc: 'r_map fwd: prev.l_next = next_lm' },
    ];
    if (!r.next.isNull()) {
        writes.push({ a: r.next.add(0xf0), v: r.prev.add(0xd0), desc: 'r_map rev: next.l_prev = prev_lm' });
    }

    const nsR = _walkNsListForName(soName);
    if (nsR) {
        // W4: head_ 或 prev_entry.next
        if (nsR.isHead) {
            writes.push({ a: nsR.headAddr, v: nsR.next_entry,
                          desc: 'ns:        head_       = entry.next' });
        } else {
            writes.push({ a: nsR.prev_entry, v: nsR.next_entry,
                          desc: 'ns:        prev.next   = entry.next' });
        }
        // W5: tail_ 修正 (self 是 tail; isHead+isTail = 单节点, prev_entry = 0)
        if (nsR.isTail) {
            writes.push({ a: nsR.tailAddr, v: nsR.prev_entry,
                          desc: 'ns:        tail_       = prev_entry' });
        }
    } else {
        console.log(`(ns: "${soName}" 不在 g_default_namespace.soinfo_list_, 跳过 W4/W5)`);
    }

    console.log(`HIT idx=${r.idx} "${r.name}"`);
    console.log(`  prev=${r.prev}  self=${r.self}  next=${r.next}`);
    if (nsR) {
        console.log(`  ns: nsIdx=${nsR.idx} prev_entry=${nsR.prev_entry} self_entry=${nsR.self_entry} next_entry=${nsR.next_entry}  (isHead=${nsR.isHead} isTail=${nsR.isTail})`);
    }

    for (let i = 0; i < writes.length; i++) {
        const w = writes[i];
        const range = Process.findRangeByAddress(w.a);
        const orig  = range ? range.protection : null;
        const need  = orig && orig.indexOf('w') < 0;
        try {
            if (need) Memory.protect(range.base, range.size, 'rw-');
            w.a.writePointer(w.v);
            if (need) Memory.protect(range.base, range.size, orig);
            console.log(`  ✓ 写[${i+1}] *(${w.a}) = ${w.v}    (${w.desc})`);
        } catch (e) {
            console.log(`  ✗ 写[${i+1}] *(${w.a}) fail: ${e.message}`);
            return false;
        }
    }
    console.log(`done. 跑 linkMap() / defaultNamespace() / detect() 验证`);
    return true;
}

// ── 5) threads: 列所有线程, 高亮 frida/gum 风控关键字 ──────────────────────
function threads() {
    // /proc/self/task 下每个目录就是一个 tid
    const taskDir = PROC_SELF + '/task';
    const opendir = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
    const readdir = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
    const closedir = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);
    const dir = opendir(Memory.allocUtf8String(taskDir));
    if (dir.isNull()) { console.log('opendir failed'); return; }
    const tids = [];
    let ent;
    while (!(ent = readdir(dir)).isNull()) {
        const name = ent.add(19).readCString();   // dirent.d_name @ +19 on bionic arm64
        if (/^\d+$/.test(name)) tids.push(name);
    }
    closedir(dir);

    console.log(`=== /proc/self/task  ${tids.length} threads ===`);
    let hits = 0;
    for (const tid of tids) {
        let comm = '';
        try { comm = _slurp(`${taskDir}/${tid}/comm`).trim(); } catch (_) {}
        const susp = /frida|gum|gmain|gdbus|pool-spawner|gjs-loop/i.test(comm);
        if (susp) { console.log(`!! ${tid.padEnd(7)} ${comm}`); hits++; }
    }
    console.log(`---- 命中 ${hits}/${tids.length} ----`);
}

// ── 6) status: /proc/self/status 摘要 (TracerPid / Name / Uid) ─────────────
function status() {
    const txt = _slurp(PROC_SELF + '/status');
    const want = /^(Name|Tgid|Pid|PPid|TracerPid|Uid|Gid|Threads):/;
    const lines = txt.split('\n').filter(l => want.test(l));
    console.log('=== /proc/self/status (摘要) ===');
    console.log(lines.join('\n'));
}

// ── 7) fds: 列 /proc/self/fd, 高亮可疑 ─────────────────────────────────────
function fds() {
    const opendir = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
    const readdir = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
    const closedir = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);
    const readlink = new NativeFunction(Module.getGlobalExportByName('readlink'), 'long',
        ['pointer', 'pointer', 'ulong']);

    const dir = opendir(Memory.allocUtf8String(PROC_SELF + '/fd'));
    if (dir.isNull()) { console.log('opendir failed'); return; }
    const buf = Memory.alloc(512);
    const entries = [];
    let ent;
    while (!(ent = readdir(dir)).isNull()) {
        const name = ent.add(19).readCString();
        if (!/^\d+$/.test(name)) continue;
        const path = PROC_SELF + '/fd/' + name;
        const n = readlink(Memory.allocUtf8String(path), buf, 511);
        let target = '';
        if (n > 0) target = buf.readUtf8String(n.toNumber());
        entries.push({fd: name, target});
    }
    closedir(dir);

    console.log(`=== /proc/self/fd  ${entries.length} fds ===`);
    let hits = 0;
    const re = /memfd:|frida|xiam|re\.frida|linjector|gadget|socket:/i;
    for (const e of entries) {
        if (re.test(e.target)) { console.log(`!! ${e.fd.padEnd(4)} -> ${e.target}`); hits++; }
    }
    console.log(`---- 可疑 ${hits}/${entries.length} ----`);
}

// ── 8) ports: /proc/net/tcp 看本地监听端口 (找 27042 / 14725 等 frida 默认) ─
function ports() {
    const txt = _slurp('/proc/net/tcp');
    const lines = txt.split('\n');
    console.log('=== /proc/net/tcp  本地监听 (state=0A) ===');
    let n = 0;
    for (const line of lines) {
        const m = line.match(/^\s*\d+:\s+([0-9A-F]{8}):([0-9A-F]{4})\s+([0-9A-F]{8}):([0-9A-F]{4})\s+(\w\w)/);
        if (!m) continue;
        if (m[5] !== '0A') continue;   // 0A = LISTEN
        const port = parseInt(m[2], 16);
        const susp = (port === 27042 || port === 27043 || port === 14725 || port === 14735);
        const flag = susp ? '!!' : '  ';
        console.log(`${flag} 0.0.0.0:${port}`);
        if (susp) n++;
    }
    console.log(`---- 命中 frida 默认端口: ${n} ----`);
}

// ── 9) rtldHook: 对比 rtld_db_dlactivity 内存字节 vs linker64 文件字节 ──
//
//   frida-gum 内部装在 linker 的 r_brk (= rtld_db_dlactivity) 上, 监听
//   dlopen/dlclose. 风控扫这条:
//     mem  = readMem(rtld_db_dlactivity, N)
//     file = readFile('/apex/.../linker64', file_offset, N)
//     if mem != file: 被 hook
//
//   frida17_shadow PTE 切 alt 让 mem read 看到干净字节, 这里能验证.
const _lseek = new NativeFunction(Module.getGlobalExportByName('lseek'), 'long', ['int', 'long', 'int']);

function rtldHook() {
    const linker = Process.getModuleByName('linker64') || Process.getModuleByName('linker');
    if (!linker) { console.log('linker module not found'); return null; }

    // 1) 找 rtld_db_dlactivity 内存地址 (优先 .symtab, 兜底 _r_debug.r_brk)
    let addr = null;
    for (const s of linker.enumerateSymbols()) {
        if (/rtld_db_dlactivity/.test(s.name)) { addr = s.address; break; }
    }
    if (!addr) {
        const rd = _findRDebugViaDtDebug();
        if (rd && !rd.isNull()) addr = rd.add(16).readPointer();   // r_brk @ +0x10
    }
    if (!addr || addr.isNull()) { console.log('rtld_db_dlactivity not resolved'); return null; }

    // 2) vaddr → file offset (走 ELF phdr)
    const vaddr   = parseInt(addr.sub(linker.base).toString());
    const phoff   = parseInt(linker.base.add(0x20).readU64().toString());
    const phentsz = linker.base.add(0x36).readU16();
    const phnum   = linker.base.add(0x38).readU16();
    let fileOff = -1;
    for (let i = 0; i < phnum; i++) {
        const ph = linker.base.add(phoff + i * phentsz);
        if (ph.readU32() !== 1) continue;   // PT_LOAD
        const pOff   = parseInt(ph.add(0x08).readU64().toString());
        const pVaddr = parseInt(ph.add(0x10).readU64().toString());
        const pFsz   = parseInt(ph.add(0x20).readU64().toString());
        if (vaddr >= pVaddr && vaddr < pVaddr + pFsz) {
            fileOff = (vaddr - pVaddr) + pOff;
            break;
        }
    }
    if (fileOff < 0) { console.log('vaddr → file offset 翻译失败'); return null; }

    // 3) 读内存
    const N = 32;
    const memBytes = new Uint8Array(addr.readByteArray(N));

    // 4) 读文件
    const fd = _open(Memory.allocUtf8String(linker.path), 0);
    if (fd < 0) { console.log('open ' + linker.path + ' 失败'); return null; }
    _lseek(fd, fileOff, 0);
    const fbuf = Memory.alloc(N);
    const n = _read(fd, fbuf, N).valueOf();
    _close(fd);
    if (n < N) { console.log(`只读到 ${n} 字节`); return null; }
    const fileBytes = new Uint8Array(fbuf.readByteArray(N));

    // 5) 对比
    const diff = [];
    for (let i = 0; i < N; i++) if (memBytes[i] !== fileBytes[i]) diff.push(i);
    const hex = a => Array.from(a).map(b => b.toString(16).padStart(2,'0')).join(' ');

    console.log(`rtld_db_dlactivity:`);
    console.log(`  ${linker.name} base=${linker.base} path=${linker.path}`);
    console.log(`  func @ ${addr}  (linker+0x${vaddr.toString(16)}, file off=0x${fileOff.toString(16)})`);
    console.log(`  file: ${hex(fileBytes)}`);
    console.log(`  mem : ${hex(memBytes)}`);
    if (diff.length === 0) {
        console.log(`  ✓ identical — 没有 hook (或 PTE shadow 让读拿到干净字节)`);
    } else {
        console.log(`  ★ ${diff.length} bytes differ at +[${diff.join(',')}]`);
        console.log(`  ★ rtld_db_dlactivity 被改写 (frida 蹦床或别的 inline hook)`);
    }
    return { addr, fileOff, mem: memBytes, file: fileBytes, diff: diff.length };
}

// ── 10) ldPreloads: 列 __dl__ZL13g_ld_preloads (LD_PRELOAD 注入清单) ─────────
//
//   bionic 私有: static soinfo_list_t g_ld_preloads;
//     soinfo_list_t = LinkedList<soinfo>: { head_ @+0, tail_ @+8 }
//     每个节点 LinkedListEntry: { next @+0, element @+8 (soinfo*) }
//
//   含义: 进程启动期 linker 从 env LD_PRELOAD 解析出来的 SO 列表.
//   - 正常 app 通常为空.
//   - frida-server 通过 ptrace + 远端 dlopen 装 agent, 不走 LD_PRELOAD → 这里看不见.
//   - frida-gadget 用 LD_PRELOAD 注入时 → 这里直接暴露.
//   风控检测点: 列表非空 + 含非系统 SO 名 ≈ 强信号.
function ldPreloads() {
    const linker = Process.getModuleByName('linker64') || Process.getModuleByName('linker');
    if (!linker) { console.log('linker module not found'); return null; }
    const sym = linker.enumerateSymbols().find(s => s.name.indexOf('_ZL13g_ld_preloads') !== -1);
    if (!sym) { console.log('linker .symtab 没有 __dl__ZL13g_ld_preloads'); return null; }

    const addr = sym.address;
    const head = addr.readPointer();          // head_ @ +0
    const tail = addr.add(8).readPointer();   // tail_ @ +8

    console.log(`=== g_ld_preloads @ ${addr}  head=${head}  tail=${tail} ===`);

    if (head.isNull()) {
        console.log('---- 空 (LD_PRELOAD 没注入任何 SO) ----');
        return 0;
    }

    let cur = head;
    let idx = 0, hits = 0;
    while (!cur.isNull() && idx < 256) {
        const next = cur.readPointer();           // LinkedListEntry.next     @ +0
        const so   = cur.add(8).readPointer();    // LinkedListEntry.element  @ +8 (soinfo*)
        let name = '<null>';
        if (!so.isNull()) {
            try { name = so.add(0xd0 + 8).readPointer().readCString() || '<empty>'; } catch (_) {}
        }
        const susp = /xiam|memfd:|frida|gadget/i.test(name);
        const tag  = susp ? '!!' : '  ';
        if (susp) hits++;
        console.log(`${tag} [${idx}] entry=${cur} so=${so}  "${name}"`);
        cur = next;
        idx++;
    }
    console.log(`---- 总 ${idx}, 命中 ${hits} ----`);
    return idx;
}

// ── 11) dlopenNoLoad: 验证 namespace.soinfo_list_ 没被摘 ──────────────────────
//
//   bionic dlopen(path, RTLD_NOLOAD): 只查当前 namespace 的 soinfo_list_,
//     - 已加载 → 返回非空 handle (不实际 load)
//     - 未加载 → 返回 NULL
//
//   即使 global solist + r_map 全摘, namespace 没摘 → 这里仍能查到.
//   不传 soPath 则从 maps 里自动找含 xiam/frida 的 .so 路径.
function dlopenNoLoad(soPath) {
    if (!soPath) {
        const txt = _slurp(PROC_SELF + '/maps');
        const m = txt.match(/\s(\/\S*xiam\S*\.so)\b/i) || txt.match(/\s(\/\S*frida\S*\.so)\b/i);
        if (!m) { console.log('maps 里未自动定位 xiam/frida agent SO, 显式传 soPath'); return null; }
        soPath = m[1];
        console.log(`(自动选 path: ${soPath})`);
    }

    const _dlopen  = new NativeFunction(Module.getGlobalExportByName('dlopen'),  'pointer', ['pointer', 'int']);
    const _dlerror = new NativeFunction(Module.getGlobalExportByName('dlerror'), 'pointer', []);

    _dlerror();
    const RTLD_NOLOAD = 4;
    const h = _dlopen(Memory.allocUtf8String(soPath), RTLD_NOLOAD);

    if (!h.isNull()) {
        console.log(`!! dlopen("${soPath}", RTLD_NOLOAD) = ${h}`);
        console.log(`   ★ namespace 仍能查到 → 摘链没碰 namespace.soinfo_list_`);
    } else {
        const ep = _dlerror();
        const err = ep.isNull() ? '<no error>' : ep.readCString();
        console.log(`✓ dlopen NULL  (err: ${err})  当前 namespace 看不到`);
    }
    return h;
}

// ── 13) dlIterPhdr: 公开 API 视角 (风控最爱直接用这条 enumerate) ─────────────
//
//   dl_iterate_phdr 是 linker 暴露的公开枚举 API. bionic 内部走 global solist,
//   等价于 soList() 但走公开 API.
//   作用: 验证 "私有 solist 摘了 → 公开 API 是否同步看不到".
//   若两者结果不一致, 说明 linker 内还有别的 SO 索引漏掉了.
function dlIterPhdr() {
    const _iter = new NativeFunction(
        Module.getGlobalExportByName('dl_iterate_phdr'),
        'int', ['pointer', 'pointer']);

    const list = [];
    const cb = new NativeCallback(function (info, _sz, _data) {
        let n = '';
        try { n = info.add(8).readPointer().readCString() || ''; } catch (_) {}
        list.push({ addr: info.readPointer(), name: n });
        return 0;
    }, 'int', ['pointer', 'ulong', 'pointer']);

    _iter(cb, ptr(0));

    console.log(`=== dl_iterate_phdr ===  ${list.length} entries (公开 API 视角)`);
    let hits = 0;
    for (const e of list) {
        if (/xiam|memfd:|frida|gadget/i.test(e.name)) {
            console.log(`!! ${e.addr}  "${e.name}"`);
            hits++;
        }
    }
    console.log(`---- xiam/frida 命中 ${hits} / 总 ${list.length} ----`);
    return { total: list.length, hits };
}

// ── 14) defaultNamespace: 反推 default namespace.soinfo_list_ ────────────────
//
//   目的: 验证 global solist + r_map 摘了之后, namespace.soinfo_list_ 是否也摘了.
//
//   两路:
//   (a) 直接符号 __dl__ZL19g_default_namespace (旧 bionic 版本有).
//   (b) 该 linker 没暴露这个符号 → 从 somain.primary_namespace_ 反推
//       (main exe 一定在 default namespace, 其 primary_namespace_ = default ns).
//
//   再用 anchor (linker/libc 一定在 ns) brute-scan namespace_t 找 soinfo_list_ 偏移
//   (LinkedList<soinfo>: { head_ @+0, tail_ @+8 }, LinkedListEntry: { next, soinfo* }).
function _findAnchorSoinfo() {
    try {
        let cur = _solistHead();
        let idx = 0;
        while (!cur.isNull() && idx < 4096) {
            let n = '';
            try { n = cur.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
            if (/^linker(64)?$/.test(n) || /\/libc\.so$/.test(n) || /^libc\.so$/.test(n)) {
                return { so: cur, name: n };
            }
            cur = cur.add(0x28).readPointer();
            idx++;
        }
    } catch (_) {}
    return null;
}

function _walkSoListFor(head, anchorSo) {
    let entry = head, safe = 8192;
    try {
        while (!entry.isNull() && safe-- > 0) {
            const next = entry.readPointer();
            const elem = entry.add(8).readPointer();
            if (elem.equals(anchorSo)) return true;
            if (next.equals(entry)) break;
            entry = next;
        }
    } catch (_) {}
    return false;
}

// 定位 g_default_namespace 地址 + soinfo_list_ 偏移
// 返回 { nsAddr, soOff, anchor, source }  source ∈ {'symbol', 'somain'}
function _findNsSoinfoList() {
    const linker = Process.getModuleByName('linker64') || Process.getModuleByName('linker');
    if (!linker) return null;
    const anchor = _findAnchorSoinfo();
    if (!anchor) return null;

    // (a) 直接符号
    const direct = linker.enumerateSymbols().find(s =>
        /(?:^__dl_g_default_namespace$|_ZL\d+g_default_namespace$)/.test(s.name));
    if (direct) {
        const nsAddr = direct.address;
        for (let off = 0; off < 0x400; off += 8) {
            let head;
            try { head = nsAddr.add(off).readPointer(); } catch (_) { continue; }
            if (head.isNull()) continue;
            if (_walkSoListFor(head, anchor.so)) {
                return { nsAddr, soOff: off, anchor, source: 'symbol', pnsOff: -1 };
            }
        }
    }

    // (b) Fallback: somain.primary_namespace_ 反推
    const somainSym = linker.enumerateSymbols().find(s => /_ZL6somain$/.test(s.name));
    if (!somainSym) return null;
    const somain = somainSym.address.readPointer();
    for (let pOff = 0xf8; pOff < 0x800; pOff += 8) {
        let P;
        try { P = somain.add(pOff).readPointer(); } catch (_) { continue; }
        if (P.isNull() || P.compare(ptr('0x1000')) < 0) continue;
        try { P.readU64(); } catch (_) { continue; }
        for (let off = 0; off < 0x200; off += 8) {
            let head;
            try { head = P.add(off).readPointer(); } catch (_) { continue; }
            if (head.isNull()) continue;
            if (_walkSoListFor(head, anchor.so)) {
                return { nsAddr: P, soOff: off, anchor, source: 'somain', pnsOff: pOff };
            }
        }
    }
    return null;
}

// 走 ns.soinfo_list_, 找匹配 soName 的 entry, 记 prev/self/next.
// 返回 { nsAddr, soOff, headAddr, tailAddr, head, tail, prev_entry, self_entry, next_entry,
//        isHead, isTail, name, idx } 或 null
function _walkNsListForName(soName) {
    const r = _findNsSoinfoList();
    if (!r) return null;
    const { nsAddr, soOff } = r;
    const headAddr = nsAddr.add(soOff);
    const tailAddr = nsAddr.add(soOff + 8);
    const head = headAddr.readPointer();
    const tail = tailAddr.readPointer();

    const re = new RegExp(soName, 'i');
    let prev_entry = ptr(0);
    let cur = head;
    let idx = 0;
    while (!cur.isNull() && idx < 4096) {
        const next_entry = cur.readPointer();
        const so = cur.add(8).readPointer();
        let n = '';
        if (!so.isNull()) {
            try { n = so.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
        }
        if (re.test(n)) {
            return {
                nsAddr, soOff, headAddr, tailAddr, head, tail,
                prev_entry, self_entry: cur, next_entry,
                isHead: cur.equals(head),
                isTail: cur.equals(tail),
                name: n, idx,
            };
        }
        prev_entry = cur;
        if (next_entry.equals(cur)) break;
        cur = next_entry;
        idx++;
    }
    return null;
}

function defaultNamespace() {
    const r = _findNsSoinfoList();
    if (!r) { console.log('定位 g_default_namespace.soinfo_list_ 失败'); return null; }
    const { nsAddr, soOff, anchor, source, pnsOff } = r;
    console.log(`anchor: "${anchor.name}" @ ${anchor.so}`);
    console.log(source === 'symbol'
        ? `g_default_namespace (符号) @ ${nsAddr}`
        : `g_default_namespace (somain +0x${pnsOff.toString(16)} 反推) @ ${nsAddr}`);

    const head = nsAddr.add(soOff).readPointer();
    const tail = nsAddr.add(soOff + 8).readPointer();
    console.log(`soinfo_list_ @ ns +0x${soOff.toString(16)}  head=${head}  tail=${tail}`);

    let entry = head, total = 0, hits = 0;
    const hitList = [];
    while (!entry.isNull() && total < 4096) {
        const next = entry.readPointer();
        const so   = entry.add(8).readPointer();
        let name = '';
        if (!so.isNull()) {
            try { name = so.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
        }
        if (/xiam|memfd:|frida|gadget/i.test(name)) {
            hitList.push(`[${total}] entry=${entry} so=${so}  "${name}"`);
            hits++;
        }
        if (next.equals(entry)) break;
        entry = next;
        total++;
    }
    console.log(`=== namespace 视角 ===  ${total} SOs`);
    if (hits) {
        console.log(`!! xiam/frida 命中 ${hits}:`);
        hitList.forEach(s => console.log('   ' + s));
        console.log(`   xiam 仍在 g_default_namespace.soinfo_list_ — 用 removeSoList 一并摘掉`);
    } else {
        console.log(`✓ xiam/frida 命中 0  (namespace 视角干净)`);
    }
    return { ns: nsAddr, soOff, total, hits };
}

// ── 15) detect: 综合 frida 反检测全套, 打印每个命中的具体内容 ───────────────
function detect() {
    const SUSP = /xiam|memfd:|frida|gadget|linjector/i;
    const TPATT = /frida|gum|gmain|gdbus|pool-spawner|gjs-loop/i;
    const FDPATT = /memfd:|frida|xiam|re\.frida|linjector|gadget/i;
    const FRIDA_PORTS = [27042, 27043, 14725, 14735];

    const hits = { maps: [], threads: [], fds: [], linkMap: [], soList: [], ns: [], ports: [], rtld: [] };
    let mapsTotal = 0, threadsTotal = 0, fdsTotal = 0, lmTotal = 0, soTotal = 0, nsTotal = 0;

    // ── 1) maps ──
    try {
        const t = _slurp(PROC_SELF + '/maps');
        const lines = t.split('\n');
        mapsTotal = lines.length;
        for (const l of lines) if (SUSP.test(l)) hits.maps.push(l);
    } catch (_) {}

    // ── 2) threads ──
    try {
        const opendir = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
        const readdir = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
        const closedir = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);
        const dir = opendir(Memory.allocUtf8String(PROC_SELF + '/task'));
        let ent;
        while (!(ent = readdir(dir)).isNull()) {
            const tid = ent.add(19).readCString();
            if (!/^\d+$/.test(tid)) continue;
            threadsTotal++;
            let c = '';
            try { c = _slurp(`${PROC_SELF}/task/${tid}/comm`).trim(); } catch (_) {}
            if (TPATT.test(c)) hits.threads.push(`${tid.padEnd(7)} ${c}`);
        }
        closedir(dir);
    } catch (_) {}

    // ── 3) fds ──
    try {
        const opendir = new NativeFunction(Module.getGlobalExportByName('opendir'), 'pointer', ['pointer']);
        const readdir = new NativeFunction(Module.getGlobalExportByName('readdir'), 'pointer', ['pointer']);
        const closedir = new NativeFunction(Module.getGlobalExportByName('closedir'), 'int', ['pointer']);
        const readlink = new NativeFunction(Module.getGlobalExportByName('readlink'), 'long', ['pointer', 'pointer', 'ulong']);
        const dir = opendir(Memory.allocUtf8String(PROC_SELF + '/fd'));
        const buf = Memory.alloc(512);
        let ent;
        while (!(ent = readdir(dir)).isNull()) {
            const fd = ent.add(19).readCString();
            if (!/^\d+$/.test(fd)) continue;
            fdsTotal++;
            const n = readlink(Memory.allocUtf8String(PROC_SELF + '/fd/' + fd), buf, 511);
            if (n > 0) {
                const target = buf.readUtf8String(n.toNumber());
                if (FDPATT.test(target)) hits.fds.push(`${fd.padEnd(4)} -> ${target}`);
            }
        }
        closedir(dir);
    } catch (_) {}

    // ── 4) link_map ──
    try {
        const rd = _findRDebugViaDtDebug();
        if (rd && !rd.isNull()) {
            let lm = rd.add(8).readPointer();
            let i = 0;
            while (!lm.isNull() && i < 1024) {
                lmTotal++;
                let n = '';
                try { n = lm.add(8).readPointer().readCString() || ''; } catch (_) {}
                if (/xiam|memfd:|frida/i.test(n)) hits.linkMap.push(`[${i}] ${lm}  "${n}"`);
                lm = lm.add(24).readPointer();
                i++;
            }
        }
    } catch (_) {}

    // ── 5) solist ──
    try {
        let cur = _solistHead();
        let i = 0;
        while (!cur.isNull() && i < 4096) {
            soTotal++;
            let n = '';
            try { n = cur.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
            if (/xiam|memfd:|frida/i.test(n)) hits.soList.push(`[${i}] ${cur}  "${n}"`);
            cur = cur.add(0x28).readPointer();
            i++;
        }
    } catch (_) {}

    // ── 5b) g_default_namespace.soinfo_list_ ──
    try {
        const linker = Process.getModuleByName('linker64') || Process.getModuleByName('linker');
        const anchor = _findAnchorSoinfo();
        if (linker && anchor) {
            let nsAddr = null, soListOff = -1;
            const direct = linker.enumerateSymbols().find(s =>
                /(?:^__dl_g_default_namespace$|_ZL\d+g_default_namespace$)/.test(s.name));
            if (direct) {
                nsAddr = direct.address;
                for (let off = 0; off < 0x400; off += 8) {
                    let head;
                    try { head = nsAddr.add(off).readPointer(); } catch (_) { continue; }
                    if (head.isNull()) continue;
                    if (_walkSoListFor(head, anchor.so)) { soListOff = off; break; }
                }
            }
            if (nsAddr && soListOff >= 0) {
                let entry = nsAddr.add(soListOff).readPointer();
                let i = 0;
                while (!entry.isNull() && i < 4096) {
                    nsTotal++;
                    const next = entry.readPointer();
                    const so   = entry.add(8).readPointer();
                    let n = '';
                    if (!so.isNull()) {
                        try { n = so.add(0xd0 + 8).readPointer().readCString() || ''; } catch (_) {}
                    }
                    if (/xiam|memfd:|frida/i.test(n)) hits.ns.push(`[${i}] entry=${entry} so=${so}  "${n}"`);
                    if (next.equals(entry)) break;
                    entry = next;
                    i++;
                }
            }
        }
    } catch (_) {}

    // ── rtld_db_dlactivity 字节对比 ──
    try {
        const linker = Process.getModuleByName('linker64') || Process.getModuleByName('linker');
        if (linker) {
            let addr = null;
            for (const s of linker.enumerateSymbols())
                if (/rtld_db_dlactivity/.test(s.name)) { addr = s.address; break; }
            if (!addr) {
                const rd = _findRDebugViaDtDebug();
                if (rd && !rd.isNull()) addr = rd.add(16).readPointer();
            }
            if (addr && !addr.isNull()) {
                const vaddr   = parseInt(addr.sub(linker.base).toString());
                const phoff   = parseInt(linker.base.add(0x20).readU64().toString());
                const phentsz = linker.base.add(0x36).readU16();
                const phnum   = linker.base.add(0x38).readU16();
                let fileOff = -1;
                for (let i = 0; i < phnum; i++) {
                    const ph = linker.base.add(phoff + i * phentsz);
                    if (ph.readU32() !== 1) continue;
                    const pOff   = parseInt(ph.add(0x08).readU64().toString());
                    const pVaddr = parseInt(ph.add(0x10).readU64().toString());
                    const pFsz   = parseInt(ph.add(0x20).readU64().toString());
                    if (vaddr >= pVaddr && vaddr < pVaddr + pFsz) {
                        fileOff = (vaddr - pVaddr) + pOff; break;
                    }
                }
                if (fileOff >= 0) {
                    const N = 32;
                    const mem = new Uint8Array(addr.readByteArray(N));
                    const fd = _open(Memory.allocUtf8String(linker.path), 0);
                    if (fd >= 0) {
                        _lseek(fd, fileOff, 0);
                        const fbuf = Memory.alloc(N);
                        const n = _read(fd, fbuf, N).valueOf();
                        _close(fd);
                        if (n === N) {
                            const file = new Uint8Array(fbuf.readByteArray(N));
                            let diff = 0;
                            for (let i = 0; i < N; i++) if (mem[i] !== file[i]) diff++;
                            if (diff > 0) hits.rtld.push(`${addr} differs at ${diff}/${N} bytes`);
                        }
                    }
                }
            }
        }
    } catch (_) {}

    // ── 6) ports ──
    try {
        const t = _slurp('/proc/net/tcp');
        for (const line of t.split('\n')) {
            const m = line.match(/^\s*\d+:\s+[0-9A-F]+:([0-9A-F]{4})\s+\S+\s+(\w\w)/);
            if (m && m[2] === '0A') {
                const p = parseInt(m[1], 16);
                if (FRIDA_PORTS.indexOf(p) >= 0) hits.ports.push(`0.0.0.0:${p}`);
            }
        }
    } catch (_) {}

    // ── 打印 ──
    const total = hits.maps.length + hits.threads.length + hits.fds.length
                + hits.linkMap.length + hits.soList.length + hits.ns.length
                + hits.ports.length + hits.rtld.length;

    function section(label, list, totalCount, viewHint) {
        const n = list.length;
        const tag = n ? '★' : '✓';
        const head = `[${label.padEnd(8)}]  ${tag} ${String(n).padStart(3)} hit / ${String(totalCount).padStart(4)} total` +
                     (viewHint ? `   (${viewHint})` : '');
        console.log(head);
        for (const item of list) console.log('             ' + item);
    }

    console.log('');
    console.log('════════════════════════════════════════════════════════════════════');
    console.log('  detect — frida 痕迹扫描');
    console.log('════════════════════════════════════════════════════════════════════');
    section('maps',     hits.maps,    mapsTotal,    '/proc/self/maps');
    section('threads',  hits.threads, threadsTotal, '/proc/self/task/*/comm');
    section('fds',      hits.fds,     fdsTotal,     '/proc/self/fd/*');
    section('link_map', hits.linkMap, lmTotal,      'r_debug.r_map');
    section('solist',   hits.soList,  soTotal,      'dl_iterate_phdr');
    section('namespace',hits.ns,      nsTotal,      'g_default_namespace.soinfo_list_');
    section('rtld',     hits.rtld,    1,            'rtld_db_dlactivity 内存 vs 文件');
    section('ports',    hits.ports,   FRIDA_PORTS.length, '/proc/net/tcp LISTEN');
    console.log('────────────────────────────────────────────────────────────────────');
    console.log(`  TOTAL: ${total} hits  ${total ? '★ DETECTED' : '✓ CLEAN'}`);
    console.log('════════════════════════════════════════════════════════════════════');
    console.log('');

    return {
        maps: hits.maps.length, threads: hits.threads.length, fds: hits.fds.length,
        linkMap: hits.linkMap.length, soList: hits.soList.length, ns: hits.ns.length,
        rtld: hits.rtld.length, ports: hits.ports.length, total,
    };
}

// ── javaHook: hook 系统类方法, 检查 libart.so VMA 分裂 ──────────────────────
//
//   hook 目标 (均为热路径, 保证方法被 JIT 编译后再 hook 最能触发 ArtQuickCodeInterceptor):
//     java.lang.String.hashCode()
//     java.lang.Object.toString()
//     android.os.SystemClock.elapsedRealtime()
//
//   流程:
//     1) 快照 hook 前 libart.so 的 VMA 段列表
//     2) Java.perform 安装 hook (TextControl 有 5ms 异步 flush)
//     3) 等 50ms 让 flush 完成, 再拍 hook 后快照
//     4) 对比: 段数量 / 新增 rwxp 段 / smaps Anonymous 字节数
//
//   调用方式: javaHook()      → hook 后 50ms 自动打印对比报告
//             javaHook(true)  → 同上, 额外打完整 maps 行

function _libartMapLines() {
    const txt = _slurp(PROC_SELF + '/maps');
    return txt.split('\n').filter(l => /libart\.so/.test(l));
}

function _libartSmapsAnon() {
    // 在 smaps 里读 libart.so 对应段的 Anonymous kB 之和
    const txt = _slurp(PROC_SELF + '/smaps');
    const lines = txt.split('\n');
    let inLibart = false, total = 0;
    for (const l of lines) {
        if (/libart\.so/.test(l)) { inLibart = true; continue; }
        if (inLibart) {
            if (/^[0-9a-f]/.test(l)) { inLibart = /libart\.so/.test(l); continue; }
            const m = l.match(/^Anonymous:\s+(\d+)/);
            if (m) total += parseInt(m[1]);
        }
    }
    return total;
}

function javaHook(verbose) {
    if (!Java.available) { console.log('[javaHook] Java 不可用'); return; }

    // ── 1) 快照 hook 前 ──
    const before = _libartMapLines();
    const anonBefore = _libartSmapsAnon();
    const rwxBefore = before.filter(l => / rwxp /.test(l)).length;

    console.log('');
    console.log('══════════════════════════════════════════════════════');
    console.log('  javaHook — 安装系统类 hook, 验证 libart.so VMA 状态');
    console.log('══════════════════════════════════════════════════════');
    console.log(`[前] libart.so 段数: ${before.length}  rwxp: ${rwxBefore}  smaps Anonymous: ${anonBefore} kB`);
    if (verbose) { before.forEach(l => console.log('  ' + l)); }

    // ── 2) 安装 hook ──
    let hookOk = false;
    let hookErr = null;
    try {
        Java.perform(() => {
            // String.hashCode — 极高频, JIT 必然编译过, 触发 ArtQuickCodeInterceptor
            const String = Java.use('java.lang.String');
            String.hashCode.implementation = function () {
                return this.hashCode();
            };

            // Object.toString — 同上
            const Object = Java.use('java.lang.Object');
            Object.toString.implementation = function () {
                return this.toString();
            };

            // SystemClock.elapsedRealtime — native static, 触发 quickGenericJniTrampoline 路径
            const SystemClock = Java.use('android.os.SystemClock');
            SystemClock.elapsedRealtime.implementation = function () {
                return SystemClock.elapsedRealtime();
            };
        });
        hookOk = true;
    } catch (e) {
        hookErr = e.message || String(e);
    }

    if (!hookOk) {
        console.log(`[javaHook] 安装失败: ${hookErr}`);
        return;
    }
    console.log('[hook] String.hashCode / Object.toString / SystemClock.elapsedRealtime 已安装');
    console.log('[hook] 等待 TextControl 异步 flush (50ms)...');

    // ── 3) 等 flush 完成再对比 ──
    setTimeout(() => {
        const after = _libartMapLines();
        const anonAfter = _libartSmapsAnon();
        const rwxAfter = after.filter(l => / rwxp /.test(l)).length;

        console.log('');
        console.log(`[后] libart.so 段数: ${after.length}  rwxp: ${rwxAfter}  smaps Anonymous: ${anonAfter} kB`);
        if (verbose) { after.forEach(l => console.log('  ' + l)); }

        // ── 4) 对比报告 ──
        console.log('');
        console.log('── 对比 ──────────────────────────────────────────────');
        const segDelta = after.length - before.length;
        const anonDelta = anonAfter - anonBefore;
        const newRwx = after.filter(l => / rwxp /.test(l) && !before.includes(l));

        if (segDelta === 0) {
            console.log(`✓ VMA 段数无变化 (${after.length} 段) — 整段 mprotect 生效，未撕段`);
        } else {
            console.log(`★ VMA 段数: ${before.length} → ${after.length}  (Δ${segDelta > 0 ? '+' : ''}${segDelta}) — 撕段了!`);
            // 找出新增的段
            const newSegs = after.filter(l => !before.includes(l));
            newSegs.forEach(l => console.log('  新增: ' + l));
        }

        if (newRwx.length === 0) {
            console.log(`✓ 无新增 rwxp 段`);
        } else {
            console.log(`★ 新增 rwxp 段 ${newRwx.length} 条:`);
            newRwx.forEach(l => console.log('  ' + l));
        }

        if (anonDelta === 0) {
            console.log(`✓ smaps Anonymous 无变化 (${anonAfter} kB)`);
        } else {
            console.log(`⚠ smaps Anonymous: ${anonBefore} → ${anonAfter} kB  (Δ+${anonDelta} kB) — COW 副本 (预期行为)`);
        }

        console.log('──────────────────────────────────────────────────────');
        const clean = segDelta === 0 && newRwx.length === 0;
        console.log(`  结论: ${clean ? '✓ VMA 层面无痕' : '★ VMA 层面有痕迹'}`);
        console.log('══════════════════════════════════════════════════════');
        console.log('');
    }, 50);
}

// ── 暴露到 REPL ────────────────────────────────────────────────────────────
rpc.exports = { maps, mapsRaw, cmdline, linkMap, soList, ldPreloads,
                dlopenNoLoad, dlIterPhdr, defaultNamespace,
                removeSoList,
                threads, status, fds, ports, rtldHook, detect, javaHook };
Object.assign(globalThis, { maps, mapsRaw, cmdline, linkMap, soList, ldPreloads,
                            dlopenNoLoad, dlIterPhdr, defaultNamespace,
                            removeSoList,
                            threads, status, fds, ports, rtldHook, detect, javaHook });

console.log('[scan] loaded (no hooks installed).');
console.log('  maps()         过滤 frida/xiam 痕迹');
console.log('  mapsRaw()      全量 maps');
console.log('  cmdline()      /proc/self/cmdline');
console.log('  status()       /proc/self/status 摘要');
console.log('  threads()      线程名扫描 (frida/gum/gmain 命中)');
console.log('  fds()          /proc/self/fd 扫描 (memfd/socket/frida 命中)');
console.log('  ports()        本地监听端口扫描 (frida 默认端口)');
console.log('  linkMap()      r_debug.r_map 双向遍历 (forward + reverse, 找半摘节点)');
console.log('  soList()       solist (bionic 私有, dl_iterate_phdr 视角) 命中');
console.log('  ldPreloads()   g_ld_preloads (LD_PRELOAD 注入清单, 正常为空)');
console.log('  dlopenNoLoad() RTLD_NOLOAD 探 → 验证 namespace.soinfo_list_ 是否摘了');
console.log('  dlIterPhdr()   公开 API dl_iterate_phdr (与 soList 对照)');
console.log('  defaultNamespace() 直读 g_default_namespace.soinfo_list_ (namespace 视角)');
console.log('  rtldHook()     ★ 对比 rtld_db_dlactivity 内存字节 vs linker 文件字节');
console.log('  detect()       一把跑完 (maps + threads + linkMap + solist + namespace + rtld + ports)');
console.log('  removeSoList(name="xiam")  摘 solist + r_map(fwd+rev) + ns.soinfo_list_ (4~5 个写)');
console.log('  javaHook()     ★ hook String/Object/SystemClock, 对比 libart.so VMA 前后 (段数/rwxp/Anonymous)');
