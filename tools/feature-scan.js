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

function linkMap() {
    const rd = _findRDebugViaDtDebug();
    if (!rd || rd.isNull()) { console.log('r_debug not found'); return; }
    console.log('r_debug @', rd);
    let lm = rd.add(8).readPointer();   // r_debug.r_map
    let idx = 0, hits = 0;
    while (!lm.isNull() && idx < 1024) {
        let name = '';
        try { name = lm.add(8).readPointer().readCString() || ''; } catch (_) {}
        if (/xiam|memfd:|frida/i.test(name)) {
            const l_addr = lm.readPointer();
            console.log(`!! [${idx}] lm=${lm} l_addr=${l_addr}  "${name}"`);
            hits++;
        }
        lm = lm.add(24).readPointer();
        idx++;
    }
    console.log(`---- 总 ${idx}, 命中 ${hits} ----`);
    return hits;
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

function unlinkProbe(soName) {
    soName = soName || 'xiam';
    const r = _walkSolist(new RegExp(soName, 'i'));
    if (!r) { console.log(`"${soName}" 不在 solist 上`); return null; }
    const a1 = r.prev.add(0x28);
    const v1 = r.next;
    const a2 = r.prev.add(0xe8);
    const v2 = r.next.isNull() ? ptr(0) : r.next.add(0xd0);
    console.log(`HIT idx=${r.idx} "${r.name}"`);
    console.log(`  prev=${r.prev}  self=${r.self}  next=${r.next}`);
    console.log(`  写[1] *(${a1}) = ${v1}    (solist: prev.next = self.next)`);
    console.log(`  写[2] *(${a2}) = ${v2}    (r_map: prev.l_next = next_lm)`);
    return { writes: [{a: a1, v: v1}, {a: a2, v: v2}] };
}

function unlinkDo(soName) {
    const r = unlinkProbe(soName);
    if (!r) return false;
    for (const w of r.writes) {
        const range = Process.findRangeByAddress(w.a);
        const orig  = range ? range.protection : null;
        const need  = orig && orig.indexOf('w') < 0;
        try {
            if (need) Memory.protect(range.base, range.size, 'rw-');
            w.a.writePointer(w.v);
            if (need) Memory.protect(range.base, range.size, orig);
            console.log(`  ✓ *(${w.a}) = ${w.v}`);
        } catch (e) {
            console.log(`  ✗ *(${w.a}) write fail: ${e.message}`);
            return false;
        }
    }
    console.log(`done. 跑 linkMap() 验证`);
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

// ── 10) detect: 综合 frida 反检测全套, 打印每个命中的具体内容 ───────────────
function detect() {
    const SUSP = /xiam|memfd:|frida|gadget|linjector/i;
    const TPATT = /frida|gum|gmain|gdbus|pool-spawner|gjs-loop/i;
    const FDPATT = /memfd:|frida|xiam|re\.frida|linjector|gadget/i;
    const FRIDA_PORTS = [27042, 27043, 14725, 14735];

    const hits = { maps: [], threads: [], fds: [], linkMap: [], soList: [], ports: [], rtld: [] };
    let mapsTotal = 0, threadsTotal = 0, fdsTotal = 0, lmTotal = 0, soTotal = 0;

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
                + hits.linkMap.length + hits.soList.length + hits.ports.length
                + hits.rtld.length;

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
    section('rtld',     hits.rtld,    1,            'rtld_db_dlactivity 内存 vs 文件');
    section('ports',    hits.ports,   FRIDA_PORTS.length, '/proc/net/tcp LISTEN');
    console.log('────────────────────────────────────────────────────────────────────');
    console.log(`  TOTAL: ${total} hits  ${total ? '★ DETECTED' : '✓ CLEAN'}`);
    console.log('════════════════════════════════════════════════════════════════════');
    console.log('');

    return {
        maps: hits.maps.length, threads: hits.threads.length, fds: hits.fds.length,
        linkMap: hits.linkMap.length, soList: hits.soList.length, rtld: hits.rtld.length,
        ports: hits.ports.length, total,
    };
}

// ── 暴露到 REPL ────────────────────────────────────────────────────────────
rpc.exports = { maps, mapsRaw, cmdline, linkMap, soList, unlinkProbe, unlinkDo,
                threads, status, fds, ports, rtldHook, detect };
Object.assign(globalThis, { maps, mapsRaw, cmdline, linkMap, soList, unlinkProbe, unlinkDo,
                            threads, status, fds, ports, rtldHook, detect });

console.log('[scan] loaded (no hooks installed).');
console.log('  maps()         过滤 frida/xiam 痕迹');
console.log('  mapsRaw()      全量 maps');
console.log('  cmdline()      /proc/self/cmdline');
console.log('  status()       /proc/self/status 摘要');
console.log('  threads()      线程名扫描 (frida/gum/gmain 命中)');
console.log('  fds()          /proc/self/fd 扫描 (memfd/socket/frida 命中)');
console.log('  ports()        本地监听端口扫描 (frida 默认端口)');
console.log('  linkMap()      r_debug.r_map 上 xiam/memfd/frida 命中 (双链表)');
console.log('  soList()       solist (bionic 私有, dl_iterate_phdr 视角) 命中');
console.log('  rtldHook()     ★ 对比 rtld_db_dlactivity 内存字节 vs linker 文件字节');
console.log('  detect()       一把跑完 (maps + threads + linkMap + solist + rtld + ports)');
console.log('  unlinkProbe()  dry-run 断链计划');
console.log('  unlinkDo()     真断链 (单向 forward, 2 个写)');
