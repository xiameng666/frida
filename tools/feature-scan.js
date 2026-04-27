/*
 * feature-scan.js  -  全量打印, 不过滤
 *
 * 注入后 REPL 直接调:
 *   all()        全跑
 *   status()
 *   cmdline()
 *   threads()
 *   maps()
 *   smaps()
 *   fds()
 *   unix()
 *   tmp([name])
 *
 *   hookDlopen() 已在脚本加载时自动调用
 */

const PROC_SELF = '/proc/self';

// ---------------- libc 直读 ----------------
const libc = Process.getModuleByName('libc.so');
function exp(name) {
  const a = libc.findExportByName(name);
  if (a !== null) return a;
  try {
    return Module.getGlobalExportByName(name);
  } catch (e) {
    return null;
  }
}

// 从主程序的 PT_DYNAMIC 里找 DT_DEBUG, 该 entry 的 d_un.d_ptr 指向 r_debug.
// 这是 gdb / lldb / 风控的标准路径, 不依赖 _r_debug 符号是否导出.
//
// 实现: dl_iterate_phdr 遍历每个加载模块, 对每个模块找 PT_DYNAMIC, 然后
//       在 PT_DYNAMIC 里找 DT_DEBUG.d_un.d_ptr != NULL. 命中即返回.
//       (DT_DEBUG 仅主程序有, 普通 so 没有这个 entry)
function findRDebugViaDtDebug() {
  const sym = exp('dl_iterate_phdr');
  if (sym === null) return null;
  const dl_iterate_phdr = new NativeFunction(sym, 'int', ['pointer', 'pointer']);

  const PT_DYNAMIC = 2;
  const DT_NULL = 0, DT_DEBUG = 21;
  let foundRDebug = null;
  let trace = [];

  const cb = new NativeCallback(function (info, size, data) {
    if (foundRDebug !== null) return 1;
    let dlpi_addr, dlpi_name, dlpi_phdr, dlpi_phnum;
    try {
      dlpi_addr  = info.readPointer();
      dlpi_name  = info.add(8).readPointer();
      dlpi_phdr  = info.add(16).readPointer();
      dlpi_phnum = info.add(24).readU16();
    } catch (e) { return 0; }

    const name = dlpi_name.isNull() ? '<null>' : dlpi_name.readCString();
    if (dlpi_phdr.isNull() || dlpi_phnum === 0) return 0;

    // 找 PT_DYNAMIC. Phdr64 字段:
    //   type(4) flags(4) offset(8) vaddr(8) paddr(8) filesz(8) memsz(8) align(8) = 56B
    let dynVaddr = null;
    for (let i = 0; i < dlpi_phnum; i++) {
      const ph = dlpi_phdr.add(i * 56);
      if (ph.readU32() === PT_DYNAMIC) {
        dynVaddr = ph.add(16).readPointer();
        break;
      }
    }
    if (dynVaddr === null) return 0;

    // PT_DYNAMIC.runtime_base = dlpi_addr + p_vaddr
    const dynRuntime = dlpi_addr.add(dynVaddr);

    // ElfW(Dyn) 64-bit: d_tag(8) d_un(8) = 16B, 直到 DT_NULL 终止
    let p = dynRuntime;
    for (let i = 0; i < 8192; i++) {
      let tag, val;
      try {
        tag = p.readU64().valueOf();
        val = p.add(8).readPointer();
      } catch (e) { break; }
      if (tag === DT_NULL) break;
      if (tag === DT_DEBUG) {
        trace.push(`  [DT_DEBUG] at ${dynRuntime.add(i*16)} in ${name || '<unnamed>'} -> ${val}`);
        if (!val.isNull()) {
          foundRDebug = val;
          return 1;
        }
      }
      p = p.add(16);
    }
    return 0;
  }, 'int', ['pointer', 'ulong', 'pointer']);

  dl_iterate_phdr(cb, NULL);

  if (trace.length) console.log('[DT_DEBUG search]\n' + trace.join('\n'));
  return foundRDebug;
}

const _open    = new NativeFunction(exp('open'),    'int',     ['pointer', 'int']);
const _read    = new NativeFunction(exp('read'),    'long',    ['int', 'pointer', 'ulong']);
const _close   = new NativeFunction(exp('close'),   'int',     ['int']);
const _opendir = new NativeFunction(exp('opendir'), 'pointer', ['pointer']);
const _readdir = new NativeFunction(exp('readdir'), 'pointer', ['pointer']);
const _closedir= new NativeFunction(exp('closedir'),'int',     ['pointer']);
const _readlink= new NativeFunction(exp('readlink'),'long',    ['pointer', 'pointer', 'ulong']);

// 把 /proc 文件按字节读完, 再逐字节拼成字符串, 不依赖 readUtf8String
// 注意: /proc 伪文件 read 可能返回小于请求量却还有数据, 必须 read 到 EOF (n==0)
function readAll(path) {
  const fd = _open(Memory.allocUtf8String(path), 0).valueOf();
  if (fd < 0) return `<open failed: ${path}>`;
  const CHUNK = 65536;
  const buf = Memory.alloc(CHUNK);
  const parts = [];
  while (true) {
    const n = _read(fd, buf, CHUNK).valueOf();
    if (n <= 0) break;
    const arr = new Uint8Array(ArrayBuffer.wrap(buf, n));
    let s = '';
    for (let i = 0; i < n; i++) s += String.fromCharCode(arr[i]);
    parts.push(s);
  }
  _close(fd);
  return parts.join('');
}

function readDir(path) {
  const out = [];
  const dir = _opendir(Memory.allocUtf8String(path));
  if (dir.isNull()) return out;
  while (true) {
    const ent = _readdir(dir);
    if (ent.isNull()) break;
    // bionic dirent: ino(8) off(8) reclen(2) type(1) name[]
    const name = ent.add(19).readUtf8String();
    if (name === '.' || name === '..') continue;
    out.push(name);
  }
  _closedir(dir);
  return out;
}

function readLink(path) {
  const buf = Memory.alloc(1024);
  const n = _readlink(Memory.allocUtf8String(path), buf, 1023).valueOf();
  if (n <= 0) return null;
  buf.add(n).writeU8(0);
  return buf.readUtf8String();
}

function dump(title, body) {
  console.log('\n========== ' + title + ' ==========');
  console.log(body && body.length ? body : '<empty>');
  console.log('========== end ' + title + ' ==========\n');
}

// ---------------- RPC + globals ----------------
function status() {
  dump('/proc/self/status', readAll(`${PROC_SELF}/status`));
}

function cmdline() {
  let s = readAll(`${PROC_SELF}/cmdline`);
  s = s.replace(/\0/g, ' ');
  dump('/proc/self/cmdline', s);
}

// 默认 maps(): 只看关心的库 (libc / libart / libandroid_runtime / 含 xiam)
// 想看完整 maps 用 mapsRaw()
function maps() {
  const txt = readAll(`${PROC_SELF}/maps`);
  const re = /(libc\.so|libart\.so|libandroid_runtime\.so|xiam)/i;
  const out = txt.split('\n').filter(line => re.test(line));
  dump('/proc/self/maps  filter=[libc | libart | libandroid_runtime | xiam]',
       out.join('\n') + `\n---- ${out.length} lines ----`);
}

function mapsRaw() {
  const txt = readAll(`${PROC_SELF}/maps`);
  const total = txt.split('\n').length;
  dump(`/proc/self/maps  FULL  (${total} lines, ${txt.length} bytes)`, txt);
}

function smaps() {
  const txt = readAll(`${PROC_SELF}/smaps`);
  dump(`/proc/self/smaps  FULL  (${txt.length} bytes)`, txt);
}

// smaps 过滤: 同样只看 libc / libart / libandroid_runtime / xiam 的段
// smaps 一段是多行 (Size/Rss/...), 用空行分段, 命中关键词的整段保留
function smapsFilt() {
  const txt = readAll(`${PROC_SELF}/smaps`);
  const re = /(libc\.so|libart\.so|libandroid_runtime\.so|xiam)/i;
  const segs = [];
  let cur = [];
  txt.split('\n').forEach(line => {
    if (/^[0-9a-f]+-[0-9a-f]+ /i.test(line)) {
      if (cur.length) segs.push(cur);
      cur = [line];
    } else {
      cur.push(line);
    }
  });
  if (cur.length) segs.push(cur);
  const kept = segs.filter(seg => re.test(seg[0]));
  const body = kept.map(seg => seg.join('\n')).join('\n');
  dump('/proc/self/smaps  filter=[libc | libart | libandroid_runtime | xiam]',
       body + `\n---- ${kept.length} segments ----`);
}

function threads() {
  const tids = readDir(`${PROC_SELF}/task`);
  tids.sort((a, b) => parseInt(a) - parseInt(b));
  const lines = ['[tid]    comm'];
  tids.forEach(tid => {
    const comm = readAll(`${PROC_SELF}/task/${tid}/comm`).replace(/\n$/, '');
    lines.push(`${tid.padStart(7)}  ${comm}`);
  });
  dump('/proc/self/task/*/comm', lines.join('\n'));
}

function fds() {
  const fdList = readDir(`${PROC_SELF}/fd`);
  fdList.sort((a, b) => parseInt(a) - parseInt(b));
  const lines = ['[fd]  ->  target'];
  fdList.forEach(fd => {
    const t = readLink(`${PROC_SELF}/fd/${fd}`) || '<readlink failed>';
    lines.push(`${fd.padStart(4)}  ->  ${t}`);
  });
  dump('/proc/self/fd', lines.join('\n'));
}

function unix() {
  dump('/proc/net/unix', readAll('/proc/net/unix'));
}

function tmp(name) {
  name = name || 'xiam-data';
  const lines = [];
  const roots = [
    '/data/local/tmp',
    '/data/local/tmp/' + name,
    '/data/local/tmp/re.frida.server',
    '/sdcard/' + name,
    '/tmp/' + name,
  ];
  roots.forEach(d => {
    try {
      const items = readDir(d);
      lines.push(`\n${d}/  (${items.length} entries)`);
      items.forEach(it => lines.push('  ' + it));
      items.forEach(it => {
        const sub = `${d}/${it}`;
        try {
          const inner = readDir(sub);
          if (inner.length) {
            lines.push(`  ${sub}/`);
            inner.forEach(i2 => lines.push('    ' + i2));
          }
        } catch (e) {}
      });
    } catch (e) {
      lines.push(`\n${d}/  <missing>`);
    }
  });
  dump('tmp dirs (looking for "' + name + '")', lines.join('\n'));
}

function all() {
  status();
  cmdline();
  threads();
  maps();
  smaps();
  fds();
  unix();
  tmp();
}

// ---------------- detect: 模拟反 frida 检测器, 一把扫所有可疑特征 ----------------
// 5 个维度: maps/rwxp, 线程名, dl_iterate_phdr+r_debug, fd readlink, 知名端口
// 强特征 (基本判定 frida 在场) 和弱特征 (glib 内置, 相关) 分开标
const _DETECT_STRONG = /xiam|\bfrida\b|frida-agent|frida-gadget|frida-server|frida-helper|gum-(?!error-quark)|gum_|re\.frida|\/memfd:xiam|\/memfd:frida/i;
const _DETECT_WEAK   = /^(gmain|gdbus|pool-spawner|pool-%s|gjs|gio[-:]|glib-)/i;

function _detectMaps() {
  console.log('\n----- [1] /proc/self/maps -----');
  const txt = readAll(`${PROC_SELF}/maps`);
  const lines = txt.split('\n');
  const rwxpAnon = [], rwxpHooked = [], featAnonName = [], featPath = [], memfdOther = [];

  lines.forEach(line => {
    if (line.length === 0) return;
    const m = line.match(/^([0-9a-f]+)-([0-9a-f]+) (\S{4}) \S+ \S+ \S+\s*(.*)$/i);
    if (!m) return;
    const [, , , perm, rest] = m;
    const path = rest.trim();

    if (perm === 'rwxp') {
      if (path === '' || path.startsWith('[anon:')) rwxpAnon.push(line);
      else if (!path.startsWith('[stack') && path !== '[heap]') rwxpHooked.push(line);
    }
    if (/\[anon:.*?(xiam|frida|gum-)/i.test(line)) featAnonName.push(line);
    if (path.startsWith('/memfd:')) {
      if (_DETECT_STRONG.test(path)) featPath.push(line);
      else memfdOther.push(line);
    } else if (_DETECT_STRONG.test(path)) {
      featPath.push(line);
    }
  });

  let hits = 0;
  function blk(title, arr, sev) {
    if (arr.length === 0) { console.log(`  [${sev}] ${title}: 0`); return; }
    console.log(`  [${sev}] ${title}: ${arr.length}`);
    arr.forEach(l => console.log('       ' + l));
    if (sev === '!!') hits += arr.length;
  }
  blk('rwxp 匿名段 (gum 跳板池, 强特征)', rwxpAnon, '!!');
  blk('rwxp 文件段 (frida hook 后撕段)', rwxpHooked, '!!');
  blk('[anon:xiam/frida/gum-*] 命名段', featAnonName, '!!');
  blk('/memfd:xiam-/frida- 路径', featPath, '!!');
  blk('其它 /memfd:* (非 frida 也可能用)', memfdOther, ' ?');
  console.log(`  ---- maps 强特征命中: ${hits} ----`);
  return hits;
}

function _detectThreads() {
  console.log('\n----- [2] /proc/self/task/*/comm -----');
  const tids = readDir(`${PROC_SELF}/task`);
  const strong = [], weak = [];
  tids.forEach(tid => {
    const comm = readAll(`${PROC_SELF}/task/${tid}/comm`).replace(/\n$/, '');
    const line = `tid=${tid.padStart(6)}  ${comm}`;
    if (_DETECT_STRONG.test(comm)) strong.push(line);
    else if (_DETECT_WEAK.test(comm)) weak.push(line);
  });
  if (strong.length === 0 && weak.length === 0) console.log('  [OK] 无可疑线程名');
  if (strong.length) {
    console.log(`  [!!] 强特征 (xiam/frida/gum-): ${strong.length}`);
    strong.forEach(l => console.log('       ' + l));
  }
  if (weak.length) {
    console.log(`  [ ?] glib 线程 (gmain/gdbus/pool-*): ${weak.length}`);
    weak.forEach(l => console.log('       ' + l));
  }
  console.log(`  ---- 线程总数: ${tids.length}, 强特征: ${strong.length}, 弱特征: ${weak.length} ----`);
  return strong.length;
}

function _detectSo() {
  console.log('\n----- [3] dl_iterate_phdr + r_debug -----');
  const dlSym = exp('dl_iterate_phdr');
  if (dlSym === null) { console.log('  [skip] dl_iterate_phdr 不可用'); return 0; }
  const dl_iterate_phdr = new NativeFunction(dlSym, 'int', ['pointer', 'pointer']);

  const dlAll = [], dlHits = [];
  const cb = new NativeCallback(function (info, size, data) {
    const addr = info.readPointer();
    const namePtr = info.add(8).readPointer();
    const name = namePtr.isNull() ? '' : namePtr.readCString();
    const line = `${addr.toString().padEnd(18)} ${name}`;
    dlAll.push(line);
    if (_DETECT_STRONG.test(name)) dlHits.push(line);
    return 0;
  }, 'int', ['pointer', 'ulong', 'pointer']);
  dl_iterate_phdr(cb, NULL);
  console.log(`  [dl_iterate_phdr] 总=${dlAll.length}, 强特征=${dlHits.length}`);
  if (dlHits.length) {
    console.log('  [!!] 命中:');
    dlHits.forEach(l => console.log('       ' + l));
  } else {
    console.log('  [OK] dl_iterate_phdr 无 frida/xiam');
  }

  // r_debug via DT_DEBUG
  const PT_DYNAMIC = 2, DT_NULL = 0, DT_DEBUG = 21;
  let rDebugAddr = null;
  const cb2 = new NativeCallback(function (info, size, data) {
    if (rDebugAddr) return 1;
    const dlpi_addr = info.readPointer();
    const dlpi_phdr = info.add(16).readPointer();
    const dlpi_phnum = info.add(24).readU16();
    if (dlpi_phdr.isNull() || dlpi_phnum === 0) return 0;
    let dynVaddr = null;
    for (let i = 0; i < dlpi_phnum; i++) {
      const ph = dlpi_phdr.add(i * 56);
      if (ph.readU32() === PT_DYNAMIC) { dynVaddr = ph.add(16).readPointer(); break; }
    }
    if (dynVaddr === null) return 0;
    let p = dlpi_addr.add(dynVaddr);
    for (let i = 0; i < 8192; i++) {
      let tag, val;
      try { tag = p.readU64().valueOf(); val = p.add(8).readPointer(); }
      catch (e) { break; }
      if (tag === DT_NULL) break;
      if (tag === DT_DEBUG && !val.isNull()) { rDebugAddr = val; return 1; }
      p = p.add(16);
    }
    return 0;
  }, 'int', ['pointer', 'ulong', 'pointer']);
  dl_iterate_phdr(cb2, NULL);

  let rHitsLen = 0;
  if (rDebugAddr === null) {
    console.log('  [r_debug] 找不到 (无 DT_DEBUG)');
  } else {
    console.log(`  [r_debug] @ ${rDebugAddr}`);
    let cur = rDebugAddr.add(8).readPointer();
    let total = 0; const rHits = [];
    while (!cur.isNull() && total < 1024) {
      const l_addr = cur.readPointer();
      const l_namePtr = cur.add(8).readPointer();
      const l_name = l_namePtr.isNull() ? '' : l_namePtr.readCString();
      const line = `${l_addr.toString().padEnd(18)} ${l_name}`;
      if (_DETECT_STRONG.test(l_name)) rHits.push(line);
      cur = cur.add(24).readPointer();
      total++;
    }
    console.log(`  [r_debug] 总=${total}, 强特征=${rHits.length}`);
    if (rHits.length) {
      console.log('  [!!] 命中:');
      rHits.forEach(l => console.log('       ' + l));
    } else {
      console.log('  [OK] r_debug 无 frida/xiam');
    }
    rHitsLen = rHits.length;
  }
  return dlHits.length + rHitsLen;
}

function _detectFds() {
  console.log('\n----- [4] /proc/self/fd -----');
  const _readlink = new NativeFunction(exp('readlink'), 'long', ['pointer', 'pointer', 'ulong']);
  const fdList = readDir(`${PROC_SELF}/fd`);
  const buf = Memory.alloc(1024);
  const hits = [], memfdOthers = [];
  fdList.forEach(fd => {
    const path = `${PROC_SELF}/fd/${fd}`;
    const n = _readlink(Memory.allocUtf8String(path), buf, 1023).valueOf();
    if (n <= 0) return;
    buf.add(n).writeU8(0);
    const target = buf.readUtf8String();
    if (_DETECT_STRONG.test(target)) hits.push(`fd=${fd.padStart(4)} -> ${target}`);
    else if (target.startsWith('/memfd:')) memfdOthers.push(`fd=${fd.padStart(4)} -> ${target}`);
  });
  if (hits.length === 0) console.log('  [OK] 无 frida/xiam fd');
  else { console.log(`  [!!] 命中 ${hits.length}:`); hits.forEach(l => console.log('       ' + l)); }
  if (memfdOthers.length) {
    console.log(`  [ ?] 其它 memfd ${memfdOthers.length}:`);
    memfdOthers.forEach(l => console.log('       ' + l));
  }
  return hits.length;
}

// 走 r_debug.r_map, 对 l_name 与 DT_SONAME 双字段做子串匹配,
// 命中即视为可被风控识别 (与 dpx 视角等同, 但不依赖具体厂商).
function _detectLinkMap() {
  console.log('\n----- [6] r_debug.r_map + DT_SONAME -----');

  // 找 r_debug
  let r_debug = exp('_r_debug');
  if (r_debug === null) {
    for (const ln of ['linker64', 'linker', 'ld-android.so']) {
      try {
        const m = Process.getModuleByName(ln);
        r_debug = m.findExportByName('_r_debug') || m.findExportByName('__dl__r_debug');
        if (r_debug) break;
      } catch (e) {}
    }
  }
  if (r_debug === null) r_debug = findRDebugViaDtDebug();
  if (!r_debug || r_debug.isNull()) {
    console.log('  [skip] r_debug 找不到');
    return 0;
  }

  const DT_NULL = 0, DT_STRTAB = 5, DT_STRSZ = 10, DT_SONAME = 14;
  const HIT_LNAME  = ['frida', '/memfd:', 'jvmti.so', 'jdwp.so'];
  const HIT_SONAME = ['frida', '-agent-raw.so'];

  let total = 0, hits = [];
  let cur = r_debug.add(8).readPointer();
  while (!cur.isNull() && total < 1024) {
    let l_addr, l_name_ptr, l_ld, l_next, l_name;
    try {
      l_addr     = cur.readPointer();
      l_name_ptr = cur.add(8).readPointer();
      l_ld       = cur.add(16).readPointer();
      l_next     = cur.add(24).readPointer();
      l_name     = l_name_ptr.isNull() ? '' : (l_name_ptr.readCString() || '');
    } catch (e) { break; }

    let soname = '';
    try {
      if (!l_ld.isNull()) {
        let strtab = NULL, strsz = 0, soname_off = -1;
        let p = l_ld;
        for (let i = 0; i < 4096; i++) {
          const tag = p.readU64().valueOf();
          if (tag === DT_NULL) break;
          if (tag === DT_STRTAB)      strtab = p.add(8).readPointer();
          else if (tag === DT_STRSZ)  strsz = p.add(8).readU64().valueOf();
          else if (tag === DT_SONAME) soname_off = p.add(8).readU64().valueOf();
          p = p.add(16);
        }
        if (!strtab.isNull() && soname_off >= 0 && soname_off < strsz + 1024) {
          try { soname = strtab.add(soname_off).readCString() || ''; } catch (e) {}
          if (soname === '' && !l_addr.isNull()) {
            try { soname = l_addr.add(strtab).add(soname_off).readCString() || ''; } catch (e) {}
          }
        }
      }
    } catch (e) {}

    let why = [];
    for (const k of HIT_LNAME)  if (l_name.indexOf(k)  !== -1) why.push(`l_name~${k}`);
    for (const k of HIT_SONAME) if (soname.indexOf(k) !== -1) why.push(`SONAME~${k}`);
    if (why.length) {
      hits.push(`${l_addr.toString().padEnd(18)} ${(l_name || '<null>').padEnd(46)} ${soname}    [${why.join(',')}]`);
    }

    cur = l_next;
    total++;
  }

  if (hits.length === 0) {
    console.log(`  [OK] link_map 总=${total}, 无命中`);
  } else {
    console.log(`  [!!] link_map 总=${total}, 命中=${hits.length}:`);
    hits.forEach(l => console.log('       ' + l));
  }
  return hits.length;
}

function _detectPorts() {
  console.log('\n----- [5] /proc/net/tcp[6] (frida 知名端口) -----');
  const KNOWN = [27042, 27043, 27052, 27053, 14725, 14735];
  const txt = readAll('/proc/net/tcp6') + '\n' + readAll('/proc/net/tcp');
  const hits = [];
  txt.split('\n').forEach(line => {
    const m = line.match(/^\s*\d+:\s+\S+:([0-9A-F]{4})\s/);
    if (!m) return;
    const port = parseInt(m[1], 16);
    if (KNOWN.indexOf(port) !== -1) hits.push(`port=${port}  ${line.trim()}`);
  });
  if (hits.length === 0) console.log('  [OK] 无 frida 知名端口');
  else { console.log(`  [!!] 命中 ${hits.length}:`); hits.forEach(l => console.log('       ' + l)); }
  return hits.length;
}

function detect() {
  console.log('\n############################################');
  console.log('# anti-frida feature scan');
  console.log(`# pid=${Process.id}, arch=${Process.arch}, os=${Process.platform}`);
  console.log('############################################');
  const m = _detectMaps();
  const t = _detectThreads();
  const s = _detectSo();
  const f = _detectFds();
  const p = _detectPorts();
  const d = _detectLinkMap();
  const total = m + t + s + f + p + d;
  console.log('\n========== SUMMARY ==========');
  console.log(`  maps   强特征:        ${m}`);
  console.log(`  thread 强特征:        ${t}`);
  console.log(`  so 链表强特征:        ${s}`);
  console.log(`  fd     强特征:        ${f}`);
  console.log(`  ports  命中:          ${p}`);
  console.log(`  link_map 命中:        ${d}    (l_name + DT_SONAME 双字段)`);
  console.log(total === 0
    ? '\n  [PASS] 当前进程未被检出 frida 特征'
    : `\n  [FAIL] 共 ${total} 处特征命中, 风控可识别 frida`);
}
// detect 子模块用法: detect.maps() / detect.threads() / detect.so() / detect.fds() / detect.ports() / detect.linkMap()
detect.maps    = _detectMaps;
detect.threads = _detectThreads;
detect.so      = _detectSo;
detect.fds     = _detectFds;
detect.ports   = _detectPorts;
detect.linkMap = _detectLinkMap;

// ---------------- dl_iterate_phdr 遍历 ----------------
// 这是公开 API, 风控最常用. 标准 glibc/bionic 都有.
// 原型: int dl_iterate_phdr(int (*cb)(struct dl_phdr_info *info, size_t size, void *data), void *data)
// dl_phdr_info: addr(8) name(8) phdr(8) phnum(2) ...
function dlIter() {
  const sym = exp('dl_iterate_phdr');
  if (sym === null) {
    console.log('[dl_iter] dl_iterate_phdr not found');
    return;
  }
  const dl_iterate_phdr = new NativeFunction(sym, 'int', ['pointer', 'pointer']);

  const lines = ['[idx]  base               name'];
  let idx = 0;
  const cb = new NativeCallback(function (info, size, data) {
    const addr = info.readPointer();
    const namePtr = info.add(8).readPointer();
    const name = namePtr.isNull() ? '<null>' : namePtr.readCString();
    lines.push(`${String(idx).padStart(5)}  ${addr.toString().padEnd(18)} ${name}`);
    idx++;
    return 0;
  }, 'int', ['pointer', 'ulong', 'pointer']);

  dl_iterate_phdr(cb, NULL);
  dump('dl_iterate_phdr (公开 API)', lines.join('\n') + `\n---- ${idx} entries ----`);
}

// ---------------- r_debug.r_map (link_map 链表) ----------------
// _r_debug 是 dynamic linker 维护的全局结构, gdb/lldb 也是用它来枚举模块.
// struct r_debug { int r_version; struct link_map *r_map; ... };
// struct link_map { ElfW(Addr) l_addr; char *l_name; ElfW(Dyn) *l_ld; struct link_map *l_next; struct link_map *l_prev; };
function rDebug() {
  // 三路找 r_debug 地址 (任一命中即可):
  //   1) libc / 全局符号 _r_debug   (glibc 上通常导出, bionic 上多半没有)
  //   2) linker64 / linker / ld-android.so 里的 _r_debug 或 __dl__r_debug
  //   3) 主程序 PT_DYNAMIC 的 DT_DEBUG entry (这是 gdb/lldb/风控的标准路径, 永远可用)
  let sym = exp('_r_debug');
  let how = sym ? 'libc/global _r_debug' : null;
  if (sym === null) {
    for (const ln of ['linker64', 'linker', 'ld-android.so']) {
      try {
        const m = Process.getModuleByName(ln);
        sym = m.findExportByName('_r_debug');
        if (sym) { how = ln + '!_r_debug'; break; }
        sym = m.findExportByName('__dl__r_debug');
        if (sym) { how = ln + '!__dl__r_debug'; break; }
      } catch (e) {}
    }
  }
  if (sym === null) {
    sym = findRDebugViaDtDebug();
    if (sym) how = 'PT_DYNAMIC/DT_DEBUG';
  }
  if (sym === null || sym.isNull()) {
    dump('_r_debug walk', '<找不到 r_debug 地址 (DT_DEBUG/符号都没)>');
    return;
  }

  const r_version = sym.readS32();
  const r_map = sym.add(8).readPointer();
  const lines = [`r_debug @ ${sym}  (via ${how})  r_version=${r_version}  r_map=${r_map}`];
  lines.push('[idx]  l_addr            l_name                                                  l_ld              l_next');

  let cur = r_map;
  let idx = 0;
  while (!cur.isNull() && idx < 1024) {
    const l_addr = cur.readPointer();
    const l_name = cur.add(8).readPointer();
    const name = l_name.isNull() ? '<null>' : l_name.readCString();
    const l_ld   = cur.add(16).readPointer();
    const l_next = cur.add(24).readPointer();
    lines.push(
      `${String(idx).padStart(5)}  ${l_addr.toString().padEnd(18)}` +
      `${(name || '').padEnd(56)}  ${l_ld.toString().padEnd(18)}${l_next}`
    );
    cur = l_next;
    idx++;
  }
  dump('_r_debug.r_map (link_map 链表, gdb/风控都看这个)',
       lines.join('\n') + `\n---- ${idx} entries ----`);
}

// ---------------- link_map 链表 + DT_SONAME ----------------
// 走 r_debug.r_map 拿到链表头, 沿 l_next 遍历每个 link_map, 对每个 DSO:
//   1) 检查 l_name (路径字符串) 是否含子串: frida / /memfd: / jvmti.so / jdwp.so
//   2) 走 l_ld (PT_DYNAMIC) 找 DT_STRTAB / DT_STRSZ / DT_SONAME, 取 SONAME 字符串
//      检查 SONAME 是否含: frida / -agent-raw.so
// 这是常见风控的检测路径, 命中通常意味着进程被 SIGKILL.
// 我们自己跑这套, 看看 frida agent 的 l_name + SONAME 各是什么, 验证改名是否到位.
function linkMap() {
  // 三路找 r_debug 地址 (与 rDebug() 共用同一套兜底)
  let r_debug = exp('_r_debug');
  let how = r_debug ? 'libc/global _r_debug' : null;
  if (r_debug === null) {
    for (const ln of ['linker64', 'linker', 'ld-android.so']) {
      try {
        const m = Process.getModuleByName(ln);
        r_debug = m.findExportByName('_r_debug');
        if (r_debug) { how = ln + '!_r_debug'; break; }
        r_debug = m.findExportByName('__dl__r_debug');
        if (r_debug) { how = ln + '!__dl__r_debug'; break; }
      } catch (e) {}
    }
  }
  if (r_debug === null) {
    r_debug = findRDebugViaDtDebug();
    if (r_debug) how = 'PT_DYNAMIC/DT_DEBUG';
  }
  if (!r_debug || r_debug.isNull()) {
    dump('link_map walk', '<找不到 r_debug>');
    return;
  }

  const lines = [`r_debug @ ${r_debug}  (via ${how})  r_version=${r_debug.readS32()}  r_map=${r_debug.add(8).readPointer()}`];
  lines.push('');
  lines.push('[idx]  l_addr            l_name                                          DT_SONAME');
  lines.push('-----  ----------------  ----------------------------------------------  --------------------------');

  const DT_NULL = 0, DT_STRTAB = 5, DT_STRSZ = 10, DT_SONAME = 14;

  // dexprotect 子串黑名单 (来自 dpx_link_map_soname_blacklist):
  const HIT_LNAME = [
    'frida',          // l_name 含 frida 即杀
    '/memfd:',        // l_name 以 /memfd: 开头即杀  <- 关键!
    'jvmti.so',
    'jdwp.so',
  ];
  const HIT_SONAME = [
    'frida',
    '-agent-raw.so',  // 包括老的 libfrida-agent-raw.so   <- 关键!
  ];

  let idx = 0, hits = 0;
  let cur = r_debug.add(8).readPointer();   // r_debug.r_map -> 第一个 link_map

  while (!cur.isNull() && idx < 1024) {
    let l_addr, l_name_ptr, l_ld, l_next, l_name;
    try {
      l_addr     = cur.readPointer();
      l_name_ptr = cur.add(8).readPointer();
      l_ld       = cur.add(16).readPointer();
      l_next     = cur.add(24).readPointer();
      l_name     = l_name_ptr.isNull() ? '' : (l_name_ptr.readCString() || '');
    } catch (e) {
      lines.push(`${String(idx).padStart(5)}  <read error at ${cur}: ${e.message}>`);
      break;
    }

    // 走 l_ld (PT_DYNAMIC) 找 SONAME
    let soname = '';
    try {
      if (!l_ld.isNull()) {
        let strtab = NULL, strsz = 0, soname_off = -1;
        let p = l_ld;
        for (let i = 0; i < 4096; i++) {
          const tag = p.readU64().valueOf();
          if (tag === DT_NULL) break;
          if (tag === DT_STRTAB) {
            const v = p.add(8).readPointer();
            // bionic 在加载时已经把 DT_STRTAB 的 d_ptr 改写成绝对地址
            strtab = v;
          } else if (tag === DT_STRSZ) {
            strsz = p.add(8).readU64().valueOf();
          } else if (tag === DT_SONAME) {
            soname_off = p.add(8).readU64().valueOf();
          }
          p = p.add(16);
        }
        if (!strtab.isNull() && soname_off >= 0 && soname_off < strsz + 1024) {
          // 有些库 strtab 是相对地址, 加上 l_addr 兜底
          let s = '';
          try { s = strtab.add(soname_off).readCString() || ''; } catch (e) {}
          if (s === '' && !l_addr.isNull()) {
            try { s = l_addr.add(strtab).add(soname_off).readCString() || ''; } catch (e) {}
          }
          soname = s;
        }
      }
    } catch (e) {}

    // 标可疑
    let mark = '   ';
    for (const k of HIT_LNAME)  if (l_name.indexOf(k)  !== -1) { mark = '!! '; break; }
    if (mark === '   ') for (const k of HIT_SONAME) if (soname.indexOf(k) !== -1) { mark = '!! '; break; }
    if (mark === '!! ') hits++;

    const namePart = (l_name || '<null>').padEnd(46);
    const soPart   = soname || '';
    lines.push(`${mark}${String(idx).padStart(5)}  ${l_addr.toString().padEnd(18)}${namePart}  ${soPart}`);

    cur = l_next;
    idx++;
  }

  lines.push('');
  lines.push(`---- 总条目: ${idx},  命中: ${hits} ----`);
  lines.push(`---- 行首 [!!] = l_name 含 frida//memfd:/jvmti.so/jdwp.so, 或 SONAME 含 frida/-agent-raw.so ----`);
  dump('link_map (l_name + DT_SONAME)', lines.join('\n'));
  return hits;
}

// ---------------- bionic solist (Android 专用, 内部链表) ----------------
// 走 linker64 的私有符号 __dl__ZL6solist (mangled, "solist")
// 每个 soinfo 节点结构在不同 Android 版本不同, 这里只读 next + base + size_or_name
// 用来对比看 dlopen 用 RTLD_NOLOAD 后, soinfo 是否还残留(常见反检测被链接器断链)
function soList() {
  const linkers = ['linker64', 'linker'];
  let listSym = null;
  let linkerName = null;
  for (const ln of linkers) {
    try {
      const m = Process.getModuleByName(ln);
      // bionic 内部全局符号常见 mangled 名
      const candidates = [
        '__dl__ZL6solist',
        '__dl_solist',
        '__dl__ZL19__linker_dl_err_buf',  // 仅作存在性测试
      ];
      for (const c of candidates) {
        const s = m.findExportByName(c);
        if (s) {
          // 我们只要 solist
          if (c.indexOf('solist') !== -1) {
            listSym = s;
            linkerName = ln;
            break;
          }
        }
      }
      if (listSym) break;
    } catch (e) {}
  }
  if (listSym === null) {
    dump('bionic solist',
      '<__dl__ZL6solist 符号在该 linker 上未导出, ' +
      '此 Android 版本需要通过解析 linker .symtab 或已知偏移寻址>');
    return;
  }
  // *listSym 即第一个 soinfo*
  let cur = listSym.readPointer();
  const lines = [`solist head @ ${listSym} (in ${linkerName})`];
  lines.push('[idx]  soinfo*           base              size       next              name');

  // soinfo 字段顺序在 bionic Android 11+ 是:
  //   char old_name[128];     // 0x000  (历史遗留)
  //   const ElfW(Phdr)* phdr; // 0x080
  //   size_t phnum;           // 0x088
  //   ElfW(Addr) base;        // 0x098
  //   size_t size;            // 0x0a0
  //   uint32_t flags_;        ...
  //   soinfo* next;           // 0x028 (历史) 或在底部
  // 不同版本偏移变化大, 这里仅做最小尝试: 假设 next 在 0x28, base 在 0x90, size 在 0x98
  // 不一定对所有 Android 版本都准, 不过链表能跑通就有价值
  let idx = 0;
  while (!cur.isNull() && idx < 512) {
    let base, size, next, name;
    try {
      next = cur.add(0x28).readPointer();
      base = cur.add(0x90).readPointer();
      size = cur.add(0x98).readU64();
      name = cur.readCString(128) || '';
    } catch (e) {
      lines.push(`${String(idx).padStart(5)}  ${cur}  <read error: ${e.message}>`);
      break;
    }
    lines.push(
      `${String(idx).padStart(5)}  ${cur.toString().padEnd(18)}` +
      `${base.toString().padEnd(18)}${('0x' + size.toString(16)).padEnd(11)} ${next.toString().padEnd(18)}${name}`
    );
    cur = next;
    idx++;
  }
  dump('bionic solist (linker 私有链表, soinfo 视角)',
       lines.join('\n') + `\n---- ${idx} entries (字段偏移按 Android 11+ 估算, 名字若错请按版本核对偏移) ----`);
}

// ---------------- dlopen 拦截 ----------------
function hookDlopen() {
  const targets = ['android_dlopen_ext', 'dlopen'];
  let hooked = 0;

  targets.forEach(name => {
    let addr = libc.findExportByName(name);
    if (addr === null) {
      const linkers = ['linker64', 'linker'];
      for (const ln of linkers) {
        try {
          const m = Process.getModuleByName(ln);
          addr = m.findExportByName(name);
          if (addr) break;
        } catch (e) {}
      }
    }
    if (addr === null) {
      console.log(`[dlopen-hook] ${name} not found, skip`);
      return;
    }

    Interceptor.attach(addr, {
      onEnter(args) {
        this.fname = args[0].isNull() ? '<null>' : args[0].readCString();
        this.flags = args[1].toInt32();
        if (name === 'android_dlopen_ext') {
          this.extinfo = args[2];
        }
      },
      onLeave(retval) {
        const flagsHex = '0x' + (this.flags >>> 0).toString(16);
        const ret = retval.toString();
        let extra = '';
        if (name === 'android_dlopen_ext' && this.extinfo && !this.extinfo.isNull()) {
          try {
            const eflags = this.extinfo.readU64();
            extra = `  ext.flags=0x${eflags.toString(16)}`;
          } catch (e) {}
        }
        console.log(`[dlopen] ${name}("${this.fname}", ${flagsHex}) = ${ret}${extra}`);
      },
    });
    hooked++;
  });

  console.log(`[dlopen-hook] installed on ${hooked} target(s).`);
}

// ---------------- 暴露 ----------------
rpc.exports = {
  all, status, cmdline, maps, mapsRaw, smaps, smapsFilt,
  threads, fds, unix, tmp, hookDlopen,
  dlIter, rDebug, soList, linkMap,
  detect,
};

// 同名挂到全局, REPL 里直接 maps() 调
Object.assign(globalThis, {
  all, status, cmdline, maps, mapsRaw, smaps, smapsFilt,
  threads, fds, unix, tmp, hookDlopen,
  dlIter, rDebug, soList, linkMap,
  detect,
});

hookDlopen();

console.log('[feature-scan] loaded.');
console.log('  maps()      只看 libc/libart/libandroid_runtime/xiam');
console.log('  mapsRaw()   全量 /proc/self/maps');
console.log('  smaps() / smapsFilt()');
console.log('  threads() fds() unix() status() cmdline() tmp([name])');
console.log('  dlIter()    dl_iterate_phdr 公开 API 枚举 so');
console.log('  rDebug()    遍历 _r_debug.r_map (link_map 链表)');
console.log('  linkMap()   link_map 链表 + DT_SONAME (常见风控视角)');
console.log('  soList()    遍历 bionic linker 私有 solist (Android)');
console.log('  all()       一把全跑 (打印各 /proc 接口原始内容)');
console.log('  detect()    模拟反 frida 检测器, 给出强/弱特征汇总报告');
console.log('              detect.maps()/threads()/so()/fds()/ports() 单跑');
console.log('  hookDlopen() 已自动挂上');
