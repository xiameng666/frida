/*
 * tools/test-shadow.js - frida17_shadow KPM PTE 隐藏测试套件
 *
 * 用法:
 *   frida -U -f com.target -l tools/test-shadow.js -e
 *
 *   或在 Python 端:
 *     script = session.create_script(open("tools/test-shadow.js").read());
 *     script.load();
 *     api = script.exports_sync;
 *     print(api.is_shadow_enabled());        # 当前 shadow 状态
 *     print(api.test_self_read("open", 16)); # 同进程自读验证
 *     ...
 *
 * 全程 logcat 配合:
 *   adb logcat -s xiam:I
 */

"use strict";

const PAGE_SIZE = 4096;

function pageOf(addr) {
    return ptr(addr.toString()).and(~(PAGE_SIZE - 1));
}

function hexBytes(p, n) {
    const arr = new Uint8Array(p.readByteArray(n));
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

function findFunc(libName, funcName) {
    const m = Process.findModuleByName(libName);
    if (m === null) throw new Error(`module not found: ${libName}`);
    const f = Module.findExportByName(libName, funcName);
    if (f === null) throw new Error(`export not found: ${libName}!${funcName}`);
    return f;
}

/* ============================================================
 * RPC 1: 状态查询 (无副作用)
 * ============================================================ */

function rpcIsShadowEnabled() {
    return {
        shadowEnabled: Interceptor.shadowEnabled,
        platform: Process.platform,
        arch: Process.arch,
    };
}

function rpcEnableShadow() {
    const ok = Interceptor.enableShadow();
    return {ok, shadowEnabled: Interceptor.shadowEnabled};
}

function rpcDisableShadow() {
    Interceptor.disableShadow();
    return {shadowEnabled: Interceptor.shadowEnabled};
}

/* ============================================================
 * RPC 2: 同进程自读验证 — 核心隐藏测试
 *   读 hook 后的函数前 N 字节, 验证是否仍然是 hook 之前的"原版"
 * ============================================================ */

function rpcTestSelfRead(libName, funcName, len) {
    libName = libName || "libc.so";
    funcName = funcName || "open";
    len = len || 16;

    const f = findFunc(libName, funcName);
    const before = hexBytes(f, len);
    console.log(`[test-shadow] ${libName}!${funcName} @ ${f}`);
    console.log(`[test-shadow] before attach: ${before}`);

    const listener = Interceptor.attach(f, {
        onEnter(args) {
            this._marker = true;
        }
    });

    const after = hexBytes(f, len);
    console.log(`[test-shadow] after  attach: ${after}`);
    console.log(`[test-shadow] equal: ${before === after}`);

    return {
        func: f.toString(),
        page: pageOf(f).toString(),
        before, after,
        equalToOriginal: before === after,
        shadowEnabled: Interceptor.shadowEnabled,
        listenerRef: listener.toString(),  // host 端可保留 detach
    };
}

/* ============================================================
 * RPC 3: hook 实际触发验证 — 防止 PTE 隐藏破坏功能
 *   先 attach, 再主动调一次, 看 callback 是否被触发
 * ============================================================ */

function rpcTestHookFires(libName, funcName) {
    libName = libName || "libc.so";
    funcName = funcName || "getpid";   // getpid 无副作用, 默认用它
    const f = findFunc(libName, funcName);

    let count = 0;
    const listener = Interceptor.attach(f, {
        onEnter(args) { count++; }
    });

    /* getpid 是 NativeFunction("int", []) */
    const fn = new NativeFunction(f, "int", []);
    const r1 = fn();
    const r2 = fn();
    const r3 = fn();

    listener.detach();
    return {
        func: f.toString(),
        callsMade: 3,
        hookFireCount: count,
        result: r1,
        shadowEnabled: Interceptor.shadowEnabled,
    };
}

/* ============================================================
 * RPC 4: 段数验证 — libc.so 不应被撕段
 *   commit 358b74d0 已经修了, text_shadow 也不应破坏
 * ============================================================ */

function rpcTestSegmentCount(libName) {
    libName = libName || "libc.so";
    const m = Process.findModuleByName(libName);
    if (m === null) return {error: `module not found: ${libName}`};

    const all = Process.enumerateRanges('---').filter(r =>
        r.file && r.file.path && r.file.path.endsWith(libName));
    const exec = all.filter(r => r.protection.indexOf('x') >= 0);

    return {
        libName,
        modulePath: m.path,
        moduleBase: m.base.toString(),
        moduleSize: m.size,
        totalSegments: all.length,
        execSegments: exec.length,
        execRanges: exec.map(r => ({
            base: r.base.toString(),
            size: r.size,
            prot: r.protection,
        })),
    };
}

/* ============================================================
 * RPC 5: 同页多函数 — 共用 alt 页 + append 蹦床白名单
 *   open 和 openat 通常在 libc.so 中相邻, 大概率同页或相邻页
 * ============================================================ */

function rpcTestSamePage(libName, funcA, funcB) {
    libName = libName || "libc.so";
    funcA = funcA || "open";
    funcB = funcB || "openat";

    const fa = findFunc(libName, funcA);
    const fb = findFunc(libName, funcB);
    const samePage = pageOf(fa).equals(pageOf(fb));

    const aBefore = hexBytes(fa, 16);
    const bBefore = hexBytes(fb, 16);

    Interceptor.attach(fa, {onEnter(args) {}});
    Interceptor.attach(fb, {onEnter(args) {}});

    const aAfter = hexBytes(fa, 16);
    const bAfter = hexBytes(fb, 16);

    return {
        funcA: fa.toString(), funcB: fb.toString(),
        pageA: pageOf(fa).toString(), pageB: pageOf(fb).toString(),
        samePage,
        aHidden: aBefore === aAfter,
        bHidden: bBefore === bAfter,
        aBefore, aAfter, bBefore, bAfter,
        shadowEnabled: Interceptor.shadowEnabled,
    };
}

/* ============================================================
 * RPC 6: 全套自动跑
 * ============================================================ */

function rpcRunAll() {
    const results = {};

    results.status = rpcIsShadowEnabled();

    try { results.selfRead = rpcTestSelfRead(); }
    catch (e) { results.selfRead = {error: e.toString()}; }

    try { results.segCount = rpcTestSegmentCount(); }
    catch (e) { results.segCount = {error: e.toString()}; }

    try { results.samePage = rpcTestSamePage(); }
    catch (e) { results.samePage = {error: e.toString()}; }

    try { results.hookFires = rpcTestHookFires(); }
    catch (e) { results.hookFires = {error: e.toString()}; }

    return results;
}

rpc.exports = {
    isShadowEnabled: rpcIsShadowEnabled,
    enableShadow: rpcEnableShadow,
    disableShadow: rpcDisableShadow,
    testSelfRead: rpcTestSelfRead,
    testHookFires: rpcTestHookFires,
    testSegmentCount: rpcTestSegmentCount,
    testSamePage: rpcTestSamePage,
    runAll: rpcRunAll,
};

console.log("[test-shadow] script loaded.");
console.log("[test-shadow] initial shadowEnabled:", Interceptor.shadowEnabled);
console.log("[test-shadow] available RPCs: isShadowEnabled, enableShadow, disableShadow,");
console.log("[test-shadow]                 testSelfRead, testHookFires, testSegmentCount,");
console.log("[test-shadow]                 testSamePage, runAll");
