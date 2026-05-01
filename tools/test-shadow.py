#!/usr/bin/env python3
"""
tools/test-shadow.py - frida17_shadow KPM PTE 隐藏自动测试驱动.

用法:
    # 推荐: spawn 模式 (装了 KPM 后默认就 enabled)
    python3 tools/test-shadow.py -f com.android.systemui

    # 或附加到运行中的进程
    python3 tools/test-shadow.py -p 1234

    # 指定单测
    python3 tools/test-shadow.py -f com.target --test selfRead
    python3 tools/test-shadow.py -f com.target --test all   (默认)

logcat 配套:
    adb logcat -c && adb logcat -s xiam:I
"""
import argparse
import json
import sys
import time

import frida


def fmt(v, indent=2):
    return json.dumps(v, indent=indent, ensure_ascii=False)


def on_message(msg, data):
    if msg.get("type") == "send":
        print(f"[js->py] {msg['payload']}")
    elif msg.get("type") == "error":
        print(f"[js error] {msg.get('description')}\n{msg.get('stack', '')}",
              file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--spawn",
                    help="spawn target package (e.g. com.example)")
    ap.add_argument("-p", "--pid", type=int,
                    help="attach to existing pid")
    ap.add_argument("-D", "--device-id",
                    help="frida device id (default usb)")
    ap.add_argument("--test", default="all",
                    choices=["all", "status", "selfRead", "hookFires",
                             "segCount", "samePage"],
                    help="which RPC to run")
    ap.add_argument("--lib", default="libc.so")
    ap.add_argument("--func", default="open")
    ap.add_argument("--len", type=int, default=16)
    ap.add_argument("--script",
                    default="tools/test-shadow.js")
    args = ap.parse_args()

    if not args.spawn and not args.pid:
        ap.error("must specify -f <package> or -p <pid>")

    dev = (frida.get_device(args.device_id) if args.device_id
           else frida.get_usb_device())
    print(f"[*] device: {dev}")

    if args.spawn:
        print(f"[*] spawning {args.spawn} ...")
        pid = dev.spawn([args.spawn])
        session = dev.attach(pid)
    else:
        pid = args.pid
        session = dev.attach(pid)

    print(f"[*] attached pid={pid}")

    with open(args.script) as fp:
        src = fp.read()
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()

    if args.spawn:
        dev.resume(pid)
        time.sleep(0.5)

    api = script.exports_sync

    print()
    print("=" * 60)

    if args.test == "all":
        result = api.run_all()
        print(fmt(result))
    elif args.test == "status":
        print(fmt(api.is_shadow_enabled()))
    elif args.test == "selfRead":
        print(fmt(api.test_self_read(args.lib, args.func, args.len)))
    elif args.test == "hookFires":
        print(fmt(api.test_hook_fires(args.lib, args.func)))
    elif args.test == "segCount":
        print(fmt(api.test_segment_count(args.lib)))
    elif args.test == "samePage":
        print(fmt(api.test_same_page(args.lib, "open", "openat")))

    print("=" * 60)
    print("[*] keep running, Ctrl-C to exit (so logcat can drain)")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
