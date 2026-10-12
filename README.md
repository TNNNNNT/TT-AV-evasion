# TT 载荷生成器 —— Cobalt Strike 内存马一键生成（ASPX / PHP / JSP）

把从 Cobalt Strike 导出的 stager/beacon（`.c` 或裸 shellcode）一键封装成**内存马**：
载荷在**站点自身进程内**解密并执行（`VirtualAlloc` → 写入 → 改 RX → `CreateThread`），
**不产生新进程、不经 cmd**。

> ⚠️ **授权使用**：本工具仅用于**已获书面授权的红队评估 / 自有资产测试 / 教学研究**。
> 请勿用于未授权目标。
> ⚠️ **不要投到公开仓库**：GitHub 的可接受使用政策禁止托管恶意软件与规避工具，此类仓库会被下架并可能封号。
> 建议放**私有仓库**或内网 GitLab/Gitea，或直接用打包 zip 分发。

---

## 为什么是"内存马"而不是 exe（实测结论）

在装有 360「极智守护 · Web 服务器入侵防护」的目标上实测：

| 形态 | 结果 |
|---|---|
| `loader.exe`（stager 加载器，stomping / VirtualAlloc 两条链都试过） | ❌ 起不来。360 弹窗点名 `C:\inetpub\...\loader.exe` |
| 把 exe 挪到 `C:\Windows\Temp\` 并用计划任务拉起 | ❌ 仍被拦，弹窗改点名 `C:\Windows\System32\cmd.exe` |
| **内存马（站点进程内执行）** | ✅ 一次上线，稳定不掉（会话进程 = `w3wp.exe`） |

**根因**：那条规则拦的是「**网站进程派生出新进程**」这个上下文组合 —— 只要 w3wp 派生了 cmd（哪怕只是 `copy`、`dir`），就会命中；
exe 根本没被启动，谈不上"被杀"。把执行搬进站点进程内部后，这个锚点消失。

---

## 特性

- **三种载体，各走各的路线**：ASPX（.NET/IIS）、PHP（php-cgi/FFI）、JSP（Tomcat/JNA）
- **零配置**：C2 由 CS 导出时编入 `.c`，工具**不改** host/port/profile（避免"IP 对了却连不上"）
- **载荷强加密**：Speck64/128-CTR + 位置相关 XOR 双层；密钥掩码混淆、运行时反推；**明文 shellcode 不落盘**
- **生成期自检**：反推密钥 → 解密 → 与原文逐字节比对，不一致直接中止
- **带环境探测页生成器**：动手前先判定目标支持哪条路线（实际试调 `VirtualAlloc`，不看配置看结果）
- **纯 Python**：无需任何编译链（无 EXE 模式）

---

## 目录

```
TT免杀/
├── make_beacon.py     主脚本（--aspx / --php / --jsp）
├── templates.py       三种语言的内存马模板
├── probe.py           环境探测页生成器（判定该走哪条路线）
├── payload_gen.py     加密库（Speck64/128-CTR + 位置相关 XOR）
├── make.bat           双击入口（1=ASPX 2=PHP 3=JSP）
├── 快速开始.md         速查：用法 / 三条路线 / 常见问题
├── 原理与实验记录.md    原理解析、实测判定、检测侧指标
└── 目标清理清单.md      目标机上需手动清除的文件与持久化项
```

---

## 快速开始

```bat
:: 双击（按提示选 1/2/3、填 .c 路径，没有其它问题）
make.bat

:: 或命令行
python make_beacon.py --aspx --shellcode "你的aaa.c"     :: -> mem.aspx
python make_beacon.py --php  --shellcode "你的aaa.c"     :: -> mem.php
python make_beacon.py --jsp  --shellcode "你的aaa.c"     :: -> mem.jsp

:: 环境探测（推荐先做这个）
python probe.py --all                                    :: -> probe.aspx / probe.php / probe.jsp
```

**投放（关键）**：用 webshell 的【**文件管理**】上传到网站目录 → **用浏览器访问** → 页面返回 `ok` 即为已在站点进程内执行 → 去 CS 看会话。
**不要用 webshell 的命令行启动任何东西** —— 那会派生 cmd，容易触发行入侵防护。

> 该页面**每次访问都会新起一条 beacon**（等于持久化入口）。用完**手动删除**，清除清单见 `目标清理清单.md`。

---

## 三条路线

| 路线 | 站点 / 执行进程 | 前置条件 | 前置不满足时 |
|---|---|---|---|
| **ASPX** | IIS + ASP.NET / `w3wp.exe` | 无（.NET 自带 P/Invoke） | 站点主语言是 PHP 也没关系：只要装了 ASP.NET，**同目录放 .aspx 照样能用**（IIS 按扩展名映射处理程序）。验证：访问不存在的 `xxx.aspx`，出现 ASP.NET 错误页即可 |
| **PHP** | PHP（IIS FastCGI / php-fpm）/ `php-cgi.exe` | PHP ≥ 7.4 且 `extension=ffi` + `ffi.enable=1` | 页面返回 `no-ffi`：改 php.ini 两行并重启站点/进程池；改不了就换 ASPX（若可用） |
| **JSP** | Tomcat / Jetty / `java.exe` | classpath 有 **JNA**（`com.sun.jna`） | 页面返回 `no-jna`：把 `jna.jar` 放进 `WEB-INF/lib` 后重启应用 |

**判据不是语言，而是「站点进程能否直接调用本机 API 把内存变成可执行」**。
经典 ASP（`.asp`）无法直接调 API，不可行。

### 探测页返回判读

```
route=aspx|php|jsp            页面类型
pinvoke=ok|fail|exception     是否真能调到 VirtualAlloc（硬指标）
verdict=...                   结论：该走哪条 / 差什么
```

其它有意义字段：`fulltrust=False`（ASP.NET 非完全信任，P/Invoke 可能被拒）、`ffi_enable=preload`（FFI 只在 preload 可用，页面里用不了）、`jna=no`。

---

## 工作原理

```
CS 导出 stager/beacon (.c / .bin)         站点进程（w3wp / php-cgi / java）
        │                                          │
        ├─ 生成期：Speck64/128-CTR + XOR 加密       │  HTTP 请求 mem.aspx|php|jsp
        │  密钥掩码混淆（无明文密钥）               │        │
        ▼                                          ▼        │
   mem.aspx / mem.php / mem.jsp  ──上传/访问──►  解密（明文只在内存）│
   （文件里只有密文）                             VirtualAlloc(RW)   │
                                                 Marshal/FFI/JNA 写入
                                                 VirtualProtect → RX（W^X，从不 RWX）
                                                 CreateThread 执行
                                                 （外联由该站点进程发出）
```

- **ASPX**：`Convert.FromBase64String` → `Marshal.Copy` → `VirtualProtect` → `Marshal.GetDelegateForFunctionPointer(kernel32!CreateThread)`
  （`CreateThread` 等 API 名以**数字数组**运行时拼装，文件里没有该字符串）
- **PHP**：`FFI::cdef("kernel32.dll")` → `VirtualAlloc` / `FFI::memcpy` / `VirtualProtect` / `CreateThread`
- **JSP**：`com.sun.jna.NativeLibrary.getInstance("kernel32")` → 同上三步 + `CreateThread`

---

## 常见问题

| 现象 | 处理 |
|---|---|
| `no-ffi` | PHP 未启用 FFI。php.ini：`extension=ffi` + `ffi.enable=1`，重启站点/进程池；否则换 ASPX |
| `no-jna` | Tomcat classpath 缺 JNA。上传 `jna.jar` 到 `WEB-INF/lib`，重启应用 |
| IIS 返回 500 / 编译错误 | 把错误原文贴出来（模板按最小依赖写，通常是载体语言版本差异） |
| `.jsp` 返回 404 | IIS 不跑 JSP，需要 Tomcat/Jetty；若该机也装了 ASP.NET，改用 ASPX |
| 弹"未知程序请求联网，是否允许" | 不是查杀，是安全软件的联网提示，允许即可 |
| 上线后不久掉线 | 换 C2 端口/协议（如 443 + 域名伪装），或检查目标到 C2 的路由/防火墙 |
| 每次访问都多一条会话 | 设计如此（页面即入口）。用完删除文件；如需一次性/口令访问可自行改造 |

---

## 检测侧参考（给蓝队）

这套技术不是"隐身"，它只是把检测面从**进程/命令行**推到了另外三处：

| 检测面 | 信号 | 落地手段 |
|---|---|---|
| **内存**（最关键） | 站点进程内出现匿名私有内存、属性由 RW 变 RX、内含高熵可执行代码；正常 Web 应用不会这样 | EDR 内存扫描（pe-sieve / Moneta 类）、周期性比对私有 RX 页与模块背书 |
| **文件/完整性** | 网站目录新增/变更 `.aspx`/`.php`/`.jsp`；文件里出现"大段密文 + 调 `VirtualAlloc`/`Marshal.Copy`/`CreateThread`"的组合 | FIM / 目录哈希巡检 / webshell 扫描（RASP 可直接在运行时拦下"页面申请可执行内存"） |
| **网络** | 站点进程发起非业务外联：裸 IP、非常用端口、伪装 UA、伪装 CDN 路径、固定心跳 | 出站白名单、代理/NDR 规则、JA3/JA3S、"进程身份 × 目的地址"基线告警 |

加固建议：站点目录对 IIS 账号只读（仅 uploads 可写）、应用池最小权限、启用 RASP、定期 webshell 普查、
对 `w3wp.exe` 建立"内存属性变化 + 外联"的行为基线。

---

## 已知限制（如实标注）

- 判定覆盖面：内存马形态在 **Windows Defender 1.459.676.0** 上实测未被处置；**火绒 / 360 / ESET 等其他引擎未做完整矩阵测试**
  （360 场景仅验证了"绕过其 Web 入侵防护的进程链规则"，不代表静态引擎全部放行）
- `mem.php` / `mem.jsp` 模板**未在真实 PHP / Tomcat 目标上运行验证**（缺少对应目标环境）；ASPX 模板已实测上线
- PHP 路线依赖 FFI，Windows 版 PHP 默认不启用；JSP 路线依赖 JNA，需自行投放 jar
- 载荷若为 stageless 全量 beacon（数百 KB），生成的内存马文件会相应变大（base64/hex 编码导致），属正常现象

---

## License / 分发

内部红队使用。**不含开源许可证**，请勿公开分发。
抓包、日志与目标残留的清理步骤见 `目标清理清单.md`。
