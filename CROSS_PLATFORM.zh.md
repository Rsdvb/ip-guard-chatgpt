# IP Guard 0.14.0 三平台测试版

目标为 Windows 10 / 11 x64、Apple 芯片 macOS arm64、Ubuntu 24.04 LTS amd64。此版本为预发布，稳定下载入口继续保留 0.12.1。

## 功能范围

| 能力                                        | Windows            | Apple 芯片 Mac                                                 | Ubuntu 24.04                                         |
| ------------------------------------------- | ------------------ | -------------------------------------------------------------- | ---------------------------------------------------- |
| 两个服务独立 IP、启停、失败处理、诊断和日志 | 支持               | 支持                                                           | 支持                                                 |
| Chrome / Edge 网页防护                      | 支持               | 支持                                                           | 支持，首个范围是原生安装的浏览器                     |
| IP Guard / 专用启动器启动前校验             | 支持               | 支持                                                           | 支持                                                 |
| 原快捷方式及原终端入口                      | 原生启动门卫       | 签名并启用过滤器后，登记应用的网络受保护；进程监测处理停止策略 | 启用系统服务后，fanotify 在执行前检查许可            |
| 系统级网络阻断                              | 防火墙及受保护 Job | NetworkExtension 按用户及程序过滤，已有流量保留后续判定回调    | cgroup v2 + eBPF 入站 / 出站过滤，撤销已有连接的流量 |

Ubuntu 保护用户自行安装的可执行程序，不附带 Claude / ChatGPT 客户端。Mac 的 `.app` 包及包内辅助程序归属于同一服务，原生 CLI 按实际文件登记，通用解释器脚本继续使用受控启动器。其他进程代发连接、插件宿主和特殊代理的路径需在目标机器核对，不应把通用解释器或代理整体归入一个服务。

CLI 优先选择 `~/.local/bin/claude` 等稳定入口。旧记录若直接指向某个版本目录，先停用旧记录，再重新添加稳定入口，以适配后续更新。

系统组件未启用时，Mac / Ubuntu 继续提供网页和受控启动防护，不接管原快捷方式打开的实例。Ubuntu 优先使用 systemd 用户 cgroup 管理受控后代进程，缺失时明确显示进程组模式；主动另建会话的进程可能脱离进程组。

## Windows

安装 `IP-Guard-Setup-0.14.0.exe`，正常打开会请求管理员权限。管理应用拦截和防火墙需要授权，防火墙三个配置文件应保持开启。分别锁定服务 IP，再添加并启用相应程序。当前安装包没有代码签名。

启动时检查权限，不足时显式请求 UAC 并重新打开完整安装目录中的主程序；取消授权不启动守护。主 EXE 保留 `asInvoker` 清单，避免沙箱子进程继承强制管理员要求导致错误码 18；界面的进程沙箱仍启用。开发模式继续从管理员终端运行。

Windows 0.14.1 修复客户端升级后旧版本路径使守护启动失败的问题。启动时、每分钟及点击启动前，按当前用户已注册的包族、架构与同一 EXE 入口更新路径，保留服务规则；无法恢复的程序单独显示「防护异常」，不影响其他程序及网页防护。商店更新后先确认程序行无异常，再启动应用。Mac / Ubuntu 安装包继续使用 0.14.0。

## Ubuntu

```sh
sudo apt install ./IP-Guard-0.14.0-Ubuntu-amd64.deb
```

GUI 以普通用户打开，不使用 `sudo ip-guard`。DEB 包含原生服务和 polkit 授权入口；便携 `tar.gz` 保留网页及受控启动。

分别锁定服务 IP，添加程序、确认归属并开启防护。保存工作并关闭登记程序的已有实例，在「防护设置 → Ubuntu 系统防护」启用并授权，等待「策略通道已确认」后再从原入口启动。已有套接字不能通过事后移动进程安全接管，因此首次启用会拒绝接管外部已有实例。每个程序进入独立控制组，后代继承该控制组。

内核需支持 cgroup v2、fanotify 执行权限事件及 cgroup eBPF，并允许加载。容器、内核或安全策略不支持时会显示失败，不会把受控启动显示为系统保护。

系统服务按用户隔离。固定入口为 `/usr/lib/ipguard/ipguard-system`、`/etc/systemd/system/ipguard@.service`；`/run/ipguard/<UID>.sock` 仅对应用户可连接，并核对内核提供的对端 UID。root 配置为 `/var/lib/ipguard/<UID>.json`，只持久化登记信息，不保存联网许可。自身的控制组、BPF 对象分别位于 `/sys/fs/cgroup/ipguard-<UID>/` 和 `/sys/fs/bpf/ip_guard/<UID>/`。

GUI 策略超过 3.5 秒未确认即撤销。服务独立于 GUI，退出时保留固定的拒绝过滤对象，由 systemd 重启恢复。管理员强停、服务升级重建执行事件监听期间存在间隙，本工具不构成抵御管理员修改系统的安全边界。

设置中的关闭操作先停止登记程序，再恢复普通启动及联网。若服务损坏或登记文件被删除导致无法连接，保存工作后执行：

```sh
sudo /usr/lib/ipguard/ipguard-system recover "$(id -u)"
```

这会关闭该用户的 IP Guard 系统服务，结束其登记控制组并移除本软件的过滤对象，保留设置以便修复后重新启用。正常卸载 DEB 执行相应恢复；升级保留设置并重启已启用服务。

## Mac：最后配置签名

解压 `IP-Guard-0.14.0-macOS-arm64.zip`，把 `IP Guard.app` 放入 `/Applications`。测试包采用 ad-hoc 签名，可先测试基础的独立 IP、网页防护和受控启动。添加程序时可选 `.app`；Claude Code 使用 Terminal / `.command` 入口。

系统过滤器核对 XPC 控制器签名、用户、策略版本和 3.5 秒许可期限。路径索引在策略更新时建立，进程扫描有缓存并响应应用启动通知；失联撤销网络许可，控制器仍存活时也执行登记进程的停止处理。

**编译、策略和进程测试通过，不等于系统过滤已经在你的 Mac 生效。** Team ID、证书和描述文件按约定留到最后在 Mac 配置。需要 Developer ID 签名、公证，以及系统设置中的扩展和网络过滤授权；不需要上传密码、私钥或验证码，也不要求关闭 SIP 或全局关闭 Gatekeeper。

源码及脚本位于 `Contents/Resources/mac-source/`，预编译组件位于 `Contents/Resources/mac-build/`。Host App ID 为 `com.ip-guard.desktop`，Extension App ID 为 `com.ip-guard.desktop.filter`，共用 `<TEAM_ID>.com.ip-guard.desktop` App Group。两个描述文件需 Content Filter 能力，宿主还需系统扩展安装权限，最终由 macOS 核验。

保留原 ZIP，对 `/Applications` 中的副本签名：

```sh
export IP_GUARD_TEAM_ID='你的10位TeamID'
export IP_GUARD_SIGN_IDENTITY='Developer ID Application: 证书名称 (你的TeamID)'
export IP_GUARD_APP_PROFILE='/绝对路径/Host.provisionprofile'
export IP_GUARD_FILTER_PROFILE='/绝对路径/Filter.provisionprofile'
export IP_GUARD_NOTARY_PROFILE='本机notarytool钥匙串凭据配置名'
bash '/Applications/IP Guard.app/Contents/Resources/mac-source/sign-local.sh' '/Applications/IP Guard.app'
```

脚本核对身份并按层级签名，提供公证配置时提交公证和装订票据。重新打开应用，在「防护设置 → macOS 系统防护」启用，并按系统提示授权。首次启用前退出登记程序，以策略通道确认状态为准。

## 浏览器

在「防护设置 → 浏览器防护」点击「准备安装扩展」，注册用户宿主。在 Chrome / Edge 扩展管理页开启开发者模式并加载解压目录。更新文件后点击「重新加载」，刷新旧检测页。新版提示插件更新，并链接本私有仓库，需要你的 GitHub 登录权限。

插件分别处理 `claude.ai`、`chatgpt.com`、`chat.openai.com`。稳定心跳继续维持许可，不再反复扫描标签、写角标或重绘未变的检测页。Snap / Flatpak 浏览器宿主隔离、Firefox、Safari 不在此次测试范围。

## 失败策略与资源

两个服务各自保存「获取不到 IP 时自动结束」开关。关闭后保留已有进程，新启动和网页继续要求有效校验；已确认 IP 不符、暂停、取消锁定及守护失联仍停止对应进程。Mac / Ubuntu 启用系统组件时，保留进程也会阻断出口未确认的网络。

- Windows 网卡和路由扫描改为网络事件触发、每分钟兜底；前台状态改为原生一次扫描供两个服务共享，移除频繁 PowerShell / WMI 查询。
- POSIX 网卡每 5 秒检查，空闲未变状态不再持续推送完整快照；原生心跳不重复全局扫描进程或保存配置。
- 隐藏或最小化后暂停界面推送、进程查询及扩展诊断自动刷新；打开时补发状态。已经开始的诊断可能运行至完成。
- 直接后台启动不创建隐藏渲染窗口；已经打开过的窗口隐藏后保留界面状态，内存通常高于冷启动到托盘。

资源报告记录前台、隐藏到托盘和冷启动到托盘，包含 Electron 与原生子进程；Ubuntu 开启系统服务时另计 root 守护器。CI 是无登记程序的隔离虚拟机空闲场景，不能代替你的 TUN、真实客户端负载或签名启用后的 Mac 网络过滤性能。

## 配置和验证

Mac 设置位于 `~/Library/Application Support/IP Guard/`，Ubuntu 位于 `~/.config/IP Guard/`。`posix-settings.json` 按服务保存规则，`launchers/` 保存启动器，`events.jsonl` 保存日志。POSIX 隔离测试可指定绝对路径 `IP_GUARD_USER_DATA_DIR`。同一用户不要运行多个守护器。

发布附验证记录：单元、真实 Chromium、C# 策略、真实 POSIX 进程、Mac 原生策略 / 进程、Ubuntu 内核执行和网络阻断、安装包 GUI / IPC / Native Messaging、托盘与安装服务路径。真实账户、TUN / VPN 分流、睡眠唤醒及 Mac 已签名过滤仍需目标机器验证。探针和应用应使用一致的代理及分流路径。

接口依据：[Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)、[Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)、[Apple NetworkExtension](https://developer.apple.com/documentation/networkextension/filtering-network-traffic)。
