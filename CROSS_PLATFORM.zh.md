# macOS / Ubuntu 0.13.0 测试版

目标为 Apple 芯片 macOS（arm64）和 Ubuntu 24.04 LTS（amd64）。Windows 稳定版继续使用 0.12.1；跨平台测试包不替换稳定下载入口。

## 功能范围

| 能力                                                     | Apple 芯片 Mac                             | Ubuntu 24.04                                     |
| -------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------ |
| Claude / ChatGPT 独立 IP、启停、检测失败策略、诊断和日志 | 支持                                       | 支持                                             |
| Chrome / Edge 网页防护                                   | 支持，需准备宿主和加载扩展                 | 支持，需准备宿主和加载扩展                       |
| IP Guard / 专用启动器的启动前校验                        | 支持                                       | 支持                                             |
| IP 不符、暂停或守护失联时结束受控进程                    | 受控进程组                                 | 优先 systemd 用户 cgroup，不可用时显示进程组模式 |
| Claude Code 交互终端                                     | Terminal / `.command`                      | 系统终端 / `.sh`                                 |
| 原快捷方式的系统级启动拦截                               | 未提供                                     | 未提供                                           |
| 系统级应用网络过滤                                       | 可选原生扩展；需本机签名、公证、授权和验证 | 当前测试版未提供                                 |

进程组模式不能保证管理主动另建会话的子进程；cgroup 模式管理该控制组内的后代进程。普通受控启动不接管从原快捷方式自行启动的实例，不结束同名的无关程序。

关闭“获取不到 IP 时自动结束”只保留已运行的受控进程，界面标记出口未确认；网页和新启动仍须通过校验，已确认 IP 不符仍结束对应服务。守护退出与失联不受该开关豁免。

## 安装

### Mac

1. 下载 `IP-Guard-0.13.0-macOS-arm64.zip`，解压，将 `IP Guard.app` 放入 `/Applications`。
2. 测试包使用 ad-hoc 签名，尚未以你的 Developer ID 签名和公证。若系统拦截，可使用“系统设置 → 隐私与安全 → 仍要打开”；若不可用，先完成下方签名流程。不要求关闭 SIP 或全局关闭 Gatekeeper。
3. 普通用户打开应用，分别获取并锁定两个服务的 IPv4。添加程序时可选择 `.app`，预设会定位实际主入口。
4. 开启程序防护，通过 IP Guard 启动。Claude Code 使用终端；也可点击“受控启动器”，双击带服务名的 `.command` 文件。

### Ubuntu

推荐下载 `.deb`：

```sh
sudo apt install ./IP-Guard-0.13.0-Ubuntu-amd64.deb
```

从应用菜单或 `ip-guard` 命令启动，以普通用户运行 GUI，无需 `sudo`。分别锁定服务 IP，添加可执行文件并开启防护，再通过 IP Guard 启动。Claude Code 使用系统默认终端；缺少图形终端时，在已有终端执行“受控启动器”目录下相应的 `.sh` 文件。

另提供 `tar.gz` 供开发和便携测试。Ubuntu 24.04 的桌面沙箱配置随安装方式不同，普通用户优先使用 `.deb`，不要用关闭 Electron 沙箱的参数解决安装问题。

### 浏览器

在“防护设置 → 浏览器防护”点击“准备安装扩展”，注册当前用户宿主并打开目录。Chrome / Edge 扩展管理页启用开发者模式，加载该目录。更新后重新加载扩展，刷新原检测页。IP Guard 需持续运行；未配置、暂停、失联或过期时保持阻断。

Ubuntu 首个支持范围是原生安装的 Chrome / Edge。Snap / Flatpak 浏览器的宿主隔离、Firefox 和 Safari 不在本次测试范围。

## Mac 系统过滤：最后配置账号签名

原生组件使用 NetworkExtension 数据过滤器和经过代码签名核对的 XPC 通道。策略按当前用户、应用包和服务区分；许可超过 3.5 秒未更新或通道断开时，已登记应用包保持拒绝。已放行流量仍保留后续数据判定回调，以便撤销。

仅纳入已开启防护的 `.app` 应用包及包内辅助程序。CLI / 解释器脚本继续使用受控启动，不纳入此系统过滤器。其他代理进程代发连接的效果需另行验证。关闭自动结束可保留进程，但系统过滤器仍拒绝出口未确认的网络。

**编译和策略测试通过，不等于系统过滤已经在你的 Mac 生效。** 完成 Developer ID 签名、公证及系统授权后，才能启用并实测该功能。未签名时设置页保持“尚未确认启用”，基础功能仍可使用。

Team ID 和证书按本次约定留到最后配置。包内已包含：

- 源码与签名脚本：`Contents/Resources/mac-source/`。
- 预编译组件：`Contents/Resources/mac-build/`。
- Host App ID：`com.ip-guard.desktop`。
- Extension App ID：`com.ip-guard.desktop.filter`。
- 两者使用同一 Team ID 与 App Group：`<TEAM_ID>.com.ip-guard.desktop`。

两个描述文件需允许 Content Filter 能力，宿主还需允许安装系统扩展。脚本核对 Team ID / App ID，最终权限由 macOS 检查。私钥留在 Mac 钥匙串，不需要上传到仓库或聊天。

保留原始 ZIP，对解压到 `/Applications` 的副本签名：

```sh
export IP_GUARD_TEAM_ID='你的10位TeamID'
export IP_GUARD_SIGN_IDENTITY='Developer ID Application: 证书名称 (你的TeamID)'
export IP_GUARD_APP_PROFILE='/绝对路径/Host.provisionprofile'
export IP_GUARD_FILTER_PROFILE='/绝对路径/Filter.provisionprofile'
export IP_GUARD_NOTARY_PROFILE='本机notarytool钥匙串凭据配置名'
bash '/Applications/IP Guard.app/Contents/Resources/mac-source/sign-local.sh' '/Applications/IP Guard.app'
```

脚本把组件放入正确位置、按层级签名；提供本机公证配置时会提交公证并装订票据。没有公证配置时明确提示，不自动启用扩展，可在准备好配置后再次执行。

完成后重新打开 IP Guard，在“防护设置 → macOS 系统网络过滤”启用，按系统提示允许扩展和网络过滤。以策略通道确认状态为准。关闭过滤器恢复这些应用的普通联网，网页插件与受控启动独立保留。

## 配置与验证边界

- Mac：`~/Library/Application Support/IP Guard/`；Ubuntu：`~/.config/IP Guard/`。
- `posix-settings.json` 按服务保存规则，采用私有目录和原子替换；`launchers/` 文件带服务前缀；`events.jsonl` 为事件日志，`app-<ID>.log` 为应用启动输出。
- 隔离开发可设置绝对路径 `IP_GUARD_USER_DATA_DIR`。本地连接按用户隔离，同一用户不要同时运行多个守护器。
- 自动化覆盖真实 OS 进程、独立终止、检测失败选项、退出、慢探针、生成启动器、配置重载、浏览器请求规则，以及打包后 GUI / IPC / Native Messaging。外部出口服务和网页使用测试输入。
- 真实 Claude / ChatGPT 账户、TUN / VPN 分流、睡眠唤醒、升级卸载和已授权 Mac 系统过滤仍需目标机器验证。探针和目标应用应使用一致的代理与分流路径。

接口依据：[Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)、[Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)、[Apple NetworkExtension 示例](https://developer.apple.com/documentation/networkextension/filtering-network-traffic)。
