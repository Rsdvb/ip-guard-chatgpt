# Claude / ChatGPT 浏览器防护

适用于 Windows 上的 Chrome / Edge。ChatGPT 支持需要本地修改版 IP Guard 0.11.0 及配套扩展；请一起更新桌面程序与扩展。

## 安装

1. 先保存 Claude 会话，再安装新版 IP Guard。覆盖安装会结束受保护程序。
2. 打开 IP Guard，在设置中点击「准备安装扩展」或「打开扩展文件夹」。它会注册当前 Windows 用户的浏览器连接，并打开扩展文件夹。
3. Chrome 打开 `chrome://extensions`，Edge 打开 `edge://extensions`。
4. 开启「开发者模式」，选择「加载已解压的扩展」，选中上一步打开的文件夹。
5. 将 IP Guard 扩展固定到工具栏，在桌面程序中分别为 Claude / ChatGPT 锁定允许的 IPv4；扩展显示「校验通过」后打开对应服务。弹窗可选择查看或打开 Claude / ChatGPT。

也可从 Releases 下载 `IP-Guard-Browser-<版本>.zip`，解压到长期保留的目录，再加载该目录。更新 ZIP 后在扩展管理页点击重新加载。桌面更新通过软件内更新完成。

## 防护规则

- 请求规则覆盖 `claude.ai`、`chatgpt.com`、`chat.openai.com` 及其子域，按桌面的两套独立规则授权；未锁定或暂停的服务保持阻断。
- ChatGPT 使用自己的出口结果与锁定 IP，Claude 使用自己的结果；允许两边使用不同的分流出口，任一失败只阻断对应服务。
- 扩展分别遵从桌面两套服务规则的锁定地址、启停和检测间隔，不覆盖 OpenAI API、移动端或未安装此扩展的浏览器。
- 连接未就绪、地址未锁定、IP 不匹配、检测失败或结果过期时阻断。
- 阻断时已打开的受保护页面切换到本地结果页，中断页面连接，未发送内容可能丢失。
- 匹配后点击「返回 Claude / ChatGPT」恢复原页面；后台持续检测。直接命中默认规则时返回相应服务主页。
- 无痕 / InPrivate 窗口需要在扩展详情中单独允许。
- 扩展需保持启用，IP Guard 需持续运行；退出桌面程序后两个服务网页保持阻断。首次连接或协议不兼容时，两个服务默认都阻断。

## 连接与隐私

使用浏览器 Native Messaging 和当前用户的只读命名管道。扩展接收防护状态、当前 IP、锁定 IP 和检测时间，不读取聊天内容，不接管系统代理。宿主仅接受固定扩展 ID `blmgamidelconfabgilaacbkokomegep`。

官方依据：[Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)、[请求规则](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)、[后台生命周期](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)。

## 开发

仓库根运行 `pnpm exec vp run --filter @ip-guard/browser-extension build`，输出 `apps/browser-extension/dist`。桌面打包会同时生成扩展 ZIP，并将扩展文件包含进安装包。
