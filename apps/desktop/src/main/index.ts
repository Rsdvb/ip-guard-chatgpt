import path from "node:path";

import { app, BrowserWindow, dialog, Menu, nativeImage, Tray } from "electron";

import { rendererOrigin } from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";

import { BrowserBridge } from "#src/main/browser-bridge.ts";
import { CoffeeDiagnostics } from "#src/main/coffee.ts";
import { defaultApiOrigin } from "#src/main/config.ts";
import { ExitIPv4 } from "#src/main/exit-ip.ts";
import { Guardian } from "#src/main/guardian.ts";
import { setupIpc } from "#src/main/ipc.ts";
import { ProtectionAlerts } from "#src/main/protection-alerts.ts";
import { ProtectionProbe } from "#src/main/protection-probe.ts";
import { parseHttpOrigin, parseLoopbackOrigin } from "#src/main/renderer-route.ts";
import { serveRenderer } from "#src/main/renderer.ts";
import { SystemProtection } from "#src/main/system-protection.ts";
import { ApplicationUpdates } from "#src/main/updates.ts";
import { createMainWindow } from "#src/main/window.ts";

app.setName("IP Guard");
if (process.platform !== "win32" && process.env.IP_GUARD_USER_DATA_DIR) {
  if (!path.isAbsolute(process.env.IP_GUARD_USER_DATA_DIR))
    throw new Error("IP_GUARD_USER_DATA_DIR must be an absolute path");
  app.setPath("userData", process.env.IP_GUARD_USER_DATA_DIR);
}

const origin = (name: string, parse: (value: string) => string | null) => {
  const value = process.env[name];

  if (value === undefined || value === "") {
    return null;
  }

  const parsed = parse(value);

  if (parsed === null) {
    throw new Error(`${name} is not a valid origin: ${value}`);
  }

  return parsed;
};

const devOrigin = origin("ELECTRON_RENDERER_URL", parseLoopbackOrigin);

const apiOrigin = origin("API_ORIGIN", parseHttpOrigin) ?? parseHttpOrigin(defaultApiOrigin);

if (apiOrigin === null) {
  throw new Error(`defaultApiOrigin is not an origin: ${defaultApiOrigin}`);
}

const claude = new ExitIPv4("claude");
const chatgpt = new ExitIPv4("chatgpt");
const probe = new ProtectionProbe({ claude, chatgpt });
const guardian = new Guardian(probe);
const systemProtection = new SystemProtection(guardian);
const coffee = {
  claude: new CoffeeDiagnostics("claude", claude),
  chatgpt: new CoffeeDiagnostics("chatgpt", chatgpt),
};
const protectionAlerts = new ProtectionAlerts(guardian, () => {
  const win = BrowserWindow.getAllWindows()[0] ?? open();
  if (win) {
    win.show();
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});
let quitting = false;
let quittingNative = false;
let quittingForUpdate = false;
const updates = new ApplicationUpdates(
  () => {
    quittingForUpdate = true;
  },
  () => {
    quittingForUpdate = false;
  },
);
const browserBridge = new BrowserBridge(guardian, updates);
let tray: Tray | undefined;
const background =
  process.argv.includes("--background") ||
  (process.platform === "darwin" && app.getLoginItemSettings().wasOpenedAtLogin);

const open = () => {
  const win = createMainWindow({
    devOrigin,
    preload: path.join(import.meta.dirname, "../preload/index.cjs"),
    url: devOrigin ?? `${rendererOrigin}/`,
    background: false,
  });
  win.on("close", (event) => {
    if (!quitting && !quittingForUpdate) {
      event.preventDefault();
      win.hide();
    }
  });
  return win;
};
const show = () => {
  void updates.check();
  const win = BrowserWindow.getAllWindows()[0] ?? open();
  win.show();
  if (win.isMinimized()) win.restore();
  win.focus();
};

const start = () => {
  setupIpc(devOrigin, guardian, coffee, probe, updates, browserBridge, systemProtection);
  guardian.start();
  updates.start();

  if (devOrigin === null) {
    serveRenderer({
      apiOrigin,
      rendererRoot: path.join(import.meta.dirname, "../renderer"),
    });
  }

  if (!background) open();
  tray = new Tray(
    nativeImage.createFromPath(
      path.join(
        app.isPackaged ? process.resourcesPath : path.join(import.meta.dirname, "../.."),
        "assets/tray.png",
      ),
    ),
  );
  tray.setToolTip("IP Guard · 公网 IPv4 守卫");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: "打开 IP Guard", click: show },
      { type: "separator" },
      {
        label: "退出并结束受保护程序",
        click: async () => {
          if ((guardian.snapshot?.running.length ?? 0) > 0) {
            const choice = await dialog.showMessageBox({
              type: "warning",
              message:
                process.platform === "win32"
                  ? "退出将结束所有受保护程序，启动拦截会继续保留。"
                  : systemProtection.active
                    ? "退出将结束系统组件登记和受控启动的程序；系统过滤和网页保持阻断，直到重新校验或关闭系统防护。"
                    : "退出将结束受控启动的程序，网页保持阻断；原快捷方式启动的程序不在防护范围。",
              buttons: ["取消", "退出"],
              defaultId: 0,
              cancelId: 0,
            });
            if (choice.response !== 1) return;
          }
          app.quit();
        },
      },
    ]),
  );
  tray.on("double-click", show);
  guardian.on("snapshot", (snapshot: Snapshot) => {
    const summary = Object.entries(snapshot.services)
      .map(
        ([key, rule]) =>
          `${key === "claude" ? "Claude" : "ChatGPT"} ${rule.ready ? "匹配" : rule.reason || "待锁定"}`,
      )
      .join(" · ");
    tray?.setToolTip(`IP Guard · ${summary}`.slice(0, 120));
  });
};

if (app.requestSingleInstanceLock()) {
  app.on("ready", start);
  app.on("activate", show);
  app.on("second-instance", show);
  app.on("window-all-closed", () => {
    if (quitting) app.quit();
  });
  app.on("before-quit", (event) => {
    if (quittingNative) return;
    event.preventDefault();
    if (quitting) return;
    quitting = true;
    protectionAlerts.stop();
    browserBridge.close();
    for (const diagnostics of Object.values(coffee)) diagnostics.stop();
    void systemProtection
      .stop()
      .catch((error) => console.error("停止系统防护进程", error))
      .then(() => guardian.stop())
      .finally(() => {
        claude.stop();
        chatgpt.stop();
        quittingNative = true;
        tray?.destroy();
        app.quit();
      });
  });
} else {
  app.quit();
}
