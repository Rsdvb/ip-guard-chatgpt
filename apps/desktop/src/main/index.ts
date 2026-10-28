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
import { ensureWindowsAdministrator } from "#src/main/windows-bootstrap.ts";

app.setName("IP Guard");
if (process.platform !== "win32" && process.env.IP_GUARD_USER_DATA_DIR) {
  if (!path.isAbsolute(process.env.IP_GUARD_USER_DATA_DIR))
    throw new Error("IP_GUARD_USER_DATA_DIR must be an absolute path");
  app.setPath("userData", process.env.IP_GUARD_USER_DATA_DIR);
}

async function runDesktop() {
  if (!(await ensureWindowsAdministrator())) {
    app.quit();
    return;
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
    async () => {
      quittingForUpdate = true;
      browserBridge.close();
      await guardian.stop();
    },
    () => {
      quittingForUpdate = false;
      guardian.start();
    },
  );
  const browserBridge = new BrowserBridge(guardian, updates);
  let tray: Tray | undefined;
  let exitPending = false;
  const quitAndRelease = async () => {
    if (exitPending) return false;
    exitPending = true;
    try {
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "完全退出并解除防护",
        message: "完全退出 IP Guard 并解除 Claude / ChatGPT 防护？",
        detail:
          "请先保存会话。将结束当前受保护的程序，解除启动拦截、网络阻断和浏览器限制。退出后可从原快捷方式正常打开应用。两项服务的 IP 设置会保留，重新打开 IP Guard 后恢复防护。",
        buttons: ["取消", "完全退出并解除防护"],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response !== 1) return false;
      if (systemProtection.active) await systemProtection.setEnabled(false);
      await guardian.releaseProtection();
      await browserBridge.release();
      app.quit();
      return true;
    } catch (error) {
      dialog.showErrorBox(
        "解除防护未完成，尚未退出",
        error instanceof Error ? error.message : "请重试退出，或运行安装目录的恢复工具",
      );
      return false;
    } finally {
      exitPending = false;
    }
  };
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
    void updates.check(false);
    const win = BrowserWindow.getAllWindows()[0] ?? open();
    win.show();
    if (win.isMinimized()) win.restore();
    win.focus();
  };

  const start = () => {
    setupIpc(
      devOrigin,
      guardian,
      coffee,
      probe,
      updates,
      browserBridge,
      systemProtection,
      quitAndRelease,
    );
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
          label: "完全退出并解除防护",
          click: () => {
            void quitAndRelease();
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
      updates.stop();
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
    await app.whenReady();
    start();
  } else {
    app.quit();
  }
}
void runDesktop().catch((error: unknown) => {
  dialog.showErrorBox(
    "IP Guard 启动失败",
    error instanceof Error ? error.message : "无法启动本机守护器",
  );
  app.quit();
});
