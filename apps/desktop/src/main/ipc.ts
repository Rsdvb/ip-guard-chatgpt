import { spawn } from "node:child_process";
import path from "node:path";

import { app, BrowserWindow, dialog, ipcMain, shell } from "electron";

import { commandSchema, desktopChannels, serviceName } from "@ip-guard/electron";
import type { Reply, Service } from "@ip-guard/electron";

import type { BrowserBridge } from "#src/main/browser-bridge.ts";
import type { CoffeeDiagnostics } from "#src/main/coffee.ts";
import type { Guardian } from "#src/main/guardian.ts";
import { NativeCommandError } from "#src/main/guardian.ts";
import { posixAutostart } from "#src/main/posix-autostart.ts";
import { resolvePosixExecutable } from "#src/main/posix-presets.ts";
import { applicationPresets } from "#src/main/presets.ts";
import type { ProtectionProbe } from "#src/main/protection-probe.ts";
import { isTrustedUrl } from "#src/main/renderer-route.ts";
import {
  cachedServiceProcessStatus,
  serviceProcessStatus,
  stopServiceTrees,
} from "#src/main/service-processes.ts";
import type { SystemProtection } from "#src/main/system-protection.ts";
import type { ApplicationUpdates } from "#src/main/updates.ts";

export const setupIpc = (
  devOrigin: string | null,
  guardian: Guardian,
  coffee: Record<Service, CoffeeDiagnostics>,
  probe: ProtectionProbe,
  updates: ApplicationUpdates,
  browser: BrowserBridge,
  systemProtection: SystemProtection,
) => {
  const sendVisible = (channel: string, value: unknown) => {
    for (const window of BrowserWindow.getAllWindows())
      if (window.isVisible() && !window.isMinimized()) window.webContents.send(channel, value);
  };
  app.on("browser-window-created", (_event, window) => {
    const resume = () => {
      if (!window.isVisible() || window.isMinimized()) return;
      if (guardian.snapshot) window.webContents.send(desktopChannels.update, guardian.snapshot);
      for (const diagnostics of Object.values(coffee)) {
        window.webContents.send(desktopChannels.coffee, diagnostics.report);
        if (diagnostics.report.phase !== "idle") diagnostics.start();
      }
      window.webContents.send(desktopChannels.appUpdate, updates.state);
    };
    const pause = () => {
      if (BrowserWindow.getAllWindows().some((item) => item.isVisible() && !item.isMinimized()))
        return;
      for (const diagnostics of Object.values(coffee)) diagnostics.pause();
    };
    window.on("show", resume);
    window.on("restore", resume);
    window.on("hide", pause);
    window.on("minimize", pause);
  });
  updates.on("update", (state) => {
    sendVisible(desktopChannels.appUpdate, state);
  });
  const stoppingServices = new Set<Service>();
  for (const diagnostics of Object.values(coffee))
    diagnostics.on("update", (report) => {
      sendVisible(desktopChannels.coffee, report);
    });
  guardian.on("snapshot", (snapshot) => {
    sendVisible(desktopChannels.update, snapshot);
  });
  ipcMain.handle(desktopChannels.invoke, async (event, input: unknown): Promise<Reply> => {
    if (
      event.senderFrame !== event.sender.mainFrame ||
      !isTrustedUrl(event.senderFrame?.url ?? "", devOrigin)
    )
      throw new Error("Untrusted IPC sender");
    const command = commandSchema.parse(input);
    if (command.action === "system:status")
      return { systemProtection: await systemProtection.status() };
    if (command.action === "system:set") {
      if (process.platform === "win32") throw new Error("Windows 使用原生门卫和防火墙管理系统防护");
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "IP Guard 系统防护",
        message: command.enabled ? "启用原入口应用的系统防护？" : "停止登记程序并关闭系统防护？",
        detail: command.enabled
          ? "请先关闭受保护程序。" +
            (process.platform === "linux"
              ? "将通过管理员授权启用独立系统服务，原入口执行前校验许可，网络由内核过滤。"
              : "需完成本机签名并在系统设置中允许网络扩展，原入口应用也按独立 IP 结果过滤网络并处理停止策略。") +
            "Claude / ChatGPT 仍各自使用独立规则。"
          : "将先停止两个服务由系统组件登记的程序，再恢复普通启动和联网。网页插件和受控启动继续工作。请先保存会话。",
        buttons: ["取消", command.enabled ? "启用并授权" : "停止并关闭"],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response !== 1)
        return { cancelled: true, systemProtection: await systemProtection.status() };
      return { systemProtection: await systemProtection.setEnabled(command.enabled) };
    }
    if (command.action === "extension:status") return { extension: await browser.status() };
    if (command.action === "extension:setup") {
      await guardian.request("browser:register");
      const directory = app.isPackaged
        ? path.join(process.resourcesPath, "browser-extension")
        : path.resolve(import.meta.dirname, "../../../browser-extension/dist");
      const error = await shell.openPath(directory);
      if (error) throw new Error(error);
      return {};
    }
    if (command.action === "update:status") return { appUpdate: updates.state };
    if (command.action === "update:check") return { appUpdate: await updates.check() };
    if (command.action === "update:download") return { appUpdate: await updates.download() };
    if (command.action === "update:install") return { appUpdate: await updates.install() };
    if (command.action === "update:releases") return { appUpdate: await updates.releases() };
    if (command.action === "unlock" || (command.action === "service:enable" && !command.enabled)) {
      const snapshot = await guardian.request("status");
      if (command.action === "unlock" && !snapshot.services[command.service].rulesLocked)
        return { snapshot };
      if (process.platform === "win32" && !snapshot.admin)
        throw new Error("请以管理员身份重启 IP Guard");
      const pause = command.action === "service:enable";
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: pause ? "暂停服务" : "取消 IP 锁定",
        message: `${pause ? "暂停" : "取消锁定并停止"} ${serviceName(command.service)}？`,
        detail: `只结束该服务的${process.platform === "win32" || systemProtection.active ? "受保护进程并封锁其连接" : "受控进程并阻断其网页；系统防护未启用时不接管原入口实例"}。${pause ? "保留该服务的锁定地址，可重新启动防护。" : "取消该服务锁定后需重新锁定才能启动。"}另一服务不受影响。请先保存会话。`,
        buttons: ["取消", pause ? "暂停并阻断" : "取消锁定并停止"],
        defaultId: 0,
        cancelId: 0,
      });
      if (answer.response !== 1)
        return { cancelled: true, snapshot: await guardian.request("status") };
      return {
        snapshot: await guardian.request(command.action, {
          service: command.service,
          ...(command.action === "service:enable" ? { enabled: false } : {}),
        }),
      };
    }
    if (command.action === "process:status") {
      const window = BrowserWindow.fromWebContents(event.sender);
      return {
        processes:
          systemProtection.processStatus(command.service) ??
          (window?.isVisible() && !window.isMinimized()
            ? await serviceProcessStatus(command.service)
            : cachedServiceProcessStatus(command.service)),
      };
    }
    if (command.action === "process:stop") {
      const service = command.service;
      const name = serviceName(service);
      if (stoppingServices.has(service)) throw new Error(`${name} 停止操作正在处理中`);
      stoppingServices.add(service);
      try {
        const current =
          systemProtection.processStatus(service) ?? (await serviceProcessStatus(service));
        if (current.phase === "stopped") return { processes: current };
        if (!current.canStop) throw new Error(current.message || `${name} 进程状态暂未确认`);
        const answer = await dialog.showMessageBox({
          type: "warning",
          title: `停止 ${name}`,
          message: `停止 ${name} 进程树？`,
          detail:
            process.platform === "win32"
              ? `将结束当前登录用户、当前 Windows 会话的 ${name}${service === "claude" ? " CLI、Desktop" : " Desktop"} 及其子进程，包含未添加到防护列表的实例。另一服务不会被选中。未保存的会话可能丢失。`
              : `停止${systemProtection.active ? "系统防护与受控启动登记的" : "由 IP Guard 或启动器启动的"} ${name} 实例。另一服务不受影响。未保存的会话可能丢失。`,
          buttons: ["取消", "停止"],
          defaultId: 0,
          cancelId: 0,
        });
        if (answer.response !== 1)
          return {
            cancelled: true,
            processes:
              systemProtection.processStatus(service) ?? (await serviceProcessStatus(service)),
          };
        await systemProtection.stopScope({ service });
        return {
          processes:
            (await guardian.stopManagedService(service)) ?? (await stopServiceTrees(service)),
        };
      } finally {
        stoppingServices.delete(service);
      }
    }
    if (command.action === "ip:current") {
      const result = await probe.check(command.service);
      if (!result.ip) throw new Error(result.error);
      return { ipv4: result.ip };
    }
    if (command.action === "presets") return { presets: await applicationPresets() };
    if (command.action === "coffee:status") {
      const window = BrowserWindow.fromWebContents(event.sender);
      if (window?.isVisible() && !window.isMinimized()) coffee[command.service].start();
      return { diagnostics: coffee[command.service].report };
    }
    if (command.action === "coffee:refresh")
      return { diagnostics: coffee[command.service].refresh() };
    if (command.action === "restart") {
      app.relaunch();
      app.quit();
      return {};
    }
    if (command.action === "pick") {
      const result = await dialog.showOpenDialog({
        title: "选择受保护程序",
        properties: process.platform === "darwin" ? ["openFile", "openDirectory"] : ["openFile"],
        ...(process.platform === "win32"
          ? { filters: [{ name: "Windows 程序", extensions: ["exe"] }] }
          : {}),
      });
      const selected = result.filePaths[0];
      return result.canceled || !selected
        ? { cancelled: true }
        : {
            selectedPath:
              process.platform === "win32" ? selected : await resolvePosixExecutable(selected),
          };
    }
    if (command.action === "launchers") {
      if (process.platform === "win32") throw new Error("Windows 版使用原快捷方式启动");
      const error = await shell.openPath(path.join(app.getPath("userData"), "launchers"));
      if (error) throw new Error(error);
      return {};
    }
    if (command.action === "logs") {
      const error = await shell.openPath(
        process.platform === "win32"
          ? path.join(
              process.env.LOCALAPPDATA ?? path.join(app.getPath("home"), "AppData/Local"),
              "IPGuard",
            )
          : app.getPath("userData"),
      );
      if (error) throw new Error(error);
      return {};
    }
    if (command.action === "elevate") {
      if (process.platform !== "win32")
        throw new Error("macOS 和 Ubuntu 测试版以普通用户运行，无需提升界面权限");
      if (!app.isPackaged) throw new Error("开发模式请从管理员终端启动。");
      await guardian.stop();
      app.releaseSingleInstanceLock();
      const escaped = process.execPath.replaceAll("'", "''");
      try {
        await new Promise<void>((resolve, reject) => {
          const child = spawn(
            "powershell.exe",
            [
              "-NoProfile",
              "-NonInteractive",
              "-Command",
              `Start-Process -FilePath '${escaped}' -Verb RunAs -ErrorAction Stop`,
            ],
            { windowsHide: true, stdio: "ignore" },
          );
          child.on("error", reject);
          child.on("exit", (code) =>
            code === 0 ? resolve() : reject(new Error("管理员授权已取消。")),
          );
        });
        app.quit();
        return {};
      } catch (error) {
        if (!app.requestSingleInstanceLock()) {
          app.quit();
          throw error;
        }
        guardian.start();
        throw error;
      }
    }
    if ((command.action === "protect" && !command.enabled) || command.action === "remove") {
      const result = await dialog.showMessageBox({
        type: "warning",
        title: "IP Guard",
        message: "解除防护后，该程序将恢复普通启动和联网。",
        buttons: ["取消", "继续"],
        defaultId: 0,
        cancelId: 0,
      });
      if (result.response !== 1) return { cancelled: true };
      await systemProtection.stopScope({ id: command.id });
    }
    if (command.action === "stop") await systemProtection.stopScope({ id: command.id });
    if (command.action === "autostart" && !app.isPackaged)
      throw new Error("请安装打包版本后开启开机启动。");
    if (command.action === "autostart" && process.platform !== "win32")
      await posixAutostart(command.enabled);
    const { action, ...payload } = command;
    const nativePayload: Record<string, unknown> = { ...payload };
    if ("id" in payload) {
      nativePayload.targetId = payload.id;
      delete nativePayload.id;
    }
    if (action === "autostart") nativePayload.executable = process.execPath;
    try {
      return { snapshot: await guardian.request(action, nativePayload) };
    } catch (error) {
      if (!(error instanceof NativeCommandError) || error.code !== "firewall_disabled") throw error;
      const answer = await dialog.showMessageBox({
        type: "warning",
        title: "开启 Windows 防火墙",
        message: error.message,
        detail: error.help,
        buttons: ["打开 Windows 防火墙", "稍后"],
        defaultId: 0,
        cancelId: 1,
      });
      if (answer.response === 0) {
        const windows = process.env.SystemRoot;
        if (!windows || !path.isAbsolute(windows))
          throw new Error("请按 Win+R，输入 wf.msc 打开防火墙管理界面");
        const openError = await shell.openPath(path.join(windows, "System32/wf.msc"));
        if (openError)
          throw new Error(`打开防火墙管理界面失败：${openError}。请按 Win+R，输入 wf.msc`);
      }
      return { cancelled: true, snapshot: await guardian.request("status") };
    }
  });
};
