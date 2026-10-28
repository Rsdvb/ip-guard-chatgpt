import { EventEmitter } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { app, dialog, shell, net } from "electron";
import updater from "electron-updater";
import { z } from "zod";

import type { UpdateState } from "@ip-guard/electron";

import { platformRelease, updateRepositorySchema } from "./update-policy.ts";

const { autoUpdater } = updater;
export class ApplicationUpdates extends EventEmitter<{ update: [UpdateState] }> {
  state: UpdateState = {
    phase: "unconfigured",
    currentVersion: app.getVersion(),
    latestVersion: "",
    progress: 0,
    checkedAt: "",
    message: "GitHub 更新源未配置",
    repository: "",
    canInstall: process.platform === "win32",
  };
  private started = false;
  private downloadedVersion = "";
  private onInstalling: () => Promise<void>;
  private onInstallError: () => void;
  private lastAttempt = 0;
  private timer: ReturnType<typeof setInterval> | undefined;
  private initial: ReturnType<typeof setTimeout> | undefined;
  constructor(onInstalling: () => Promise<void>, onInstallError: () => void) {
    super();
    this.onInstalling = onInstalling;
    this.onInstallError = onInstallError;
  }
  start() {
    if (this.started) return;
    this.started = true;
    const info = path.join(process.resourcesPath, "release-info.json");
    if (
      !app.isPackaged ||
      !existsSync(info) ||
      (process.platform === "win32" &&
        !existsSync(path.join(process.resourcesPath, "app-update.yml")))
    )
      return;
    try {
      const data: unknown = JSON.parse(readFileSync(info, "utf8"));
      const repository = z.object({ repository: updateRepositorySchema }).parse(data).repository;
      this.state = { ...this.state, phase: "idle", repository, message: "" };
    } catch (error) {
      this.state.message =
        error instanceof Error ? `更新源配置无效：${error.message}` : "更新源配置无效";
      return;
    }
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowDowngrade = false;
    autoUpdater.allowPrerelease = true;
    autoUpdater.on("checking-for-update", () =>
      this.set({ phase: "checking", message: "正在检查 GitHub Releases" }),
    );
    autoUpdater.on("update-available", (info) =>
      this.set({
        phase: this.downloadedVersion === info.version ? "downloaded" : "available",
        latestVersion: info.version,
        checkedAt: new Date().toISOString(),
        message: this.downloadedVersion === info.version ? "更新已下载" : "发现新版本",
      }),
    );
    autoUpdater.on("update-not-available", () =>
      this.set({ phase: "current", checkedAt: new Date().toISOString(), message: "已是最新版本" }),
    );
    autoUpdater.on("download-progress", (progress) =>
      this.set({
        phase: "downloading",
        progress: Math.max(0, Math.min(100, progress.percent)),
        message: "正在下载更新",
      }),
    );
    autoUpdater.on("update-downloaded", (info) => {
      this.downloadedVersion = info.version;
      this.set({
        phase: "downloaded",
        latestVersion: info.version,
        progress: 100,
        message: "更新已下载",
      });
    });
    autoUpdater.on("error", (error) => {
      if (this.state.phase === "installing") this.onInstallError();
      this.set({ phase: "error", message: error.message.slice(0, 220) });
    });
    this.initial = setTimeout(() => void this.check(false), 15000);
    this.initial.unref();
    this.timer = setInterval(() => void this.check(false), 6 * 60 * 60 * 1000);
    this.timer.unref();
  }
  private set(value: Partial<UpdateState>) {
    this.state = { ...this.state, ...value };
    this.emit("update", this.state);
  }
  async check(manual = true) {
    if (
      this.state.phase === "unconfigured" ||
      ["checking", "downloading", "installing"].includes(this.state.phase)
    )
      return this.state;
    if (!manual && Date.now() - this.lastAttempt < 10 * 60 * 1000) return this.state;
    this.lastAttempt = Date.now();
    try {
      if (process.platform === "win32") await autoUpdater.checkForUpdates();
      else {
        this.set({ phase: "checking", message: "正在检查本平台的新版本" });
        const response = await net.fetch(
          `https://api.github.com/repos/${this.state.repository}/releases?per_page=20`,
          {
            signal: AbortSignal.timeout(20000),
            headers: { Accept: "application/vnd.github+json" },
          },
        );
        if (!response.ok) throw new Error(`GitHub 更新检查失败（HTTP ${response.status}）`);
        const latest = platformRelease(
          await response.json(),
          this.state.currentVersion,
          process.platform,
        );
        const available = latest !== this.state.currentVersion;
        this.set({
          phase: available ? "available" : "current",
          latestVersion: latest,
          checkedAt: new Date().toISOString(),
          message: available ? "发现本平台新版本，请打开发布页下载安装" : "已是本平台最新版本",
        });
      }
    } catch (error) {
      this.set({
        phase: "error",
        checkedAt: new Date().toISOString(),
        message: error instanceof Error ? error.message.slice(0, 220) : "更新检查失败",
      });
    }
    return this.state;
  }
  async download() {
    if (!this.state.canInstall) return this.releases();
    if (this.state.phase !== "available") return this.state;
    this.set({ phase: "downloading", progress: 0, message: "正在下载更新" });
    try {
      await autoUpdater.downloadUpdate();
    } catch (error) {
      this.set({
        phase: "error",
        message: error instanceof Error ? error.message.slice(0, 220) : "更新下载失败",
      });
    }
    return this.state;
  }
  async install() {
    if (!this.state.canInstall || this.state.phase !== "downloaded") return this.state;
    const answer = await dialog.showMessageBox({
      type: "warning",
      title: "安装更新",
      message: `安装 IP Guard ${this.state.latestVersion}？`,
      detail: "将退出 IP Guard 并结束受保护程序，更新后重新校验。",
      buttons: ["取消", "安装并重启"],
      defaultId: 0,
      cancelId: 0,
    });
    if (answer.response !== 1) return this.state;
    this.set({ phase: "installing", message: "正在安装更新" });
    try {
      await this.onInstalling();
      autoUpdater.quitAndInstall(false, true);
    } catch (error) {
      this.onInstallError();
      this.set({
        phase: "error",
        message: error instanceof Error ? error.message : "更新安装失败",
      });
    }
    return this.state;
  }
  async releases() {
    if (this.state.repository)
      await shell.openExternal(`https://github.com/${this.state.repository}/releases`);
    return this.state;
  }
  stop() {
    clearInterval(this.timer);
    clearTimeout(this.initial);
  }
}
