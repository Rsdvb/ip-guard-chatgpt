import { chmod, unlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import path from "node:path";

import { z } from "zod";

import {
  extensionVersionSchema,
  isNewerExtensionVersion,
  nativeVersion,
  offlineBrowserPermission,
} from "@ip-guard/electron";
import type { BrowserState, BrowserPermission, ExtensionStatus, Service } from "@ip-guard/electron";

import { browserInstallations } from "#src/main/browser-installation.ts";
import type { Guardian } from "#src/main/guardian.ts";
import { fileMissing, preparePosixSocket } from "#src/main/posix-paths.ts";
import type { ApplicationUpdates } from "#src/main/updates.ts";

export class BrowserBridge {
  private server: Server | undefined;
  private clients = new Map<Socket, string | undefined>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private guardian: Guardian;
  private endpoint = "";
  private lastMessage = "";
  private error = "";
  private released = false;
  private updates: ApplicationUpdates;
  constructor(guardian: Guardian, updates: ApplicationUpdates) {
    this.guardian = guardian;
    this.updates = updates;
    guardian.on("endpoint", (endpoint: string) => {
      void this.listen(endpoint).catch((error: unknown) => console.error("浏览器连接服务", error));
    });
    guardian.on("snapshot", () => this.publish());
    updates.on("update", () => this.publish());
  }
  private latestVersion() {
    const candidate = this.updates.state.latestVersion;
    return isNewerExtensionVersion(candidate, nativeVersion) ? candidate : nativeVersion;
  }
  private state(): BrowserState {
    const value = this.guardian.snapshot;
    const permission = (key: Service): BrowserPermission => {
      if (this.released)
        return {
          ...offlineBrowserPermission("IP Guard 已完全退出并解除防护；重新打开后恢复校验"),
          phase: "released",
        };
      const rule = value?.services[key];
      if (!value?.online || !rule || this.guardian.error) return offlineBrowserPermission();
      const base = {
        currentIp: rule.currentIp,
        expectedIp: rule.settings.expectedIp,
        checkedAt: rule.lastChecked,
        reason: rule.reason,
      };
      if (!rule.rulesLocked)
        return { ...base, phase: "unlocked", reason: "请锁定该服务允许的 IPv4" };
      if (!rule.enabled) return { ...base, phase: "paused", reason: "该服务已暂停，访问保持阻断" };
      const age = Date.now() - Date.parse(rule.lastChecked);
      if (
        rule.ready &&
        rule.currentIp &&
        rule.currentIp === rule.settings.expectedIp &&
        Number.isFinite(age) &&
        age >= -1000 &&
        age <= (rule.settings.intervalSeconds + 8) * 1000
      )
        return { ...base, phase: "allowed", reason: "IPv4 与该服务锁定地址匹配" };
      return { ...base, phase: rule.checking && !rule.currentIp ? "checking" : "blocked" };
    };
    return {
      protocol: 3,
      appVersion: nativeVersion,
      latestExtensionVersion: this.latestVersion(),
      services: { claude: permission("claude"), chatgpt: permission("chatgpt") },
    };
  }

  private async listen(endpoint: string) {
    if (this.server) return;
    if (process.platform !== "win32") {
      await preparePosixSocket(endpoint);
      await unlink(path.join(path.dirname(endpoint), "browser-released")).catch(
        (error: unknown) => {
          if (!fileMissing(error)) throw error;
        },
      );
    }
    const server = createServer((socket) => {
      if (this.clients.size >= 16) {
        socket.destroy();
        return;
      }
      this.clients.set(socket, undefined);
      let input = "",
        received = false;
      socket.setEncoding("utf8");
      socket.on("data", (chunk: string) => {
        input += chunk;
        if (received || Buffer.byteLength(input) > 512) {
          socket.destroy();
          return;
        }
        if (!input.includes("\n")) return;
        try {
          const value: unknown = JSON.parse(input);
          const metadata = z
            .object({ extensionVersion: z.union([z.literal(""), extensionVersionSchema]) })
            .strict()
            .parse(value);
          this.clients.set(socket, metadata.extensionVersion);
          received = true;
        } catch {
          socket.destroy();
        }
      });
      socket.on("error", () => socket.destroy());
      socket.on("close", () => {
        this.clients.delete(socket);
        if (!this.clients.size) {
          clearInterval(this.timer);
          this.timer = undefined;
        }
      });
      if (!this.timer) this.timer = setInterval(() => this.publish(true), 1000);
      this.send(socket);
    });
    server.on("error", (error) => {
      console.error("浏览器连接服务", error);
      this.close();
    });
    this.endpoint = endpoint;
    server.listen(endpoint, () => {
      if (process.platform === "win32")
        void this.guardian.request("browser:permissions").catch((error: unknown) => {
          this.error = error instanceof Error ? error.message : "浏览器管道权限设置失败";
          console.error(this.error);
          this.close();
        });
      else
        void chmod(endpoint, 0o600).catch((error: unknown) => {
          console.error(error);
          this.close();
        });
    });
    this.server = server;
  }
  private send(socket: Socket, message = JSON.stringify(this.state())) {
    if (socket.destroyed) return;
    if (socket.writableLength > 16384) {
      socket.destroy();
      return;
    }
    socket.write(`${message}\n`);
  }
  private publish(heartbeat = false) {
    if (!this.clients.size) return;
    const message = JSON.stringify(this.state());
    if (!heartbeat && message === this.lastMessage) return;
    this.lastMessage = message;
    for (const socket of this.clients.keys()) this.send(socket, message);
  }
  async status(): Promise<ExtensionStatus> {
    const latestVersion = this.latestVersion();
    const info = await browserInstallations(latestVersion);
    const connections = this.clients.size;
    return {
      ...info,
      error: this.error || info.error,
      connections,
      latestVersion,
      outdatedConnections: [...this.clients.values()].filter(
        (version) =>
          version !== undefined &&
          (version === "" || isNewerExtensionVersion(latestVersion, version)),
      ).length,
      phase:
        connections > 0
          ? "running"
          : info.installedBrowsers.length
            ? "installed"
            : this.error || info.error
              ? "unknown"
              : "missing",
    };
  }
  async release() {
    if (process.platform !== "win32" && this.endpoint)
      await writeFile(path.join(path.dirname(this.endpoint), "browser-released"), "released", {
        mode: 0o600,
      });
    this.released = true;
    const message = `${JSON.stringify(this.state())}\n`;
    await Promise.all(
      [...this.clients.keys()].map(
        (socket) =>
          new Promise<void>((resolve) => {
            if (socket.destroyed) return resolve();
            socket.write(message, () => resolve());
          }),
      ),
    );
  }
  close() {
    clearInterval(this.timer);
    for (const socket of this.clients.keys()) socket.destroy();
    this.clients.clear();
    const endpoint = this.endpoint;
    this.server?.close(() => {
      if (process.platform !== "win32" && endpoint)
        void unlink(endpoint).catch((error: unknown) => {
          if (!fileMissing(error)) console.error(error);
        });
    });
    this.server = undefined;
  }
}
