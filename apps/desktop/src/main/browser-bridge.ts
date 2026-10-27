import { createServer } from "node:net";
import type { Server, Socket } from "node:net";

import { nativeVersion, offlineBrowserPermission } from "@ip-guard/electron";
import type { BrowserState, BrowserPermission, ExtensionStatus, Service } from "@ip-guard/electron";

import { browserInstallations } from "#src/main/browser-installation.ts";
import type { Guardian } from "#src/main/guardian.ts";

export class BrowserBridge {
  private server: Server | undefined;
  private clients = new Set<Socket>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private guardian: Guardian;
  constructor(guardian: Guardian) {
    this.guardian = guardian;
    guardian.on("identity", (sid: string) => this.listen(sid));
    guardian.on("snapshot", () => this.publish());
  }
  private state(): BrowserState {
    const value = this.guardian.snapshot;
    const permission = (key: Service): BrowserPermission => {
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
      services: { claude: permission("claude"), chatgpt: permission("chatgpt") },
    };
  }

  private listen(sid: string) {
    if (this.server) return;
    const server = createServer((socket) => {
      if (this.clients.size >= 16) {
        socket.destroy();
        return;
      }
      this.clients.add(socket);
      socket.on("data", () => socket.destroy());
      socket.on("error", () => socket.destroy());
      socket.on("close", () => this.clients.delete(socket));
      this.send(socket);
    });
    server.on("error", (error) => {
      console.error("浏览器连接服务", error);
      this.close();
    });
    server.listen(`\\\\.\\pipe\\IPGuard-Browser-${sid}`);
    this.server = server;
    this.timer = setInterval(() => this.publish(), 1000);
  }
  private send(socket: Socket) {
    if (socket.destroyed) return;
    if (socket.writableLength > 16384) {
      socket.destroy();
      return;
    }
    socket.write(`${JSON.stringify(this.state())}\n`);
  }
  private publish() {
    for (const socket of this.clients) this.send(socket);
  }
  async status(): Promise<ExtensionStatus> {
    const info = await browserInstallations();
    const connections = this.clients.size;
    return {
      ...info,
      connections,
      phase:
        connections > 0
          ? "running"
          : info.installedBrowsers.length
            ? "installed"
            : info.error
              ? "unknown"
              : "missing",
    };
  }
  close() {
    clearInterval(this.timer);
    for (const socket of this.clients) socket.destroy();
    this.clients.clear();
    this.server?.close();
    this.server = undefined;
  }
}
