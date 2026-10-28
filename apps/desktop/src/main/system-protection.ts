import type { Service } from "@ip-guard/electron";

import type { Guardian } from "./guardian.ts";
import { LinuxSystemProtection } from "./linux-system.ts";
import { MacNetworkFilter } from "./mac-filter.ts";

export class SystemProtection {
  private backend: MacNetworkFilter | LinuxSystemProtection | undefined;
  private guardian: Guardian;
  private started = false;
  constructor(guardian: Guardian) {
    this.guardian = guardian;
    this.backend =
      process.platform === "darwin"
        ? new MacNetworkFilter(guardian)
        : process.platform === "linux"
          ? new LinuxSystemProtection(guardian)
          : undefined;
    this.backend?.on("update", (state, running) => guardian.setSystemProtection(state, running));
    guardian.on("snapshot", (snapshot) => {
      if (!snapshot.online || this.started) return;
      this.started = true;
      void this.status().catch((error) => console.error("系统防护状态", error));
    });
  }
  get active() {
    return this.backend?.active ?? false;
  }
  async status() {
    return this.backend
      ? await this.backend.status()
      : {
          phase: "unavailable" as const,
          message: "Windows 使用原生启动门卫和防火墙",
          active: false,
        };
  }
  async setEnabled(enabled: boolean) {
    if (!this.backend) throw new Error("当前平台不支持该系统组件开关");
    return await this.backend.setEnabled(enabled);
  }
  async stopScope(scope: { service: Service } | { id: string }) {
    await this.backend?.stopScope(scope);
  }
  processStatus(service: Service) {
    const result = this.guardian.managedProcessStatus(service);
    if (result && this.backend?.active && this.backend.state.phase !== "enabled")
      return { ...result, phase: "unknown" as const, message: "系统进程状态等待策略通道确认" };
    return result;
  }
  async stop() {
    try {
      await this.backend?.stopScope({ service: "claude" });
      await this.backend?.stopScope({ service: "chatgpt" });
    } finally {
      this.backend?.stop();
    }
  }
}
