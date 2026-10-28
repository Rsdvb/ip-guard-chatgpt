import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";

import { app } from "electron";

import { systemProtectionStateSchema, systemProtectionFrameSchema } from "@ip-guard/electron";
import type { SystemProtectionState, Service } from "@ip-guard/electron";

import type { Guardian } from "./guardian.ts";
import { systemFilterPolicy } from "./system-filter-policy.ts";
import type { SystemFilterTarget } from "./system-filter-policy.ts";
import { SystemProtectionEvents } from "./system-protection-events.ts";

export class MacNetworkFilter extends SystemProtectionEvents {
  private stream: ChildProcess | undefined;
  private pending: Promise<SystemProtectionState> | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private bindings: SystemFilterTarget[] = [];
  private acknowledged = 0;
  private watchStarted = 0;
  private checkedOS = 0;
  private reconnect: ReturnType<typeof setTimeout> | undefined;
  private stopped = false;
  private sequence = 0;
  private awaiting = 0;
  private sentAt = 0;
  private sentPolicy = "";
  private publishPolicy: (() => void) | undefined;
  private guardian: Guardian;
  constructor(guardian: Guardian) {
    super("系统过滤器需完成 Mac 本机签名后启用");
    this.guardian = guardian;
    guardian.on("snapshot", () => {
      if (this.stream && JSON.stringify(this.policy()) !== this.sentPolicy) {
        this.state = { phase: "approval", message: "正在同步最新独立 IP 策略" };
        this.publishPolicy?.();
      }
    });
  }
  private helper() {
    return app.isPackaged
      ? path.join(path.dirname(process.execPath), "IpGuardMacControl")
      : path.join(import.meta.dirname, "../mac/IpGuardMacControl");
  }
  private policy() {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("系统过滤只支持 macOS");
    const result = systemFilterPolicy(
      this.guardian.snapshot,
      uid,
      Date.now(),
      this.bindings,
      "darwin",
    );
    this.bindings = result.targets;
    return result;
  }
  private supported() {
    return process.platform === "darwin" && existsSync(this.helper());
  }
  async status(): Promise<SystemProtectionState> {
    if (!this.supported()) return this.state;
    if (this.pending) return this.state;
    if (this.stream && performance.now() - (this.acknowledged || this.watchStarted) < 3500)
      return this.state;
    if (
      !this.stream &&
      this.state.phase === "disabled" &&
      performance.now() - this.checkedOS < 15000
    )
      return this.state;
    if (this.stream) this.closeStream();
    const state = await this.command("status");
    this.checkedOS = performance.now();
    if (state.phase === "enabled" && !this.stream) this.watch();
    return this.state;
  }
  async setEnabled(enabled: boolean): Promise<SystemProtectionState> {
    if (!this.supported()) throw new Error("先完成 Mac 本机 Developer ID 签名，再启用系统过滤");
    if (this.pending) throw new Error("系统过滤授权操作正在进行");
    if (enabled && (!this.guardian.snapshot?.online || !app.isPackaged))
      throw new Error("请运行已签名并安装的 IP Guard，等待守护器连接后再启用");
    this.stopped = false;
    if (!enabled) {
      await this.stopScope({ service: "claude" });
      await this.stopScope({ service: "chatgpt" });
      this.closeStream();
    }
    const state = await this.command(enabled ? "enable" : "disable");
    if (state.phase === "enabled") this.watch();
    return this.state;
  }
  private command(
    operation: "status" | "enable" | "disable" | "stop",
    scope?: { service: Service } | { id: string },
  ) {
    const request = new Promise<SystemProtectionState>((resolve, reject) => {
      const child = spawn(this.helper(), [operation], { stdio: ["pipe", "pipe", "pipe"] });
      let latest: SystemProtectionState | undefined,
        errors = "";
      const timeout = setTimeout(
        () => {
          child.kill();
          reject(new Error("系统过滤操作等待超时，请检查 macOS 系统授权"));
        },
        operation === "enable" ? 125000 : 20000,
      );
      const finish = (error?: Error) => {
        clearTimeout(timeout);
        if (error) {
          this.state = { phase: "error", message: error.message };
          reject(error);
        } else resolve(this.state);
      };
      if (child.stdout)
        createInterface({ input: child.stdout }).on("line", (line) => {
          if (line.length > 16384) {
            child.kill();
            return;
          }
          try {
            const value: unknown = JSON.parse(line);
            latest = systemProtectionStateSchema.parse(value);
            this.state = latest;
          } catch {
            child.kill();
          }
        });
      child.stderr?.setEncoding("utf8");
      child.stderr?.on("data", (text: string) => {
        errors = (errors + text).slice(-8192);
      });
      child.stdin?.on("error", () => child.kill());
      child.on("error", finish);
      child.on("exit", (code) =>
        finish(
          code !== 0 || !latest
            ? new Error(latest?.message || errors || "系统过滤控制器退出")
            : undefined,
        ),
      );
      child.stdin?.end(
        operation === "enable" || operation === "stop"
          ? JSON.stringify({
              ...this.policy(),
              targets: this.bindings
                .filter(
                  (target) =>
                    !scope ||
                    ("id" in scope ? target.id === scope.id : target.service === scope.service),
                )
                .map((target) => ({ ...target, allowed: false, keepRunning: false })),
            }) + "\n"
          : "",
      );
    }).finally(() => {
      this.pending = undefined;
    });
    this.pending = request;
    return request;
  }
  private watch() {
    if (this.stream || this.stopped) return;
    if (!this.guardian.snapshot?.online) {
      this.state = { phase: "approval", message: "等待本机守护器就绪；已登记应用保持拒绝" };
      return;
    }
    const child = spawn(this.helper(), ["stream"], { stdio: ["pipe", "pipe", "pipe"] });
    this.stream = child;
    this.acknowledged = 0;
    this.watchStarted = performance.now();
    this.awaiting = 0;
    this.sentPolicy = "";
    this.state = { phase: "approval", message: "正在等待系统过滤器确认策略通道" };
    const failed = (reason: string) => {
      if (this.stream !== child) return;
      clearInterval(this.timer);
      this.stream = undefined;
      this.publishPolicy = undefined;
      child.kill();
      this.state = { phase: "error", message: reason };
      clearTimeout(this.reconnect);
      if (!this.stopped)
        this.reconnect = setTimeout(() => void this.status().catch(() => this.watch()), 3000);
    };
    if (child.stdout)
      createInterface({ input: child.stdout }).on("line", (line) => {
        if (this.stream !== child) return;
        try {
          if (line.length > 16384) throw new Error("过滤器响应过长");
          const value: unknown = JSON.parse(line);
          const state = systemProtectionFrameSchema.parse(value);
          if (state.phase !== "enabled") {
            failed(state.message);
            return;
          }
          if (!this.awaiting || state.sequence !== this.awaiting) {
            failed("系统过滤器未确认当前策略版本，请重新签名当前版本组件");
            return;
          }
          this.awaiting = 0;
          this.acknowledged = performance.now();
          if (JSON.stringify(this.policy()) !== this.sentPolicy) {
            this.apply(
              { ...state, phase: "approval", message: "正在同步最新独立 IP 策略" },
              state.running ?? [],
            );
            this.publishPolicy?.();
          } else this.apply(state, state.running ?? []);
        } catch {
          failed("系统过滤器响应无效，已停止发放网络许可");
        }
      });
    child.stderr?.on("data", () => {
      /* stderr is drained; only validated status reaches the UI. */
    });
    child.stdin?.on("error", () => failed("系统过滤策略通道写入失败"));
    child.on("error", (error) => failed(error.message));
    child.once("exit", () =>
      failed("系统过滤策略通道已退出；已登记应用保持拒绝，直至恢复校验或关闭过滤器"),
    );
    const publish = () => {
      if (this.stream !== child) return;
      if (this.awaiting) {
        if (performance.now() - this.sentAt > 3500)
          failed("系统过滤未及时确认当前策略，已撤销许可");
        return;
      }
      if (!child.stdin?.writable || child.stdin.writableLength > 524288) {
        failed("系统过滤策略通道繁忙，已停止发放网络许可");
        return;
      }
      if (performance.now() - (this.acknowledged || this.watchStarted) > 3500) {
        failed("系统过滤器未及时确认许可，已停止发放网络许可");
        return;
      }
      const policy = this.policy();
      this.sentPolicy = JSON.stringify(policy);
      this.awaiting = ++this.sequence;
      this.sentAt = performance.now();
      child.stdin.write(JSON.stringify({ ...policy, sequence: this.awaiting }) + "\n");
    };
    this.publishPolicy = publish;
    publish();
    this.timer = setInterval(publish, 1000);
  }
  private closeStream() {
    clearTimeout(this.reconnect);
    clearInterval(this.timer);
    const child = this.stream;
    this.stream = undefined;
    this.publishPolicy = undefined;
    if (child?.stdin?.writable)
      child.stdin.end(
        JSON.stringify({
          ...this.policy(),
          sequence: ++this.sequence,
          targets: this.bindings.map((target) => ({
            ...target,
            allowed: false,
            keepRunning: false,
          })),
        }) + "\n",
      );
    const timer = setTimeout(() => child?.kill(), 1500);
    timer.unref();
  }
  stop() {
    this.stopped = true;
    this.closeStream();
  }
  async stopScope(scope: { service: Service } | { id: string }) {
    if (!this.active) return;
    await this.command("stop", scope);
    this.apply(
      this.state,
      this.running.filter((item) =>
        "id" in scope ? item.id !== scope.id : item.service !== scope.service,
      ),
    );
  }
}
