import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";

import { app } from "electron";

import { macFilterStateSchema } from "@ip-guard/electron";
import type { MacFilterState } from "@ip-guard/electron";

import type { Guardian } from "./guardian.ts";
import { macFilterPolicy } from "./mac-filter-policy.ts";
import type { MacFilterTarget } from "./mac-filter-policy.ts";

export class MacNetworkFilter {
  state: MacFilterState = { phase: "unavailable", message: "系统过滤器需完成 Mac 本机签名后启用" };
  private stream: ChildProcess | undefined;
  private pending: Promise<MacFilterState> | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private bindings: MacFilterTarget[] = [];
  private acknowledged = 0;
  private guardian: Guardian;
  constructor(guardian: Guardian) {
    this.guardian = guardian;
  }
  private helper() {
    return app.isPackaged
      ? path.join(path.dirname(process.execPath), "IpGuardMacControl")
      : path.join(import.meta.dirname, "../mac/IpGuardMacControl");
  }
  private policy() {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("系统过滤只支持 macOS");
    const result = macFilterPolicy(this.guardian.snapshot, uid, Date.now(), this.bindings);
    this.bindings = result.targets;
    return result;
  }
  private supported() {
    return process.platform === "darwin" && existsSync(this.helper());
  }
  async status(): Promise<MacFilterState> {
    if (!this.supported()) return this.state;
    if (this.pending) return this.state;
    if (this.stream && performance.now() - this.acknowledged < 3500) return this.state;
    if (this.stream) this.stop();
    const state = await this.command("status");
    if (state.phase === "enabled" && !this.stream) this.watch();
    return this.state;
  }
  async setEnabled(enabled: boolean): Promise<MacFilterState> {
    if (!this.supported()) throw new Error("先完成 Mac 本机 Developer ID 签名，再启用系统过滤");
    if (this.pending) throw new Error("系统过滤授权操作正在进行");
    if (enabled && (!this.guardian.snapshot?.online || !app.isPackaged))
      throw new Error("请运行已签名并安装的 IP Guard，等待守护器连接后再启用");
    if (!enabled) this.stop();
    const state = await this.command(enabled ? "enable" : "disable");
    if (state.phase === "enabled") this.watch();
    return this.state;
  }
  private command(operation: "status" | "enable" | "disable") {
    const request = new Promise<MacFilterState>((resolve, reject) => {
      const child = spawn(this.helper(), [operation], { stdio: ["pipe", "pipe", "pipe"] });
      let latest: MacFilterState | undefined,
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
            latest = macFilterStateSchema.parse(value);
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
        operation === "enable"
          ? JSON.stringify({
              ...this.policy(),
              targets: this.bindings.map((target) => ({ ...target, allowed: false })),
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
    if (this.stream) return;
    if (!this.guardian.snapshot?.online) {
      this.state = { phase: "approval", message: "等待本机守护器就绪；已登记应用保持拒绝" };
      return;
    }
    const child = spawn(this.helper(), ["stream"], { stdio: ["pipe", "pipe", "pipe"] });
    this.stream = child;
    this.acknowledged = 0;
    this.state = { phase: "approval", message: "正在等待系统过滤器确认策略通道" };
    const failed = (reason: string) => {
      if (this.stream !== child) return;
      clearInterval(this.timer);
      this.stream = undefined;
      child.kill();
      this.state = { phase: "error", message: reason };
    };
    if (child.stdout)
      createInterface({ input: child.stdout }).on("line", (line) => {
        try {
          if (line.length > 16384) throw new Error("过滤器响应过长");
          const value: unknown = JSON.parse(line);
          const state = macFilterStateSchema.parse(value);
          if (state.phase !== "enabled") {
            failed(state.message);
            return;
          }
          this.acknowledged = performance.now();
          this.state = state;
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
      if (!child.stdin?.writable || child.stdin.writableLength > 524288) {
        failed("系统过滤策略通道繁忙，已停止发放网络许可");
        return;
      }
      child.stdin.write(JSON.stringify(this.policy()) + "\n");
    };
    publish();
    this.timer = setInterval(publish, 1000);
  }
  stop() {
    clearInterval(this.timer);
    const child = this.stream;
    this.stream = undefined;
    if (child?.stdin?.writable)
      child.stdin.end(
        JSON.stringify({
          ...this.policy(),
          targets: this.bindings.map((target) => ({ ...target, allowed: false })),
        }) + "\n",
      );
    const timer = setTimeout(() => child?.kill(), 1500);
    timer.unref();
  }
}
