import { spawn } from "node:child_process";
import { lstat } from "node:fs/promises";
import { createConnection } from "node:net";
import type { Socket } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import { z } from "zod";

import { nativeVersion, systemProtectionFrameSchema } from "@ip-guard/electron";
import type { Service, SystemProtectionState } from "@ip-guard/electron";

import type { Guardian } from "./guardian.ts";
import { fileMissing } from "./posix-paths.ts";
import { systemFilterPolicy } from "./system-filter-policy.ts";
import type { SystemFilterTarget } from "./system-filter-policy.ts";
import { SystemProtectionEvents } from "./system-protection-events.ts";

const frameSchema = systemProtectionFrameSchema.extend({
  version: z.literal(nativeVersion),
  active: z.boolean(),
});
type Frame = z.infer<typeof frameSchema>;
const helper = "/usr/lib/ipguard/ipguard-system";
export class LinuxSystemProtection extends SystemProtectionEvents {
  private guardian: Guardian;
  private stream: Socket | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private reconnect: ReturnType<typeof setTimeout> | undefined;
  private bindings: SystemFilterTarget[] = [];
  private pending: Promise<SystemProtectionState> | undefined;
  private acknowledged = 0;
  private stopped = false;
  private sequence = 0;
  private awaiting = 0;
  private sentAt = 0;
  private sentPolicy = "";
  private publishPolicy: (() => void) | undefined;
  constructor(guardian: Guardian) {
    super("请安装 Ubuntu DEB 后启用系统防护");
    this.guardian = guardian;
    guardian.on("snapshot", () => {
      if (this.stream && JSON.stringify(this.policy()) !== this.sentPolicy) {
        this.state = { phase: "approval", message: "正在同步最新独立 IP 策略" };
        this.publishPolicy?.();
      }
    });
  }
  private policy() {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("系统组件只支持 Ubuntu");
    const result = systemFilterPolicy(
      this.guardian.snapshot,
      uid,
      Date.now(),
      this.bindings,
      "linux",
    );
    this.bindings = result.targets;
    return result;
  }
  private async installed() {
    try {
      const info = await lstat(helper);
      if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0)
        throw new Error("系统组件的所有者或权限不安全，请重新安装 DEB");
      return true;
    } catch (error) {
      if (fileMissing(error)) return false;
      throw error;
    }
  }
  private async connect() {
    const directory = await lstat("/run/ipguard");
    if (
      !directory.isDirectory() ||
      directory.isSymbolicLink() ||
      directory.uid !== 0 ||
      (directory.mode & 0o022) !== 0
    )
      throw new Error("系统连接目录权限不正确");
    const endpoint = `/run/ipguard/${process.getuid?.()}.sock`;
    const info = await lstat(endpoint);
    if (!info.isSocket() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0)
      throw new Error("系统连接权限不正确");
    return await new Promise<Socket>((resolve, reject) => {
      const socket = createConnection(endpoint);
      socket.setTimeout(2000, () => socket.destroy(new Error("系统组件连接超时")));
      socket.once("error", reject);
      socket.once("connect", () => {
        socket.removeListener("error", reject);
        socket.setTimeout(0);
        resolve(socket);
      });
    });
  }
  private async request(value: Record<string, unknown>): Promise<Frame> {
    const socket = await this.connect();
    return await new Promise((resolve, reject) => {
      let input = "";
      socket.setEncoding("utf8");
      socket.setTimeout(5000, () => socket.destroy(new Error("系统组件响应超时")));
      socket.on("error", reject);
      socket.once("close", () => reject(new Error("系统组件连接已关闭")));
      socket.on("data", (text: string) => {
        input += text;
        if (Buffer.byteLength(input) > 1048576) {
          socket.destroy(new Error("系统响应过长"));
          return;
        }
        if (!input.includes("\n")) return;
        try {
          const data: unknown = JSON.parse(input.slice(0, input.indexOf("\n")));
          const frame = frameSchema.parse(data);
          resolve(frame);
          socket.end();
        } catch (error) {
          socket.destroy();
          reject(error);
        }
      });
      socket.write(JSON.stringify(value) + "\n");
    });
  }
  async status(): Promise<SystemProtectionState> {
    if (this.pending) return this.state;
    if (this.stream && performance.now() - this.acknowledged < 3500) return this.state;
    if (!(await this.installed())) {
      this.state = {
        phase: "unavailable",
        message: "请使用 Ubuntu 24.04 DEB 安装系统组件；便携包保留受控启动",
      };
      return this.state;
    }
    try {
      const frame = await this.request({ action: "status" });
      this.apply(frame, frame.running ?? []);
      if (frame.active && !this.stream) void this.watch();
    } catch (error) {
      this.state = {
        phase: this.active ? "error" : "disabled",
        message: this.active
          ? "系统策略通道中断，已登记程序保持阻断；正在重连"
          : "系统组件尚未启用，点击下方按钮进行管理员授权",
      };
      if (!fileMissing(error) && !this.active) throw error;
      if (this.active) this.retry();
    }
    return this.state;
  }
  async setEnabled(enabled: boolean): Promise<SystemProtectionState> {
    if (this.pending) throw new Error("系统授权操作正在进行");
    this.stopped = false;
    const task = this.change(enabled)
      .catch((error) => {
        this.state = {
          phase: "error",
          message: error instanceof Error ? error.message : "系统操作失败",
        };
        throw error;
      })
      .finally(() => {
        this.pending = undefined;
      });
    this.pending = task;
    return task;
  }
  private async change(enabled: boolean) {
    if (!(await this.installed())) throw new Error("请先安装 Ubuntu DEB");
    if (enabled) {
      if (!this.guardian.snapshot?.online) throw new Error("请等待本机守护器就绪");
      if (this.guardian.snapshot.running.length)
        throw new Error("请先关闭受保护程序，再启用系统防护；已有连接不能安全接管");
      this.state = { phase: "approval", message: "正在等待系统管理员授权" };
      await new Promise<void>((resolve, reject) => {
        const child = spawn("/usr/bin/pkexec", [helper, "enable", String(process.getuid?.())], {
          stdio: ["pipe", "pipe", "pipe"],
        });
        let output = "",
          error = "";
        const timeout = setTimeout(() => {
          child.kill();
          reject(new Error("系统授权等待超时"));
        }, 125000);
        child.stdout?.setEncoding("utf8");
        child.stderr?.setEncoding("utf8");
        child.stdout?.on("data", (chunk: string) => {
          output += chunk;
          if (output.length > 16384) child.kill();
        });
        child.stderr?.on("data", (chunk: string) => {
          error = (error + chunk).slice(-8192);
        });
        child.stdin?.on("error", () => child.kill());
        child.on("error", (err) => {
          clearTimeout(timeout);
          reject(err);
        });
        child.on("exit", (code) => {
          clearTimeout(timeout);
          if (code !== 0) {
            reject(new Error(error || "系统授权未完成"));
            return;
          }
          try {
            const value: unknown = JSON.parse(output.trim());
            const frame = frameSchema.parse(value);
            this.apply(
              { ...frame, phase: "approval", message: "系统组件已授权，等待策略确认" },
              [],
            );
            resolve();
          } catch (err) {
            reject(err);
          }
        });
        const policy = this.policy();
        child.stdin?.end(
          JSON.stringify({
            action: "policy",
            policy: {
              ...policy,
              targets: policy.targets.map((target) => ({
                ...target,
                allowed: false,
                keepRunning: false,
              })),
            },
          }),
        );
      });
      await this.status();
      // status() is suppressed while authorization is pending, so establish the first lease here.
      await this.watch();
    } else {
      clearInterval(this.timer);
      clearTimeout(this.reconnect);
      const frame = await this.request({ action: "disable" });
      if (frame.active) throw new Error("系统过滤关闭尚未确认");
      const stream = this.stream;
      this.stream = undefined;
      stream?.destroy();
      this.apply(frame, []);
    }
    return this.state;
  }
  private async watch() {
    if (this.stream || this.stopped) return;
    this.state = { phase: "approval", message: "正在等待内核确认独立 IP 策略" };
    try {
      const socket = await this.connect();
      if (this.stopped) {
        socket.destroy();
        return;
      }
      if (this.stream) {
        socket.destroy();
        return;
      }
      this.stream = socket;
      this.acknowledged = 0;
      this.awaiting = 0;
      this.sentPolicy = "";
      let input = "";
      const failed = (message: string) => {
        if (this.stream !== socket) return;
        this.stream = undefined;
        this.publishPolicy = undefined;
        clearInterval(this.timer);
        socket.destroy();
        this.state = { phase: "error", message };
        this.retry();
      };
      socket.on("error", (err) => failed(err.message));
      socket.on("close", () => failed("系统策略通道断开，已登记程序保持阻断"));
      socket.setEncoding("utf8");
      socket.setTimeout(3500, () => failed("内核策略确认超时，已停止发放网络许可"));
      socket.on("data", (text: string) => {
        if (this.stream !== socket) return;
        input += text;
        if (Buffer.byteLength(input) > 1048576) {
          failed("系统响应过长");
          return;
        }
        let split: number;
        while ((split = input.indexOf("\n")) >= 0) {
          const line = input.slice(0, split);
          input = input.slice(split + 1);
          try {
            const value: unknown = JSON.parse(line);
            const frame = frameSchema.parse(value);
            if (frame.phase !== "enabled") {
              failed(frame.message);
              return;
            }
            if (!this.awaiting || frame.sequence !== this.awaiting) {
              failed("内核确认的策略版本不一致，已撤销许可");
              return;
            }
            this.awaiting = 0;
            this.acknowledged = performance.now();
            const current = JSON.stringify(this.policy());
            if (current !== this.sentPolicy) {
              this.apply(
                { ...frame, phase: "approval", message: "正在同步最新独立 IP 策略" },
                frame.running ?? [],
              );
              this.publishPolicy?.();
            } else this.apply(frame, frame.running ?? []);
          } catch {
            failed("系统组件版本或响应无效，请重新安装匹配版本的 DEB");
          }
        }
      });
      const publish = () => {
        if (this.stream !== socket) return;
        if (this.awaiting) {
          if (performance.now() - this.sentAt > 3500) failed("内核未及时确认当前策略，已撤销许可");
          return;
        }
        if (socket.writableLength > 524288) {
          failed("系统策略通道繁忙");
          return;
        }
        if (this.acknowledged && performance.now() - this.acknowledged > 3500) {
          failed("内核许可确认已过期");
          return;
        }
        const policy = this.policy();
        this.sentPolicy = JSON.stringify(policy);
        this.awaiting = ++this.sequence;
        this.sentAt = performance.now();
        socket.write(JSON.stringify({ action: "policy", policy, sequence: this.awaiting }) + "\n");
      };
      this.publishPolicy = publish;
      publish();
      this.timer = setInterval(publish, 1000);
    } catch (error) {
      this.state = {
        phase: "error",
        message: error instanceof Error ? error.message : "系统连接失败",
      };
      this.retry();
    }
  }
  private retry() {
    clearTimeout(this.reconnect);
    if (!this.stopped)
      this.reconnect = setTimeout(() => void this.status().catch(() => this.retry()), 3000);
  }
  async stopScope(scope: { service: Service } | { id: string }) {
    if (!this.active) return;
    let frame = await this.request({ action: "stop", ...scope });
    const matches = () =>
      frame.running?.some((item) =>
        "id" in scope ? item.id === scope.id : item.service === scope.service,
      );
    const deadline = performance.now() + 5000;
    while (matches() && performance.now() < deadline) {
      await delay(100);
      frame = await this.request({ action: "status" });
    }
    if (matches()) throw new Error("系统进程停止尚未确认，请检查后台日志");
    this.apply(frame, frame.running ?? []);
  }
  stop() {
    this.stopped = true;
    clearTimeout(this.reconnect);
    clearInterval(this.timer);
    const stream = this.stream;
    this.stream = undefined;
    stream?.destroy();
  }
}
