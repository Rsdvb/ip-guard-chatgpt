import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";

import { app } from "electron";
import { z } from "zod";

import type { Snapshot, SystemProtectionState, SystemProcess } from "@ip-guard/electron";
import { nativeProtocol, nativeVersion, snapshotSchema, serviceSchema } from "@ip-guard/electron";
import type { Service } from "@ip-guard/electron";

import type { ProbeProgress } from "#src/main/exit-ip.ts";
import { PosixGuardian } from "#src/main/posix-guardian.ts";
import type { ProtectionProbe } from "#src/main/protection-probe.ts";

const messageSchema = z.object({
  id: z.string().optional(),
  type: z.string().optional(),
  ok: z.boolean().optional(),
  error: z.string().optional(),
  code: z.enum(["firewall_disabled", ""]).optional(),
  help: z.string().optional(),
  data: z.unknown().optional(),
  service: serviceSchema.optional(),
  version: z.string().optional(),
  protocol: z.number().int().optional(),
  sid: z
    .string()
    .regex(/^S-1-\d+(?:-\d+)+$/)
    .optional(),
});
export const nativePath = () =>
  app.isPackaged
    ? path.join(process.resourcesPath, "native", nativeVersion, "IpGuard.Native.exe")
    : path.join(import.meta.dirname, "../native", nativeVersion, "IpGuard.Native.exe");

export class NativeCommandError extends Error {
  readonly code: "firewall_disabled" | "";
  readonly help: string;
  constructor(message: string, code: "firewall_disabled" | "", help: string) {
    super(message);
    this.code = code;
    this.help = help;
  }
}

export class Guardian extends EventEmitter {
  private readonly probeService: ProtectionProbe;
  private ready: Promise<void> = Promise.resolve();
  private resolveReady: (() => void) | undefined;
  private rejectReady: ((error: Error) => void) | undefined;
  private helloTimer: ReturnType<typeof setTimeout> | undefined;
  private child: ReturnType<typeof spawn> | undefined;
  private posix: PosixGuardian | undefined;
  private stopping = false;
  private releasing = false;
  get isStopping() {
    return this.stopping || this.releasing;
  }
  private stderr = "";
  private pending = new Map<
    string,
    {
      resolve: (snapshot: Snapshot) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  snapshot: Snapshot | undefined;
  error = "";
  constructor(probe: ProtectionProbe) {
    super();
    this.probeService = probe;
  }
  start() {
    this.error = "";
    this.stopping = false;
    this.releasing = false;
    this.stderr = "";
    this.ready = new Promise<void>((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
    void this.ready.catch(() => undefined);
    if (process.platform !== "win32") {
      const posix = new PosixGuardian(this.probeService, {
        directory: app.getPath("userData"),
        executable: process.env.APPIMAGE || process.execPath,
        resources: app.isPackaged
          ? path.join(process.resourcesPath, "posix")
          : path.resolve(import.meta.dirname, "../../posix"),
      });
      this.posix = posix;
      posix.on("endpoint", (endpoint: string) => this.emit("endpoint", endpoint));
      posix.on("snapshot", (snapshot: Snapshot) => {
        this.snapshot = snapshot;
        this.emit("snapshot", snapshot);
      });
      posix.on("failure", (reason: string) => this.fail(reason));
      void posix
        .start()
        .then(() => {
          this.resolveReady?.();
          this.resolveReady = undefined;
          this.rejectReady = undefined;
        })
        .catch((error: unknown) =>
          this.fail(error instanceof Error ? error.message : "守护启动失败"),
        );
      return;
    }
    if (!existsSync(nativePath())) {
      this.fail(`原生组件 ${nativeVersion} 未安装完整，请关闭旧版拦截窗口后重新安装。`);
      return;
    }
    const child = spawn(nativePath(), ["guard"], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    this.helloTimer = setTimeout(() => this.fail("原生组件握手失败，请重新安装当前版本。"), 15000);
    if (child.stdout)
      createInterface({ input: child.stdout }).on("line", (line) => {
        try {
          const message = messageSchema.parse(JSON.parse(line));
          if (message.type === "hello") {
            if (
              message.version !== nativeVersion ||
              message.protocol !== nativeProtocol ||
              !message.sid
            ) {
              this.fail(
                `界面与原生组件版本不一致，需要 ${nativeVersion}，实际 ${message.version ?? "未知"}。`,
              );
              return;
            }
            this.emit("endpoint", `\\\\.\\pipe\\IPGuard-Browser-${message.sid}`);
            this.send({ action: "initialize", version: nativeVersion, protocol: nativeProtocol });
            return;
          }
          if (message.type === "probe" && message.id && message.service) {
            void this.probe(message.id, message.service);
            return;
          }
          if (message.type === "fatal") {
            this.fail(message.error ?? "原生守护器启动失败");
            return;
          }
          if (message.type === "snapshot") {
            this.snapshot = snapshotSchema.parse(message.data);
            clearTimeout(this.helloTimer);
            this.resolveReady?.();
            this.resolveReady = undefined;
            this.rejectReady = undefined;
            this.emit("snapshot", this.snapshot);
            return;
          }
          if (!message.id) return;
          const item = this.pending.get(message.id);
          if (!item) return;
          const snapshot = message.ok ? snapshotSchema.parse(message.data) : undefined;
          clearTimeout(item.timer);
          this.pending.delete(message.id);
          if (snapshot) item.resolve(snapshot);
          else
            item.reject(
              new NativeCommandError(
                message.error ?? "操作失败",
                message.code ?? "",
                message.help ?? "",
              ),
            );
        } catch (error) {
          this.fail(error instanceof Error ? error.message : "守护通信异常");
        }
      });
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (data: string) => {
      this.stderr = `${this.stderr}${data}`.slice(-8000);
      console.error(data);
    });
    child.stdin?.on("error", (error) => this.fail(error.message));
    child.on("error", (error) => this.fail(error.message));
    child.on("exit", (code, signal) => {
      if (this.stopping) return;
      const exit =
        code === null ? signal || "未知" : `0x${(code >>> 0).toString(16).toUpperCase()}`;
      const detail = `${new Date().toISOString()} exit=${exit}\n${this.error}\n${this.stderr}\n`;
      try {
        const directory = path.join(
          process.env.LOCALAPPDATA ?? path.join(app.getPath("home"), "AppData/Local"),
          "IPGuard",
        );
        mkdirSync(directory, { recursive: true });
        appendFileSync(path.join(directory, "guardian-errors.log"), detail, "utf8");
      } catch (error) {
        console.error("守护退出日志写入失败", error);
      }
      this.fail(
        this.error ||
          `守护程序异常退出（${exit}），受保护程序已结束。请重启 IP Guard；详情见 guardian-errors.log。`,
      );
    });
  }
  private send(value: Record<string, unknown>) {
    const input = this.child?.stdin;
    if (this.stopping || !input?.writable) return;
    input.write(`${JSON.stringify(value)}\n`, (error) => {
      if (error && !this.stopping) this.fail(error.message);
    });
  }
  private async probe(id: string, service: Service) {
    const child = this.child;
    const progress = (data: ProbeProgress) => {
      if (this.child === child) this.send({ action: "probe-progress", id, data });
    };
    try {
      const result = await this.probeService.check(service, progress);
      if (this.child === child) this.send({ action: "probe-result", id, data: result });
    } catch (error) {
      if (this.child === child)
        this.send({
          action: "probe-result",
          id,
          data: {
            ip: "",
            error: error instanceof Error ? error.message : "服务出口检测失败",
            checkedAt: new Date().toISOString(),
            adapter: "",
          },
        });
    }
  }
  private fail(message: string) {
    this.error = message;
    if (this.posix) void this.posix.stop();
    clearTimeout(this.helloTimer);
    this.rejectReady?.(new Error(message));
    this.resolveReady = undefined;
    this.rejectReady = undefined;
    if (this.child?.pid && this.child.exitCode === null && this.child.signalCode === null)
      this.child.kill();
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error(message));
    }
    this.pending.clear();
    if (this.snapshot) {
      this.snapshot = {
        ...this.snapshot,
        online: false,
        services: {
          claude: {
            ...this.snapshot.services.claude,
            ready: false,
            unverified: false,
            checking: false,
            reason: message,
          },
          chatgpt: {
            ...this.snapshot.services.chatgpt,
            ready: false,
            unverified: false,
            checking: false,
            reason: message,
          },
        },
        running: [],
        launches: this.snapshot.launches.map((launch) =>
          launch.phase === "starting" ? { ...launch, phase: "failed", message } : launch,
        ),
      };
      this.emit("snapshot", this.snapshot);
    }
  }
  async request(action: string, payload: Record<string, unknown> = {}): Promise<Snapshot> {
    await this.ready;
    if (this.posix) return this.posix.request(action, payload);
    const input = this.child?.stdin;
    if (!input || this.error || !input.writable)
      return Promise.reject(new Error(this.error || "守护程序尚未就绪"));
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("操作等待超时，请查看当前状态；后台防护仍在运行。"));
      }, 25000);
      this.pending.set(id, { resolve, reject, timer });
      input.write(`${JSON.stringify({ ...payload, action, id })}\n`, (error) => {
        if (error) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(error);
        }
      });
    });
  }
  async releaseProtection() {
    this.releasing = true;
    try {
      return await this.request("release-protection");
    } catch (error) {
      this.releasing = false;
      throw error;
    }
  }
  async stop() {
    if (this.posix) {
      this.stopping = true;
      await this.posix.stop();
      this.posix = undefined;
      return;
    }
    if (!this.child) return;
    const child = this.child;
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
    this.stopping = true;
    clearTimeout(this.helloTimer);
    this.rejectReady?.(new Error("守护程序正在退出"));
    this.resolveReady = undefined;
    this.rejectReady = undefined;
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    child.stdin?.end(`${JSON.stringify({ action: "shutdown", id: crypto.randomUUID() })}\n`);
    const timer = setTimeout(() => child.kill(), 8000);
    await exited;
    clearTimeout(timer);
  }
  managedProcessStatus(service: Service) {
    return this.posix?.processStatus(service);
  }
  setSystemProtection(state: SystemProtectionState, running: SystemProcess[]) {
    this.posix?.setSystemProtection(state, running);
  }
  stopManagedService(service: Service) {
    return this.posix?.stopService(service);
  }
}
