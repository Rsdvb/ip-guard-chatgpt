import { execFile, spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { closeSync, openSync } from "node:fs";
import { constants } from "node:fs";
import {
  access,
  appendFile,
  chmod,
  readFile,
  realpath,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { z } from "zod";

import {
  appSchema,
  commandSchema,
  nativeVersion,
  serviceKeys,
  serviceName,
  snapshotSchema,
} from "@ip-guard/electron";
import type {
  ProcessState,
  ProtectedApp,
  Service,
  ServiceSnapshot,
  Snapshot,
} from "@ip-guard/electron";

import { registerPosixBrowser } from "./posix-browser.ts";
import {
  fileMissing,
  posixSocketDirectory,
  preparePosixSocket,
  privateDirectory,
} from "./posix-paths.ts";
import { parsePosixArguments, posixPermission, shellQuote } from "./posix-policy.ts";
import type { ProtectionProbe } from "./protection-probe.ts";

const run = promisify(execFile);
const storedRule = z
  .object({
    enabled: z.boolean(),
    rulesLocked: z.boolean(),
    stopOnProbeFailure: z.boolean(),
    settings: z.object({
      expectedIp: z.union([z.literal(""), z.ipv4()]),
      intervalSeconds: z.number().int().min(1).max(60),
    }),
  })
  .refine((rule) => !rule.rulesLocked || rule.settings.expectedIp !== "");
const configSchema = z
  .object({
    format: z.literal(1),
    services: z.object({ claude: storedRule, chatgpt: storedRule }),
    apps: z.array(appSchema).max(256),
    autostart: z.boolean(),
    networkAdapterId: z.string().max(256),
  })
  .refine((value) => new Set(value.apps.map((target) => target.id)).size === value.apps.length);
const launchRequest = z.object({
  action: z.literal("launch"),
  targetId: z.uuid(),
  extra: z.array(z.string().max(4096)).max(128),
});
const launchEvent = z.discriminatedUnion("type", [
  z.object({ type: z.literal("started"), pid: z.number().int().positive() }),
  z.object({ type: z.literal("closed"), code: z.number().int() }),
  z.object({ type: z.literal("failed"), message: z.string().max(4096) }),
]);
const emptyRule = (): ServiceSnapshot => ({
  enabled: false,
  rulesLocked: false,
  stopOnProbeFailure: true,
  unverified: false,
  ready: false,
  checking: false,
  currentIp: "",
  adapter: "",
  lastChecked: "",
  reason: "请先锁定该服务允许的公网 IPv4",
  settings: { expectedIp: "", intervalSeconds: 2 },
});
const message = (error: unknown) => (error instanceof Error ? error.message : "操作失败");
type Connection = {
  socket: Socket;
  service: Service;
  started: boolean;
  pid: number;
  stopping: boolean;
};

export class PosixGuardian extends EventEmitter {
  snapshot: Snapshot;
  error = "";
  private config: z.infer<typeof configSchema> = {
    format: 1,
    services: { claude: storedRule.parse(emptyRule()), chatgpt: storedRule.parse(emptyRule()) },
    apps: [],
    autostart: false,
    networkAdapterId: "",
  };
  private readonly checks = new Map<Service, Promise<boolean>>();
  private readonly epochs = { claude: 0, chatgpt: 0 };
  private readonly verified = { claude: 0, chatgpt: 0 };
  private readonly nextCheck = { claude: 0, chatgpt: 0 };
  private readonly sessions = new Map<string, Connection>();
  private readonly connections = new Set<Socket>();
  private persistence = Promise.resolve();
  private server: Server | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private closed = false;
  private topology = "";
  private cgroups = false;
  readonly endpoint = path.join(posixSocketDirectory(), "control.sock");
  private probe: Pick<ProtectionProbe, "check">;
  private options: { directory: string; executable: string; resources: string };
  constructor(
    probe: Pick<ProtectionProbe, "check">,
    options: { directory: string; executable: string; resources: string },
  ) {
    super();
    this.probe = probe;
    this.options = options;
    if (process.platform !== "darwin" && process.platform !== "linux")
      throw new Error("POSIX 守护器需要 macOS 或 Linux");
    this.snapshot = snapshotSchema.parse({
      online: false,
      admin: false,
      nativeVersion,
      platform: process.platform,
      processProtection: "managed-group",
      services: { claude: emptyRule(), chatgpt: emptyRule() },
      detection: "",
      running: [],
      autostart: false,
      networkAdapters: [],
      watchedAdapter: {
        id: "",
        name: "自动识别联网网卡",
        exists: false,
        up: false,
        ipv4: false,
        error: "",
      },
      networkAdapterId: "",
      launches: [],
      apps: [],
      logs: [],
    });
  }
  async start() {
    if (process.getuid?.() === 0) throw new Error("请以普通用户运行 IP Guard，测试版无需 sudo");
    await privateDirectory(this.options.directory);
    try {
      this.config = configSchema.parse(JSON.parse(await readFile(this.configFile(), "utf8")));
    } catch (error) {
      if (!fileMissing(error)) throw new Error(`配置读取失败，原文件已保留：${message(error)}`);
    }
    for (const key of serviceKeys)
      Object.assign(this.snapshot.services[key], this.config.services[key]);
    this.snapshot.apps = this.config.apps;
    this.snapshot.autostart = this.config.autostart;
    this.snapshot.networkAdapterId = this.config.networkAdapterId;
    if (process.platform === "linux") {
      try {
        await run("systemctl", ["--user", "show-environment"], { timeout: 2000, maxBuffer: 65536 });
        this.cgroups = true;
      } catch {
        this.log(
          "warning",
          "当前会话的 systemd 用户服务不可用，使用受控进程组；不提供系统级网络过滤",
        );
      }
    }
    this.snapshot.processProtection = this.cgroups ? "managed-cgroup" : "managed-group";
    await preparePosixSocket(this.endpoint);
    const server = createServer((socket) => this.accept(socket));
    this.server = server;
    server.on("error", (error) => this.fail(error));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.endpoint, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    await chmod(this.endpoint, 0o600);
    for (const target of this.config.apps.filter((item) => item.enabled))
      await this.launcher(target, true);
    try {
      await access(path.join(this.options.directory, "browser/ipguard-native-host"));
      await this.registerBrowser();
    } catch (error) {
      if (!fileMissing(error)) this.log("warning", `浏览器宿主刷新失败：${message(error)}`);
    }
    this.snapshot.online = true;
    this.refreshAdapters();
    this.publish();
    this.emit("endpoint", path.join(posixSocketDirectory(), "browser.sock"));
    this.timer = setInterval(() => this.tick(), 500);
    this.tick();
  }
  private configFile() {
    return path.join(this.options.directory, "posix-settings.json");
  }
  private async save() {
    const data = JSON.stringify(this.config, null, 2);
    const next = this.persistence.then(async () => {
      const temporary = `${this.configFile()}.tmp`;
      await writeFile(temporary, data, { mode: 0o600 });
      await chmod(temporary, 0o600);
      await rename(temporary, this.configFile());
    });
    this.persistence = next.catch(() => undefined);
    await next;
  }
  private publish() {
    this.snapshot.apps = this.config.apps;
    this.snapshot.running = [...this.sessions].filter(([, item]) => item.started).map(([id]) => id);
    this.emit("snapshot", this.snapshot);
  }
  private log(level: "info" | "warning" | "error", text: string) {
    const entry = { time: new Date().toISOString(), level, message: text };
    this.snapshot.logs = [entry, ...this.snapshot.logs].slice(0, 200);
    void appendFile(
      path.join(this.options.directory, "events.jsonl"),
      JSON.stringify(entry) + "\n",
      { mode: 0o600 },
    ).catch((error: unknown) => console.error("事件日志", error));
  }
  private fresh(key: Service) {
    return (
      this.verified[key] > 0 &&
      performance.now() - this.verified[key] <=
        (this.snapshot.services[key].settings.intervalSeconds + 8) * 1000
    );
  }
  private canContinue(key: Service) {
    return !this.closed && posixPermission(this.snapshot.services[key], this.fresh(key), true);
  }
  private stopConnection(item: Connection) {
    item.stopping = true;
    if (item.socket.writable) item.socket.end(JSON.stringify({ type: "stop" }) + "\n");
    else item.socket.destroy();
  }
  private revoke(key: Service, reason: string, preserveIp = false) {
    this.epochs[key]++;
    this.verified[key] = 0;
    const rule = this.snapshot.services[key];
    rule.ready = false;
    rule.unverified = false;
    rule.reason = reason;
    if (!preserveIp) rule.currentIp = "";
    for (const item of this.sessions.values()) if (item.service === key) this.stopConnection(item);
  }
  private unavailable(key: Service, reason: string) {
    const rule = this.snapshot.services[key];
    const changed = rule.ready || rule.reason !== reason;
    if (rule.stopOnProbeFailure || !rule.enabled || !rule.rulesLocked) this.revoke(key, reason);
    else {
      rule.ready = false;
      rule.unverified = true;
      rule.currentIp = "";
      rule.reason = reason;
    }
    if (changed) this.log("warning", `${serviceName(key)} · ${reason}`);
  }
  private async check(key: Service): Promise<boolean> {
    const pending = this.checks.get(key);
    if (pending) return pending;
    const task = this.read(key).finally(() => {
      this.checks.delete(key);
    });
    this.checks.set(key, task);
    return task;
  }
  private async read(key: Service) {
    const rule = this.snapshot.services[key],
      epoch = this.epochs[key];
    if (!rule.enabled || !rule.rulesLocked || this.closed) return false;
    rule.checking = true;
    this.publish();
    try {
      const result = await this.probe.check(key);
      if (this.closed || epoch !== this.epochs[key]) return false;
      rule.lastChecked = result.checkedAt;
      rule.adapter = result.adapter;
      rule.currentIp = result.ip;
      if (!result.ip) {
        this.unavailable(key, `出口检测失败（未确认 IP 变化） · ${result.error}`);
        return false;
      }
      if (result.ip !== rule.settings.expectedIp) {
        const reason = `出口 IPv4 不符 · 实测 ${result.ip} · 锁定 ${rule.settings.expectedIp}`;
        this.revoke(key, reason, true);
        this.log("warning", `${serviceName(key)} · ${reason}`);
        return false;
      }
      rule.ready = true;
      rule.unverified = false;
      rule.reason = "";
      this.verified[key] = performance.now();
      return true;
    } catch (error) {
      if (!this.closed && epoch === this.epochs[key])
        this.unavailable(key, `出口检测失败（未确认 IP 变化） · ${message(error)}`);
      return false;
    } finally {
      rule.checking = false;
      this.nextCheck[key] = performance.now() + rule.settings.intervalSeconds * 1000;
      this.publish();
    }
  }
  private refreshAdapters() {
    const adapters = Object.entries(networkInterfaces())
      .filter(([, values]) => values?.some((value) => !value.internal))
      .map(([name, values]) => ({
        id: name,
        name,
        exists: true,
        up: Boolean(values?.length),
        ipv4: Boolean(values?.some((value) => value.family === "IPv4")),
        error: "",
      }));
    const fingerprint = JSON.stringify(
      Object.entries(networkInterfaces())
        .flatMap(([name, values]) =>
          (values ?? [])
            .filter((value) => value.family === "IPv4" && !value.internal)
            .map((value) => [name, value.address, value.netmask]),
        )
        .sort((a, b) => a.join("\0").localeCompare(b.join("\0"))),
    );
    if (this.topology && this.topology !== fingerprint)
      for (const key of serviceKeys) this.nextCheck[key] = 0;
    this.topology = fingerprint;
    this.snapshot.networkAdapters = adapters;
    this.snapshot.watchedAdapter = adapters.find(
      (adapter) => adapter.id === this.snapshot.networkAdapterId,
    ) ??
      (!this.snapshot.networkAdapterId ? adapters.find((adapter) => adapter.ipv4) : undefined) ?? {
        id: this.snapshot.networkAdapterId,
        name: this.snapshot.networkAdapterId || "未发现 IPv4 网卡",
        exists: false,
        up: false,
        ipv4: false,
        error: "仅作诊断，不以网卡通知直接判定 IP 改变",
      };
  }
  private tick() {
    if (this.closed) return;
    this.refreshAdapters();
    for (const key of serviceKeys) {
      const rule = this.snapshot.services[key];
      if (rule.ready && !this.fresh(key))
        this.unavailable(key, "服务出口结果已过期，未确认 IP 变化");
      if (rule.enabled && rule.rulesLocked && performance.now() >= this.nextCheck[key])
        void this.check(key);
    }
    for (const item of this.sessions.values()) {
      if (item.stopping) continue;
      if (!this.canContinue(item.service)) this.stopConnection(item);
      else if (item.socket.writable) item.socket.write(JSON.stringify({ type: "lease" }) + "\n");
    }
    this.publish();
  }
  private target(id: string) {
    const target = this.config.apps.find((item) => item.id === id);
    if (!target) throw new Error("找不到该程序");
    return target;
  }
  private launchState(id: string, phase: "starting" | "started" | "failed", detail: string) {
    this.snapshot.launches = [
      ...this.snapshot.launches.filter((item) => item.id !== id),
      { id, phase, message: detail },
    ];
    this.publish();
  }
  private accept(socket: Socket) {
    if (this.connections.size >= 32) {
      socket.destroy();
      return;
    }
    this.connections.add(socket);
    let buffer = "",
      id = "",
      accepted = false;
    socket.setEncoding("utf8");
    socket.setTimeout(12000, () => socket.destroy());
    socket.on("error", (error) => {
      if (id && !this.closed) this.log("warning", `受控连接断开：${message(error)}`);
    });
    socket.on("close", () => {
      this.connections.delete(socket);
      if (id && this.sessions.get(id)?.socket === socket) {
        this.sessions.delete(id);
        if (this.snapshot.launches.find((item) => item.id === id)?.phase === "starting")
          this.launchState(id, "failed", "应用在确认启动前退出，请检查应用运行日志");
        this.publish();
      }
    });
    socket.on("data", (data: string) => {
      buffer += data;
      if (Buffer.byteLength(buffer) > 32768) {
        socket.destroy();
        return;
      }
      let split: number;
      while ((split = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, split);
        buffer = buffer.slice(split + 1);
        try {
          const value: unknown = JSON.parse(line);
          if (!accepted) {
            const request = launchRequest.parse(value);
            accepted = true;
            id = request.targetId;
            void this.authorize(socket, request).catch((error: unknown) => {
              if (this.sessions.get(id)?.socket === socket)
                this.launchState(id, "failed", message(error));
              socket.end(JSON.stringify({ type: "denied", message: message(error) }) + "\n");
            });
          } else {
            const event = launchEvent.parse(value);
            const item = this.sessions.get(id);
            if (!item || item.socket !== socket) {
              socket.destroy();
              return;
            }
            if (event.type === "started" && !item.stopping && this.canContinue(item.service)) {
              item.started = true;
              item.pid = event.pid;
              this.launchState(id, "started", "受控进程已启动；应用窗口由程序自身显示");
            } else if (event.type === "failed") this.launchState(id, "failed", event.message);
            else if (event.type === "closed") {
              item.stopping = true;
              this.publish();
            }
          }
        } catch {
          socket.destroy();
          return;
        }
      }
    });
  }
  private async authorize(socket: Socket, request: z.infer<typeof launchRequest>) {
    const target = this.target(request.targetId);
    if (this.sessions.has(target.id)) throw new Error("该程序已有受控启动或运行实例");
    this.sessions.set(target.id, {
      socket,
      service: target.service,
      started: false,
      pid: 0,
      stopping: false,
    });
    this.launchState(target.id, "starting", "正在核对该服务出口 IPv4");
    if (!target.enabled) throw new Error("请先开启该程序防护");
    await this.check(target.service);
    if (
      this.closed ||
      socket.destroyed ||
      this.target(target.id) !== target ||
      !target.enabled ||
      !posixPermission(this.snapshot.services[target.service], this.fresh(target.service), false)
    )
      throw new Error(this.snapshot.services[target.service].reason || "该服务未通过出口校验");
    const executable = await this.executable(target.path);
    const args = [...parsePosixArguments(target.arguments), ...request.extra];
    await this.requireClosed(executable);
    if (
      this.closed ||
      !posixPermission(this.snapshot.services[target.service], this.fresh(target.service), false) ||
      socket.destroyed
    )
      throw new Error("启动校验结果已失效，请重试");
    socket.setTimeout(0);
    socket.write(
      JSON.stringify({
        type: "launch",
        executable,
        args,
        mode: this.cgroups ? "cgroup" : "group",
        unit: `ipguard-${crypto.randomUUID()}.scope`,
      }) + "\n",
    );
  }
  private async executable(filename: string) {
    if (!path.isAbsolute(filename)) throw new Error("请选择可执行文件的绝对路径");
    const file = await realpath(filename);
    if (!(await stat(file)).isFile()) throw new Error("请选择应用中的实际可执行文件");
    await access(file, constants.X_OK);
    if (file === (await realpath(this.options.executable)))
      throw new Error("不能把 IP Guard 自身作为受保护程序");
    return file;
  }
  private async requireClosed(filename: string) {
    const result = await run("/bin/ps", ["-ww", "-ax", "-o", "uid=,pid=,comm="], {
      timeout: 2000,
      maxBuffer: 1048576,
    });
    for (const line of result.stdout.split("\n")) {
      const row = line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/);
      if (!row || Number(row[1]) !== process.getuid?.()) continue;
      let executable = row[3];
      if (process.platform === "linux") {
        // Linux comm is limited to 15 bytes; unrelated non-dumpable processes must not
        // prevent protection from being enabled for an application with a different name.
        if (executable !== Buffer.from(path.basename(filename)).subarray(0, 15).toString())
          continue;
        try {
          executable = await realpath(`/proc/${row[2]}/exe`);
        } catch (error) {
          if (fileMissing(error)) continue;
          throw error;
        }
      }
      if (executable === filename)
        throw new Error(
          "请先关闭该程序现有实例，再通过 IP Guard 启动；测试版不会接管自行启动的实例",
        );
    }
  }
  private async launcher(target: ProtectedApp, enabled: boolean) {
    const folder = path.join(this.options.directory, "launchers");
    await privateDirectory(folder);
    const filename = path.join(
      folder,
      `IPGuard-${target.id}${process.platform === "darwin" ? ".command" : ".sh"}`,
    );
    if (!enabled) {
      await unlink(filename).catch((error: unknown) => {
        if (!fileMissing(error)) throw error;
      });
      return;
    }
    const runtime = path.join(this.options.resources, "managed-run.mjs");
    await writeFile(
      filename,
      `#!/bin/sh\nELECTRON_RUN_AS_NODE=1 exec ${shellQuote(this.options.executable)} ${shellQuote(runtime)} --socket ${shellQuote(this.endpoint)} --app ${shellQuote(target.id)} -- "$@"\n`,
      { mode: 0o700 },
    );
    await chmod(filename, 0o700);
  }
  private registerBrowser() {
    return registerPosixBrowser(
      this.options.directory,
      this.options.executable,
      path.join(this.options.resources, "native-host.mjs"),
    );
  }
  async request(action: string, payload: Record<string, unknown> = {}): Promise<Snapshot> {
    if (this.closed) throw new Error("守护程序正在退出");
    if (action === "browser:register") {
      await this.registerBrowser();
      return this.snapshot;
    }
    const command = commandSchema.parse({ ...payload, id: payload.targetId, action });
    if (command.action === "status") return this.snapshot;
    if (command.action === "check") {
      await this.check(command.service);
      return this.snapshot;
    }
    if (command.action === "lock") {
      const key = command.service;
      if (this.snapshot.services[key].rulesLocked) throw new Error("请先取消该服务锁定再修改地址");
      this.revoke(key, "正在锁定");
      Object.assign(this.snapshot.services[key], {
        settings: command.settings,
        enabled: true,
        rulesLocked: true,
      });
      this.config.services[key] = storedRule.parse(this.snapshot.services[key]);
      await this.save();
      await this.checks.get(key);
      await this.check(key);
    } else if (command.action === "unlock" || command.action === "service:enable") {
      const key = command.service,
        rule = this.snapshot.services[key];
      this.revoke(
        key,
        command.action === "unlock"
          ? "请先锁定该服务允许的公网 IPv4"
          : "该服务已暂停，网页保持阻断",
      );
      if (command.action === "unlock") {
        rule.rulesLocked = false;
        rule.enabled = false;
      } else {
        if (!rule.rulesLocked) throw new Error("请先锁定 IP");
        rule.enabled = command.enabled;
      }
      this.config.services[key] = storedRule.parse(rule);
      await this.save();
      if (rule.enabled) {
        await this.checks.get(key);
        await this.check(key);
      }
    } else if (command.action === "failure-policy") {
      const rule = this.snapshot.services[command.service];
      rule.stopOnProbeFailure = command.stopOnProbeFailure;
      this.config.services[command.service] = storedRule.parse(rule);
      await this.save();
      if (rule.unverified && rule.stopOnProbeFailure)
        this.revoke(command.service, "已恢复检测失败时自动结束");
      await this.check(command.service);
    } else if (command.action === "add") {
      if (this.config.apps.length >= 256) throw new Error("程序数量已达上限");
      if (
        this.config.apps.some(
          (target) => target.id === command.app.id || target.path === command.app.path,
        )
      )
        throw new Error("该程序已添加");
      await this.executable(command.app.path);
      parsePosixArguments(command.app.arguments);
      if (command.app.enabled && !this.snapshot.services[command.app.service].rulesLocked)
        throw new Error("请先锁定该服务 IP");
      this.config.apps.push(command.app);
      await this.launcher(command.app, command.app.enabled);
      await this.save();
    } else if (command.action === "edit") {
      const target = this.target(command.id);
      if (target.enabled && target.service !== command.service)
        throw new Error("修改归属前请先关闭该程序防护");
      parsePosixArguments(command.arguments);
      Object.assign(target, {
        name: command.name,
        arguments: command.arguments,
        service: command.service,
      });
      await this.save();
    } else if (command.action === "protect") {
      const target = this.target(command.id);
      if (command.enabled && !this.snapshot.services[target.service].rulesLocked)
        throw new Error("请先锁定该服务 IP");
      if (command.enabled) {
        const executable = await this.executable(target.path);
        await this.requireClosed(executable);
      } else {
        const item = this.sessions.get(target.id);
        if (item) this.stopConnection(item);
      }
      target.enabled = command.enabled;
      await this.launcher(target, command.enabled);
      await this.save();
    } else if (command.action === "remove") {
      const target = this.target(command.id),
        item = this.sessions.get(target.id);
      if (item) this.stopConnection(item);
      await this.launcher(target, false);
      this.config.apps = this.config.apps.filter((app) => app.id !== target.id);
      this.snapshot.launches = this.snapshot.launches.filter((launch) => launch.id !== target.id);
      await this.save();
    } else if (command.action === "start") {
      const target = this.target(command.id);
      if (
        this.sessions.has(target.id) ||
        this.snapshot.launches.find((item) => item.id === target.id)?.phase === "starting"
      )
        throw new Error("该程序已在启动或运行");
      if (!target.enabled) throw new Error("请先开启该程序防护");
      this.launchState(target.id, "starting", "正在连接受控启动器");
      const log = openSync(path.join(this.options.directory, `app-${target.id}.log`), "a", 0o600);
      try {
        const child = spawn(
          this.options.executable,
          [
            path.join(this.options.resources, "managed-run.mjs"),
            "--socket",
            this.endpoint,
            "--app",
            target.id,
          ],
          { env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }, stdio: ["ignore", log, log] },
        );
        child.on("error", (error) => this.launchState(target.id, "failed", error.message));
        child.once("exit", () => {
          if (this.snapshot.launches.find((item) => item.id === target.id)?.phase === "starting")
            this.launchState(target.id, "failed", "启动器未能确认应用启动，请查看应用运行日志");
        });
      } finally {
        closeSync(log);
      }
    } else if (command.action === "stop") {
      const item = this.sessions.get(command.id);
      if (item) {
        this.stopConnection(item);
        await this.waitStopped([item]);
      }
    } else if (command.action === "adapter:set") {
      this.snapshot.networkAdapterId = command.adapterId;
      this.config.networkAdapterId = command.adapterId;
      await this.save();
      this.refreshAdapters();
    } else if (command.action === "autostart") {
      this.config.autostart = command.enabled;
      this.snapshot.autostart = command.enabled;
      await this.save();
    } else throw new Error(`此操作不由 POSIX 守护器处理：${command.action}`);
    this.publish();
    return this.snapshot;
  }
  processStatus(key: Service): ProcessState {
    const items = [...this.sessions.values()].filter(
      (item) => item.service === key && item.started,
    );
    const count = items.length;
    return {
      service: key,
      phase: count ? "running" : "stopped",
      count,
      canStop: items.some((item) => !item.stopping),
      message: "仅统计由 IP Guard 或受控启动器启动的实例，不接管其他程序",
      checkedAt: new Date().toISOString(),
    };
  }
  private async waitStopped(items: Connection[]) {
    await Promise.all(
      items.map(
        (item) =>
          new Promise<void>((resolve, reject) => {
            if (item.socket.destroyed) {
              resolve();
              return;
            }
            const timer = setTimeout(
              () => reject(new Error("程序停止尚未确认，请查看运行日志")),
              7000,
            );
            item.socket.once("close", () => {
              clearTimeout(timer);
              resolve();
            });
          }),
      ),
    );
  }
  async stopService(key: Service) {
    const items = [...this.sessions.values()].filter((item) => item.service === key);
    for (const item of items) this.stopConnection(item);
    await this.waitStopped(items);
    this.publish();
    return this.processStatus(key);
  }
  private fail(error: Error) {
    if (this.closed) return;
    this.error = error.message;
    void this.stop();
    this.emit("failure", error.message);
  }
  async stop() {
    this.closed = true;
    clearInterval(this.timer);
    for (const key of serviceKeys) this.revoke(key, "守护程序已退出");
    this.snapshot.online = false;
    this.publish();
    const server = this.server;
    this.server = undefined;
    if (server) {
      for (const item of this.sessions.values()) this.stopConnection(item);
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          for (const socket of this.connections) socket.destroy();
          resolve();
        }, 4000);
        server.close(() => {
          clearTimeout(timeout);
          resolve();
        });
      });
      await unlink(this.endpoint).catch((error: unknown) => {
        if (!fileMissing(error)) console.error(error);
      });
    }
    await this.persistence;
  }
}
