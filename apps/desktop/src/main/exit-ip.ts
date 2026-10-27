import { EventEmitter } from "node:events";

import { session } from "electron";
import type { Session } from "electron";

import { ipv4Schema, services } from "@ip-guard/electron";
import type { SingleService } from "@ip-guard/electron";

import type { ExitResult } from "#src/main/exit-policy.ts";

export interface ProbeProgress {
  step: string;
  label: string;
  status: string;
  detail: string;
}
const publicIPv4 = (value: string) => {
  if (!ipv4Schema.safeParse(value).success) return false;
  const [a, b, c] = value.split(".").map(Number);
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a !== undefined && a >= 224) ||
    (a === 100 && b !== undefined && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b !== undefined && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  );
};
async function bounded<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) void work.catch(() => undefined);
  signal.throwIfAborted();
  let cancel: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    cancel = () => reject(new Error("出口检测超时或已取消"));
    signal.addEventListener("abort", cancel, { once: true });
  });
  try {
    return await Promise.race([work, aborted]);
  } finally {
    if (cancel) signal.removeEventListener("abort", cancel);
  }
}
export class ExitIPv4 extends EventEmitter<{
  update: [ExitResult];
  progress: [ProbeProgress];
}> {
  latest: ExitResult | undefined;
  steps: ProbeProgress[] = [];
  private pending: Promise<ExitResult> | undefined;
  private abort = new AbortController();
  private transport: Session | undefined;
  private service: SingleService;
  constructor(service: SingleService) {
    super();
    this.service = service;
  }
  private progress(value: ProbeProgress) {
    const index = this.steps.findIndex((step) => step.step === value.step);
    if (index < 0) this.steps.push(value);
    else this.steps[index] = value;
    this.emit("progress", value);
  }
  check(): Promise<ExitResult> {
    if (this.pending) return this.pending;
    this.steps = [];
    this.pending = this.read()
      .then((result) => {
        this.latest = result;
        this.emit("update", result);
        return result;
      })
      .finally(() => {
        this.pending = undefined;
      });
    return this.pending;
  }
  stop() {
    this.abort.abort();
  }
  private async read(): Promise<ExitResult> {
    const { endpoint, name } = services[this.service];
    const hostname = new URL(endpoint).hostname;
    const started = performance.now();
    const signal = AbortSignal.any([this.abort.signal, AbortSignal.timeout(4500)]);
    let status = 0,
      adapter = "";
    this.progress({ step: "dns", label: "DNS 解析", status: "running", detail: hostname });
    try {
      const transport = (this.transport ??= session.fromPartition(`ip-guard-ipv4-${this.service}`, {
        cache: false,
      }));
      await bounded(transport.closeAllConnections(), signal);
      const proxy = await bounded(transport.resolveProxy(endpoint), signal);
      adapter = proxy === "DIRECT" ? "系统直连" : "系统代理";
      if (proxy !== "DIRECT")
        this.progress({ step: "dns", label: "DNS 解析", status: "info", detail: "由系统代理解析" });
      else {
        try {
          const host = await bounded(transport.resolveHost(hostname, { queryType: "A" }), signal);
          this.progress({
            step: "dns",
            label: "DNS 解析",
            status: "ok",
            detail: host.endpoints[0]?.address ?? "系统解析",
          });
        } catch (error) {
          signal.throwIfAborted();
          this.progress({
            step: "dns",
            label: "DNS 解析",
            status: "unknown",
            detail: error instanceof Error ? error.message : "未取得解析信息",
          });
        }
      }
      this.progress({ step: "ipv4", label: `${name} IPv4`, status: "running", detail: adapter });
      const response = await bounded(
        transport.fetch(endpoint, {
          signal,
          cache: "no-store",
          redirect: "manual",
          bypassCustomProtocolHandlers: true,
        }),
        signal,
      );
      status = response.status;
      if (status !== 200) throw new Error(`${name} 出口返回 HTTP ${status}`);
      const reader = response.body?.getReader();
      if (!reader) throw new Error(`${name} 出口响应为空`);
      const decoder = new TextDecoder();
      let body = "",
        bytes = 0;
      try {
        while (true) {
          const chunk = await bounded(reader.read(), signal);
          if (chunk.done) break;
          bytes += chunk.value.byteLength;
          if (bytes > 32768) throw new Error(`${name} 出口响应超过 32 KB`);
          body += decoder.decode(chunk.value, { stream: true });
        }
        body += decoder.decode();
      } finally {
        void reader.cancel().catch(() => undefined);
      }
      const ip = /^ip=([^\r\n]+)$/m.exec(body)?.[1]?.trim() ?? "";
      if (!publicIPv4(ip)) throw new Error(`${name} 出口未返回公网 IPv4，请确认代理提供 IPv4 出口`);
      this.progress({ step: "ipv4", label: `${name} IPv4`, status: "ok", detail: ip });
      return {
        ip,
        error: "",
        checkedAt: new Date().toISOString(),
        adapter,
        status,
        ms: Math.round(performance.now() - started),
      };
    } catch (error) {
      const detail = signal.aborted
        ? `${name} 出口检测超时或已取消`
        : error instanceof Error
          ? error.message
          : `${name} 出口检测失败`;
      return {
        ip: "",
        error: detail,
        checkedAt: new Date().toISOString(),
        adapter,
        status,
        ms: Math.round(performance.now() - started),
      };
    }
  }
}
