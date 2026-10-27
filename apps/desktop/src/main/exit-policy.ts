import { selectedServices, services } from "@ip-guard/electron";
import type { Service, SingleService } from "@ip-guard/electron";

export interface ExitResult {
  ip: string;
  error: string;
  checkedAt: string;
  adapter: string;
  status: number;
  ms: number;
}

// Both probes must agree: a Claude-only measurement cannot authorize ChatGPT.
export function evaluateExits(
  service: Service,
  results: Record<SingleService, ExitResult>,
): ExitResult {
  const selected = selectedServices(service).map((key) => ({ key, result: results[key] }));
  const first = selected[0];
  if (!first) throw new Error("未选择防护服务");
  const failed = selected.find(({ result }) => !result.ip || result.error);
  const mismatch = selected.some(({ result }) => result.ip !== first.result.ip);
  return {
    ...first.result,
    checkedAt: selected.map(({ result }) => result.checkedAt).sort()[0] ?? "",
    ms: Math.max(...selected.map(({ result }) => result.ms)),
    ip: failed || mismatch ? "" : first.result.ip,
    error: failed
      ? `${services[failed.key].name} 出口校验失败 · ${failed.result.error || "未返回公网 IPv4"}`
      : mismatch
        ? "Claude 与 ChatGPT 的出口 IPv4 不一致，请统一代理分流，或只选择其中一个服务"
        : "",
  };
}
