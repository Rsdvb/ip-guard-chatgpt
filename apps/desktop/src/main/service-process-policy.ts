import { z } from "zod";

import { serviceName } from "@ip-guard/electron";
import type { ProcessState, Service } from "@ip-guard/electron";

export const windowsProcessSnapshotSchema = z.object({
  session: z.number().int().nonnegative(),
  username: z.string().min(1),
  unknown: z.number().int().nonnegative(),
  selfInTree: z.boolean(),
  mixedServices: z.boolean(),
  processes: z.array(
    z.object({ pid: z.number().int().positive(), parent: z.number().int().nonnegative() }),
  ),
});
export type WindowsProcessSnapshot = z.infer<typeof windowsProcessSnapshotSchema>;
export const processImage = (service: Service) =>
  service === "claude" ? "Claude.exe" : "ChatGPT.exe";
export function evaluateProcesses(service: Service, value: WindowsProcessSnapshot): ProcessState {
  const running = value.processes.length > 0;
  return {
    service,
    phase: running ? "running" : value.unknown ? "unknown" : "stopped",
    count: value.processes.length,
    canStop: running && !value.selfInTree && !value.mixedServices,
    message: value.selfInTree
      ? `请从 Windows 快捷方式打开 IP Guard 后停止 ${serviceName(service)}`
      : value.mixedServices
        ? "进程树内包含另一服务，请分别从各自快捷方式启动后操作"
        : value.unknown
          ? "部分进程信息读取失败"
          : "",
    checkedAt: new Date().toISOString(),
  };
}
