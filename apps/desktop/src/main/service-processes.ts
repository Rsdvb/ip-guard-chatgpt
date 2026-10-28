import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { z } from "zod";

import { serviceName } from "@ip-guard/electron";
import type { ProcessState, Service } from "@ip-guard/electron";

import {
  evaluateProcesses,
  processImage,
  windowsProcessSnapshotSchema,
} from "#src/main/service-process-policy.ts";
import type { WindowsProcessSnapshot } from "#src/main/service-process-policy.ts";

import { nativePath } from "./guardian.ts";

const run = promisify(execFile);
const windows = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32");
const inventorySchema = z.object({
  claude: windowsProcessSnapshotSchema,
  chatgpt: windowsProcessSnapshotSchema,
});
let inventory: z.infer<typeof inventorySchema> | undefined;
let readAt = 0;
let reading: Promise<z.infer<typeof inventorySchema>> | undefined;
async function readInventory() {
  const result = await run(nativePath(), ["process-inventory", String(process.pid)], {
    windowsHide: true,
    timeout: 5000,
    maxBuffer: 131072,
    encoding: "utf8",
  });
  const value: unknown = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
  inventory = inventorySchema.parse(value);
  readAt = performance.now();
  return inventory;
}
async function snapshot(service: Service, force = false): Promise<WindowsProcessSnapshot> {
  if (force) return (await readInventory())[service];
  if (inventory && performance.now() - readAt < 1500) return inventory[service];
  reading ??= readInventory().finally(() => {
    reading = undefined;
  });
  return (await reading)[service];
}
export function cachedServiceProcessStatus(service: Service): ProcessState {
  return inventory
    ? evaluateProcesses(service, inventory[service])
    : {
        service,
        phase: "unknown",
        count: 0,
        canStop: false,
        message: "打开窗口后刷新进程状态",
        checkedAt: "",
      };
}
const pending = new Map<Service, Promise<ProcessState>>();
export function serviceProcessStatus(service: Service): Promise<ProcessState> {
  const current = pending.get(service);
  if (current) return current;
  const request = snapshot(service)
    .then((value) => evaluateProcesses(service, value))
    .catch((): ProcessState => ({
      service,
      phase: "unknown",
      count: 0,
      canStop: false,
      message: `${serviceName(service)} 进程状态读取失败`,
      checkedAt: new Date().toISOString(),
    }))
    .finally(() => {
      pending.delete(service);
    });
  pending.set(service, request);
  return request;
}
export async function stopServiceTrees(service: Service): Promise<ProcessState> {
  const before = await snapshot(service, true);
  const current = evaluateProcesses(service, before);
  if (current.phase === "stopped") return current;
  if (!current.canStop) throw new Error(current.message || "无法确认可停止的服务进程");
  const ids = new Set(before.processes.map((item) => item.pid));
  const roots = before.processes.filter((item) => !ids.has(item.parent));
  await Promise.allSettled(
    roots.map((item) =>
      run(
        path.join(windows, "taskkill.exe"),
        [
          "/PID",
          String(item.pid),
          "/T",
          "/F",
          "/FI",
          `IMAGENAME eq ${processImage(service)}`,
          "/FI",
          `SESSION eq ${before.session}`,
          "/FI",
          `USERNAME eq ${before.username}`,
        ],
        { windowsHide: true, timeout: 10000, maxBuffer: 131072, encoding: "utf8" },
      ),
    ),
  );
  const after = evaluateProcesses(service, await snapshot(service, true));
  if (after.phase === "running")
    throw new Error(`部分 ${serviceName(service)} 进程仍在运行，请检查权限后重试`);
  if (after.phase === "unknown") throw new Error("停止请求已发送，进程状态暂未确认");
  return after;
}
