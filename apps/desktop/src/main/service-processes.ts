import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { serviceName } from "@ip-guard/electron";
import type { ProcessState, Service } from "@ip-guard/electron";

import {
  evaluateProcesses,
  processImage,
  windowsProcessSnapshotSchema,
} from "#src/main/service-process-policy.ts";
import type { WindowsProcessSnapshot } from "#src/main/service-process-policy.ts";

const run = promisify(execFile);
const windows = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32");
const query = (service: Service) => `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$username=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$session=[System.Diagnostics.Process]::GetCurrentProcess().SessionId
$all=@(Get-CimInstance Win32_Process -Filter ("SessionId="+$session) -Property Handle,ProcessId,ParentProcessId,Name -ErrorAction Stop)
$image='${processImage(service)}'
$otherImage='${processImage(service === "claude" ? "chatgpt" : "claude")}'
$items=@(); $unknown=0; $parents=@{}
foreach($p in $all) {
  $parents[[int]$p.ProcessId]=[int]$p.ParentProcessId
  if($p.Name -ne $image) { continue }
  try {
    $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
    if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $sid) { $items+=@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId} }
    elseif($owner.ReturnValue -ne 0) { $unknown++ }
  } catch { $unknown++ }
}
$targets=[System.Collections.Generic.HashSet[int]]::new()
foreach($p in $items) { [void]$targets.Add($p.pid) }
$mixedServices=$false
foreach($p in $all) {
  if($p.Name -ne $otherImage) { continue }
  $visited=[System.Collections.Generic.HashSet[int]]::new(); $cursor=[int]$p.ProcessId
  while($cursor -gt 0 -and $visited.Add($cursor)) {
    if($targets.Contains($cursor)) { $mixedServices=$true; break }
    if(-not $parents.ContainsKey($cursor)) { break }
    $cursor=$parents[$cursor]
  }
}
$ancestors=[System.Collections.Generic.HashSet[int]]::new()
$cursor=${process.pid}
while($cursor -gt 0 -and $ancestors.Add($cursor)) {
  if(-not $parents.ContainsKey($cursor)) { break }
  $cursor=$parents[$cursor]
}
$selfInTree=$false
foreach($p in $items) { if($ancestors.Contains($p.pid)) { $selfInTree=$true } }
@{session=$session;username=$username;unknown=$unknown;selfInTree=$selfInTree;mixedServices=$mixedServices;processes=@($items)} | ConvertTo-Json -Depth 4 -Compress
`;
async function snapshot(service: Service): Promise<WindowsProcessSnapshot> {
  const result = await run(
    path.join(windows, "WindowsPowerShell/v1.0/powershell.exe"),
    ["-NoProfile", "-NonInteractive", "-Command", query(service)],
    { windowsHide: true, timeout: 12000, maxBuffer: 131072, encoding: "utf8" },
  );
  const value: unknown = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
  return windowsProcessSnapshotSchema.parse(value);
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
  const before = await snapshot(service);
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
  const after = evaluateProcesses(service, await snapshot(service));
  if (after.phase === "running")
    throw new Error(`部分 ${serviceName(service)} 进程仍在运行，请检查权限后重试`);
  if (after.phase === "unknown") throw new Error("停止请求已发送，进程状态暂未确认");
  return after;
}
