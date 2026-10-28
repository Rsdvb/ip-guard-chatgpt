import { execFile } from "node:child_process";
import { cpus } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const run = promisify(execFile);
function processUsage(value: unknown): {
  pid: number;
  parent: number;
  seconds: number;
  rss: number;
} {
  if (
    !value ||
    typeof value !== "object" ||
    !("pid" in value) ||
    typeof value.pid !== "number" ||
    !("parent" in value) ||
    typeof value.parent !== "number" ||
    !("seconds" in value) ||
    typeof value.seconds !== "number" ||
    !("rss" in value) ||
    typeof value.rss !== "number"
  )
    throw new Error("Invalid process usage record");
  return { pid: value.pid, parent: value.parent, seconds: value.seconds, rss: value.rss };
}
async function processes() {
  if (process.platform === "win32") {
    const { stdout } = await run(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ pid=[int]$_.ProcessId; parent=[int]$_.ParentProcessId; seconds=([double]$_.KernelModeTime+[double]$_.UserModeTime)/10000000; rss=[double]$_.WorkingSetSize } } | ConvertTo-Json -Compress",
      ],
      { windowsHide: true },
    );
    const value: unknown = JSON.parse(stdout);
    if (!Array.isArray(value)) throw new Error("Invalid process list");
    return value.map(processUsage);
  }
  const { stdout } = await run("/bin/ps", ["-axo", "pid=,ppid=,time=,rss="]);
  return stdout
    .trim()
    .split("\n")
    .map((line) => {
      const fields = line.trim().split(/\s+/),
        time = fields[2]?.split(":").map(Number) ?? [];
      if (fields.length !== 4 || time.length < 2 || time.length > 3)
        throw new Error("Unexpected ps process format");
      const seconds = time.reduce((total, value) => total * 60 + value, 0);
      return processUsage({
        pid: Number(fields[0]),
        parent: Number(fields[1]),
        seconds,
        rss: Number(fields[3]) * 1024,
      });
    });
}
export async function sampleResources(pid: number, scope: string) {
  const before = await processes(),
    start = performance.now();
  await delay(10000);
  const after = await processes(),
    elapsed = (performance.now() - start) / 1000;
  const selected = new Set([pid]);
  let added = true;
  while (added) {
    added = false;
    for (const item of [...before, ...after])
      if (selected.has(item.parent) && !selected.has(item.pid)) {
        selected.add(item.pid);
        added = true;
      }
  }
  const prior = new Map(before.map((item) => [item.pid, item.seconds]));
  const result = after.filter((item) => selected.has(item.pid));
  const cpu =
    (result.reduce(
      (sum, item) => sum + Math.max(0, item.seconds - (prior.get(item.pid) ?? item.seconds)),
      0,
    ) /
      elapsed) *
    100;
  return {
    scope,
    elapsedSeconds: elapsed,
    logicalCPUs: cpus().length,
    cpuPercentOfOneCore: cpu,
    cpuPercentOfMachine: cpu / cpus().length,
    rssMiB: result.reduce((sum, item) => sum + item.rss, 0) / 1048576,
    processes: result.length,
    includesNativeChildren: true,
    configuration: "idle, no registered programs; CI VM measurement",
  };
}
