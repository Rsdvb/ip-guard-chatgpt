import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import {
  existsSync,
  mkdtempSync,
  copyFileSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";

import { nativeVersion, nativeProtocol, snapshotSchema } from "@ip-guard/electron";

assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
assert.equal(process.platform, "win32");
const root = path.resolve(import.meta.dirname, "..");
const native = path.join(root, "dist/native", nativeVersion, "IpGuard.Native.exe");
const localData = process.env.LOCALAPPDATA;
assert.ok(
  localData && path.isAbsolute(localData),
  "Windows must provide an absolute per-user data directory",
);
const data = path.join(localData, "IPGuard");
assert.ok(!existsSync(data), "An isolated runner must have no existing IP Guard data to replace");
const directory = mkdtempSync(path.join(root, "dist/upgrade-fixture-"));
copyFileSync(path.join(root, "dist/NativePolicyTests.exe"), path.join(directory, "fixture.exe"));
copyFileSync(path.join(root, "assets/tray.png"), path.join(directory, "logo.png"));
const valid = path.join(directory, `ipguard-fixture-${randomUUID()}.exe`);
copyFileSync(path.join(directory, "fixture.exe"), valid);
function fixture(action: "install" | "remove", version = 1) {
  const result = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      path.join(root, "tests/package-upgrade-fixture.ps1"),
      "-Root",
      directory,
      "-Action",
      action,
      "-Version",
      String(version),
    ],
    { encoding: "utf8", timeout: 120000 },
  );
  if (result.status !== 0) throw result.error || new Error(result.stdout + result.stderr);
  if (action === "remove") return "";
  const last = result.stdout.trim().split(/\r?\n/u).at(-1);
  const value: unknown = JSON.parse(last || "null");
  if (!value || typeof value !== "object" || typeof Reflect.get(value, "executable") !== "string")
    throw new Error("Missing registered fixture executable");
  return String(Reflect.get(value, "executable"));
}
const rule = (expectedIp: string) => ({
  settings: { expectedIp, intervalSeconds: 60 },
  rulesLocked: true,
  enabled: false,
  stopOnProbeFailure: false,
});
const packageId = randomUUID(),
  missingId = randomUUID(),
  validId = randomUUID();
async function guardian(expected: string) {
  const child = spawn(native, ["guard"], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  let initialized: (() => void) | undefined;
  let initializeFailed: ((error: Error) => void) | undefined;
  const hello = new Promise<void>((resolve, reject) => {
    initialized = resolve;
    initializeFailed = reject;
  });
  const helloTimer = setTimeout(
    () => initializeFailed?.(new Error("Guardian handshake timed out")),
    15000,
  );
  const requests = new Map<
    string,
    {
      resolve: (value: unknown) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  createInterface({ input: child.stdout }).on("line", (line) => {
    const value: unknown = JSON.parse(line);
    if (!value || typeof value !== "object") throw new Error("Invalid native response");
    if (Reflect.get(value, "type") === "hello") {
      child.stdin.write(
        JSON.stringify({ action: "initialize", version: nativeVersion, protocol: nativeProtocol }) +
          "\n",
      );
      clearTimeout(helloTimer);
      initialized?.();
    }
    if (Reflect.get(value, "type") === "fatal") {
      for (const request of requests.values())
        request.reject(new Error(String(Reflect.get(value, "error"))));
    }
    const request = requests.get(String(Reflect.get(value, "id")));
    if (request) {
      clearTimeout(request.timer);
      requests.delete(String(Reflect.get(value, "id")));
      if (Reflect.get(value, "ok") === true) request.resolve(Reflect.get(value, "data"));
      else request.reject(new Error(String(Reflect.get(value, "error"))));
    }
  });
  child.once("exit", (code) => {
    clearTimeout(helloTimer);
    initializeFailed?.(new Error(`Guardian exited ${code}: ${stderr}`));
    for (const request of requests.values())
      request.reject(new Error(`Guardian exited ${code}: ${stderr}`));
  });
  const request = (action: string, payload: Record<string, unknown> = {}) =>
    new Promise<unknown>((resolve, reject) => {
      const id = randomUUID();
      const timer = setTimeout(() => {
        requests.delete(id);
        reject(new Error(`Native request timed out: ${action}, ${stderr}`));
      }, 20000);
      requests.set(id, { resolve, reject, timer });
      child.stdin.write(JSON.stringify({ ...payload, id, action }) + "\n");
    });
  try {
    await hello;
    const snapshot = snapshotSchema.parse(await request("status"));
    assert.equal(
      snapshot.online,
      true,
      "A missing executable cannot take the whole guardian offline",
    );
    assert.equal(snapshot.apps.find((app) => app.id === packageId)?.path, expected);
    assert.equal(snapshot.apps.find((app) => app.id === packageId)?.protectionError, "");
    assert.match(snapshot.apps.find((app) => app.id === missingId)?.protectionError || "", /EXE/u);
    assert.equal(
      snapshot.apps.find((app) => app.id === validId)?.protectionError,
      "",
      "The other service must retain its valid protection",
    );
    assert.equal(snapshot.apps.find((app) => app.id === validId)?.enabled, true);
    assert.equal(snapshot.services.claude.settings.expectedIp, "8.8.8.8");
    assert.equal(snapshot.services.chatgpt.settings.expectedIp, "1.1.1.1");
    assert.equal(snapshot.services.claude.stopOnProbeFailure, false);
    assert.equal(snapshot.services.chatgpt.enabled, false);
    if (expected.includes("_2.0.0.0_")) {
      const upgraded = fixture("install", 3);
      await assert.rejects(request("start", { targetId: packageId }), /锁定并开启/u);
      const after = snapshotSchema.parse(await request("status"));
      assert.equal(
        after.apps.find((app) => app.id === packageId)?.path,
        upgraded,
        "Start must reconcile a package upgraded while the guardian is running",
      );
      assert.equal(after.apps.find((app) => app.id === validId)?.path, valid);
    }
    await request("shutdown");
    await once(child, "exit");
  } finally {
    clearTimeout(helloTimer);
    if (child.exitCode === null) {
      try {
        await request("shutdown");
        await once(child, "exit");
      } finally {
        if (child.exitCode === null) {
          child.kill();
          await once(child, "exit");
        }
      }
    }
    for (const pending of requests.values()) clearTimeout(pending.timer);
  }
}
let testFailure: unknown;
try {
  const old = fixture("install", 1);
  mkdirSync(data, { recursive: true });
  writeFileSync(
    path.join(data, "settings.json"),
    JSON.stringify({
      format: 2,
      services: { claude: rule("8.8.8.8"), chatgpt: rule("1.1.1.1") },
      apps: [
        {
          id: packageId,
          service: "claude",
          name: "Updated package",
          path: old,
          arguments: "",
          enabled: true,
        },
        {
          id: missingId,
          service: "claude",
          name: "Removed app",
          path: path.join(directory, "removed.exe"),
          arguments: "",
          enabled: true,
        },
        {
          id: validId,
          service: "chatgpt",
          name: "Other service",
          path: valid,
          arguments: "",
          enabled: true,
        },
      ],
    }),
  );
  const current = fixture("install", 2);
  const resolve = spawnSync(
    path.join(root, "dist/NativePolicyTests.exe"),
    ["--resolve-upgraded-package", old, current],
    { encoding: "utf8" },
  );
  assert.equal(resolve.status, 0, resolve.stdout + resolve.stderr);
  await guardian(current);
  const persisted: unknown = JSON.parse(readFileSync(path.join(data, "settings.json"), "utf8"));
  if (!persisted || typeof persisted !== "object") throw new Error("Missing persisted settings");
  const apps: unknown = Reflect.get(persisted, "apps");
  assert.ok(Array.isArray(apps));
  const updated: unknown = apps.find(
    (app: unknown) => app && typeof app === "object" && Reflect.get(app, "id") === packageId,
  );
  if (!updated || typeof updated !== "object") throw new Error("Missing persisted package");
  await guardian(String(Reflect.get(updated, "path")));
  console.log(
    "PASS: real MSIX upgrades before startup and during operation, stale EXE isolation, unchanged independent policies and repeat startup.",
  );
} catch (error) {
  testFailure = error;
}
try {
  const recovered = spawnSync(native, ["recover"], { encoding: "utf8", timeout: 30000 });
  if (recovered.status !== 0)
    throw (
      recovered.error ||
      new Error("Fixture protection recovery failed: " + recovered.stdout + recovered.stderr)
    );
  fixture("remove");
  rmSync(data, { recursive: true, force: true });
  rmSync(directory, { recursive: true, force: true });
} catch (error) {
  if (testFailure)
    throw new AggregateError([testFailure, error], "Upgrade test and cleanup failed");
  throw error;
}
if (testFailure) throw testFailure;
