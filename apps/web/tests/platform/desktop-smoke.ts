import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { _electron } from "@playwright/test";

import {
  browserExtensionId,
  browserStateSchema,
  nativeVersion,
  snapshotSchema,
  replySchema,
} from "@ip-guard/electron";

import { registerPosixBrowser } from "../../../desktop/src/main/posix-browser.ts";
import { sampleResources } from "./resource-sample.ts";

if (process.platform === "win32" && process.env.GITHUB_ACTIONS !== "true")
  throw new Error("Windows packaged system test runs only in an isolated GitHub Actions VM");
const desktop = path.resolve(import.meta.dirname, "../../../desktop");
const requestedExecutable =
  process.env.IP_GUARD_PACKAGED_EXECUTABLE ||
  (process.platform === "darwin"
    ? path.join(desktop, "release/mac-arm64/IP Guard.app/Contents/MacOS/IP Guard")
    : process.platform === "win32"
      ? path.join(desktop, "release/win-unpacked/IP Guard.exe")
      : path.join(desktop, "release/linux-unpacked/ip-guard"));
const executable = await realpath(requestedExecutable);
const resources =
  process.platform === "darwin"
    ? path.resolve(executable, "../../Resources")
    : path.join(path.dirname(executable), "resources");
await access(path.join(resources, "browser-extension/manifest.json"));
if (process.platform !== "win32") await access(path.join(resources, "posix/managed-run.mjs"));
const profile = await realpath(await mkdtemp(path.join(tmpdir(), "ipg-desktop-")));
const application = await _electron.launch({
  executablePath: executable,
  env: { ...process.env, IP_GUARD_USER_DATA_DIR: profile },
  timeout: 30000,
});
let nativeHost: ReturnType<typeof spawn> | undefined;
try {
  const page = await application.firstWindow();
  await page.waitForLoadState("networkidle");
  const deadline = performance.now() + 15000;
  let snapshot;
  do {
    const value = await page.evaluate(async () => {
      const bridge: unknown = Reflect.get(globalThis, "desktop");
      if (!bridge || typeof bridge !== "object") throw new Error("Preload bridge missing");
      const invoke: unknown = Reflect.get(bridge, "invoke");
      if (typeof invoke !== "function") throw new Error("Preload invocation missing");
      const result: unknown = await Reflect.apply(invoke, bridge, [{ action: "status" }]);
      return result;
    });
    snapshot = snapshotSchema.parse(replySchema.parse(value).snapshot);
    if (snapshot.online) break;
    await delay(100);
  } while (performance.now() < deadline);
  assert(snapshot?.online, "Packaged guardian must be online");
  assert.equal(snapshot.platform ?? "win32", process.platform);
  assert.equal(snapshot.nativeVersion, nativeVersion);
  assert.equal(snapshot.admin, process.platform === "win32");
  if (process.platform !== "win32") {
    await page
      .getByText(process.env.IP_GUARD_EXPECT_SYSTEM ? "系统防护" : "受控启动测试版", {
        exact: true,
      })
      .first()
      .waitFor({ state: "visible" });
    await registerPosixBrowser(profile, executable, path.join(resources, "posix/native-host.mjs"));
  }
  const launcher = path.join(profile, "browser/ipguard-native-host");
  nativeHost = spawn(
    process.platform === "win32"
      ? path.join(resources, "native", nativeVersion, "IpGuard.Native.exe")
      : "/bin/sh",
    [
      ...(process.platform === "win32" ? [] : [launcher]),
      `chrome-extension://${browserExtensionId}/`,
    ],
    {
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const response = new Promise<unknown>((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(
      () => reject(new Error("Packaged Native Messaging heartbeat timed out")),
      8000,
    );
    nativeHost?.stdout?.on("data", (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);
      if (buffer.length < 4) return;
      const size = buffer.readUInt32LE();
      if (size > 16384) {
        clearTimeout(timer);
        reject(new Error("Native frame too large"));
        return;
      }
      if (buffer.length < size + 4) return;
      clearTimeout(timer);
      try {
        const value: unknown = JSON.parse(buffer.subarray(4, size + 4).toString());
        resolve(value);
      } catch (error) {
        reject(error);
      }
    });
    nativeHost?.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    nativeHost?.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`Native host exited before heartbeat: ${code}`));
    });
  });
  const request = Buffer.from(JSON.stringify({ action: "watch", protocol: 3 })),
    header = Buffer.alloc(4);
  header.writeUInt32LE(request.length);
  nativeHost.stdin?.write(Buffer.concat([header, request]));
  const browser = browserStateSchema.parse(await response);
  assert.equal(browser.appVersion, nativeVersion);
  assert.equal(browser.services.claude.phase, "unlocked");
  assert.equal(browser.services.chatgpt.phase, "unlocked");
  const foreground = await sampleResources(application.process().pid!, "foreground");
  await page.evaluate(() => {
    const bridge: unknown = Reflect.get(globalThis, "desktop");
    if (!bridge || typeof bridge !== "object") throw new Error("Missing bridge");
    const subscribe: unknown = Reflect.get(bridge, "subscribe");
    if (typeof subscribe !== "function") throw new Error("Missing subscription");
    Reflect.set(globalThis, "testSnapshotUpdates", 0);
    Reflect.apply(subscribe, bridge, [
      () =>
        Reflect.set(
          globalThis,
          "testSnapshotUpdates",
          Number(Reflect.get(globalThis, "testSnapshotUpdates")) + 1,
        ),
    ]);
  });
  await application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.hide());
  await page.evaluate(async () => {
    const bridge: unknown = Reflect.get(globalThis, "desktop");
    if (!bridge || typeof bridge !== "object") throw new Error("Missing bridge");
    const invoke: unknown = Reflect.get(bridge, "invoke");
    if (typeof invoke !== "function") throw new Error("Missing invocation");
    for (const stopOnProbeFailure of [false, true])
      await Reflect.apply(invoke, bridge, [
        { action: "failure-policy", service: "claude", stopOnProbeFailure },
      ]);
  });
  const hidden = await sampleResources(application.process().pid!, "hidden to tray");
  assert.equal(
    await page.evaluate(() => Reflect.get(globalThis, "testSnapshotUpdates")),
    0,
    "Hidden windows must not receive protection snapshots",
  );
  await application.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]?.show());
  await page.waitForFunction(() => Number(Reflect.get(globalThis, "testSnapshotUpdates")) > 0);
  await page.screenshot({
    path: path.resolve(
      import.meta.dirname,
      "../../test-results",
      `packaged-${process.platform}.png`,
    ),
    fullPage: true,
  });
  const evidence = {
    platform: process.platform,
    arch: process.arch,
    version: nativeVersion,
    executable,
    guardianOnline: true,
    rendererIPC: true,
    packagedNativeMessaging: true,
    permission: "ordinary user",
    processProtection: snapshot.processProtection,
    resources: { foreground, hidden },
    hiddenNotificationsPaused: true,
    restoredSnapshot: true,
  };
  await writeFile(
    path.resolve(import.meta.dirname, "../../../../packaged-smoke.json"),
    JSON.stringify(evidence, null, 2),
  );
  console.log("PASS packaged desktop", evidence);
} finally {
  nativeHost?.stdin?.end();
  nativeHost?.kill();
  await application.close();
  // This private directory was created by mkdtemp for this smoke test only.
  await rm(profile, { recursive: true, force: true });
}
const backgroundProfile = await realpath(await mkdtemp(path.join(tmpdir(), "ipg-tray-")));
const backgroundApp = await _electron.launch({
  executablePath: executable,
  args: ["--background"],
  env: { ...process.env, IP_GUARD_USER_DATA_DIR: backgroundProfile },
  timeout: 30000,
});
try {
  await delay(3000);
  assert.equal(
    await backgroundApp.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length),
    0,
    "Cold tray startup must not create a hidden renderer",
  );
  const resources = await sampleResources(backgroundApp.process().pid!, "cold tray startup");
  await backgroundApp.evaluate(({ app }) => app.emit("activate"));
  const restored = await backgroundApp.firstWindow();
  await restored.waitForLoadState("networkidle");
  await restored.getByText("IP Guard", { exact: true }).first().waitFor({ state: "visible" });
  await writeFile(
    "cold-tray-smoke.json",
    JSON.stringify(
      { platform: process.platform, resources, rendererCountBeforeOpen: 0, reopened: true },
      null,
      2,
    ),
  );
} finally {
  await backgroundApp.close();
  await rm(backgroundProfile, { recursive: true, force: true });
}
