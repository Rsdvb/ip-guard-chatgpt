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

if (process.platform !== "darwin" && process.platform !== "linux")
  throw new Error("Packaged desktop smoke test needs macOS or Ubuntu");
const desktop = path.resolve(import.meta.dirname, "../../../desktop");
const requestedExecutable =
  process.env.IP_GUARD_PACKAGED_EXECUTABLE ||
  (process.platform === "darwin"
    ? path.join(desktop, "release/mac-arm64/IP Guard.app/Contents/MacOS/IP Guard")
    : path.join(desktop, "release/linux-unpacked/ip-guard"));
const executable = await realpath(requestedExecutable);
const resources =
  process.platform === "darwin"
    ? path.resolve(executable, "../../Resources")
    : path.join(path.dirname(executable), "resources");
await access(path.join(resources, "browser-extension/manifest.json"));
await access(path.join(resources, "posix/managed-run.mjs"));
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
  assert.equal(snapshot.platform, process.platform);
  assert.equal(snapshot.nativeVersion, nativeVersion);
  assert.equal(snapshot.admin, false);
  await page.getByText("受控启动测试版", { exact: true }).waitFor({ state: "visible" });
  await registerPosixBrowser(profile, executable, path.join(resources, "posix/native-host.mjs"));
  const launcher = path.join(profile, "browser/ipguard-native-host");
  nativeHost = spawn("/bin/sh", [launcher, `chrome-extension://${browserExtensionId}/`], {
    stdio: ["pipe", "pipe", "pipe"],
  });
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
