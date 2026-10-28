import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, copyFile, mkdtemp, realpath, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { z } from "zod";

import type { Service } from "@ip-guard/electron";

import { PosixGuardian } from "../src/main/posix-guardian.ts";

const run = promisify(execFile);
const root = await realpath(await mkdtemp(path.join(tmpdir(), "ipg-policy-")));
const responses = { claude: "8.8.8.8", chatgpt: "8.8.4.4" };
let claudeDelay = 0;
// Only the external exit-IP endpoint is a fixture. Policy, disk persistence, Unix IPC,
// launch wrappers, actual OS processes and their termination all run from repository code.
const server = createServer((request, response) => {
  const service = request.url === "/claude" ? "claude" : "chatgpt";
  response.setHeader("content-type", "application/json");
  const body = JSON.stringify({
    ip: responses[service],
    error: responses[service] ? "" : "fixture network unavailable",
    checkedAt: new Date().toISOString(),
    adapter: "fixture",
    status: responses[service] ? 200 : 0,
    ms: 1,
  });
  const timer = setTimeout(() => response.end(body), service === "claude" ? claudeDelay : 0);
  response.on("close", () => clearTimeout(timer));
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
assert(address && typeof address !== "string");
const resultSchema = z.object({
  ip: z.string(),
  error: z.string(),
  checkedAt: z.string(),
  adapter: z.string(),
  status: z.number(),
  ms: z.number(),
});
const probe = {
  check: async (service: Service) =>
    resultSchema.parse(await (await fetch(`http://127.0.0.1:${address.port}/${service}`)).json()),
};
const options = {
  directory: path.join(root, "data"),
  executable: process.execPath,
  resources: path.resolve(import.meta.dirname, "../posix"),
};
let guard = new PosixGuardian(probe, options);
const unrelatedFile = path.join(root, "outside"),
  claudeFile = path.join(root, "claude-fixture"),
  chatgptFile = path.join(root, "chatgpt-fixture");
for (const file of [unrelatedFile, claudeFile, chatgptFile]) {
  await copyFile("/bin/sleep", file);
  await chmod(file, 0o700);
}
const unrelated = spawn(unrelatedFile, ["120"], { stdio: "ignore" });
const claudeId = randomUUID(),
  chatgptId = randomUUID();
async function until(check: () => boolean | Promise<boolean>, description: string) {
  const deadline = performance.now() + 15000;
  while (performance.now() < deadline) {
    if (await check()) return;
    await delay(50);
  }
  throw new Error(`Timed out: ${description}`);
}
async function running(file: string) {
  const ps = await run("/bin/ps", ["-ax", "-o", "pid=,command="], { timeout: 2000 });
  return ps.stdout.split("\n").some((line) => line.trim().replace(/^\d+\s+/, "") === `${file} 120`);
}
try {
  await guard.start();
  assert.equal(guard.snapshot.admin, false);
  for (const service of ["claude", "chatgpt"] as const)
    await guard.request("lock", {
      service,
      settings: { expectedIp: responses[service], intervalSeconds: 2 },
    });
  for (const target of [
    { id: claudeId, service: "claude", path: claudeFile, name: "Claude fixture" },
    { id: chatgptId, service: "chatgpt", path: chatgptFile, name: "ChatGPT fixture" },
  ]) {
    await guard.request("add", { app: { ...target, arguments: "120", enabled: false } });
    await guard.request("protect", { targetId: target.id, enabled: true });
    await guard.request("start", { targetId: target.id });
  }
  await until(
    () => guard.snapshot.running.includes(claudeId) && guard.snapshot.running.includes(chatgptId),
    "both services start",
  );
  assert(await running(claudeFile));
  assert(await running(chatgptFile));
  responses.chatgpt = "1.1.1.1";
  await guard.request("check", { service: "chatgpt" });
  await until(
    async () => !(await running(chatgptFile)),
    "only mismatching ChatGPT process terminates",
  );
  assert(await running(claudeFile));
  assert(await running(unrelatedFile));
  responses.chatgpt = "8.8.4.4";
  await until(() => !guard.processStatus("chatgpt").count, "ChatGPT lease closes");
  await guard.request("check", { service: "chatgpt" });
  await guard.request("failure-policy", { service: "chatgpt", stopOnProbeFailure: false });
  await guard.request("start", { targetId: chatgptId });
  await until(
    () => guard.snapshot.running.includes(chatgptId),
    "restart ChatGPT after restoring allowed IP",
  );
  responses.chatgpt = "";
  await guard.request("check", { service: "chatgpt" });
  assert.equal(guard.snapshot.services.chatgpt.unverified, true);
  assert.equal(guard.snapshot.services.chatgpt.ready, false);
  assert(await running(chatgptFile));
  assert(await running(claudeFile));
  responses.chatgpt = "1.1.1.1";
  await guard.request("check", { service: "chatgpt" });
  await until(
    async () => !(await running(chatgptFile)),
    "confirmed mismatch terminates despite disabled unavailable-IP stop",
  );
  await guard.request("service:enable", { service: "chatgpt", enabled: false });
  assert.equal(guard.snapshot.services.claude.ready, true);
  await guard.stop();
  await until(
    async () => !(await running(claudeFile)),
    "controller shutdown terminates managed application",
  );
  assert(await running(unrelatedFile));
  responses.chatgpt = "8.8.4.4";
  claudeDelay = 1000;
  guard = new PosixGuardian(probe, options);
  await guard.start();
  assert.equal(guard.snapshot.services.chatgpt.stopOnProbeFailure, false);
  assert.equal(guard.snapshot.services.chatgpt.enabled, false);
  assert.equal(guard.snapshot.services.claude.settings.expectedIp, "8.8.8.8");
  const launcher = path.join(
    options.directory,
    "launchers",
    `IPGuard-claude-${claudeId}${process.platform === "darwin" ? ".command" : ".sh"}`,
  );
  const cli = spawn("/bin/sh", [launcher], { stdio: "ignore" });
  await until(
    async () => await running(claudeFile),
    "generated terminal launcher enforces and grants IP policy",
  );
  await guard.request("service:enable", { service: "claude", enabled: false });
  await until(async () => !(await running(claudeFile)), "pause stops the launcher-managed process");
  await new Promise<void>((resolve) => {
    if (cli.exitCode !== null) resolve();
    else cli.once("exit", () => resolve());
  });
  console.log(
    `PASS POSIX ${process.platform}/${process.arch}: real process start, scoped mismatch, unavailable-IP preference, shutdown, launcher and config reload; mode=${guard.snapshot.processProtection}`,
  );
} finally {
  await guard.stop();
  unrelated.kill("SIGKILL");
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  // This exact private directory was returned by mkdtemp and contains only this test's fixtures.
  await rm(root, { recursive: true, force: true });
}
