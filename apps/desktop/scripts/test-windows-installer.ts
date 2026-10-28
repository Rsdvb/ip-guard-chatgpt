import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { nativeProtocol, nativeVersion } from "@ip-guard/electron";

assert.equal(process.platform, "win32");
assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
const root = path.resolve(import.meta.dirname, "..");
const directory = mkdtempSync(path.join(root, "dist/installer-test-"));
const installed = path.join(directory, "Installed IP Guard");
const localData = process.env.LOCALAPPDATA;
assert.ok(localData && path.isAbsolute(localData));
const data = path.join(localData, "IPGuard");
assert.ok(
  !existsSync(path.join(data, "settings.json")),
  "Installer regression requires a fresh isolated profile",
);
const old = await fetch(
  "https://github.com/Rsdvb/ip-guard-chatgpt/releases/download/v0.14.0/IP-Guard-Setup-0.14.0.exe",
);
assert.equal(old.status, 200);
const bytes = Buffer.from(await old.arrayBuffer());
assert.equal(
  createHash("sha256").update(bytes).digest("hex"),
  "ac73545c178372ba3b8a0ff92d367ff9d1d7ca200c367baa888042d288104556",
);
const previous = path.join(directory, "Setup-0.14.0.exe");
writeFileSync(previous, bytes);
function execute(executable: string, args: string[], timeout = 180000) {
  const result = spawnSync(executable, args, {
    argv0: `"${executable}"`,
    encoding: "utf8",
    windowsHide: true,
    windowsVerbatimArguments: true,
    timeout,
  });
  assert.equal(
    result.status,
    0,
    `${executable}: ${result.error?.message || result.stdout + result.stderr}`,
  );
  return result.stdout;
}
execute(previous, ["/S", `/D=${installed}`]);
assert.ok(existsSync(path.join(installed, "resources/native/0.14.0/IpGuard.Native.exe")));
const rule = (expectedIp: string) => ({
  settings: { expectedIp, intervalSeconds: 60 },
  rulesLocked: true,
  enabled: false,
  stopOnProbeFailure: false,
});
const config = {
  format: 2,
  services: { claude: rule("8.8.8.8"), chatgpt: rule("1.1.1.1") },
  apps: [],
  autostart: false,
};
mkdirSync(data, { recursive: true });
writeFileSync(path.join(data, "settings.json"), JSON.stringify(config));
execute(path.join(root, "release", `IP-Guard-Setup-${nativeVersion}.exe`), [
  "/S",
  `/D=${installed}`,
]);
assert.deepEqual(
  JSON.parse(readFileSync(path.join(data, "settings.json"), "utf8")),
  config,
  "An upgrade must preserve both independent rules without running the old destructive recovery",
);
const native = path.join(installed, "resources/native", nativeVersion, "IpGuard.Native.exe");
const version: unknown = JSON.parse(execute(native, ["version"]));
assert.deepEqual(version, { version: nativeVersion, protocol: nativeProtocol });
execute(path.join(installed, "Uninstall IP Guard.exe"), ["/S", `_?=${installed}`]);
assert.ok(!existsSync(native), "The fixed uninstaller must finish instead of failing at recovery");
assert.deepEqual(
  JSON.parse(readFileSync(path.join(data, "settings.json.recovery.bak"), "utf8")),
  config,
  "Uninstall must retain the recoverable original settings",
);
const evidence = {
  version: nativeVersion,
  previousVersion: "0.14.0",
  installedOld: true,
  upgraded: true,
  policiesPreserved: true,
  nativeVersionConfirmed: true,
  uninstalled: true,
  settingsBackupPreserved: true,
};
mkdirSync(path.resolve(root, "../web/test-results"), { recursive: true });
writeFileSync(
  path.resolve(root, "../web/test-results/installer-validation-win32.json"),
  JSON.stringify(evidence, null, 2) + "\n",
);
console.log(
  "PASS: real 0.14.0 install, settings-preserving NSIS upgrade, installed native version and successful uninstall with backup.",
);
