import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { nativeVersion } from "@ip-guard/electron";

if (process.platform !== "darwin")
  throw new Error("Swift network filter must be compiled on macOS");
const root = path.resolve(import.meta.dirname, "..");
const source = path.join(root, "mac"),
  output = path.join(root, "dist/mac");
const team = process.env.IP_GUARD_TEAM_ID || "TEAMIDHERE";
if (!/^[A-Z0-9]{10}$/.test(team))
  throw new Error("IP_GUARD_TEAM_ID must contain 10 uppercase letters or digits");
const contents = path.join(output, "com.ip-guard.desktop.filter.systemextension/Contents");
mkdirSync(path.join(contents, "MacOS"), { recursive: true });
writeFileSync(
  path.join(contents, "Info.plist"),
  readFileSync(path.join(source, "ExtensionInfo.plist.in"), "utf8")
    .replaceAll("@TEAM@", team)
    .replaceAll("@VERSION@", nativeVersion),
);
for (const entry of [
  {
    module: "IPGuardFilter",
    files: ["Policy.swift", "PolicyIPC.swift", "FilterDataProvider.swift", "ExtensionMain.swift"],
    binary: path.join(contents, "MacOS/IPGuardFilter"),
  },
  {
    module: "IPGuardMacControl",
    files: ["Policy.swift", "PolicyIPC.swift", "ProcessMonitor.swift", "FilterControl.swift"],
    binary: path.join(output, "IpGuardMacControl"),
  },
  {
    module: "IPGuardPolicyTests",
    files: ["Policy.swift", "PolicyTests.swift"],
    binary: path.join(output, "PolicyTests"),
  },
]) {
  const built = spawnSync(
    "xcrun",
    [
      "swiftc",
      "-swift-version",
      "5",
      "-O",
      "-target",
      "arm64-apple-macos13.0",
      "-module-name",
      entry.module,
      "-framework",
      "NetworkExtension",
      "-framework",
      "SystemExtensions",
      "-framework",
      "Security",
      "-framework",
      "AppKit",
      ...entry.files.map((file) => path.join(source, file)),
      "-o",
      entry.binary,
    ],
    { stdio: "inherit" },
  );
  if (built.status !== 0)
    throw built.error || new Error(`Swift compilation failed: ${entry.module}`);
}
const tested = spawnSync(path.join(output, "PolicyTests"), [], { stdio: "inherit" });
if (tested.status !== 0) throw tested.error || new Error("Swift policy tests failed");
console.log(
  "macOS network extension, authenticated XPC controller and policy tests compiled; system activation requires Developer ID signing",
);
