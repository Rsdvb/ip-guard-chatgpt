import { expect, it } from "vite-plus/test";

import { nativeVersion, snapshotSchema } from "@ip-guard/electron";

import { systemFilterPolicy } from "./system-filter-policy.ts";

it("independently authorizes fresh target services and retains deny bindings on guard loss", () => {
  const now = Date.now();
  const rule = (ip: string, ready: boolean) => ({
    ready,
    checking: false,
    currentIp: ip,
    adapter: "",
    lastChecked: new Date(now).toISOString(),
    reason: "",
    rulesLocked: true,
    enabled: true,
    stopOnProbeFailure: true,
    unverified: false,
    settings: { expectedIp: ip, intervalSeconds: 2 },
  });
  const snapshot = snapshotSchema.parse({
    online: true,
    admin: false,
    nativeVersion,
    platform: "darwin",
    services: { claude: rule("8.8.8.8", true), chatgpt: rule("1.1.1.1", false) },
    detection: "",
    running: [],
    autostart: false,
    networkAdapters: [],
    watchedAdapter: { id: "", name: "", exists: false, up: false, ipv4: false, error: "" },
    networkAdapterId: "",
    launches: [],
    logs: [],
    apps: [
      {
        id: "6c73011e-71f0-4bdf-940c-50ae25da24c3",
        service: "claude",
        name: "Claude",
        path: "/Applications/Claude.app/Contents/MacOS/Claude",
        arguments: "",
        enabled: true,
      },
      {
        id: "00b7b137-e7b8-451a-8451-d029bd8472fe",
        service: "chatgpt",
        name: "GPT",
        path: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
        arguments: "",
        enabled: true,
      },
    ],
  });
  const policy = systemFilterPolicy(snapshot, 501, now, [], "darwin");
  expect(policy.targets.map((target) => target.allowed)).toEqual([true, false]);
  expect(policy.targets[0]?.bundleRoot).toBe("/Applications/Claude.app");
  expect(
    systemFilterPolicy(
      {
        ...snapshot,
        apps: snapshot.apps.map((app) => ({ ...app, path: `/usr/local/bin/${app.service}` })),
      },
      501,
      now,
      [],
      "darwin",
    ).targets,
  ).toEqual([]);
  expect(
    systemFilterPolicy(snapshot, 501, now + 11000, [], "darwin").targets.every(
      (target) => !target.allowed,
    ),
  ).toBe(true);
  expect(systemFilterPolicy(undefined, 501, now, policy.targets, "darwin").targets).toEqual(
    policy.targets.map((target) => ({ ...target, allowed: false, keepRunning: false })),
  );
  expect(
    systemFilterPolicy({ ...snapshot, online: false }, 501, now, policy.targets, "darwin").targets,
  ).toHaveLength(2);
});
