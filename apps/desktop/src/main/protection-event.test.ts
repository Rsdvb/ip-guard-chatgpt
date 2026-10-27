import { expect, it } from "vite-plus/test";

import { nativeVersion, snapshotSchema } from "@ip-guard/electron";

import { detectProtectionStop } from "./protection-event.ts";

const id = "00000000-0000-4000-8000-000000000001";
const rule = {
  ready: true,
  checking: false,
  currentIp: "8.8.8.8",
  adapter: "",
  lastChecked: "",
  reason: "",
  rulesLocked: true,
  enabled: true,
  stopOnProbeFailure: false,
  unverified: false,
  settings: { expectedIp: "8.8.8.8", intervalSeconds: 2 },
};
const previous = () =>
  snapshotSchema.parse({
    online: true,
    admin: true,
    nativeVersion,
    services: { claude: rule, chatgpt: rule },
    detection: "",
    running: [id],
    autostart: false,
    networkAdapters: [],
    watchedAdapter: { id: "", name: "", exists: false, up: false, ipv4: false, error: "" },
    networkAdapterId: "",
    launches: [],
    logs: [],
    apps: [
      {
        id,
        service: "chatgpt",
        name: "ChatGPT",
        path: "C:\\ChatGPT.exe",
        arguments: "",
        enabled: true,
      },
    ],
  });
it("does not report a manually closed app as terminated by an opted out IP failure", () => {
  const before = previous(),
    after = previous();
  after.running = [];
  after.services.chatgpt = { ...rule, ready: false, unverified: true, currentIp: "" };
  expect(detectProtectionStop(before, after, false)).toBeUndefined();
});
it("still reports confirmed IP mismatch when automatic termination on missing IP is off", () => {
  const before = previous(),
    after = previous();
  after.running = [];
  after.services.chatgpt = { ...rule, ready: false, currentIp: "1.1.1.1" };
  expect(detectProtectionStop(before, after, false)).toMatchObject({
    kind: "ip_changed",
    apps: ["ChatGPT"],
  });
});
it("still reports guardian loss independently of the missing-IP preference", () => {
  const before = previous(),
    after = previous();
  after.online = false;
  after.running = [];
  after.services.chatgpt.ready = false;
  expect(detectProtectionStop(before, after, false)?.kind).toBe("guard_offline");
});
