import { expect, test } from "vite-plus/test";

import { allowedBrowserDomains, browserStateSchema, shouldBlockUrl } from "./index.ts";

test("explicitly releasing protection allows browsing after exit without treating a crash as a release", () => {
  const permission = {
    phase: "released",
    currentIp: "",
    expectedIp: "",
    checkedAt: "",
    reason: "已完全退出并解除防护",
  };
  const released = browserStateSchema.parse({
    protocol: 3,
    appVersion: "0.14.2",
    services: { claude: permission, chatgpt: permission },
  });
  expect(shouldBlockUrl("https://claude.ai/new", released, false)).toBe(false);
  expect(shouldBlockUrl("https://chatgpt.com/", released, false)).toBe(false);
  expect(allowedBrowserDomains(released, false)).toContain("claude.ai");
  const crashed = browserStateSchema.parse({
    ...released,
    services: { ...released.services, claude: { ...permission, phase: "offline" } },
  });
  expect(shouldBlockUrl("https://claude.ai/new", crashed, false)).toBe(true);
  expect(shouldBlockUrl("https://chatgpt.com/", crashed, false)).toBe(false);
});
