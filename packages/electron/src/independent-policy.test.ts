import { expect, it } from "vite-plus/test";

import { allowedBrowserDomains, shouldBlockUrl } from "./browser-policy.ts";
import { browserStateSchema, commandSchema } from "./index.ts";

const permission = (ip: string, phase: string) => ({
  phase,
  currentIp: ip,
  expectedIp: ip,
  checkedAt: new Date().toISOString(),
  reason: "",
});
it("keeps Claude available when ChatGPT fails with a different locked IP", () => {
  const state = browserStateSchema.parse({
    protocol: 3,
    appVersion: "0.11.0",
    services: {
      claude: permission("8.8.8.8", "allowed"),
      chatgpt: permission("1.1.1.1", "blocked"),
    },
  });
  expect(allowedBrowserDomains(state, true)).toEqual(["claude.ai"]);
  expect(shouldBlockUrl("https://claude.ai/new", state, true)).toBe(false);
  expect(shouldBlockUrl("https://chatgpt.com/", state, true)).toBe(true);
});
it("keeps a paused service blocked and the other service independently authorized", () => {
  const state = browserStateSchema.parse({
    protocol: 3,
    appVersion: "0.11.0",
    services: {
      claude: permission("8.8.8.8", "paused"),
      chatgpt: permission("1.1.1.1", "allowed"),
    },
  });
  expect(allowedBrowserDomains(state, true)).toEqual(["chatgpt.com", "chat.openai.com"]);
  expect(allowedBrowserDomains(state, false)).toEqual([]);
});
it("requires an explicit single service for lock, pause and program ownership", () => {
  expect(commandSchema.safeParse({ action: "unlock" }).success).toBe(false);
  expect(
    commandSchema.safeParse({ action: "service:enable", service: "chatgpt", enabled: false })
      .success,
  ).toBe(true);
  expect(
    commandSchema.safeParse({
      action: "lock",
      service: "both",
      settings: { expectedIp: "8.8.8.8", intervalSeconds: 2 },
    }).success,
  ).toBe(false);
});
