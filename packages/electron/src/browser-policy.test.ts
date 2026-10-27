import { describe, expect, it } from "vite-plus/test";

import { allowedBrowserDomains, shouldBlockUrl } from "./browser-policy.ts";
import { browserStateSchema } from "./index.ts";
import type { BrowserState } from "./index.ts";

const state = (service: BrowserState["service"], phase: BrowserState["phase"]): BrowserState =>
  browserStateSchema.parse({
    protocol: 2,
    service,
    phase,
    appVersion: "0.10.0",
    currentIp: "8.8.8.8",
    expectedIp: "8.8.8.8",
    checkedAt: "2026-10-27T01:00:00.000Z",
    reason: "",
  });

describe("browser service authorization", () => {
  it("keeps ChatGPT blocked while its selected probe is unavailable", () => {
    const value = state("chatgpt", "blocked");
    expect(allowedBrowserDomains(value, true)).toEqual(["claude.ai"]);
    expect(shouldBlockUrl("https://chatgpt.com/c/123", value, true)).toBe(true);
    expect(shouldBlockUrl("https://chat.openai.com/", value, true)).toBe(true);
    expect(shouldBlockUrl("https://claude.ai/", value, true)).toBe(false);
  });
  it("revokes both services when permission or heartbeat is lost", () => {
    expect(allowedBrowserDomains(state("both", "allowed"), false)).toEqual([]);
    expect(allowedBrowserDomains(state("both", "offline"), true)).toEqual([]);
    expect(allowedBrowserDomains(state("both", "unlocked"), true)).toEqual([]);
    expect(allowedBrowserDomains(state("both", "checking"), true)).toEqual([]);
  });
  it("allows all protected hosts only for a fresh shared permission", () => {
    expect(allowedBrowserDomains(state("both", "allowed"), true)).toEqual([
      "claude.ai",
      "chatgpt.com",
      "chat.openai.com",
    ]);
  });
  it("changes the blocked scope when the selected service changes", () => {
    expect(allowedBrowserDomains(state("claude", "blocked"), true)).toEqual([
      "chatgpt.com",
      "chat.openai.com",
    ]);
    expect(allowedBrowserDomains(state("chatgpt", "blocked"), true)).toEqual(["claude.ai"]);
  });
});
