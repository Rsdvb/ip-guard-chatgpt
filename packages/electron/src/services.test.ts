import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import { browserStateSchema, settingsSchema } from "./index.ts";
import { protectedService } from "./services.ts";

describe("AI browser protection", () => {
  it.each([
    ["https://claude.ai/new", "claude"],
    ["https://api.claude.ai/", "claude"],
    ["https://chatgpt.com/c/123", "chatgpt"],
    ["https://chat.openai.com/", "chatgpt"],
    ["https://chatgpt.com.attacker.example/", undefined],
    ["https://evilchatgpt.com/", undefined],
    ["javascript:alert(1)", undefined],
    ["https://platform.openai.com/", undefined],
  ])("recognizes only protected hosts: %s", (url, expected) => {
    expect(protectedService(url)).toBe(expected);
  });

  it("ships default-deny rules and host access for both ChatGPT hosts", () => {
    const root = new URL("../../../", import.meta.url);
    const manifest = JSON.parse(
      readFileSync(new URL("apps/browser-extension/manifest.json", root), "utf8"),
    );
    const rules = JSON.parse(
      readFileSync(new URL("apps/browser-extension/public/rules.json", root), "utf8"),
    );
    for (const domain of ["claude.ai", "chatgpt.com", "chat.openai.com"]) {
      expect(manifest.host_permissions).toContain(`*://${domain}/*`);
      expect(
        rules.some(
          (rule: { action: { type: string }; condition: { requestDomains: string[] } }) =>
            rule.action.type === "block" && rule.condition.requestDomains.includes(domain),
        ),
      ).toBe(true);
    }
  });

  it("preserves Claude for persisted settings written before service selection existed", () => {
    expect(settingsSchema.parse({ expectedIp: "8.8.8.8", intervalSeconds: 2 }).service).toBe(
      "claude",
    );
  });

  it("rejects an old browser host that cannot identify the measured service", () => {
    expect(
      browserStateSchema.safeParse({
        protocol: 1,
        appVersion: "0.9.3",
        phase: "allowed",
        currentIp: "8.8.8.8",
        expectedIp: "8.8.8.8",
        checkedAt: new Date().toISOString(),
        reason: "",
      }).success,
    ).toBe(false);
  });
});
