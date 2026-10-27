import { describe, expect, it } from "vite-plus/test";

import { evaluateExits } from "./exit-policy.ts";
import type { ExitResult } from "./exit-policy.ts";

const result = (ip: string, error = ""): ExitResult => ({
  ip,
  error,
  checkedAt: "2026-10-27T01:00:00.000Z",
  adapter: "系统代理",
  status: 200,
  ms: 30,
});
describe("service-specific IPv4 authorization", () => {
  it("does not substitute Claude's IP when ChatGPT fails", () => {
    const results = { claude: result("8.8.8.8"), chatgpt: result("", "HTTP 403") };
    expect(evaluateExits("claude", results).ip).toBe("8.8.8.8");
    expect(evaluateExits("chatgpt", results).ip).toBe("");
    expect(evaluateExits("both", results).ip).toBe("");
    expect(evaluateExits("both", results).error).toContain("ChatGPT");
  });
  it("requires both destinations to agree when both are protected", () => {
    const results = { claude: result("8.8.8.8"), chatgpt: result("1.1.1.1") };
    expect(evaluateExits("chatgpt", results).ip).toBe("1.1.1.1");
    expect(evaluateExits("both", results).ip).toBe("");
    expect(evaluateExits("both", results).error).toContain("不一致");
  });
  it("permits the shared address only after both checks succeed", () => {
    const results = { claude: result("8.8.8.8"), chatgpt: result("8.8.8.8") };
    expect(evaluateExits("both", results)).toMatchObject({ ip: "8.8.8.8", error: "" });
  });
});
