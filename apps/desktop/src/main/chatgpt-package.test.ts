import { expect, it } from "vite-plus/test";

import { isChatgptEntry } from "./chatgpt-package.ts";

it("recognizes the installed OpenAI.Codex package's ChatGPT main executable", () => {
  expect(
    isChatgptEntry(
      "OpenAI.Codex",
      "C:\\Program Files\\WindowsApps\\OpenAI.Codex_version\\app\\ChatGPT.exe",
    ),
  ).toBe(true);
  expect(isChatgptEntry("OpenAI.ChatGPT-Desktop", "C:\\Apps\\ChatGPT.exe")).toBe(true);
});
it("excludes the package's command runner and unrelated applications", () => {
  expect(isChatgptEntry("OpenAI.Codex", "C:\\Apps\\codex-command-runner.exe")).toBe(false);
  expect(isChatgptEntry("OtherVendor.ChatGPT", "C:\\Apps\\ChatGPT.exe")).toBe(false);
});
