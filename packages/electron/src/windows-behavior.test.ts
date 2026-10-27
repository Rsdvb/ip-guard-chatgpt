import { readFileSync } from "node:fs";

import { expect, it } from "vite-plus/test";

import { commandSchema } from "./index.ts";

it("accepts an explicit service pause separately from an IP lock", () => {
  expect(
    commandSchema.safeParse({ action: "service:enable", service: "chatgpt", enabled: false })
      .success,
  ).toBe(true);
  expect(
    commandSchema.safeParse({ action: "service:enable", service: "unknown", enabled: false })
      .success,
  ).toBe(false);
});

it("requests administrator privileges when the installed application starts", () => {
  const config = readFileSync(
    new URL("../../../apps/desktop/electron-builder.yml", import.meta.url),
    "utf8",
  );
  expect(config).toMatch(/requestedExecutionLevel:\s*requireAdministrator/);
});
