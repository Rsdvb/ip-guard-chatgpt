import { expect, test } from "vite-plus/test";

import { newerVersion, platformRelease } from "./update-policy.ts";

test("update selection never downgrades and requires an artifact for this platform", () => {
  expect(newerVersion("0.14.2", "0.14.1")).toBe(true);
  expect(newerVersion("0.12.1", "0.14.1")).toBe(false);
  expect(newerVersion("0.14.2-beta.1", "0.14.1")).toBe(false);
  const releases = [
    { draft: false, tag_name: "v0.15.0", assets: [{ name: "IP-Guard-Setup-0.15.0.exe" }] },
    { draft: false, tag_name: "v0.14.2", assets: [{ name: "IP-Guard-0.14.2-macOS-arm64.zip" }] },
    { draft: true, tag_name: "v9.0.0", assets: [{ name: "IP-Guard-9.0.0-macOS-arm64.zip" }] },
  ];
  expect(platformRelease(releases, "0.14.0", "darwin")).toBe("0.14.2");
  expect(platformRelease(releases, "0.14.0", "linux")).toBe("0.14.0");
});
