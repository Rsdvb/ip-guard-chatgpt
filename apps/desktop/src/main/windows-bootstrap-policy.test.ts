import { expect, it } from "vite-plus/test";

import { windowsStartupAction } from "./windows-bootstrap-policy.ts";

it("requests administrator privileges before an installed Windows guardian starts", () => {
  expect(windowsStartupAction({ platform: "win32", packaged: true })).toBe("check");
  expect(windowsStartupAction({ platform: "win32", packaged: true, administrator: false })).toBe(
    "elevate",
  );
  expect(windowsStartupAction({ platform: "win32", packaged: true, administrator: true })).toBe(
    "continue",
  );
  expect(windowsStartupAction({ platform: "win32", packaged: false, administrator: false })).toBe(
    "continue",
  );
  for (const platform of ["darwin", "linux"])
    expect(windowsStartupAction({ platform, packaged: true, administrator: false })).toBe(
      "continue",
    );
});
