import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { app } from "electron";
import { z } from "zod";

import { nativePath } from "./guardian.ts";
import { windowsStartupAction } from "./windows-bootstrap-policy.ts";

const run = promisify(execFile);
export async function ensureWindowsAdministrator() {
  const context = { platform: process.platform, packaged: app.isPackaged };
  if (windowsStartupAction(context) === "continue") return true;
  const result = await run(nativePath(), ["admin-status"], {
    windowsHide: true,
    timeout: 5000,
    maxBuffer: 8192,
    encoding: "utf8",
  });
  const value: unknown = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
  if (
    windowsStartupAction({
      ...context,
      administrator: z.object({ admin: z.boolean() }).parse(value).admin,
    }) === "continue"
  )
    return true;
  try {
    await run(
      nativePath(),
      ["elevate-desktop", ...(process.argv.includes("--background") ? ["--background"] : [])],
      { windowsHide: true, timeout: 125000, maxBuffer: 8192 },
    );
  } catch (error) {
    if (!error || typeof error !== "object" || !("code" in error) || error.code !== 1223)
      throw error;
  }
  return false;
}
