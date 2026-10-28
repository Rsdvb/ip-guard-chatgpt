import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import { browserExtensionId, browserHostName } from "@ip-guard/electron";

import { fileMissing, posixSocketDirectory, privateDirectory } from "./posix-paths.ts";
import { shellQuote } from "./posix-policy.ts";

export function browserProfiles() {
  const base =
    process.platform === "darwin"
      ? path.join(homedir(), "Library/Application Support")
      : process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config");
  return process.platform === "darwin"
    ? ([
        { name: "Chrome", root: path.join(base, "Google/Chrome") },
        { name: "Edge", root: path.join(base, "Microsoft Edge") },
      ] as const)
    : ([
        { name: "Chrome", root: path.join(base, "google-chrome") },
        { name: "Edge", root: path.join(base, "microsoft-edge") },
      ] as const);
}

export async function registerPosixBrowser(directory: string, executable: string, runtime: string) {
  if (!path.isAbsolute(executable) || !path.isAbsolute(runtime))
    throw new Error("浏览器宿主路径必须是绝对路径");
  const folder = path.join(directory, "browser");
  await privateDirectory(folder);
  const launcher = path.join(folder, "ipguard-native-host");
  const manifest = JSON.stringify(
    {
      name: browserHostName,
      description: "IP Guard browser connection",
      path: launcher,
      type: "stdio",
      allowed_origins: [`chrome-extension://${browserExtensionId}/`],
    },
    null,
    2,
  );
  const files = browserProfiles().map(({ root }) =>
    path.join(root, "NativeMessagingHosts", `${browserHostName}.json`),
  );
  for (const filename of files) {
    try {
      const old: unknown = JSON.parse(await readFile(filename, "utf8"));
      if (!old || typeof old !== "object" || Reflect.get(old, "path") !== launcher)
        throw new Error("已有其他 IP Guard 宿主注册，请先移除旧版宿主");
    } catch (error) {
      if (!fileMissing(error)) throw error;
    }
  }
  await writeFile(
    launcher,
    `#!/bin/sh\nELECTRON_RUN_AS_NODE=1 exec ${shellQuote(executable)} ${shellQuote(runtime)} --socket ${shellQuote(path.join(posixSocketDirectory(), "browser.sock"))} "$@"\n`,
    { mode: 0o700 },
  );
  await chmod(launcher, 0o700);
  for (const filename of files) {
    await mkdir(path.dirname(filename), { recursive: true });
    const temporary = `${filename}.tmp`;
    await writeFile(temporary, manifest, { mode: 0o600 });
    await rename(temporary, filename);
  }
}
