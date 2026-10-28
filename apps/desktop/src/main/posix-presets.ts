import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import type { AppPreset } from "@ip-guard/electron";

const run = promisify(execFile);
export async function resolvePosixExecutable(filename: string) {
  if (!path.isAbsolute(filename)) throw new Error("程序路径必须为绝对路径");
  let executable = filename;
  if (process.platform === "darwin" && filename.toLowerCase().endsWith(".app")) {
    const result = await run(
      "/usr/libexec/PlistBuddy",
      ["-c", "Print :CFBundleExecutable", path.join(filename, "Contents/Info.plist")],
      { timeout: 3000, maxBuffer: 8192 },
    );
    const name = result.stdout.trim();
    if (!name || name === "." || name === ".." || /[/\\\0]/.test(name))
      throw new Error("应用清单的主入口无效");
    executable = path.join(filename, "Contents/MacOS", name);
  }
  const file = await realpath(executable);
  if (!(await stat(file)).isFile()) throw new Error("请选择实际可执行文件，macOS 也可选择 .app");
  await access(file, constants.X_OK);
  return path.resolve(executable);
}
async function first(files: string[]) {
  for (const file of files) {
    try {
      return await resolvePosixExecutable(file);
    } catch {
      /* Other installation locations remain candidates. */
    }
  }
  return "";
}
export async function posixPresets(): Promise<AppPreset[]> {
  const home = homedir();
  const bins = [
    ...new Set(
      [
        path.join(home, ".local/bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        ...(process.env.PATH || "").split(":"),
      ].filter((folder) => path.isAbsolute(folder)),
    ),
  ];
  const cli = await first(bins.map((folder) => path.join(folder, "claude")));
  const desktop =
    process.platform === "darwin"
      ? await first(["/Applications/Claude.app", path.join(home, "Applications/Claude.app")])
      : await first(["/usr/bin/claude-desktop", "/usr/local/bin/claude-desktop"]);
  const chatgpt =
    process.platform === "darwin"
      ? await first(["/Applications/ChatGPT.app", path.join(home, "Applications/ChatGPT.app")])
      : await first(bins.map((folder) => path.join(folder, "chatgpt")));
  return [
    {
      id: "claude-native",
      name: "Claude Code",
      path: cli,
      version: "",
      status: cli ? "ready" : "missing",
      message: cli ? "" : "未找到可执行的 claude，请手动浏览选择",
    },
    {
      id: "claude-desktop",
      name: "Claude Desktop",
      path: desktop,
      version: "",
      status: desktop ? "ready" : "missing",
      message: desktop ? "" : "未发现桌面程序，可手动选择本机应用",
    },
    {
      id: "chatgpt-desktop",
      name: "ChatGPT Desktop",
      path: chatgpt,
      version: "",
      status: chatgpt ? "ready" : "missing",
      message: chatgpt ? "" : "未发现桌面程序，可手动选择本机应用",
    },
  ];
}
