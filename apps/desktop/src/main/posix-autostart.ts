import { mkdir, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import { app } from "electron";

import { fileMissing } from "./posix-paths.ts";

export async function posixAutostart(enabled: boolean) {
  if (process.platform === "darwin") {
    app.setLoginItemSettings({ openAtLogin: enabled });
    if (app.getLoginItemSettings().openAtLogin !== enabled)
      throw new Error("登录启动设置未生效，请在系统设置中检查登录项");
    return;
  }
  const root = process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config");
  if (!path.isAbsolute(root)) throw new Error("XDG_CONFIG_HOME 必须是绝对路径");
  const filename = path.join(root, "autostart/ip-guard.desktop");
  if (!enabled) {
    await unlink(filename).catch((error: unknown) => {
      if (!fileMissing(error)) throw error;
    });
    return;
  }
  const executable = process.env.APPIMAGE || process.execPath;
  const quoted = executable.replaceAll("%", "%%").replace(/["\\`$]/g, "\\$&");
  await mkdir(path.dirname(filename), { recursive: true });
  await writeFile(
    `${filename}.tmp`,
    `[Desktop Entry]\nType=Application\nName=IP Guard\nExec="${quoted}" --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n`,
    { mode: 0o600 },
  );
  await rename(`${filename}.tmp`, filename);
}
