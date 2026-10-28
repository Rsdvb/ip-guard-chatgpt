import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import { createConnection } from "node:net";
import path from "node:path";

export function posixSocketDirectory() {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("此功能需要 macOS 或 Linux");
  return `/tmp/ipguard-${uid}`;
}
export async function privateDirectory(directory: string) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.())
    throw new Error(`目录权限或所有者不正确：${directory}`);
  await chmod(directory, 0o700);
}
export function fileMissing(error: unknown) {
  return error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT";
}
export async function preparePosixSocket(endpoint: string) {
  await privateDirectory(path.dirname(endpoint));
  try {
    const info = await lstat(endpoint);
    if (!info.isSocket() || info.uid !== process.getuid?.())
      throw new Error("连接路径被其他文件占用");
  } catch (error) {
    if (fileMissing(error)) return;
    throw error;
  }
  const active = await new Promise<boolean>((resolve, reject) => {
    const socket = createConnection(endpoint);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED" || error.code === "ENOENT") resolve(false);
      else reject(error);
    });
    socket.setTimeout(1000, () => {
      socket.destroy();
      reject(new Error("已有守护连接无响应，请先退出旧版"));
    });
  });
  if (active) throw new Error("另一个 IP Guard 守护器仍在运行");
  await unlink(endpoint).catch((error: unknown) => {
    if (!fileMissing(error)) throw error;
  });
}
