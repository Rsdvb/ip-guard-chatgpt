import { spawn, execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";

if (
  process.platform !== "win32" ||
  process.env.GITHUB_ACTIONS !== "true" ||
  !process.env.IP_GUARD_PACKAGED_EXECUTABLE
)
  throw new Error("Isolated Windows fixture only");
const child = spawn(
  process.env.IP_GUARD_PACKAGED_EXECUTABLE,
  ["--inspect=0", "--remote-debugging-port=0"],
  { env: { ...process.env, __COMPAT_LAYER: "RunAsInvoker" }, stdio: ["pipe", "pipe", "pipe"] },
);
let nodeURL = "",
  browserURL = "",
  errors = "";
child.stderr.setEncoding("utf8");
child.stderr.on("data", (data: string) => {
  errors = (errors + data).slice(-32768);
  nodeURL = /Debugger listening on (ws:\/\/[^\s]+)/.exec(errors)?.[1] ?? nodeURL;
  browserURL = /DevTools listening on (ws:\/\/[^\s]+)/.exec(errors)?.[1] ?? browserURL;
});
child.stdout.resume();
const sockets: WebSocket[] = [];
async function request(url: string, method: string, params: Record<string, unknown> = {}) {
  const socket = new WebSocket(url);
  sockets.push(socket);
  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", () => reject(new Error("Inspector connection failed")), {
      once: true,
    });
  });
  return await new Promise<unknown>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${method} response timeout`)), 5000);
    socket.addEventListener("message", (event) => {
      const value: unknown = JSON.parse(String(event.data));
      if (value && typeof value === "object" && Reflect.get(value, "id") === 1) {
        clearTimeout(timer);
        resolve(value);
      }
    });
    socket.send(JSON.stringify({ id: 1, method, params }));
  });
}
try {
  const deadline = performance.now() + 10000;
  while ((!nodeURL || !browserURL) && performance.now() < deadline) await delay(100);
  if (!nodeURL || !browserURL) throw new Error("Fixture debugger endpoints not ready");
  const values = await Promise.allSettled([
    request(nodeURL, "Runtime.evaluate", {
      expression:
        "(()=>{const e=require('electron');return {ready:e.app.isReady(),argv:process.argv,windows:e.BrowserWindow.getAllWindows().map(w=>({url:w.webContents.getURL(),visible:w.isVisible(),loading:w.webContents.isLoading()}))}})()",
      includeCommandLineAPI: true,
      returnByValue: true,
    }),
    request(browserURL, "Target.getTargets"),
    request(browserURL, "Browser.getVersion"),
  ]);
  console.log("DIRECT INSPECTOR", JSON.stringify(values));
  await writeFile("windows-inspector.json", JSON.stringify(values, null, 2));
  await request(nodeURL, "Runtime.evaluate", {
    expression: "require('electron').app.quit()",
    includeCommandLineAPI: true,
  });
} finally {
  for (const socket of sockets) socket.close();
  if (child.exitCode === null && child.pid)
    execFileSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
    });
}
