import { spawn, execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";

if (
  process.platform !== "win32" ||
  process.env.GITHUB_ACTIONS !== "true" ||
  !process.env.IP_GUARD_PACKAGED_EXECUTABLE
)
  throw new Error("Isolated Windows fixture only");
const executable = process.env.IP_GUARD_PACKAGED_EXECUTABLE;
const evidence: unknown[] = [];
for (const setup of [
  { name: "normal", args: [], compat: false },
  { name: "without GPU", args: ["--disable-gpu"], compat: false },
  { name: "compat invoker", args: [], compat: true },
  { name: "diagnostic sandbox comparison", args: ["--no-sandbox"], compat: false },
]) {
  const child = spawn(executable, ["--inspect=0", "--remote-debugging-port=0", ...setup.args], {
    env: { ...process.env, ...(setup.compat ? { __COMPAT_LAYER: "RunAsInvoker" } : {}) },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let nodeURL = "",
    browserURL = "",
    errors = "",
    ownEvents = "";
  child.on("error", (error) => {
    errors = error.message;
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (data: string) => {
    errors = (errors + data).slice(-32768);
    nodeURL = /Debugger listening on (ws:\/\/[^\s]+)/.exec(errors)?.[1] ?? nodeURL;
    browserURL = /DevTools listening on (ws:\/\/[^\s]+)/.exec(errors)?.[1] ?? browserURL;
  });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (data: string) => {
    if (/IPG_/.test(data)) ownEvents += data;
  });
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
      const timer = setTimeout(() => reject(new Error(`${method} timeout`)), 5000);
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
    while ((!nodeURL || !browserURL) && child.exitCode === null && performance.now() < deadline)
      await delay(100);
    if (!nodeURL || !browserURL) throw new Error("Fixture debugger endpoints not ready");
    await request(nodeURL, "Runtime.evaluate", {
      expression:
        "(()=>{const e=require('electron');for(const w of e.BrowserWindow.getAllWindows()){w.webContents.on('render-process-gone',(_event,d)=>console.log('IPG_RENDERER_EXIT',JSON.stringify(d)));void w.webContents.loadURL('https://app.localhost/').catch(error=>console.log('IPG_LOAD_ERROR',error.message));}return true})()",
      includeCommandLineAPI: true,
    });
    await delay(2000);
    const values = await Promise.allSettled([
      request(nodeURL, "Runtime.evaluate", {
        expression:
          "(()=>{const e=require('electron');return {ready:e.app.isReady(),windows:e.BrowserWindow.getAllWindows().map(w=>({url:w.webContents.getURL(),visible:w.isVisible(),loading:w.webContents.isLoading()}))}})()",
        includeCommandLineAPI: true,
        returnByValue: true,
      }),
      request(browserURL, "Target.getTargets"),
    ]);
    const result = { name: setup.name, values, events: ownEvents };
    evidence.push(result);
    console.log("DIRECT INSPECTOR", JSON.stringify(result));
    await request(nodeURL, "Runtime.evaluate", {
      expression: "require('electron').app.quit()",
      includeCommandLineAPI: true,
    });
  } catch (error) {
    const result = {
      name: setup.name,
      error: error instanceof Error ? error.message : "Probe failed",
    };
    evidence.push(result);
    console.log("DIRECT INSPECTOR", JSON.stringify(result));
  } finally {
    for (const socket of sockets) socket.close();
    await delay(1000);
    if (child.exitCode === null && child.pid)
      try {
        execFileSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
          stdio: "ignore",
          windowsHide: true,
        });
      } catch {
        await delay(100);
        if (child.exitCode === null) throw new Error("Fixture process cleanup failed");
      }
  }
}
await writeFile("windows-inspector.json", JSON.stringify(evidence, null, 2));
