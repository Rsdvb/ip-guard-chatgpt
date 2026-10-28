import { spawn, execFile } from "node:child_process";
import { createConnection } from "node:net";
import { isAbsolute } from "node:path";

const [socketOption, endpoint, appOption, targetId, separator, ...extra] = process.argv.slice(2);
if (
  socketOption !== "--socket" ||
  !endpoint ||
  appOption !== "--app" ||
  !/^[0-9a-f-]{36}$/.test(targetId || "") ||
  (separator && separator !== "--")
)
  process.exit(1);
const socket = createConnection(endpoint);
let child,
  targetPid,
  unit,
  lines = "",
  lastLease = performance.now(),
  stopping = false,
  launched = false;
const write = (value) => {
  if (socket.writable) socket.write(JSON.stringify(value) + "\n");
};
function signalGroup(signal) {
  if (!targetPid) return;
  try {
    process.kill(-targetPid, signal);
  } catch (error) {
    if (error.code !== "ESRCH")
      console.error("IP Guard: cannot signal protected group:", error.message);
  }
}
function stop(code = 1) {
  if (stopping) return;
  stopping = true;
  if (unit) {
    execFile("systemctl", ["--user", "stop", unit], { timeout: 5000 }, (error) => {
      if (error)
        execFile("systemctl", ["--user", "kill", "--signal=SIGKILL", unit], { timeout: 3000 }, () =>
          process.exit(code),
        );
      else process.exit(code);
    });
  } else {
    signalGroup("SIGTERM");
    setTimeout(() => {
      signalGroup("SIGKILL");
      process.exit(code);
    }, 1000);
    if (!child) process.exit(code);
  }
}
function launch(message) {
  if (
    launched ||
    !isAbsolute(message.executable || "") ||
    !Array.isArray(message.args) ||
    message.args.length > 512 ||
    !message.args.every((arg) => typeof arg === "string" && arg.length <= 4096)
  )
    throw new Error("Invalid launch authorization");
  if (message.mode !== "group" && message.mode !== "cgroup")
    throw new Error("Invalid supervision mode");
  if (
    message.mode === "cgroup" &&
    (process.platform !== "linux" || !/^ipguard-[0-9a-f-]+\.scope$/.test(message.unit || ""))
  )
    throw new Error("Invalid systemd unit");
  launched = true;
  lastLease = performance.now();
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.ELECTRON_NO_ASAR;
  unit = message.mode === "cgroup" ? message.unit : undefined;
  const executable = unit ? "systemd-run" : message.executable;
  const args = unit
    ? [
        "--user",
        "--quiet",
        "--scope",
        "--collect",
        `--unit=${unit}`,
        "--",
        message.executable,
        ...message.args,
      ]
    : message.args;
  child = spawn(executable, args, { detached: !unit, stdio: "inherit", env });
  child.on("error", (error) => {
    write({ type: "failed", message: error.message });
    stop();
  });
  child.once("spawn", () => {
    targetPid = unit ? undefined : child.pid;
    if (unit) {
      let attempts = 0;
      const confirm = () => {
        if (stopping || child.exitCode !== null || child.signalCode !== null) return;
        execFile(
          "systemctl",
          ["--user", "show", "--property=ActiveState", "--value", unit],
          { timeout: 1500 },
          (error, stdout) => {
            if (!error && stdout.trim() === "active") write({ type: "started", pid: child.pid });
            else if (++attempts < 30) setTimeout(confirm, 100);
            else {
              write({ type: "failed", message: "无法确认 systemd 受控进程组" });
              stop();
            }
          },
        );
      };
      confirm();
    } else write({ type: "started", pid: targetPid });
  });
  child.on("exit", (code) => {
    write({ type: "closed", code: code ?? 1 });
    stop(code ?? 1);
  });
}
socket.setEncoding("utf8");
socket.on("connect", () => write({ action: "launch", targetId, extra }));
socket.on("data", (data) => {
  lines += data;
  if (Buffer.byteLength(lines) > 65536) return stop();
  let split;
  while ((split = lines.indexOf("\n")) >= 0) {
    const line = lines.slice(0, split);
    lines = lines.slice(split + 1);
    try {
      const message = JSON.parse(line);
      if (message.type === "lease" && launched) lastLease = performance.now();
      else if (message.type === "launch") launch(message);
      else if (message.type === "denied") {
        console.error("IP Guard:", message.message);
        stop();
      } else if (message.type === "stop") stop();
      else throw new Error("Unexpected controller message");
    } catch (error) {
      console.error("IP Guard:", error.message);
      stop();
    }
  }
});
socket.on("error", (error) => {
  console.error("IP Guard:", error.message);
  stop();
});
socket.on("close", () => stop());
setInterval(() => {
  if (performance.now() - lastLease > (launched ? 3500 : 15000)) stop();
}, 250);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => stop());
