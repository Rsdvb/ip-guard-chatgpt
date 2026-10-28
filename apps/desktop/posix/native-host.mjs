import { createConnection } from "node:net";

const [option, endpoint, origin] = process.argv.slice(2);
if (
  option !== "--socket" ||
  !endpoint ||
  origin !== "chrome-extension://blmgamidelconfabgilaacbkokomegep/"
)
  process.exit(1);
let input = Buffer.alloc(0),
  connected = false,
  socket;
const offline = {
  phase: "offline",
  currentIp: "",
  expectedIp: "",
  checkedAt: "",
  reason: "IP Guard 连接已断开，请启动桌面程序",
};
function send(value) {
  const bytes = Buffer.from(JSON.stringify(value));
  if (bytes.length > 16384 || process.stdout.writableLength > 65536) return finish();
  const header = Buffer.alloc(4);
  header.writeUInt32LE(bytes.length);
  process.stdout.write(Buffer.concat([header, bytes]));
}
function finish() {
  socket?.destroy();
  process.exit(1);
}
process.stdin.on("data", (chunk) => {
  if (connected) return finish();
  input = Buffer.concat([input, chunk]);
  if (input.length < 4) return;
  const length = input.readUInt32LE();
  if (!length || length > 16384 || input.length > length + 4) return finish();
  if (input.length < length + 4) return;
  try {
    const request = JSON.parse(input.subarray(4).toString("utf8"));
    if (!request || request.action !== "watch" || request.protocol !== 3) return finish();
  } catch {
    return finish();
  }
  connected = true;
  input = Buffer.alloc(0);
  socket = createConnection(endpoint);
  let lines = "";
  socket.setEncoding("utf8");
  socket.setTimeout(2500, () => socket.destroy(new Error("Heartbeat expired")));
  socket.on("data", (data) => {
    lines += data;
    if (Buffer.byteLength(lines) > 32768) return finish();
    let split;
    while ((split = lines.indexOf("\n")) >= 0) {
      const line = lines.slice(0, split);
      lines = lines.slice(split + 1);
      try {
        send(JSON.parse(line));
      } catch {
        return finish();
      }
    }
  });
  socket.on("error", () => {
    send({ protocol: 3, appVersion: "", services: { claude: offline, chatgpt: offline } });
  });
  socket.on("close", finish);
});
process.stdin.on("end", finish);
process.stdin.on("error", finish);
process.stdout.on("error", finish);
