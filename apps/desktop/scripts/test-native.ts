import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
if (process.platform !== "win32") {
  const result = spawnSync(process.execPath, [path.join(root, "scripts/test-posix.ts")], {
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}
const binary = path.join(root, "dist/NativePolicyTests.exe");
const result = spawnSync(
  path.join(process.env.WINDIR ?? "C:\\Windows", "Microsoft.NET/Framework64/v4.0.30319/csc.exe"),
  [
    "/nologo",
    "/target:exe",
    "/main:IpGuard.NativePolicyTests",
    "/platform:x64",
    "/utf8output",
    "/reference:System.Web.Extensions.dll",
    "/reference:Microsoft.CSharp.dll",
    "/reference:System.Windows.Forms.dll",
    "/reference:System.Drawing.dll",
    `/out:${binary}`,
    path.join(root, "dist/native-build-info.g.cs"),
    ...readdirSync(path.join(root, "native"))
      .filter((file) => file.endsWith(".cs"))
      .map((file) => path.join(root, "native", file)),
    path.join(root, "tests/NativePolicyTests.cs"),
  ],
  { stdio: "inherit" },
);
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
const tested = spawnSync(binary, [], { stdio: "inherit" });
if (tested.error) throw tested.error;
process.exitCode = tested.status ?? 1;
