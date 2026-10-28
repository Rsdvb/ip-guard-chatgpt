import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const repository = process.env.GITHUB_REPOSITORY ?? "";
if (repository && !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(repository))
  throw new Error("Invalid GITHUB_REPOSITORY");
writeFileSync(path.join(root, "dist/release-info.json"), JSON.stringify({ repository }), "utf8");
const args = ["--config", "electron-builder.yml", "--publish", "never"];
if (process.platform === "darwin") args.push("--mac", "--arm64");
if (process.platform === "linux") args.push("--linux", "--x64");
if (repository) {
  const [owner, repo] = repository.split("/");
  args.push(
    "--config.publish.provider=github",
    `--config.publish.owner=${owner}`,
    `--config.publish.repo=${repo}`,
  );
}
const cli = createRequire(import.meta.url).resolve("electron-builder/cli.js");
const result = spawnSync(process.execPath, [cli, ...args], {
  cwd: root,
  stdio: "inherit",
});
if (result.error) throw result.error;
if (result.status === 0) {
  const metadata: unknown = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  if (
    !metadata ||
    typeof metadata !== "object" ||
    !("version" in metadata) ||
    typeof metadata.version !== "string"
  )
    throw new Error("Invalid package metadata");
  const directory = path.resolve(root, "../browser-extension/dist");
  const archive = path.join(root, "release", `IP-Guard-Browser-${metadata.version}.zip`);
  if (!/^\d+\.\d+\.\d+$/.test(metadata.version)) throw new Error("Invalid archive version");
  rmSync(archive, { force: true });
  const zip = spawnSync(
    process.platform === "win32" ? "powershell.exe" : "zip",
    process.platform === "win32"
      ? [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.File]::Delete($env:IP_GUARD_EXTENSION_ZIP); [System.IO.Compression.ZipFile]::CreateFromDirectory($env:IP_GUARD_EXTENSION_DIR,$env:IP_GUARD_EXTENSION_ZIP)",
        ]
      : ["-r", "-q", archive, "."],
    {
      env: {
        ...process.env,
        IP_GUARD_EXTENSION_DIR: directory,
        IP_GUARD_EXTENSION_ZIP: archive,
      },
      cwd: directory,
      windowsHide: true,
      stdio: "inherit",
    },
  );
  if (zip.error) throw zip.error;
  if (zip.status !== 0) throw new Error("Browser extension archive failed");
  if (
    process.platform === "win32" &&
    process.env.GITHUB_ACTIONS === "true" &&
    process.env.RUNNER_ENVIRONMENT === "github-hosted"
  ) {
    const installed = spawnSync(
      process.execPath,
      [path.join(root, "scripts/test-windows-installer.ts")],
      { stdio: "inherit" },
    );
    if (installed.error) throw installed.error;
    if (installed.status !== 0)
      throw new Error("Windows install, upgrade and uninstall regression failed");
  }
}
process.exitCode = result.status ?? 1;
