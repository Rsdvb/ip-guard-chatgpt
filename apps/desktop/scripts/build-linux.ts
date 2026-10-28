import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import { nativeVersion } from "@ip-guard/electron";

if (process.platform !== "linux") throw new Error("Ubuntu native components must build on Linux");
const root = path.resolve(import.meta.dirname, "..");
const source = path.join(root, "linux");
const output = path.join(root, "dist/linux");
mkdirSync(output, { recursive: true });
for (const args of [
  ["test", "./..."],
  [
    "build",
    "-buildvcs=false",
    "-trimpath",
    `-ldflags=-s -w -X main.buildVersion=${nativeVersion}`,
    "-o",
    path.join(output, "ipguard-system"),
    ".",
  ],
]) {
  const result = spawnSync("go", args, {
    cwd: source,
    stdio: "inherit",
    env: { ...process.env, CGO_ENABLED: "0" },
  });
  if (result.status !== 0)
    throw result.error ?? new Error("Ubuntu native build failed; Go 1.27 is required");
}
const require = createRequire(import.meta.url);
const builder = createRequire(require.resolve("electron-builder/cli.js"));
const templates = path.join(
  path.dirname(builder.resolve("app-builder-lib/package.json")),
  "templates/linux",
);
for (const name of ["after-install", "after-remove"]) {
  const standard = readFileSync(path.join(templates, `${name}.tpl`), "utf8");
  const own = readFileSync(path.join(source, `${name}.sh`), "utf8");
  writeFileSync(
    path.join(output, `${name}.tpl`),
    name === "after-install"
      ? `${standard}\n${own}`
      : `#!/bin/bash\n${own}\n${standard.replace(/^#![^\n]*\n/, "")}`,
  );
}
