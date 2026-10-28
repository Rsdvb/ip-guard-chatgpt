import assert from "node:assert/strict";
import { copyFile, mkdtemp, rm, symlink, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { resolvePosixExecutable } from "../src/main/posix-presets.ts";

const root = await mkdtemp(path.join(tmpdir(), "ipg-presets-"));
try {
  const first = path.join(root, "version-1"),
    second = path.join(root, "version-2"),
    cli = path.join(root, "claude");
  await copyFile("/bin/sleep", first);
  await copyFile("/bin/sleep", second);
  await symlink(first, cli);
  assert.equal(
    await resolvePosixExecutable(cli),
    cli,
    "Keep the CLI entry path so an application update cannot bypass its registered rule",
  );
  await unlink(cli);
  await symlink(second, cli);
  assert.equal(
    await resolvePosixExecutable(cli),
    cli,
    "A retargeted CLI entry keeps the same registered path",
  );
  console.log("PASS native CLI entry survives a symlink-based application update");
} finally {
  await rm(root, { recursive: true, force: true });
}
