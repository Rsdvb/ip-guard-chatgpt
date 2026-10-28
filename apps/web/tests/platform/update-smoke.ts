import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";

import type { ElectronApplication, Page } from "@playwright/test";

import { nativeVersion, replySchema, updateStateSchema } from "@ip-guard/electron";

export async function testWindowsUpdates(
  application: ElectronApplication,
  page: Page,
  desktop: string,
) {
  const installer = await readFile(
    path.join(desktop, "release", `IP-Guard-Setup-${nativeVersion}.exe`),
  );
  const parts = nativeVersion.split(".").map(Number);
  const offered = `${parts[0]}.${parts[1]}.${Number(parts[2]) + 1}`;
  const filename = `IP-Guard-Setup-${offered}.exe`;
  const digest = createHash("sha512").update(installer).digest("base64");
  const publishedMetadata = await readFile(path.join(desktop, "release/latest.yml"), "utf8");
  assert.ok(publishedMetadata.includes(`version: ${nativeVersion}\n`));
  assert.ok(publishedMetadata.includes(`IP-Guard-Setup-${nativeVersion}.exe`));
  assert.ok(
    publishedMetadata.includes(`sha512: ${digest}`),
    "Published metadata must describe the exact installer bytes",
  );
  let corrupt = true;
  const seen: string[] = [];
  // GitHub is external. Only its HTTP transport is replaced; the packaged IPC, updater,
  // feed parser, downloader and checksum verifier use the actual installer bytes.
  const server = createServer((request, response) => {
    const requested = new URL(request.url || "/", "http://localhost").pathname;
    seen.push(requested);
    if (requested.endsWith("/releases.atom"))
      response.end(
        `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Update fixture</title><link href="https://github.com/Rsdvb/ip-guard-chatgpt/releases/tag/v${offered}"/><updated>2026-10-29T00:00:00Z</updated><content>Isolated update regression</content></entry></feed>`,
      );
    else if (requested.endsWith("/latest.yml")) {
      const sha512 = corrupt ? Buffer.alloc(64).toString("base64") : digest;
      response.end(
        `version: ${offered}\nfiles:\n  - url: ${filename}\n    sha512: ${sha512}\n    size: ${installer.length}\npath: ${filename}\nsha512: ${sha512}\nreleaseDate: '2026-10-29T00:00:00.000Z'\n`,
      );
    } else if (requested.endsWith(`/${filename}`)) {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": installer.length,
      });
      response.end(installer);
    } else {
      response.writeHead(404);
      response.end("Missing update fixture");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await application.evaluate(({ app }, base) => {
      const { createRequire } = process.getBuiltinModule("module");
      const path = process.getBuiltinModule("path");
      const module: unknown = createRequire(path.join(app.getAppPath(), "package.json"))(
        "electron-updater",
      );
      if (!module || typeof module !== "object") throw new Error("Packaged updater missing");
      const updater: unknown = Reflect.get(module, "autoUpdater");
      if (!updater || typeof updater !== "object")
        throw new Error("Packaged updater instance missing");
      Reflect.set(updater, "disableDifferentialDownload", true);
      const session: unknown = Reflect.get(updater, "netSession");
      if (!session || typeof session !== "object") throw new Error("Updater session missing");
      const webRequest: unknown = Reflect.get(session, "webRequest");
      if (!webRequest || typeof webRequest !== "object")
        throw new Error("Updater requests missing");
      const intercept: unknown = Reflect.get(webRequest, "onBeforeRequest");
      if (typeof intercept !== "function") throw new Error("Updater request interception missing");
      Reflect.apply(intercept, webRequest, [
        { urls: ["https://github.com/Rsdvb/ip-guard-chatgpt/releases*"] },
        (details: { url: string }, callback: (result: { redirectURL: string }) => void) =>
          callback({ redirectURL: base + new URL(details.url).pathname }),
      ]);
    }, `http://127.0.0.1:${address.port}`);
    const invoke = async (action: "update:status" | "update:check" | "update:download") =>
      updateStateSchema.parse(
        replySchema.parse(
          await page.evaluate(async (name) => {
            const bridge: unknown = Reflect.get(globalThis, "desktop");
            if (!bridge || typeof bridge !== "object") throw new Error("Missing IPC bridge");
            const command: unknown = Reflect.get(bridge, "invoke");
            if (typeof command !== "function") throw new Error("Missing IPC invocation");
            return Reflect.apply(command, bridge, [{ action: name }]);
          }, action),
        ).appUpdate,
      );
    const initial = await invoke("update:status");
    assert.notEqual(
      initial.phase,
      "unconfigured",
      "Every published Windows installer needs a working update feed",
    );
    assert.equal(initial.repository, "Rsdvb/ip-guard-chatgpt");
    const available = await invoke("update:check");
    assert.equal(available.phase, "available", available.message);
    const rejected = await invoke("update:download");
    assert.equal(rejected.phase, "error", "Corrupt installer bytes must never become installable");
    assert.match(rejected.message, /checksum|sha512|mismatch/i);
    corrupt = false;
    assert.equal((await invoke("update:check")).phase, "available");
    const downloaded = await invoke("update:download");
    assert.equal(downloaded.phase, "downloaded", downloaded.message);
    assert.equal(downloaded.progress, 100);
    assert.equal(
      (await invoke("update:check")).phase,
      "downloaded",
      "A repeated check must retain a verified download",
    );
    await writeFile(
      path.join(desktop, "../web/test-results/online-update-win32.json"),
      JSON.stringify(
        {
          currentVersion: nativeVersion,
          offeredVersion: offered,
          configured: true,
          previewFeed: true,
          corruptDownloadRejected: true,
          verifiedDownload: true,
          downloadedStatePreserved: true,
          sha512: digest,
          requests: seen,
        },
        null,
        2,
      ) + "\n",
    );
    console.log(
      "PASS: packaged online update check, corrupt download rejection, valid installer checksum and repeat check",
    );
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
