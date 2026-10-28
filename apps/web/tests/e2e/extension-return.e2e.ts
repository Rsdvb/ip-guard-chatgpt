import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";
import type { BrowserContext, Worker } from "@playwright/test";

import { browserStateSchema, offlineBrowserPermission } from "@ip-guard/electron";
import type { BrowserState, Service } from "@ip-guard/electron";

const extension = fileURLToPath(new URL("../../../browser-extension/dist", import.meta.url));

async function installNativeHost(worker: Worker) {
  // The Windows desktop host is external to Chromium; exercise the real worker and DNR rules
  // with only Native Messaging replaced, without touching the user's installed host or registry.
  await worker.evaluate(() => {
    const api: unknown = Reflect.get(globalThis, "chrome");
    if (!api || typeof api !== "object") throw new Error("Missing Chrome API");
    const runtime: unknown = Reflect.get(api, "runtime");
    if (!runtime || typeof runtime !== "object") throw new Error("Missing runtime API");
    let latest: unknown;
    let emit = (_message: unknown) => {};
    Reflect.set(globalThis, "nativeTestSend", (message: unknown) => {
      latest = message;
      emit(message);
    });
    Reflect.set(runtime, "connectNative", (host: string) => {
      if (host !== "com.ipguard.browser") throw new Error("Unexpected native host");
      const listeners: ((message: unknown) => void)[] = [];
      const disconnected: (() => void)[] = [];
      emit = (message) => listeners.forEach((listener) => listener(message));
      const heartbeat = setInterval(() => {
        if (latest) emit(latest);
      }, 250);
      return {
        onMessage: {
          addListener: (listener: (message: unknown) => void) => listeners.push(listener),
        },
        onDisconnect: { addListener: (listener: () => void) => disconnected.push(listener) },
        postMessage: (input: unknown) => {
          if (
            !input ||
            typeof input !== "object" ||
            Reflect.get(input, "action") !== "watch" ||
            Reflect.get(input, "protocol") !== 3
          )
            throw new Error("Unexpected watch contract");
          if (latest) emit(latest);
        },
        disconnect: () => {
          clearInterval(heartbeat);
          disconnected.forEach((listener) => listener());
        },
      };
    });
  });
}

async function sendState(worker: Worker, service: Service, allow: boolean) {
  const state: BrowserState = browserStateSchema.parse({
    protocol: 3,
    appVersion: "0.12.0", // The protocol-3 extension update also works with the deployed desktop.
    services: {
      claude: offlineBrowserPermission(),
      chatgpt: offlineBrowserPermission(),
      [service]: allow
        ? {
            phase: "allowed",
            currentIp: "8.8.8.8",
            expectedIp: "8.8.8.8",
            checkedAt: new Date().toISOString(),
            reason: "IPv4 与该服务锁定地址匹配",
          }
        : offlineBrowserPermission("测试宿主失联"),
    },
  });
  await worker.evaluate((value) => {
    const send: unknown = Reflect.get(globalThis, "nativeTestSend");
    if (typeof send !== "function") throw new Error("Missing native test transport");
    Reflect.apply(send, globalThis, [value]);
  }, state);
}

for (const { service, name, url } of [
  { service: "claude", name: "Claude", url: "https://claude.ai/new?test=return#draft" },
  { service: "chatgpt", name: "ChatGPT", url: "https://chatgpt.com/?test=return#draft" },
  { service: "chatgpt", name: "ChatGPT legacy", url: "https://chat.openai.com/?test=return#draft" },
] as const) {
  test(`returns to ${name} after verification and can recover after a later block`, async ({
    playwright,
  }) => {
    // Chromium's Windows worker storage cannot initialize under a MAX_PATH-length profile.
    const profile = await mkdtemp(path.join(tmpdir(), "ipg-ext-"));
    let context: BrowserContext | undefined;
    try {
      context = await playwright.chromium.launchPersistentContext(profile, {
        channel: "chromium",
        headless: true,
        args: [
          `--disable-extensions-except=${extension}`,
          `--load-extension=${extension}`,
          "--host-resolver-rules=MAP claude.ai ~NOTFOUND, MAP chatgpt.com ~NOTFOUND, MAP chat.openai.com ~NOTFOUND",
        ],
      });
      const serviceName = service === "claude" ? "Claude" : "ChatGPT";
      // The destination website is external; no chat accounts or actual network requests are used.
      await context.route(/^https:\/\/(claude\.ai|chatgpt\.com|chat\.openai\.com)\//, (route) =>
        route.fulfill({ contentType: "text/html", body: `<h1>Service destination</h1>` }),
      );
      let [worker] = context.serviceWorkers();
      worker ??= await context.waitForEvent("serviceworker");
      const id = new URL(worker.url()).hostname;
      const page = await context.newPage();
      await page.goto(`chrome-extension://${id}/popup.html`, { waitUntil: "networkidle" });
      await installNativeHost(worker);
      await page.getByRole("button", { name: "重新连接", exact: true }).click();
      await sendState(worker, service, false);
      await page.goto(url, { waitUntil: "networkidle" });
      await expect(page).toHaveURL(new RegExp(`^chrome-extension://${id}/blocked\\.html`));
      await expect(
        page.getByRole("button", { name: `返回 ${serviceName}`, exact: true }),
      ).toBeDisabled();
      await sendState(worker, service, true);
      await expect(page.getByRole("status")).toHaveText("校验通过");
      await page.getByRole("button", { name: `返回 ${serviceName}`, exact: true }).click();
      await expect(page.getByRole("heading", { name: "Service destination" })).toBeVisible();
      const serviceHome = service === "claude" ? "https://claude.ai/" : "https://chatgpt.com/";
      await expect(page).toHaveURL(serviceHome);
      // Once allowed, direct navigation must also work, including a legacy domain and deep link.
      await page.goto(url, { waitUntil: "networkidle" });
      await expect(page).toHaveURL(url);
      await sendState(worker, service, false);
      await expect(page).toHaveURL(new RegExp(`^chrome-extension://${id}/blocked\\.html`));
      await sendState(worker, service, true);
      await expect(page.getByRole("status")).toHaveText("校验通过");
      await page.getByRole("button", { name: `返回 ${serviceName}`, exact: true }).click();
      await expect(page.getByRole("heading", { name: "Service destination" })).toBeVisible();
      await expect(page).toHaveURL(url);
      const other = await context.newPage();
      await other.goto(service === "claude" ? "https://chatgpt.com/" : "https://claude.ai/", {
        waitUntil: "networkidle",
      });
      await expect(other).toHaveURL(new RegExp(`^chrome-extension://${id}/blocked\\.html`));
      await expect(other.getByRole("status")).toHaveText("访问已阻断");
      await expect(other.getByRole("button", { name: /返回/ })).toBeDisabled();
    } finally {
      try {
        await context?.close();
      } finally {
        await rm(profile, { recursive: true, force: true });
      }
    }
  });
}

test("steady native heartbeats keep permissions without repeating tab scans and badge writes", async ({
  playwright,
}) => {
  const profile = await mkdtemp(path.join(tmpdir(), "ipg-idle-"));
  let context: BrowserContext | undefined;
  try {
    context = await playwright.chromium.launchPersistentContext(profile, {
      channel: "chromium",
      headless: true,
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    });
    const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
    await installNativeHost(worker);
    const id = new URL(worker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${id}/blocked.html?target=https%3A%2F%2Fclaude.ai%2F`, {
      waitUntil: "networkidle",
    });
    await page.getByRole("button", { name: "重新连接", exact: true }).click();
    await sendState(worker, "claude", true);
    await expect(page.getByRole("status")).toHaveText("校验通过");
    await page.evaluate(() => {
      Reflect.set(globalThis, "idleDomWrites", 0);
      const root = document.getElementById("app");
      if (!root) throw new Error("Extension root missing");
      new MutationObserver((changes) =>
        Reflect.set(
          globalThis,
          "idleDomWrites",
          Number(Reflect.get(globalThis, "idleDomWrites")) + changes.length,
        ),
      ).observe(root, {
        subtree: true,
        childList: true,
        attributes: true,
        characterData: true,
      });
    });
    await worker.evaluate(() => {
      const api: unknown = Reflect.get(globalThis, "chrome");
      if (!api || typeof api !== "object") throw new Error("Chrome API missing");
      const counts = { scans: 0, badges: 0 };
      for (const [objectName, methodName, counter] of [
        ["tabs", "query", "scans"],
        ["action", "setBadgeText", "badges"],
      ] as const) {
        const object: unknown = Reflect.get(api, objectName);
        if (!object || typeof object !== "object") throw new Error("Chrome API object missing");
        const method: unknown = Reflect.get(object, methodName);
        if (typeof method !== "function") throw new Error("Chrome API method missing");
        Reflect.set(object, methodName, (...args: unknown[]) => {
          counts[counter]++;
          return Reflect.apply(method, object, args);
        });
      }
      Reflect.set(globalThis, "idleApiCounts", counts);
    });
    // Native Messaging is an external transport; its 250 ms fixture heartbeat remains active.
    await page.waitForTimeout(1800);
    const counts = await worker.evaluate(() => Reflect.get(globalThis, "idleApiCounts"));
    expect(counts).toEqual({ scans: 0, badges: 0 });
    expect(await page.evaluate(() => Reflect.get(globalThis, "idleDomWrites"))).toBe(0);
    await expect(page.getByRole("status")).toHaveText("校验通过");
  } finally {
    await context?.close();
    await rm(profile, { recursive: true, force: true });
  }
});
