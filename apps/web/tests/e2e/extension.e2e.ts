import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

const extension = fileURLToPath(new URL("../../../browser-extension/dist", import.meta.url));

test("the unpacked extension blocks ChatGPT and restores the correct destination", async ({
  playwright,
}, testInfo) => {
  const context = await playwright.chromium.launchPersistentContext(
    testInfo.outputPath("profile"),
    {
      channel: "chromium",
      headless: true,
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    },
  );
  try {
    let [worker] = context.serviceWorkers();
    worker ??= await context.waitForEvent("serviceworker");
    const id = new URL(worker.url()).hostname;
    expect(id).toBe("blmgamidelconfabgilaacbkokomegep");
    const page = await context.newPage();
    await page.goto(`chrome-extension://${id}/popup.html`, { waitUntil: "networkidle" });
    await page.getByLabel("查看服务").selectOption("chatgpt");
    await expect(page.getByRole("button", { name: "打开 ChatGPT", exact: true })).toBeDisabled();
    await expect(page.getByRole("status")).toHaveText("访问已阻断");
    for (const url of ["https://chatgpt.com/", "https://chat.openai.com/"]) {
      await page.goto(url, { waitUntil: "networkidle" });
      await expect(page).toHaveURL(new RegExp(`^chrome-extension://${id}/blocked\\.html`));
      await expect(page.getByLabel("查看服务")).toHaveValue("chatgpt");
      await expect(page.getByRole("button", { name: "返回 ChatGPT", exact: true })).toBeDisabled();
    }
    await page.screenshot({
      path: path.join(testInfo.outputDir, "chatgpt-blocked.png"),
      fullPage: true,
    });
  } finally {
    await context.close();
  }
});
