import { expect, test } from "@playwright/test";

test("ChatGPT has its own diagnostics page and service context", async ({ page }) => {
  await page.goto("/", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "ChatGPT 检测", exact: true }).click();
  await expect(page.getByRole("heading", { name: "ChatGPT 检测", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "ChatGPT 出口历史" })).toBeVisible();
  await expect(page.getByText("请在 Windows 桌面版运行检测", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Claude 检测", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Claude 出口历史" })).toBeVisible();
});
