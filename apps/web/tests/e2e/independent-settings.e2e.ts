import { expect, test } from "@playwright/test";

test("switching the viewed service preserves both independent forms without stopping protection", async ({
  page,
}) => {
  await page.goto("/", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "防护设置", exact: true }).click();
  await expect(page.getByLabel("防护服务")).toHaveValue("claude");
  await expect(page.getByLabel("IPv4 来源 · Claude 出口")).toHaveValue(
    "https://claude.ai/cdn-cgi/trace",
  );
  await page.getByLabel("防护服务").selectOption("chatgpt");
  await expect(page.getByLabel("IPv4 来源 · ChatGPT 出口")).toHaveValue(
    "https://chatgpt.com/cdn-cgi/trace",
  );
  await expect(page.getByText("两套规则独立保存", { exact: false })).toBeVisible();
  await page.locator(".service-summary").filter({ hasText: "Claude" }).click();
  await expect(page.getByLabel("防护服务")).toHaveValue("claude");
  await expect(page.locator(".service-summary")).toHaveCount(2);
  await expect(page.getByRole("button", { name: "锁定", exact: true })).toBeDisabled();
});
