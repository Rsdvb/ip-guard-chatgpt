import { expect, test } from "@playwright/test";
test("each service shows its own default-on unavailable-IP stop policy", async ({ page }) => {
  await page.goto("/", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "防护设置", exact: true }).click();
  await expect(
    page.getByRole("switch", { name: "Claude 获取不到 IP 时自动结束程序", exact: true }),
  ).toHaveAttribute("aria-checked", "true");
  await page.getByLabel("防护服务").selectOption("chatgpt");
  await expect(
    page.getByRole("switch", { name: "ChatGPT 获取不到 IP 时自动结束程序", exact: true }),
  ).toHaveAttribute("aria-checked", "true");
  await expect(page.getByText("已确认 IP 不符时仍会结束并阻断", { exact: false })).toBeVisible();
});
