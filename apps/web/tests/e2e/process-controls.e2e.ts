import { expect, test } from "@playwright/test";

test("the header exposes independent Claude and ChatGPT process controls at narrow widths", async ({
  page,
}) => {
  await page.goto("/", { waitUntil: "networkidle" });
  for (const service of ["Claude", "ChatGPT"]) {
    const control = page.getByRole("group", { name: `${service} 进程控制`, exact: true });
    await expect(
      control.getByRole("button", { name: `停止 ${service} 进程树`, exact: true }),
    ).toBeVisible();
    await expect(control.getByRole("button")).toBeDisabled();
    await expect(control.getByRole("status")).toHaveText("状态未知");
  }
  for (const width of [1024, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect
      .poll(() =>
        page.locator(".topbar").evaluate((element) => element.scrollWidth <= element.clientWidth),
      )
      .toBe(true);
    await expect(
      page.getByRole("button", { name: "停止 ChatGPT 进程树", exact: true }),
    ).toBeVisible();
  }
});
