import { expect, it } from "vite-plus/test";

import type { ExitResult } from "./exit-ip.ts";
import { readServiceExit } from "./exit-retry.ts";

const result = (ip: string, status: number): ExitResult => ({
  ip,
  status,
  error: ip ? "" : "network error",
  checkedAt: new Date().toISOString(),
  adapter: "",
  ms: 0,
});
// Only the remote trace response and its elapsed time are simulated.
it("retries a transport interruption within the original lease budget", async () => {
  let now = 0;
  const limits: number[] = [];
  const value = await readServiceExit(
    async (timeout) => {
      limits.push(timeout);
      now += timeout;
      return limits.length === 1 ? result("", 0) : result("8.8.8.8", 200);
    },
    () => true,
    () => now,
  );
  expect(limits).toEqual([4500, 1500]);
  expect(value.ip).toBe("8.8.8.8");
});
it.each([200, 301, 403, 500])(
  "does not retry or replace an invalid HTTP %s response",
  async (status) => {
    let calls = 0;
    await readServiceExit(
      async () => {
        calls++;
        return result("", status);
      },
      () => true,
    );
    expect(calls).toBe(1);
  },
);
it("returns a changed IP immediately so native protection can block it", async () => {
  let calls = 0;
  const value = await readServiceExit(
    async () => {
      calls++;
      return result("1.1.1.1", 200);
    },
    () => true,
  );
  expect(calls).toBe(1);
  expect(value.ip).toBe("1.1.1.1");
});
it("does not retry after cancellation or deadline expiry", async () => {
  for (const cancelled of [true, false]) {
    let calls = 0,
      now = 0;
    await readServiceExit(
      async () => {
        calls++;
        now = 6000;
        return result("", 0);
      },
      () => !cancelled,
      () => now,
    );
    expect(calls).toBe(1);
  }
});
