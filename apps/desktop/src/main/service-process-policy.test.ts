import { expect, it } from "vite-plus/test";

import { evaluateProcesses } from "./service-process-policy.ts";

// These snapshots represent the external Windows process inventory, not a fake of repository code.
const snapshot = {
  session: 1,
  username: "test-user",
  unknown: 0,
  selfInTree: false,
  mixedServices: false,
  processes: [{ pid: 100, parent: 1 }],
};
it.each(["claude", "chatgpt"] as const)("keeps %s process state explicitly scoped", (service) => {
  expect(evaluateProcesses(service, snapshot)).toMatchObject({
    service,
    phase: "running",
    count: 1,
    canStop: true,
  });
  expect(evaluateProcesses(service, { ...snapshot, processes: [] })).toMatchObject({
    service,
    phase: "stopped",
    canStop: false,
  });
});
it("refuses to stop a tree containing the controller or the other service", () => {
  expect(evaluateProcesses("chatgpt", { ...snapshot, selfInTree: true }).canStop).toBe(false);
  expect(evaluateProcesses("claude", { ...snapshot, mixedServices: true }).canStop).toBe(false);
});
it("does not claim completion when Windows cannot identify remaining processes", () => {
  expect(evaluateProcesses("chatgpt", { ...snapshot, unknown: 1, processes: [] })).toMatchObject({
    phase: "unknown",
    canStop: false,
  });
});
