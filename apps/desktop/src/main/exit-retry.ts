import { setTimeout as delay } from "node:timers/promises";

import type { ExitResult } from "./exit-ip.ts";

export async function readServiceExit(
  read: (timeoutMs: number, attempt: number) => Promise<ExitResult>,
  active: () => boolean,
  now = () => performance.now(),
): Promise<ExitResult> {
  const started = now();
  let result: ExitResult | undefined;
  for (let attempt = 0; attempt < 16; attempt++) {
    const remaining = Math.floor(6000 - (now() - started));
    if (result && (!active() || remaining <= 0)) break;
    const before = now();
    result = await read(Math.min(4500, remaining), attempt);
    // Retry only transport failures, within the same lease budget. An observed IP or HTTP denial is final.
    if (result.ip || result.status !== 0 || !active()) break;
    const rest = Math.floor(6000 - (now() - started));
    if (rest <= 0) break;
    if (now() - before < 1000) await delay(Math.min(250 * (attempt + 1), 1000, rest));
  }
  if (!result) throw new Error("出口检测未开始");
  return { ...result, ms: Math.round(now() - started) };
}
