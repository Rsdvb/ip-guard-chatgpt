import type { ExitResult } from "./exit-ip.ts";

export async function readServiceExit(
  read: (timeoutMs: number) => Promise<ExitResult>,
  active: () => boolean,
  now = () => performance.now(),
): Promise<ExitResult> {
  const started = now();
  const first = await read(4500);
  const remaining = Math.floor(6000 - (now() - started));
  // A transport interruption may be transient. Never retry an IP change, invalid body or HTTP denial.
  if (!first.ip && first.status === 0 && active() && remaining > 0) {
    const result = await read(Math.min(4500, remaining));
    return { ...result, ms: Math.round(now() - started) };
  }
  return first;
}
