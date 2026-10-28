import type { Snapshot } from "@ip-guard/electron";

export interface SystemFilterTarget {
  id: string;
  service: string;
  executable: string;
  bundleRoot: string | null;
  allowed: boolean;
  keepRunning: boolean;
}
export function systemFilterPolicy(
  snapshot: Snapshot | undefined,
  uid: number,
  now: number,
  previous: SystemFilterTarget[],
  platform: "darwin" | "linux",
) {
  const targets: SystemFilterTarget[] = snapshot?.online
    ? snapshot.apps
        .filter((target) => target.enabled)
        .map((target) => {
          const rule = snapshot.services[target.service],
            age = now - Date.parse(rule.lastChecked);
          const allowed =
            rule.ready &&
            rule.enabled &&
            rule.rulesLocked &&
            rule.currentIp !== "" &&
            rule.currentIp === rule.settings.expectedIp &&
            Number.isFinite(age) &&
            age >= -1000 &&
            age <= (rule.settings.intervalSeconds + 8) * 1000;
          const mismatch = rule.currentIp !== "" && rule.currentIp !== rule.settings.expectedIp;
          return {
            id: target.id,
            service: target.service,
            executable: target.path,
            bundleRoot:
              platform === "darwin"
                ? (target.path.match(/^(.*\.app)\/Contents\//)?.[1] ?? null)
                : null,
            allowed,
            keepRunning:
              rule.enabled &&
              rule.rulesLocked &&
              (allowed || (!rule.stopOnProbeFailure && !mismatch)),
            nativeExecutable: target.nativeExecutable,
          };
        })
        .filter(
          (target) =>
            platform === "linux" || target.bundleRoot !== null || target.nativeExecutable === true,
        )
        .map(({ nativeExecutable: _kind, ...target }) => target)
    : previous.map((target) => ({ ...target, allowed: false, keepRunning: false }));
  return { format: 1, uid, targets };
}
