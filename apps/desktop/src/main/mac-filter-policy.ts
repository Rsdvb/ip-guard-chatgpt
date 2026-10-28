import type { Snapshot } from "@ip-guard/electron";

export interface MacFilterTarget {
  id: string;
  service: string;
  executable: string;
  bundleRoot: string | null;
  allowed: boolean;
}
export function macFilterPolicy(
  snapshot: Snapshot | undefined,
  uid: number,
  now: number,
  previous: MacFilterTarget[],
) {
  const targets: MacFilterTarget[] = snapshot?.online
    ? snapshot.apps
        .filter((target) => target.enabled)
        .map((target) => {
          const rule = snapshot.services[target.service],
            age = now - Date.parse(rule.lastChecked);
          return {
            id: target.id,
            service: target.service,
            executable: target.path,
            bundleRoot: target.path.match(/^(.*\.app)\/Contents\//)?.[1] ?? null,
            allowed:
              rule.ready &&
              rule.enabled &&
              rule.rulesLocked &&
              rule.currentIp !== "" &&
              rule.currentIp === rule.settings.expectedIp &&
              Number.isFinite(age) &&
              age >= -1000 &&
              age <= (rule.settings.intervalSeconds + 8) * 1000,
          };
        })
        .filter((target) => target.bundleRoot !== null)
    : previous.map((target) => ({ ...target, allowed: false }));
  return { format: 1, uid, targets };
}
