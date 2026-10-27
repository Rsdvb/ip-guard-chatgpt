import { serviceKeys } from "@ip-guard/electron";
import type { Snapshot } from "@ip-guard/electron";
export type ProtectionNotice = {
  kind: "ip_changed" | "ip_unavailable" | "guard_offline";
  apps: string[];
  currentIp: string;
  expectedIp: string;
};
export function detectProtectionStop(
  previous: Snapshot | undefined,
  current: Snapshot,
  stopping: boolean,
): ProtectionNotice | undefined {
  if (stopping || !previous) return;
  for (const service of serviceKeys) {
    const rule = current.services[service];
    if (rule.ready || !rule.rulesLocked || !rule.enabled) continue;
    const apps = previous.apps
      .filter(
        (app) =>
          app.service === service &&
          previous.running.includes(app.id) &&
          !current.running.includes(app.id),
      )
      .map((app) => app.name);
    if (!apps.length) continue;
    return {
      kind: !current.online
        ? "guard_offline"
        : rule.currentIp && rule.currentIp !== rule.settings.expectedIp
          ? "ip_changed"
          : "ip_unavailable",
      apps: [...new Set(apps)],
      currentIp: current.online ? rule.currentIp : "",
      expectedIp: rule.settings.expectedIp,
    };
  }
}
