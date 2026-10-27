import type { Service } from "@ip-guard/electron";

import type { ExitIPv4, ProbeProgress } from "#src/main/exit-ip.ts";
export class ProtectionProbe {
  private probes: Record<Service, ExitIPv4>;
  constructor(probes: Record<Service, ExitIPv4>) {
    this.probes = probes;
  }
  async check(service: Service, progress?: (step: ProbeProgress) => void) {
    const probe = this.probes[service];
    if (progress) probe.on("progress", progress);
    try {
      const pending = probe.check();
      if (progress) for (const step of probe.steps) progress(step);
      return await pending;
    } finally {
      if (progress) probe.off("progress", progress);
    }
  }
}
