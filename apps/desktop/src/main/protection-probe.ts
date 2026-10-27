import { EventEmitter } from "node:events";

import { selectedServices } from "@ip-guard/electron";
import type { Service, SingleService } from "@ip-guard/electron";

import type { ExitIPv4, ProbeProgress } from "#src/main/exit-ip.ts";
import { evaluateExits } from "#src/main/exit-policy.ts";
import type { ExitResult } from "#src/main/exit-policy.ts";

export class ProtectionProbe extends EventEmitter<{ progress: [ProbeProgress] }> {
  steps: ProbeProgress[] = [];
  private probes: Record<SingleService, ExitIPv4>;
  private pending = new Map<Service, Promise<ExitResult>>();
  constructor(probes: Record<SingleService, ExitIPv4>) {
    super();
    this.probes = probes;
  }
  check(service: Service): Promise<ExitResult> {
    const existing = this.pending.get(service);
    if (existing) return existing;
    this.steps = [];
    const pending = this.read(service).finally(() => this.pending.delete(service));
    this.pending.set(service, pending);
    return pending;
  }
  private async read(service: Service): Promise<ExitResult> {
    const progress = (key: SingleService, step: ProbeProgress) => {
      const value = { ...step, step: `${key}-${step.step}` };
      const index = this.steps.findIndex((item) => item.step === value.step);
      if (index < 0) this.steps.push(value);
      else this.steps[index] = value;
      this.emit("progress", value);
    };
    const unavailable: ExitResult = {
      ip: "",
      error: "未检测",
      checkedAt: "",
      adapter: "",
      status: 0,
      ms: 0,
    };
    const results: Record<SingleService, ExitResult> = {
      claude: unavailable,
      chatgpt: unavailable,
    };
    await Promise.all(
      selectedServices(service).map(async (key) => {
        const probe = this.probes[key];
        const listener = (step: ProbeProgress) => progress(key, step);
        probe.on("progress", listener);
        try {
          const pending = probe.check();
          for (const step of probe.steps) progress(key, step);
          results[key] = await pending;
        } finally {
          probe.off("progress", listener);
        }
      }),
    );
    return evaluateExits(service, results);
  }
}
