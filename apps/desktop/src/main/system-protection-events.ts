import { EventEmitter } from "node:events";

import type { SystemProtectionState, SystemProcess } from "@ip-guard/electron";

export class SystemProtectionEvents extends EventEmitter<{
  update: [SystemProtectionState, SystemProcess[]];
}> {
  private current: SystemProtectionState;
  private processes: SystemProcess[] = [];
  constructor(message: string) {
    super();
    this.current = { phase: "unavailable", message, active: false };
  }
  get state() {
    return this.current;
  }
  set state(value: SystemProtectionState) {
    this.apply(value);
  }
  get active() {
    return this.current.active === true;
  }
  get running() {
    return this.processes;
  }
  protected apply(value: SystemProtectionState, running = this.processes) {
    const active =
      value.active ??
      (value.phase === "enabled" ? true : value.phase === "disabled" ? false : this.current.active);
    const next = { phase: value.phase, message: value.message, active };
    const processes = [...running].sort((a, b) => a.id.localeCompare(b.id) || a.pid - b.pid);
    if (JSON.stringify([next, processes]) === JSON.stringify([this.current, this.processes]))
      return;
    this.current = next;
    this.processes = processes;
    this.emit("update", next, processes);
  }
}
