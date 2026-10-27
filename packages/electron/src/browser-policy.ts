import type { BrowserState } from "./index.ts";
import { protectedService, selectedServices, serviceDomains } from "./services.ts";

export function allowedBrowserDomains(state: BrowserState, fresh: boolean): string[] {
  const domains =
    state.service === "both"
      ? []
      : serviceDomains(state.service === "claude" ? "chatgpt" : "claude");
  if (fresh && state.phase === "allowed") domains.push(...serviceDomains(state.service));
  return domains;
}

export function shouldBlockUrl(url: string, state: BrowserState, fresh: boolean): boolean {
  const service = protectedService(url);
  return (
    service !== undefined &&
    selectedServices(state.service).includes(service) &&
    !(fresh && state.phase === "allowed")
  );
}
