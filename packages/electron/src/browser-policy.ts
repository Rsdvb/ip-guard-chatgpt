import type { BrowserState } from "./index.ts";
import { protectedService, serviceKeys, serviceDomains } from "./services.ts";
export function allowedBrowserDomains(state: BrowserState, fresh: boolean): string[] {
  return serviceKeys
    .filter(
      (key) =>
        state.services[key].phase === "released" ||
        (fresh && state.services[key].phase === "allowed"),
    )
    .flatMap(serviceDomains);
}
export function shouldBlockUrl(url: string, state: BrowserState, fresh: boolean): boolean {
  const key = protectedService(url);
  return (
    key !== undefined &&
    state.services[key].phase !== "released" &&
    !(fresh && state.services[key].phase === "allowed")
  );
}
