import { z } from "zod";

export const serviceSchema = z.enum(["claude", "chatgpt", "both"]);
export type Service = z.infer<typeof serviceSchema>;
export type SingleService = Exclude<Service, "both">;
export const services = {
  claude: { name: "Claude", endpoint: "https://claude.ai/cdn-cgi/trace", domains: ["claude.ai"] },
  chatgpt: {
    name: "ChatGPT",
    endpoint: "https://chatgpt.com/cdn-cgi/trace",
    domains: ["chatgpt.com", "chat.openai.com"],
  },
} as const;
export const selectedServices = (service: Service): SingleService[] =>
  service === "both" ? ["claude", "chatgpt"] : [service];
export const serviceName = (service: Service) =>
  selectedServices(service)
    .map((key) => services[key].name)
    .join(" + ");
export const serviceSource = (service: Service) =>
  selectedServices(service)
    .map((key) => services[key].endpoint)
    .join(" + ");
export const serviceDomains = (service: Service) =>
  selectedServices(service).flatMap((key) => [...services[key].domains]);
export const protectedService = (value: string): SingleService | undefined => {
  try {
    const url = new URL(value);
    if (!["https:", "http:"].includes(url.protocol)) return;
    return (["claude", "chatgpt"] as const).find((key) =>
      services[key].domains.some(
        (domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`),
      ),
    );
  } catch {
    return;
  }
};
