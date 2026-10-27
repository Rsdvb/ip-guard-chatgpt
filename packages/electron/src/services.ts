import { z } from "zod";

export const serviceSchema = z.enum(["claude", "chatgpt"]);
export type Service = z.infer<typeof serviceSchema>;
export const services = {
  claude: { name: "Claude", endpoint: "https://claude.ai/cdn-cgi/trace", domains: ["claude.ai"] },
  chatgpt: {
    name: "ChatGPT",
    endpoint: "https://chatgpt.com/cdn-cgi/trace",
    domains: ["chatgpt.com", "chat.openai.com"],
  },
} as const;
export const serviceKeys = ["claude", "chatgpt"] as const;
export const serviceName = (service: Service) => services[service].name;
export const serviceSource = (service: Service) => services[service].endpoint;
export const serviceDomains = (service: Service) => [...services[service].domains];
export const allServiceDomains = () => serviceKeys.flatMap(serviceDomains);
export const protectedService = (value: string): Service | undefined => {
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
