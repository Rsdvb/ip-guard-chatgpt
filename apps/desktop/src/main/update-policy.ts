import { z } from "zod";

export const updateRepositorySchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/);
const version = z.string().regex(/^\d+\.\d+\.\d+$/);
const releaseSchema = z.object({
  draft: z.boolean(),
  tag_name: z.string(),
  assets: z.array(z.object({ name: z.string() })),
});
export function newerVersion(candidate: string, current: string) {
  if (!version.safeParse(candidate).success || !version.safeParse(current).success) return false;
  const a = candidate.split(".").map(Number),
    b = current.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i]! > b[i]!; // Both validated versions have three numeric parts.
  return false;
}
export function platformRelease(input: unknown, current: string, platform: NodeJS.Platform) {
  const releases = z.array(releaseSchema).max(100).parse(input);
  const suffix = platform === "darwin" ? /-macOS-arm64\.zip$/ : /-Ubuntu-x64\.deb$/;
  let latest = current;
  for (const release of releases) {
    const next = release.tag_name.replace(/^v/, "");
    if (
      !release.draft &&
      newerVersion(next, latest) &&
      release.assets.some(
        (asset) =>
          asset.name ===
            `IP-Guard-${next}${platform === "darwin" ? "-macOS-arm64.zip" : "-Ubuntu-x64.deb"}` &&
          suffix.test(asset.name),
      )
    )
      latest = next;
  }
  return latest;
}
