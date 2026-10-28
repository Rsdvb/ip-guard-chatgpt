import type { ServiceSnapshot } from "@ip-guard/electron";

export function parsePosixArguments(source: string): string[] {
  const result: string[] = [];
  let value = "",
    quote = "",
    started = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === undefined) break;
    if (char === quote) {
      quote = "";
      continue;
    }
    if (!quote && (char === "'" || char === '"')) {
      quote = char;
      started = true;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      const next = source[++i];
      if (next === undefined) throw new Error("启动参数末尾的反斜杠缺少字符");
      if (quote === '"' && !['"', "\\", "$", "`", "\n"].includes(next)) value += "\\";
      value += next;
      started = true;
      continue;
    }
    if (!quote && /\s/.test(char)) {
      if (started) result.push(value);
      value = "";
      started = false;
      continue;
    }
    value += char;
    started = true;
  }
  if (quote) throw new Error("启动参数中的引号未闭合");
  if (started) result.push(value);
  return result;
}

export function posixPermission(
  rule: Pick<
    ServiceSnapshot,
    "enabled" | "rulesLocked" | "ready" | "unverified" | "stopOnProbeFailure"
  >,
  fresh: boolean,
  existing: boolean,
): boolean {
  return (
    rule.enabled &&
    rule.rulesLocked &&
    ((rule.ready && fresh) || (existing && rule.unverified && !rule.stopOnProbeFailure))
  );
}

export const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
