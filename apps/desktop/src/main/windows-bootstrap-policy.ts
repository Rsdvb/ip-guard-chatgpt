export function windowsStartupAction(context: {
  platform: string;
  packaged: boolean;
  administrator?: boolean;
}) {
  if (context.platform !== "win32" || !context.packaged || context.administrator === true)
    return "continue";
  return context.administrator === undefined ? "check" : "elevate";
}
