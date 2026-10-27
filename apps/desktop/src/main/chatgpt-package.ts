import path from "node:path";

export function isChatgptEntry(packageName: string, executable: string) {
  return (
    /^OpenAI\./i.test(packageName) &&
    path.win32.basename(executable).toLowerCase() === "chatgpt.exe"
  );
}
