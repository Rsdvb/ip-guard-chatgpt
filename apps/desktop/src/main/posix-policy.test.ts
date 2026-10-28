import { expect, it } from "vite-plus/test";

import { parsePosixArguments, posixPermission } from "./posix-policy.ts";

it("passes quoted arguments literally without invoking a shell or expanding commands", () => {
  expect(parsePosixArguments("--name \"hello world\" '' '$HOME;$(id)' a\\ b")).toEqual([
    "--name",
    "hello world",
    "",
    "$HOME;$(id)",
    "a b",
  ]);
  expect(() => parsePosixArguments('"unfinished')).toThrow();
  expect(() => parsePosixArguments("trailing\\")).toThrow();
});

it("only grants a new launch to an enabled, locked, fresh and matching service", () => {
  const rule = {
    enabled: true,
    rulesLocked: true,
    ready: true,
    unverified: false,
    stopOnProbeFailure: true,
  };
  expect(posixPermission(rule, true, false)).toBe(true);
  expect(posixPermission(rule, false, false)).toBe(false);
  expect(posixPermission({ ...rule, enabled: false }, true, true)).toBe(false);
  expect(posixPermission({ ...rule, rulesLocked: false }, true, true)).toBe(false);
});

it("retains only existing processes on an opted-out unavailable probe and never on an IP mismatch", () => {
  const unavailable = {
    enabled: true,
    rulesLocked: true,
    ready: false,
    unverified: true,
    stopOnProbeFailure: false,
  };
  expect(posixPermission(unavailable, false, true)).toBe(true);
  expect(posixPermission(unavailable, false, false)).toBe(false);
  expect(posixPermission({ ...unavailable, unverified: false }, false, true)).toBe(false);
  expect(posixPermission({ ...unavailable, stopOnProbeFailure: true }, false, true)).toBe(false);
});
