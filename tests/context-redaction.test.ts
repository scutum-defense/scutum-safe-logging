import { describe, it, expect } from "vitest";
import { ContextRedactionGuard } from "../src/guards/context-redaction";
import { JsonFormatter } from "../src/formatters/json";
import type { LogEntry } from "../src/core/types";

function entry(partial: Partial<LogEntry>): LogEntry {
  return {
    level: "info",
    message: "test",
    timestamp: new Date().toISOString(),
    service: "test-svc",
    args: {},
    ...partial,
  };
}

describe("ContextRedactionGuard", () => {
  const guard = new ContextRedactionGuard();

  it("redacts sensitive keys in context", () => {
    const result = guard.check(
      entry({
        context: { user: "alice", password: "hunter2", nested: { apiKey: "k-123" } },
      })
    );
    expect(result.context).toMatchObject({
      user: "alice",
      password: "[REDACTED]",
      nested: { apiKey: "[REDACTED]" },
    });
  });

  it("redacts JWT-shaped values even in safe-marked object args", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const result = guard.check(
      entry({ args: { request: { value: { token: jwt, path: "/x" }, safe: true } } })
    );
    const scrubbed = result.args.request.value as Record<string, unknown>;
    expect(scrubbed.token).toBe("[REDACTED]");
    expect(scrubbed.path).toBe("/x");
  });

  it("redacts credit card numbers in plain string args", () => {
    const result = guard.check(
      entry({ args: { note: { value: "card 4111111111111111 on file", safe: true } } })
    );
    expect(String(result.args.note.value)).not.toContain("4111111111111111");
  });

  it("redacts private key blocks", () => {
    const result = guard.check(
      entry({
        args: { blob: { value: "-----BEGIN RSA PRIVATE KEY-----\nabc", safe: true } },
      })
    );
    expect(String(result.args.blob.value)).toBe("[REDACTED]");
  });

  it("leaves ordinary safe values untouched", () => {
    const result = guard.check(
      entry({ args: { count: { value: 42, safe: true } }, context: { zone: "north" } })
    );
    expect(result.args.count.value).toBe(42);
    expect(result.context?.zone).toBe("north");
  });
});

describe("ContextRedactionGuard with JsonFormatter end-to-end", () => {
  it("produces logs with no leaked secrets", () => {
    const guard = new ContextRedactionGuard();
    const formatter = new JsonFormatter();
    const scrubbed = guard.check(
      entry({
        context: { actor: "op-1", session_token: "abc123" },
        args: { password: { value: "hunter2", safe: true } },
      })
    );
    const line = formatter.format(scrubbed, true);
    expect(line).not.toContain("hunter2");
    expect(line).not.toContain("abc123");
    expect(line).toContain("[REDACTED]");
  });
});
