import { describe, it, expect } from "vitest";
import { LeakAuditGuard, auditConfigForLeaks } from "../src/guards/leak-audit";
import type { LogEntry } from "../src/core/types";

const JWT =
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVNHdR9t7U";

function entry(partial: Partial<LogEntry>): LogEntry {
  return {
    level: "info",
    message: "ok",
    timestamp: new Date().toISOString(),
    service: "test",
    args: {},
    ...partial,
  };
}

describe("LeakAuditGuard", () => {
  it("detects JWTs in messages", () => {
    const guard = new LeakAuditGuard({ dropOnFinding: false });
    const checked = guard.check(entry({ message: `token was ${JWT}` }));
    const result = guard.getAuditResult();
    expect(result.clean).toBe(false);
    expect(result.findings[0].pattern).toBe("jwt");
    expect(result.findings[0].location).toBe("message");
    expect(checked.message).toContain(JWT);
  });

  it("detects sensitive keys in nested context", () => {
    const guard = new LeakAuditGuard({ dropOnFinding: false });
    guard.check(
      entry({
        context: { db: { password: "hunter2" } },
      })
    );
    const result = guard.getAuditResult();
    expect(result.findings.some((f) => f.pattern === "sensitive-key")).toBe(true);
    expect(
      result.findings.find((f) => f.pattern === "sensitive-key")?.location
    ).toBe("context.db.password");
  });

  it("detects private key headers", () => {
    const guard = new LeakAuditGuard({ dropOnFinding: false });
    guard.check(
      entry({
        args: { key: { value: "-----BEGIN RSA PRIVATE KEY-----", safe: false } },
      })
    );
    expect(guard.getLastCheckFindings()[0].pattern).toBe("private-key");
  });

  it("drops the entire entry when dropOnFinding is set", () => {
    const guard = new LeakAuditGuard({ dropOnFinding: true });
    const checked = guard.check(
      entry({ message: `leak ${JWT}`, context: { x: 1 } })
    );
    expect(checked.message).toBe("[redacted: potential sensitive data leak]");
    expect(checked.args).toEqual({});
    expect(checked.context).toBeUndefined();
  });

  it("leaves clean entries untouched", () => {
    const guard = new LeakAuditGuard({ dropOnFinding: true });
    const e = entry({ message: "sensor reading nominal", context: { zone: "a" } });
    expect(guard.check(e)).toEqual(e);
    expect(guard.getLastCheckFindings()).toHaveLength(0);
  });

  it("does not scan args marked safe", () => {
    const guard = new LeakAuditGuard({ dropOnFinding: false });
    guard.check(
      entry({
        args: { token: { value: JWT, safe: true } },
      })
    );
    expect(guard.getLastCheckFindings()).toHaveLength(0);
  });

  it("self-check helper reports across multiple entries", () => {
    const result = auditConfigForLeaks(
      [
        { message: "clean entry" },
        { message: `dirty ${JWT}` },
        { message: "another clean" },
      ],
      (guard) => ({
        log: (message) => {
          guard.check(entry({ message }));
        },
      })
    );
    expect(result.scanned).toBe(3);
    expect(result.findings).toHaveLength(1);
  });
});
