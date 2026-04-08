import { describe, it, expect } from "vitest";
import { SensitiveFieldGuard } from "../src/guards/sensitive-field";
import { RedactionGuard } from "../src/guards/redaction";
import type { LogEntry } from "../src/core/types";

function makeEntry(args: Record<string, { value: unknown; safe: boolean }>): LogEntry {
  return { level: "info", message: "test", timestamp: new Date().toISOString(), service: "test", args };
}

describe("SensitiveFieldGuard", () => {
  it("should force-redact fields matching sensitive patterns", () => {
    const guard = new SensitiveFieldGuard();
    const entry = makeEntry({
      userId: { value: "user-1", safe: true },
      password: { value: "secret123", safe: true },
      apiKey: { value: "key-abc", safe: true },
    });
    const result = guard.check(entry);
    expect(result.args.userId.safe).toBe(true);
    expect(result.args.password.safe).toBe(false);
    expect(result.args.apiKey.safe).toBe(false);
  });

  it("should support custom patterns", () => {
    const guard = new SensitiveFieldGuard([/classification/i]);
    const entry = makeEntry({ classification: { value: "top-secret", safe: true } });
    const result = guard.check(entry);
    expect(result.args.classification.safe).toBe(false);
  });
});

describe("RedactionGuard", () => {
  it("should truncate oversized values", () => {
    const guard = new RedactionGuard({ maxValueLength: 100 });
    const longValue = "x".repeat(500);
    const entry = makeEntry({ payload: { value: longValue, safe: true } });
    const result = guard.check(entry);
    expect((result.args.payload.value as string).length).toBeLessThan(200);
    expect(result.args.payload.value).toContain("truncated");
  });
});
