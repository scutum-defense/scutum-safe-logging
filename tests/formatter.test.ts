import { describe, it, expect } from "vitest";
import { JsonFormatter } from "../src/formatters/json";
import type { LogEntry } from "../src/core/types";

describe("JsonFormatter", () => {
  const entry: LogEntry = {
    level: "info", message: "Test", timestamp: "2026-04-01T00:00:00Z", service: "test",
    args: {
      incidentId: { value: "inc-001", safe: true },
      token: { value: "secret-123", safe: false },
    },
  };

  it("should redact unsafe values by default", () => {
    const formatter = new JsonFormatter();
    const output = JSON.parse(formatter.format(entry));
    expect(output.params.incidentId).toBe("inc-001");
    expect(output.params.token).toBe("REDACTED");
  });

  it("should show all values when redaction disabled", () => {
    const formatter = new JsonFormatter();
    const output = JSON.parse(formatter.format(entry, false));
    expect(output.params.token).toBe("secret-123");
  });

  it("should include service and level", () => {
    const formatter = new JsonFormatter();
    const output = JSON.parse(formatter.format(entry));
    expect(output.service).toBe("test");
    expect(output.level).toBe("info");
  });
});
