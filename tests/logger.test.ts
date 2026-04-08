import { describe, it, expect, vi } from "vitest";
import { SafeLogger, createLogger } from "../src/core/logger";
import { SafeArg, UnsafeArg } from "../src/core/safe-arg";
import type { LogEntry, LogTransport } from "../src/core/types";

function createTestTransport(): LogTransport & { entries: LogEntry[] } {
  const entries: LogEntry[] = [];
  return { name: "test", entries, write: (entry) => entries.push(entry) };
}

describe("SafeLogger", () => {
  it("should log with safe args in plaintext", () => {
    const transport = createTestTransport();
    const logger = createLogger({ service: "test", level: "info", transports: [transport] });
    logger.info("Incident detected", SafeArg("incidentId", "inc-001"), SafeArg("severity", "high"));
    expect(transport.entries.length).toBe(1);
    expect(transport.entries[0].args.incidentId.safe).toBe(true);
    expect(transport.entries[0].args.incidentId.value).toBe("inc-001");
  });

  it("should mark unsafe args for redaction", () => {
    const transport = createTestTransport();
    const logger = createLogger({ service: "test", level: "info", transports: [transport] });
    logger.info("Auth attempt", SafeArg("userId", "user-1"), UnsafeArg("token", "secret-token-123"));
    expect(transport.entries[0].args.token.safe).toBe(false);
    expect(transport.entries[0].args.token.value).toBe("secret-token-123");
  });

  it("should respect log level filtering", () => {
    const transport = createTestTransport();
    const logger = createLogger({ service: "test", level: "warn", transports: [transport] });
    logger.debug("should not appear");
    logger.info("should not appear");
    logger.warn("should appear");
    logger.error("should appear");
    expect(transport.entries.length).toBe(2);
  });

  it("should create child loggers with context", () => {
    const transport = createTestTransport();
    const logger = createLogger({ service: "test", level: "info", transports: [transport] });
    const child = logger.child({ incidentId: "inc-001", zone: "perimeter" });
    child.info("Zone breach detected");
    expect(transport.entries[0].context?.incidentId).toBe("inc-001");
    expect(transport.entries[0].context?.zone).toBe("perimeter");
  });

  it("should include timestamp and service", () => {
    const transport = createTestTransport();
    const logger = createLogger({ service: "scutum-api", level: "info", transports: [transport] });
    logger.info("Started");
    expect(transport.entries[0].service).toBe("scutum-api");
    expect(transport.entries[0].timestamp).toBeDefined();
  });
});
