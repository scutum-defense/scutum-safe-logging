import { createLogger, SafeArg, UnsafeArg, ConsoleTransport, SensitiveFieldGuard, RedactionGuard } from "../src";

const logger = createLogger({
  service: "scutum-api",
  level: "info",
  transports: [new ConsoleTransport({ redactUnsafe: true })],
  guards: [new SensitiveFieldGuard(), new RedactionGuard()],
});

// Safe args appear in plaintext
logger.info(
  "Incident detected",
  SafeArg("incidentId", "inc-001"),
  SafeArg("severity", "high"),
  SafeArg("affectedZone", "perimeter-north"),
);

// Unsafe args are redacted in output
logger.warn(
  "Authentication attempt",
  SafeArg("userId", "operator-1"),
  UnsafeArg("token", "bearer-abc-123-secret"),
  UnsafeArg("ipAddress", "10.0.1.42"),
);

// Even if you accidentally mark a sensitive field as safe, the guard catches it
logger.info(
  "Config loaded",
  SafeArg("apiKey", "this-will-be-caught"),
  SafeArg("region", "abudhabi"),
);

// Child loggers inherit context
const incidentLogger = logger.child({ incidentId: "inc-001", zone: "fuel-storage" });
incidentLogger.info("Recommendation generated", SafeArg("actionCount", 3));
incidentLogger.error("Approval timeout", SafeArg("waitMs", 30000));
