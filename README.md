```
 ____            _                     ____         __        _                      _
/ ___|  ___ _   _| |_ _   _ _ __ ___  / ___|  __ _ / _| ___  | |    ___   __ _  __ _(_)_ __   __ _
\___ \ / __| | | | __| | | | '_ ` _ \ \___ \ / _` | |_ / _ \ | |   / _ \ / _` |/ _` | | '_ \ / _` |
 ___) | (__| |_| | |_| |_| | | | | | | ___) | (_| |  _|  __/ | |__| (_) | (_| | (_| | | | | | (_| |
|____/ \___|\__,_|\__|\__,_|_| |_| |_||____/ \__,_|_|  \___| |_____\___/ \__, |\__, |_|_| |_|\__, |
                                                                         |___/ |___/         |___/
```

# @scutum/safe-logging

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6+-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)](package.json)
[![Guards](https://img.shields.io/badge/Guards-2-orange.svg)](#guards)
[![Transports](https://img.shields.io/badge/Transports-1-purple.svg)](#transports)

**Structured, safe logging for defense operations -- prevents sensitive data leakage in log output.**

---

## The Problem

In defense and critical infrastructure environments, logging is a double-edged sword. Every log entry is a potential intelligence leak. Standard logging libraries treat all data equally -- a user ID and a bearer token are just strings. When an operator writes `logger.info("Auth", { token })`, that token flows into Elasticsearch, Splunk, CloudWatch, and every log aggregator in the pipeline. In production, this means:

- **PII exposure**: Operator names, IP addresses, and identification numbers appear in plaintext across distributed log stores.
- **Credential leakage**: API keys, JWT tokens, bearer tokens, and service credentials end up in log files that are often retained for years.
- **Classification violations**: In defense contexts, accidentally logging classified parameters can constitute a security incident requiring formal review.
- **Compliance failures**: GDPR, ITAR, and defense-specific regulations impose strict controls on what data can be persisted and where.
- **Lateral movement risk**: Attackers who gain read access to log aggregators can harvest credentials from carelessly logged entries.

The root cause is that traditional loggers provide no mechanism to distinguish between data that is safe to persist and data that must never leave the process boundary.

## The Solution: SafeArg / UnsafeArg

`@scutum/safe-logging` solves this by requiring developers to explicitly classify every logged parameter as either **safe** or **unsafe** at the call site. This is not a convention -- it is enforced by the type system.

```typescript
import { createLogger, SafeArg, UnsafeArg, ConsoleTransport } from "@scutum/safe-logging";

const logger = createLogger({
  service: "scutum-api",
  level: "info",
  transports: [new ConsoleTransport()],
});

// Every parameter must be explicitly classified
logger.info(
  "Operator authenticated",
  SafeArg("operatorId", "op-7734"),      // Appears in logs
  SafeArg("region", "gulf-east"),         // Appears in logs
  UnsafeArg("sessionToken", "eyJhbG..."), // REDACTED in logs
  UnsafeArg("ipAddress", "10.0.1.42"),    // REDACTED in logs
);
```

**Output (production):**
```json
{
  "level": "info",
  "message": "Operator authenticated",
  "timestamp": "2026-04-01T14:30:00.000Z",
  "service": "scutum-api",
  "params": {
    "operatorId": "op-7734",
    "region": "gulf-east",
    "sessionToken": "REDACTED",
    "ipAddress": "REDACTED"
  }
}
```

There is no way to accidentally log sensitive data. If a developer forgets to wrap a parameter, the TypeScript compiler rejects it. If they incorrectly mark a sensitive field as safe, the `SensitiveFieldGuard` catches it at runtime.

---

## Architecture

```
  Application Code
        |
        v
  +-------------+
  |  SafeLogger  |  <-- SafeArg / UnsafeArg classification
  +-------------+
        |
        v
  +-------------+
  |   Guards    |  <-- SensitiveFieldGuard, RedactionGuard
  +-------------+
        |
        v
  +--------------+
  |  Formatter   |  <-- JsonFormatter (redacts unsafe values)
  +--------------+
        |
        v
  +--------------+
  |  Transport   |  <-- ConsoleTransport (or custom)
  +--------------+
        |
        v
    Log Output
```

Each log entry flows through a pipeline:

1. **SafeLogger** creates a structured `LogEntry` with explicitly classified arguments.
2. **Guards** inspect and potentially modify entries (e.g., force-redacting sensitive field names, truncating oversized values).
3. **Formatter** serializes the entry to JSON, replacing unsafe values with `REDACTED`.
4. **Transport** writes the formatted output to the destination (console, file, network).

---

## Installation

```bash
npm install @scutum/safe-logging
# or
pnpm add @scutum/safe-logging
# or
yarn add @scutum/safe-logging
```

---

## Quick Start

```typescript
import {
  createLogger,
  SafeArg,
  UnsafeArg,
  ConsoleTransport,
  SensitiveFieldGuard,
  RedactionGuard,
} from "@scutum/safe-logging";

const logger = createLogger({
  service: "scutum-api",
  level: "info",
  transports: [new ConsoleTransport({ redactUnsafe: true })],
  guards: [new SensitiveFieldGuard(), new RedactionGuard()],
});

logger.info(
  "Incident detected",
  SafeArg("incidentId", "inc-001"),
  SafeArg("severity", "high"),
  SafeArg("affectedZone", "perimeter-north"),
);
```

---

## Core Concepts

### SafeArg

`SafeArg(key, value)` marks a value as **safe for logging**. Safe values appear in plaintext in all log outputs, across all transports and environments.

Use `SafeArg` for:
- Incident identifiers
- Severity levels
- Zone or region names
- Non-sensitive configuration values
- Counts and metrics
- Public-facing identifiers

```typescript
logger.info(
  "Zone scan complete",
  SafeArg("zoneId", "zone-alpha-7"),
  SafeArg("threatCount", 3),
  SafeArg("scanDurationMs", 1240),
);
```

### UnsafeArg

`UnsafeArg(key, value)` marks a value as **unsafe for logging**. Unsafe values are redacted in production logs and only shown in debug-level output when explicitly enabled.

Use `UnsafeArg` for:
- Authentication tokens
- API keys and secrets
- IP addresses
- Personal identifiers (names, emails, phone numbers)
- Coordinates and precise locations
- Any data subject to classification or regulation

```typescript
logger.warn(
  "Authentication failed",
  SafeArg("userId", "operator-1"),
  UnsafeArg("attemptedPassword", "..."),
  UnsafeArg("sourceIp", "10.0.1.42"),
  UnsafeArg("userAgent", "Mozilla/5.0..."),
);
```

### Child Loggers

Child loggers inherit configuration and context from their parent. Context fields are automatically included in every log entry from the child logger.

```typescript
const baseLogger = createLogger({
  service: "scutum-api",
  level: "info",
  transports: [new ConsoleTransport()],
});

const incidentLogger = baseLogger.child({
  incidentId: "inc-001",
  zone: "fuel-storage",
});

// All entries from incidentLogger include incidentId and zone
incidentLogger.info("Recommendation generated", SafeArg("actionCount", 3));
incidentLogger.error("Approval timeout", SafeArg("waitMs", 30000));
```

**Output:**
```json
{
  "level": "info",
  "message": "Recommendation generated",
  "service": "scutum-api",
  "timestamp": "2026-04-01T14:30:00.000Z",
  "context": {
    "incidentId": "inc-001",
    "zone": "fuel-storage"
  },
  "params": {
    "actionCount": 3
  }
}
```

---

## Guards

Guards are middleware that inspect and transform log entries before they reach the formatter. They provide defense-in-depth against accidental data leakage.

| Guard | Description | Default Behavior |
|-------|-------------|-----------------|
| `SensitiveFieldGuard` | Detects sensitive field names and forces them to `unsafe` | Matches 13 patterns: `password`, `secret`, `token`, `api_key`, `credential`, `auth`, `bearer`, `jwt`, `ssn`, `social_security`, `credit_card`, `private_key`, `certificate` |
| `RedactionGuard` | Truncates oversized values to prevent log bloat | Truncates strings longer than 1000 characters |

### SensitiveFieldGuard

The `SensitiveFieldGuard` protects against developers who accidentally mark sensitive fields as `SafeArg`. It inspects field names against a list of known sensitive patterns and forces matching fields to `unsafe`, regardless of how they were classified at the call site.

```typescript
import { SensitiveFieldGuard } from "@scutum/safe-logging";

// Default patterns
const guard = new SensitiveFieldGuard();

// With custom patterns for defense-specific fields
const defenseGuard = new SensitiveFieldGuard([
  /classification/i,
  /clearance/i,
  /coordinates/i,
  /munitions/i,
]);
```

**Example: Guard catches misclassified field**

```typescript
// Developer accidentally marks apiKey as safe
logger.info(
  "Config loaded",
  SafeArg("apiKey", "sk-live-abc123"),  // Guard catches this!
  SafeArg("region", "abudhabi"),
);
```

**Output (the guard forced `apiKey` to unsafe):**
```json
{
  "level": "info",
  "message": "Config loaded",
  "params": {
    "apiKey": "REDACTED",
    "region": "abudhabi"
  }
}
```

### RedactionGuard

The `RedactionGuard` prevents log bloat by truncating oversized string values. This is important in defense contexts where large payloads (e.g., base64-encoded documents, full request bodies) can overwhelm log aggregators.

```typescript
import { RedactionGuard } from "@scutum/safe-logging";

// Default: truncate at 1000 characters
const guard = new RedactionGuard();

// Custom limit
const strictGuard = new RedactionGuard({ maxValueLength: 500 });
```

**Example: Truncated output**

```typescript
logger.info(
  "Document received",
  SafeArg("payload", "x".repeat(5000)),
);
```

**Output:**
```json
{
  "params": {
    "payload": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx... [truncated, 5000 chars]"
  }
}
```

### Writing Custom Guards

Guards implement the `LogGuard` interface:

```typescript
import type { LogEntry, LogGuard } from "@scutum/safe-logging";

class ClassificationGuard implements LogGuard {
  name = "classification";

  check(entry: LogEntry): LogEntry {
    // Example: reject any log entry that contains classified data
    for (const [key, arg] of Object.entries(entry.args)) {
      if (typeof arg.value === "string" && arg.value.includes("TOP SECRET")) {
        return {
          ...entry,
          args: {
            ...entry.args,
            [key]: { value: "[CLASSIFICATION VIOLATION - VALUE STRIPPED]", safe: false },
          },
        };
      }
    }
    return entry;
  }
}
```

---

## Transports

Transports are responsible for writing formatted log entries to their destination.

### ConsoleTransport

The built-in `ConsoleTransport` writes JSON-formatted entries to `console.log`, `console.warn`, or `console.error` based on the log level.

```typescript
import { ConsoleTransport } from "@scutum/safe-logging";

// Default: redact unsafe values
const transport = new ConsoleTransport();

// Disable redaction (for local development only)
const devTransport = new ConsoleTransport({ redactUnsafe: false });
```

| Level | Console Method |
|-------|---------------|
| `trace` | `console.log` |
| `debug` | `console.log` |
| `info` | `console.log` |
| `warn` | `console.warn` |
| `error` | `console.error` |
| `fatal` | `console.error` |

### Writing Custom Transports

Transports implement the `LogTransport` interface:

```typescript
import type { LogEntry, LogTransport } from "@scutum/safe-logging";
import { JsonFormatter } from "@scutum/safe-logging";

class FileTransport implements LogTransport {
  name = "file";
  private formatter = new JsonFormatter();
  private stream: WritableStream;

  constructor(filePath: string) {
    // Open file stream...
  }

  write(entry: LogEntry): void {
    const line = this.formatter.format(entry, true);
    // Write to file...
  }
}
```

---

## Log Levels

Log levels are enforced hierarchically. When you configure a logger with a level, only entries at that level or higher are emitted.

| Level | Priority | Use Case |
|-------|----------|----------|
| `trace` | 0 | Extremely detailed diagnostic output |
| `debug` | 1 | Development-time diagnostic information |
| `info` | 2 | Normal operational events |
| `warn` | 3 | Potentially harmful situations |
| `error` | 4 | Error events that allow continued operation |
| `fatal` | 5 | Severe errors that require immediate attention |

```typescript
// Only warn, error, and fatal will be emitted
const logger = createLogger({
  service: "scutum-api",
  level: "warn",
  transports: [new ConsoleTransport()],
});

logger.debug("This will be silently dropped");
logger.info("This will also be dropped");
logger.warn("This will be emitted");
logger.error("This will be emitted");
logger.fatal("This will be emitted");
```

---

## Safe vs. Unsafe: Output Comparison

The following table shows how the same log call produces different output depending on the redaction setting:

### Log Call

```typescript
logger.warn(
  "Authentication attempt",
  SafeArg("userId", "operator-1"),
  SafeArg("action", "login"),
  UnsafeArg("token", "bearer-abc-123-secret"),
  UnsafeArg("ipAddress", "10.0.1.42"),
);
```

### Production Output (redaction enabled)

```json
{
  "level": "warn",
  "message": "Authentication attempt",
  "timestamp": "2026-04-01T14:30:00.000Z",
  "service": "scutum-api",
  "params": {
    "userId": "operator-1",
    "action": "login",
    "token": "REDACTED",
    "ipAddress": "REDACTED"
  }
}
```

### Development Output (redaction disabled)

```json
{
  "level": "warn",
  "message": "Authentication attempt",
  "timestamp": "2026-04-01T14:30:00.000Z",
  "service": "scutum-api",
  "params": {
    "userId": "operator-1",
    "action": "login",
    "token": "bearer-abc-123-secret",
    "ipAddress": "10.0.1.42"
  }
}
```

---

## API Reference

### createLogger(config: LoggerConfig): SafeLogger

Creates a new `SafeLogger` instance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config.service` | `string` | Yes | Service name included in every log entry |
| `config.level` | `LogLevel` | Yes | Minimum log level to emit |
| `config.transports` | `LogTransport[]` | Yes | Array of transports to write entries to |
| `config.guards` | `LogGuard[]` | No | Array of guards to process entries through |
| `config.context` | `Record<string, unknown>` | No | Default context included in every entry |

### SafeLogger

| Method | Signature | Description |
|--------|-----------|-------------|
| `trace` | `(message: string, ...args: LogArg[]) => void` | Log at trace level |
| `debug` | `(message: string, ...args: LogArg[]) => void` | Log at debug level |
| `info` | `(message: string, ...args: LogArg[]) => void` | Log at info level |
| `warn` | `(message: string, ...args: LogArg[]) => void` | Log at warn level |
| `error` | `(message: string, ...args: LogArg[]) => void` | Log at error level |
| `fatal` | `(message: string, ...args: LogArg[]) => void` | Log at fatal level |
| `child` | `(context: Record<string, unknown>) => SafeLogger` | Create a child logger with additional context |

### SafeArg(key: string, value: unknown): LogArg

Creates a log argument marked as safe for logging. The value will appear in plaintext in all outputs.

### UnsafeArg(key: string, value: unknown): LogArg

Creates a log argument marked as unsafe for logging. The value will be replaced with `REDACTED` in production outputs.

### JsonFormatter

| Method | Signature | Description |
|--------|-----------|-------------|
| `format` | `(entry: LogEntry, redactUnsafe?: boolean) => string` | Serialize a log entry to JSON. When `redactUnsafe` is `true` (default), unsafe values are replaced with `REDACTED`. |

### ConsoleTransport

| Constructor Option | Type | Default | Description |
|-------------------|------|---------|-------------|
| `redactUnsafe` | `boolean` | `true` | Whether to redact unsafe values in output |

### SensitiveFieldGuard

| Constructor Option | Type | Default | Description |
|-------------------|------|---------|-------------|
| `additionalPatterns` | `RegExp[]` | `[]` | Additional regex patterns to match against field names |

**Default sensitive patterns:**
`password`, `secret`, `token`, `api_key`, `credential`, `auth`, `bearer`, `jwt`, `ssn`, `social_security`, `credit_card`, `private_key`, `certificate`

### RedactionGuard

| Constructor Option | Type | Default | Description |
|-------------------|------|---------|-------------|
| `maxValueLength` | `number` | `1000` | Maximum string length before truncation |

### LogEntry

| Field | Type | Description |
|-------|------|-------------|
| `level` | `LogLevel` | The log level of this entry |
| `message` | `string` | The human-readable log message |
| `timestamp` | `string` | ISO 8601 timestamp |
| `service` | `string` | The service name |
| `args` | `Record<string, { value: unknown; safe: boolean }>` | Classified log arguments |
| `context` | `Record<string, unknown>` | Optional context from child loggers |
| `traceId` | `string` | Optional distributed trace ID |
| `spanId` | `string` | Optional span ID |

---

## Usage Patterns

### Per-Request Logging

```typescript
function handleRequest(req: Request) {
  const requestLogger = logger.child({
    requestId: req.id,
    method: req.method,
    path: req.url,
  });

  requestLogger.info("Request received");

  try {
    const result = processRequest(req);
    requestLogger.info("Request completed", SafeArg("statusCode", 200));
  } catch (err) {
    requestLogger.error(
      "Request failed",
      SafeArg("statusCode", 500),
      UnsafeArg("errorDetail", (err as Error).message),
    );
  }
}
```

### Incident Response Logging

```typescript
function handleIncident(incident: Incident) {
  const incidentLogger = logger.child({
    incidentId: incident.id,
    severity: incident.severity,
    zone: incident.zone,
  });

  incidentLogger.info(
    "Incident created",
    SafeArg("type", incident.type),
    SafeArg("assetCount", incident.assets.length),
  );

  for (const recommendation of incident.recommendations) {
    incidentLogger.info(
      "Recommendation generated",
      SafeArg("recommendationId", recommendation.id),
      SafeArg("action", recommendation.action),
      UnsafeArg("detail", recommendation.detail),
    );
  }
}
```

### Multi-Transport Setup

```typescript
const logger = createLogger({
  service: "scutum-gateway",
  level: "info",
  transports: [
    new ConsoleTransport({ redactUnsafe: true }),
    // Add custom transports for file, network, etc.
  ],
  guards: [
    new SensitiveFieldGuard([/classification/i, /clearance/i]),
    new RedactionGuard({ maxValueLength: 500 }),
  ],
});
```

---

<details>
<summary><strong>Security Model</strong></summary>

### Defense-in-Depth

`@scutum/safe-logging` implements a multi-layered security model:

1. **Type-level enforcement**: The `LogArg` type requires explicit classification. You cannot pass raw values to logging methods.

2. **Guard-level enforcement**: Even if a developer incorrectly classifies a value, guards like `SensitiveFieldGuard` catch common mistakes by inspecting field names against known sensitive patterns.

3. **Formatter-level enforcement**: The `JsonFormatter` replaces all unsafe values with `REDACTED` by default. This is the final barrier before data reaches the transport.

4. **Transport-level enforcement**: Each transport can independently control whether to redact unsafe values. Production transports should always redact.

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Developer accidentally logs a secret | `SensitiveFieldGuard` catches common field names |
| Developer intentionally marks a secret as safe | Code review + CODEOWNERS on `/src/guards/` |
| Oversized payload causes log aggregator DoS | `RedactionGuard` truncates large values |
| Log aggregator compromised | Unsafe values never reach logs in production |
| Credential harvesting from log stores | All credentials are `REDACTED` by default |

### Audit Trail

Every log entry includes:
- ISO 8601 timestamp
- Service identifier
- Structured, machine-parseable JSON
- Clear distinction between safe and redacted values
- Optional trace/span IDs for distributed tracing

</details>

---

<details>
<summary><strong>Contributing</strong></summary>

### Development Setup

```bash
git clone https://github.com/ScutumDefense/scutum-safe-logging.git
cd scutum-safe-logging
pnpm install
pnpm test
```

### Running Tests

```bash
# Run all tests
pnpm test

# Watch mode
pnpm test:watch

# Type checking
pnpm typecheck
```

### Code Standards

- All code must be written in TypeScript with strict mode enabled
- All new features must include tests
- All public APIs must include JSDoc comments
- Guard changes require review from `@ScutumDefense/platform-security`
- Follow conventional commits for commit messages

### Pull Request Process

1. Create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure all tests pass: `pnpm test`
4. Ensure type checking passes: `pnpm typecheck`
5. Submit a PR with a clear description
6. Obtain required reviews per CODEOWNERS

</details>

---

<details>
<summary><strong>Roadmap</strong></summary>

### v0.2.0 (Planned)
- [ ] `FileTransport` -- write structured JSON logs to rotated files
- [ ] `OpenTelemetryTransport` -- emit logs as OTLP data
- [ ] `RateLimitGuard` -- prevent log flooding from hot paths
- [ ] `StructuredError` -- rich error logging with stack traces and error codes

### v0.3.0 (Planned)
- [ ] `AuditLogger` -- specialized logger for compliance audit trails
- [ ] `EncryptedTransport` -- encrypt log entries at rest
- [ ] `SIEMTransport` -- direct integration with SIEM platforms (Splunk, Elastic)
- [ ] `ClassificationGuard` -- enforce data classification labels (UNCLASSIFIED, CONFIDENTIAL, SECRET)

### v1.0.0 (Target)
- [ ] Stable API with semantic versioning guarantees
- [ ] Performance benchmarks and optimization
- [ ] Comprehensive documentation site
- [ ] Plugin system for third-party guards and transports
- [ ] Multi-language SDKs (Go, Python, Rust)

</details>

---

<details>
<summary><strong>Inspiration</strong></summary>

This library draws inspiration from:

- **Palantir safe-logging** -- The SafeArg/UnsafeArg pattern for preventing sensitive data in logs
- **Palantir witchcraft-go-logging** -- Structured, safe logging in Go with similar safety guarantees
- **Pino** -- High-performance structured logging for Node.js
- **Winston** -- Multi-transport logging with formatting pipelines

The key difference is that `@scutum/safe-logging` is purpose-built for defense and critical infrastructure contexts, where the consequences of a logging mistake can be severe.

</details>

---

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.

Copyright 2026 Scutum Defense.
