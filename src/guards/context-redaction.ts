import type { LogEntry, LogGuard } from "../core/types";

const SENSITIVE_KEY_PATTERN =
  /password|secret|token|api[_-]?key|credential|auth|bearer|jwt|ssn|social[_-]?security|credit[_-]?card|private[_-]?key|certificate|session[_-]?id|cookie/i;

const SENSITIVE_VALUE_PATTERNS: RegExp[] = [
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/,
  /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bSK-[A-Za-z0-9]{20,}\b/,
];

const REDACTED = "[REDACTED]";

export class ContextRedactionGuard implements LogGuard {
  name = "context-redaction";
  private deepScanArgs: boolean;

  constructor(options?: { deepScanArgs?: boolean }) {
    this.deepScanArgs = options?.deepScanArgs ?? true;
  }

  check(entry: LogEntry): LogEntry {
    const context =
      entry.context === undefined ? undefined : (this.scrub(entry.context) as Record<string, unknown>);
    const args = this.deepScanArgs ? this.scrubArgs(entry.args) : entry.args;
    return { ...entry, context, args };
  }

  private scrubArgs(args: LogEntry["args"]): LogEntry["args"] {
    const out: LogEntry["args"] = {};
    for (const [key, arg] of Object.entries(args)) {
      if (!arg.safe && typeof arg.value !== "object") {
        out[key] = arg;
        continue;
      }
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        out[key] = { value: REDACTED, safe: false };
        continue;
      }
      if (arg.safe && typeof arg.value === "object" && arg.value !== null) {
        out[key] = { value: this.scrub(arg.value), safe: arg.safe };
        continue;
      }
      out[key] = { value: this.redactValues(arg.value), safe: arg.safe };
    }
    return out;
  }

  private scrub(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map((v) => this.scrub(v));
    }
    if (value !== null && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (SENSITIVE_KEY_PATTERN.test(k)) {
          out[k] = REDACTED;
        } else {
          out[k] = this.scrub(v);
        }
      }
      return out;
    }
    return this.redactValues(value);
  }

  private redactValues(value: unknown): unknown {
    if (typeof value === "string" && SENSITIVE_VALUE_PATTERNS.some((p) => p.test(value))) {
      return REDACTED;
    }
    return value;
  }
}
