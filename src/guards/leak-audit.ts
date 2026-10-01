import type { LogEntry, LogGuard } from "../core/types";
import { ContextRedactionGuard } from "./context-redaction";
import { RedactionGuard } from "./redaction";

export interface LeakFinding {
  /** Where the finding was detected: message, arg:<key>, context:<path>. */
  location: string;
  /** Which sensitive pattern matched. */
  pattern: "jwt" | "bearer" | "private-key" | "card" | "api-key" | "sensitive-key";
  /** The substring that matched (already truncated). */
  matched: string;
}

export interface LeakAuditResult {
  /** Number of entries scanned. */
  scanned: number;
  findings: LeakFinding[];
  /** True when findings.length === 0. */
  clean: boolean;
}

const VALUE_PATTERNS: Array<{
  pattern: LeakFinding["pattern"];
  regex: RegExp;
}> = [
  {
    pattern: "jwt",
    regex: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  { pattern: "bearer", regex: /Bearer\s+[A-Za-z0-9._-]{16,}/gi },
  { pattern: "private-key", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { pattern: "card", regex: /\b(?:\d[ -]?){13,19}\b/g },
  { pattern: "api-key", regex: /\b(?:sk|pk|api)[-_](?:test_)?[A-Za-z0-9]{16,}\b/gi },
];

const SENSITIVE_KEY = /(password|passwd|secret|token|api[_-]?key|authorization|credential)/i;

function scanValue(
  value: unknown,
  prefix: string,
  findings: LeakFinding[]
): void {
  if (typeof value === "string") {
    for (const { pattern, regex } of VALUE_PATTERNS) {
      regex.lastIndex = 0;
      const m = regex.exec(value);
      if (m) {
        findings.push({
          location: prefix,
          pattern,
          matched: m[0].slice(0, 24),
        });
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => scanValue(v, `${prefix}[${i}]`, findings));
    return;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const path = `${prefix}.${k}`;
      if (SENSITIVE_KEY.test(k) && v !== undefined) {
        findings.push({ location: path, pattern: "sensitive-key", matched: String(k) });
      }
      scanValue(v, path, findings);
    }
  }
}

/**
 * Post-redaction leak auditor: runs after the redaction guards and scans the
 * final entry for anything the guards should have caught. Used both as a
 * belt-and-suspenders guard in production (finding => drop the entry) and as
 * a self-check in tests (finding => fail the test).
 */
export class LeakAuditGuard implements LogGuard {
  name = "leak-audit";
  private scannedCount = 0;
  private cumulativeFindings: LeakFinding[] = [];
  private lastFindings: LeakFinding[] = [];
  private readonly dropOnFinding: boolean;

  constructor(options: { dropOnFinding?: boolean } = {}) {
    this.dropOnFinding = options.dropOnFinding ?? true;
  }

  check(entry: LogEntry): LogEntry {
    const findings: LeakFinding[] = [];
    scanValue(entry.message, "message", findings);
    for (const [key, arg] of Object.entries(entry.args)) {
      if (!arg.safe) {
        scanValue(arg.value, `arg:${key}`, findings);
      }
    }
    scanValue(entry.context, "context", findings);
    this.scannedCount += 1;
    this.lastFindings = findings;
    this.cumulativeFindings.push(...findings);
    if (findings.length > 0 && this.dropOnFinding) {
      return this.redactEntire(entry);
    }
    return entry;
  }

  private redactEntire(entry: LogEntry): LogEntry {
    return {
      ...entry,
      message: "[redacted: potential sensitive data leak]",
      args: {},
      context: undefined,
    };
  }

  /** Findings from the most recent check() call. */
  getLastCheckFindings(): readonly LeakFinding[] {
    return this.lastFindings;
  }

  /** Cumulative audit across all checked entries. */
  getAuditResult(): LeakAuditResult {
    return {
      scanned: this.scannedCount,
      findings: [...this.cumulativeFindings],
      clean: this.cumulativeFindings.length === 0,
    };
  }

  resetAudit(): void {
    this.scannedCount = 0;
    this.cumulativeFindings = [];
    this.lastFindings = [];
  }

  getLastResult(): LeakAuditResult | null {
    return this.scannedCount === 0
      ? null
      : {
          scanned: this.scannedCount,
          findings: [...this.lastFindings],
          clean: this.lastFindings.length === 0,
        };
  }
}

/**
 * Self-check helper for test suites: pass a logger config, log the given
 * entries at every level, and assert no pattern survived the guard pipeline.
 */
export function auditConfigForLeaks(
  entries: Array<{ message: string; args?: Record<string, unknown>; context?: Record<string, unknown> }>,
  makeLogger: (
    guard: LeakAuditGuard
  ) => {
    log: (message: string, args?: Record<string, unknown>, context?: Record<string, unknown>) => void;
  }
): LeakAuditResult {
  const audit = new LeakAuditGuard({ dropOnFinding: true });
  const logger = makeLogger(audit);
  for (const e of entries) {
    logger.log(e.message, e.args, e.context);
  }
  return audit.getAuditResult();
}

export { ContextRedactionGuard, RedactionGuard };
