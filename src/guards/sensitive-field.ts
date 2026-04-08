import type { LogEntry, LogGuard } from "../core/types";

const DEFAULT_SENSITIVE_PATTERNS = [
  /password/i, /secret/i, /token/i, /api[_-]?key/i,
  /credential/i, /auth/i, /bearer/i, /jwt/i,
  /ssn/i, /social.security/i, /credit.card/i,
  /private[_-]?key/i, /certificate/i,
];

export class SensitiveFieldGuard implements LogGuard {
  name = "sensitive-field";
  private patterns: RegExp[];

  constructor(additionalPatterns?: RegExp[]) {
    this.patterns = [...DEFAULT_SENSITIVE_PATTERNS, ...(additionalPatterns ?? [])];
  }

  check(entry: LogEntry): LogEntry {
    const sanitizedArgs = { ...entry.args };

    for (const [key, arg] of Object.entries(sanitizedArgs)) {
      if (this.isSensitiveKey(key) && arg.safe) {
        sanitizedArgs[key] = { value: arg.value, safe: false };
      }
    }

    return { ...entry, args: sanitizedArgs };
  }

  private isSensitiveKey(key: string): boolean {
    return this.patterns.some((p) => p.test(key));
  }
}
