import type { LogEntry, LogGuard } from "../core/types";

export class RedactionGuard implements LogGuard {
  name = "redaction";
  private maxValueLength: number;

  constructor(options?: { maxValueLength?: number }) {
    this.maxValueLength = options?.maxValueLength ?? 1000;
  }

  check(entry: LogEntry): LogEntry {
    const sanitizedArgs = { ...entry.args };

    for (const [key, arg] of Object.entries(sanitizedArgs)) {
      if (typeof arg.value === "string" && arg.value.length > this.maxValueLength) {
        sanitizedArgs[key] = {
          value: `${(arg.value as string).substring(0, 50)}... [truncated, ${(arg.value as string).length} chars]`,
          safe: arg.safe,
        };
      }
    }

    return { ...entry, args: sanitizedArgs };
  }
}
