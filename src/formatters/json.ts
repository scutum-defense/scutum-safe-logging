import type { LogEntry } from "../core/types";

export class JsonFormatter {
  format(entry: LogEntry, redactUnsafe: boolean = true): string {
    const output: Record<string, unknown> = {
      level: entry.level,
      message: entry.message,
      timestamp: entry.timestamp,
      service: entry.service,
    };

    if (entry.traceId) output.traceId = entry.traceId;
    if (entry.spanId) output.spanId = entry.spanId;
    if (entry.context) output.context = entry.context;

    const args: Record<string, unknown> = {};
    for (const [key, arg] of Object.entries(entry.args)) {
      if (arg.safe || !redactUnsafe) {
        args[key] = arg.value;
      } else {
        args[key] = "REDACTED";
      }
    }

    if (Object.keys(args).length > 0) {
      output.params = args;
    }

    return JSON.stringify(output);
  }
}
