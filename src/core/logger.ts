import type { LogLevel, LogEntry, LoggerConfig, LogGuard } from "./types";
import { shouldLog } from "./types";
import type { LogArg } from "./safe-arg";

export class SafeLogger {
  private config: LoggerConfig;
  private guards: LogGuard[];

  constructor(config: LoggerConfig) {
    this.config = config;
    this.guards = config.guards ?? [];
  }

  trace(message: string, ...args: LogArg[]): void { this.log("trace", message, args); }
  debug(message: string, ...args: LogArg[]): void { this.log("debug", message, args); }
  info(message: string, ...args: LogArg[]): void { this.log("info", message, args); }
  warn(message: string, ...args: LogArg[]): void { this.log("warn", message, args); }
  error(message: string, ...args: LogArg[]): void { this.log("error", message, args); }
  fatal(message: string, ...args: LogArg[]): void { this.log("fatal", message, args); }

  child(context: Record<string, unknown>): SafeLogger {
    return new SafeLogger({
      ...this.config,
      context: { ...this.config.context, ...context },
    });
  }

  private log(level: LogLevel, message: string, args: LogArg[]): void {
    if (!shouldLog(this.config.level, level)) return;

    let entry: LogEntry = {
      level,
      message,
      timestamp: new Date().toISOString(),
      service: this.config.service,
      args: Object.fromEntries(args.map((a) => [a.key, { value: a.value, safe: a.safe }])),
      context: this.config.context,
    };

    for (const guard of this.guards) {
      entry = guard.check(entry);
    }

    for (const transport of this.config.transports) {
      transport.write(entry);
    }
  }
}

export function createLogger(config: LoggerConfig): SafeLogger {
  return new SafeLogger(config);
}
