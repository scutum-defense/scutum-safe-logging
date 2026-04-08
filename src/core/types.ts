export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  service: string;
  args: Record<string, { value: unknown; safe: boolean }>;
  context?: Record<string, unknown>;
  traceId?: string;
  spanId?: string;
}

export interface LoggerConfig {
  service: string;
  level: LogLevel;
  transports: LogTransport[];
  guards?: LogGuard[];
  context?: Record<string, unknown>;
}

export interface LogTransport {
  name: string;
  write(entry: LogEntry): void;
}

export interface LogGuard {
  name: string;
  check(entry: LogEntry): LogEntry;
}

const LOG_LEVELS: Record<LogLevel, number> = {
  trace: 0, debug: 1, info: 2, warn: 3, error: 4, fatal: 5,
};

export function shouldLog(configured: LogLevel, actual: LogLevel): boolean {
  return LOG_LEVELS[actual] >= LOG_LEVELS[configured];
}
