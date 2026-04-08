import type { LogEntry, LogTransport } from "../core/types";
import { JsonFormatter } from "../formatters/json";

export class ConsoleTransport implements LogTransport {
  name = "console";
  private formatter = new JsonFormatter();
  private redactUnsafe: boolean;

  constructor(options?: { redactUnsafe?: boolean }) {
    this.redactUnsafe = options?.redactUnsafe ?? true;
  }

  write(entry: LogEntry): void {
    const line = this.formatter.format(entry, this.redactUnsafe);
    switch (entry.level) {
      case "error":
      case "fatal":
        console.error(line);
        break;
      case "warn":
        console.warn(line);
        break;
      default:
        console.log(line);
    }
  }
}
