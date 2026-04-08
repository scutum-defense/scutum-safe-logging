export interface LogArg {
  key: string;
  value: unknown;
  safe: boolean;
}

/**
 * Mark a value as safe for logging.
 * Safe values will appear in plaintext in all log outputs.
 */
export function SafeArg(key: string, value: unknown): LogArg {
  return { key, value, safe: true };
}

/**
 * Mark a value as unsafe for logging.
 * Unsafe values will be redacted in production logs
 * and only shown in debug-level output when explicitly enabled.
 */
export function UnsafeArg(key: string, value: unknown): LogArg {
  return { key, value, safe: false };
}
