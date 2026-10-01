import type { LogEntry, LogGuard } from "../core/types";

/** Entity kind recognized in free text. */
export type PiiEntityKind =
  | "email"
  | "phone"
  | "card"
  | "ssn"
  | "iban"
  | "ip"
  | "ipv6";

export interface PiiEntity {
  kind: PiiEntityKind;
  /** Character offsets in the source string. */
  start: number;
  end: number;
  /** The matched substring. */
  text: string;
  /** Redacted replacement the guard would apply. */
  replacement: string;
}

export interface PiiExtractionResult {
  entities: PiiEntity[];
  /** Text with every entity replaced by its redaction token. */
  redacted: string;
}

const REDACTIONS: Record<PiiEntityKind, string> = {
  email: "[REDACTED_EMAIL]",
  phone: "[REDACTED_PHONE]",
  card: "[REDACTED_CARD]",
  ssn: "[REDACTED_SSN]",
  iban: "[REDACTED_IBAN]",
  ip: "[REDACTED_IP]",
  ipv6: "[REDACTED_IP]",
};

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

interface PatternSpec {
  kind: PiiEntityKind;
  regex: RegExp;
  /** Optional structural validator on the captured digits/text. */
  validate?: (captured: string) => boolean;
  /** Which capture group carries the payload (default 0). */
  group?: number;
}

const PATTERNS: PatternSpec[] = [
  { kind: "email", regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  {
    kind: "card",
    regex: /(?:\d[ -]?){12,17}\d/g,
    validate: (raw) => luhnValid(raw.replace(/[^0-9]/g, "")),
  },
  { kind: "ssn", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  {
    kind: "iban",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,26}\b/g,
    validate: (raw) => /^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(raw) && raw.length >= 15,
  },
  { kind: "phone", regex: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?\b/g, validate: (raw) => (raw.replace(/[^0-9]/g, "").length >= 7) },
  { kind: "ipv6", regex: /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/g },
  { kind: "ip", regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, validate: (raw) => raw.split(".").every((o) => Number(o) <= 255) },
];

/**
 * Extract and redact PII entities from arbitrary text. Overlapping matches
 * are resolved by earliest start, then longest span (card > phone > ip).
 */
export function extractPii(text: string): PiiExtractionResult {
  const candidates: PiiEntity[] = [];
  for (const spec of PATTERNS) {
    spec.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = spec.regex.exec(text)) !== null) {
      const captured = m[spec.group ?? 0];
      if (spec.validate && !spec.validate(captured)) continue;
      candidates.push({
        kind: spec.kind,
        start: m.index,
        end: m.index + captured.length,
        text: captured,
        replacement: REDACTIONS[spec.kind],
      });
    }
  }
  candidates.sort(
    (a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start),
  );
  const entities: PiiEntity[] = [];
  let cursor = 0;
  for (const c of candidates) {
    if (c.start < cursor) continue;
    entities.push(c);
    cursor = c.end;
  }
  let redacted = "";
  let pos = 0;
  for (const e of entities) {
    redacted += text.slice(pos, e.start) + e.replacement;
    pos = e.end;
  }
  redacted += text.slice(pos);
  return { entities, redacted };
}

/**
 * Log guard that redacts PII entities from the entry message and from
 * string-valued args. Args flagged `safe` by the caller are left untouched.
 */
export class PiiEntityGuard implements LogGuard {
  name = "pii-entities";

  check(entry: LogEntry): LogEntry {
    const message = extractPii(entry.message);
    const args = { ...entry.args };
    for (const [key, arg] of Object.entries(args)) {
      if (typeof arg.value === "string" && !arg.safe) {
        const res = extractPii(arg.value);
        if (res.entities.length > 0) {
          args[key] = { ...arg, value: res.redacted };
        }
      }
    }
    return { ...entry, message: message.redacted, args };
  }
}
