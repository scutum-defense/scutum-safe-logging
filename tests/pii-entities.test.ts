import { describe, expect, it } from "vitest";
import { extractPii, PiiEntityGuard } from "../src/guards/pii-entities";

describe("extractPii", () => {
  it("extracts emails", () => {
    const res = extractPii("contact ops.john.doe@example-corp.com now");
    expect(res.entities).toHaveLength(1);
    expect(res.entities[0].kind).toBe("email");
    expect(res.redacted).toBe("contact [REDACTED_EMAIL] now");
  });

  it("extracts Luhn-valid cards and ignores Luhn-invalid digit runs", () => {
    const valid = extractPii("card 4111 1111 1111 1111 on file");
    expect(valid.entities[0].kind).toBe("card");
    expect(valid.redacted).toBe("card [REDACTED_CARD] on file");
    const invalid = extractPii("ref 1234567812345678 end");
    expect(invalid.entities.map((e) => e.kind)).not.toContain("card");
  });

  it("extracts SSNs", () => {
    const res = extractPii("ssn 123-45-6789 logged");
    expect(res.entities[0].kind).toBe("ssn");
    expect(res.redacted).toContain("[REDACTED_SSN]");
  });

  it("extracts phone numbers with country code", () => {
    const res = extractPii("call +1 (415) 555-2671 today");
    expect(res.entities.some((e) => e.kind === "phone")).toBe(true);
    expect(res.redacted).not.toContain("555-2671");
  });

  it("extracts IPv4 but rejects octets > 255", () => {
    const ok = extractPii("host 10.0.42.7 down");
    expect(ok.entities[0].kind).toBe("ip");
    const bad = extractPii("version 999.999.999.999");
    expect(bad.entities.map((e) => e.kind)).not.toContain("ip");
  });

  it("extracts multiple entities in one string with correct offsets", () => {
    const res = extractPii("user a@b.com from 192.168.1.1");
    expect(res.entities).toHaveLength(2);
    for (const e of res.entities) {
      expect(text(e)).toBe(
        ["a@b.com", "192.168.1.1"][res.entities.indexOf(e)],
      );
    }
    function text(e: { text: string }): string {
      return e.text;
    }
    expect(res.redacted).toBe("user [REDACTED_EMAIL] from [REDACTED_IP]");
  });

  it("keeps offsets usable for locating matches", () => {
    const src = "email x@y.io";
    const res = extractPii(src);
    expect(src.slice(res.entities[0].start, res.entities[0].end)).toBe("x@y.io");
  });
});

describe("PiiEntityGuard", () => {
  const base = {
    level: "info" as const,
    timestamp: new Date().toISOString(),
    service: "test",
  };

  it("redacts PII from message", () => {
    const out = new PiiEntityGuard().check({
      ...base,
      message: "login for user@corp.io",
      args: {},
    });
    expect(out.message).toBe("login for [REDACTED_EMAIL]");
  });

  it("redacts PII from unsafe string args but preserves safe args", () => {
    const out = new PiiEntityGuard().check({
      ...base,
      message: "ok",
      args: {
        note: { value: "phone 555-867-5309", safe: false },
        cidr: { value: "10.0.0.0/8", safe: true },
      },
    });
    expect(out.args.note.value).toBe("phone [REDACTED_PHONE]");
    expect(out.args.cidr.value).toBe("10.0.0.0/8");
  });

  it("leaves clean entries untouched", () => {
    const entry = { ...base, message: "all good", args: {} };
    expect(new PiiEntityGuard().check(entry)).toEqual(entry);
  });
});
