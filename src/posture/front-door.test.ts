import { describe, it, expect } from "vitest";
import { analyzeHeaders, analyzeProbe, analyzeCookies } from "./front-door.ts";

const URL = "https://app.example.com/";

describe("analyzeHeaders", () => {
  it("flags every missing security header + disclosure", () => {
    const out = analyzeHeaders(URL, new Headers({ "x-powered-by": "Express", server: "nginx/1.25.3" }));
    const rules = out.map((f) => f.rule);
    expect(out.filter((f) => f.rule === "missing-security-header")).toHaveLength(5);
    expect(rules.filter((r) => r === "version-disclosure")).toHaveLength(2); // X-Powered-By + versioned Server
  });

  it("is clean when all headers are present", () => {
    const out = analyzeHeaders(URL, new Headers({
      "strict-transport-security": "max-age=63072000",
      "content-security-policy": "default-src 'self'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
    }));
    expect(out).toHaveLength(0);
  });

  it("CSP frame-ancestors satisfies clickjacking protection (no x-frame-options finding)", () => {
    const out = analyzeHeaders(URL, new Headers({ "content-security-policy": "frame-ancestors 'none'" }));
    expect(out.some((f) => f.fix.includes("X-Frame-Options"))).toBe(false);
  });

  it("does not flag a version-less Server header", () => {
    const out = analyzeHeaders(URL, new Headers({ server: "cloudflare" }));
    expect(out.some((f) => f.rule === "version-disclosure")).toBe(false);
  });
});

const ENV_PROBE = { path: "/.env", label: ".env file", looksExposed: (b: string) => /^[A-Z][A-Z0-9_]*=/m.test(b) && !/<html/i.test(b) };

describe("analyzeProbe", () => {
  it("flags a 200 that matches the file signature", () => {
    const f = analyzeProbe("app.example.com", ENV_PROBE, 200, "DATABASE_URL=postgres://x\nSECRET=abc\n");
    expect(f?.rule).toBe("exposed-file");
    expect(f?.severity).toBe("high");
  });
  it("ignores an SPA catch-all 200 that returns HTML", () => {
    expect(analyzeProbe("app.example.com", ENV_PROBE, 200, "<!DOCTYPE html><html>...</html>")).toBeNull();
  });
  it("ignores non-200", () => {
    expect(analyzeProbe("app.example.com", ENV_PROBE, 404, "")).toBeNull();
  });
});

describe("analyzeCookies", () => {
  it("flags a cookie missing all three flags (medium — Secure missing)", () => {
    const out = analyzeCookies("app.example.com", ["sid=abc; Path=/"]);
    expect(out).toHaveLength(1);
    expect(out[0]?.severity).toBe("medium");
    expect(out[0]?.detail).toContain("Secure");
    expect(out[0]?.detail).toContain("HttpOnly");
    expect(out[0]?.detail).toContain("SameSite");
  });

  it("is low when only HttpOnly/SameSite are missing but Secure is set", () => {
    const out = analyzeCookies("app.example.com", ["sid=abc; Secure"]);
    expect(out[0]?.severity).toBe("low");
    expect(out[0]?.detail).not.toContain("Secure,");
  });

  it("is clean for a fully-hardened cookie", () => {
    expect(analyzeCookies("app.example.com", ["sid=abc; Secure; HttpOnly; SameSite=Lax"])).toHaveLength(0);
  });

  it("returns nothing when no cookies are set", () => {
    expect(analyzeCookies("app.example.com", [])).toHaveLength(0);
  });
});
