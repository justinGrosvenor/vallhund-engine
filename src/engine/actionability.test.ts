import { describe, it, expect } from "vitest";
import type { Detection } from "./schema.ts";
import { actionabilityOf } from "./overview.ts";
import { runAll } from "./detectors.ts";
import { normalizeNative } from "../ingest/shims.ts";

function d(detector: string, evidence: Record<string, unknown>): Detection {
  return { detector, actor: "x", ts: 1, severity: "medium", reason: "", sources: [], coverage: ["app"], evidence };
}

describe("actionability v2 scoring", () => {
  it("web_exploit all-404 low-signal probing is noise", () => {
    expect(actionabilityOf(d("web_exploit_probing", { scanner: false, blocks: 0, sigs: 3, sensitiveHit: false }))).toBe("noise");
  });

  it("heavy probing volume is actionable (one-time; recurrence decays repeats)", () => {
    expect(actionabilityOf(d("web_exploit_probing", { scanner: false, blocks: 0, sigs: 45, sensitiveHit: false }))).toBe("actionable");
  });

  it("a 2xx on a probed sensitive path is actionable (real exposure)", () => {
    expect(actionabilityOf(d("web_exploit_probing", { scanner: false, blocks: 0, sigs: 2, sensitiveHit: true }))).toBe("actionable");
  });

  it("scanner UA and WAF blocks are actionable", () => {
    expect(actionabilityOf(d("web_exploit_probing", { scanner: true, blocks: 0, sigs: 0, sensitiveHit: false }))).toBe("actionable");
    expect(actionabilityOf(d("web_exploit_probing", { scanner: false, blocks: 3, sigs: 0, sensitiveHit: false }))).toBe("actionable");
  });

  it("identity / credential / enumeration / aggregate stay actionable", () => {
    for (const det of ["identity_chain", "credential_stuffing", "enumeration", "fourohfour_rate", "distinct_path_fanout", "new_asn_surge"]) {
      expect(actionabilityOf(d(det, {}))).toBe("actionable");
    }
  });

  it("detector sets sensitiveHit when an exploit path returns 2xx (end-to-end)", () => {
    const cfh = (path: string, status: number) => ({
      datetime: 1000, clientIP: "5.5.5.5", clientAsn: 1, clientCountryName: "US",
      clientRequestPath: path, clientRequestQuery: "", edgeResponseStatus: status, userAgent: "Mozilla/5.0",
    });
    const events = normalizeNative({ cloudflare_http: [cfh("/.env", 200), cfh("/wp-login.php", 404)] });
    const web = runAll(events).filter((x) => x.detector === "web_exploit_probing");
    const first = web[0];
    expect(first).toBeDefined();
    if (first) {
      expect(first.evidence["sensitiveHit"]).toBe(true);
      expect(actionabilityOf(first)).toBe("actionable");
    }
  });
});
