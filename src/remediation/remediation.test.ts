import { describe, it, expect } from "vitest";
import { baseFindingView } from "../engine/overview.ts";
import type { Detection } from "../engine/schema.ts";
import { buildRemediation, redactSecrets } from "./remediation.ts";

const ctx = { project: "p", connectedSources: ["Cloudflare: edge/request telemetry", "Zitadel: identity events"] };

function actionable(detector: string, evidence: Record<string, unknown> = {}): ReturnType<typeof baseFindingView> {
  const d: Detection = {
    detector, actor: "203.0.113.9", ts: 1, severity: "high",
    reason: "test reason", sources: ["cloudflare"], coverage: ["app"], evidence,
  };
  const v = baseFindingView(d);
  v.actionability = "actionable";
  return v;
}

describe("remediation prompt generator", () => {
  it("redacts secret-shaped values (hard gate — prompt is pasted into external agents)", () => {
    const dirty = "token sk_live_ABCDEF123456 key AKIAABCDEFGHIJKLMNOP db postgres://u:p4ss@h/db";
    const clean = redactSecrets(dirty);
    expect(clean).not.toContain("sk_live_ABCDEF123456");
    expect(clean).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(clean).not.toContain(":p4ss@");
    expect(clean).toContain("[redacted]");
  });

  it("never leaks a planted secret from evidence into any mode", () => {
    const r = buildRemediation(actionable("web_exploit_probing", { leak: "sk_live_DEADBEEF00112233" }), ctx);
    for (const text of [r.explain, r.investigate, r.patch]) {
      expect(text).not.toContain("sk_live_DEADBEEF00112233");
    }
  });

  it("generates all three modes for multiple detector families", () => {
    for (const det of ["identity_chain", "credential_stuffing", "distinct_path_fanout"]) {
      const r = buildRemediation(actionable(det), ctx);
      expect(r.available).toBe(true);
      expect(r.explain.length).toBeGreaterThan(0);
      expect(r.investigate).toContain("investigate only");
      expect(r.patch).toContain("If — and only if — you confirm");
    }
  });

  it("every prompt states the coverage boundary and what can't be proven", () => {
    const r = buildRemediation(actionable("identity_chain"), ctx);
    expect(r.investigate).toContain("cannot see host/kernel");
    expect(r.investigate).toContain("Connected services:");
  });

  it("is unavailable for non-actionable findings (no prompts on noise)", () => {
    const v = baseFindingView({
      detector: "web_exploit_probing", actor: "1.2.3.4", ts: 1, severity: "medium",
      reason: "noise", sources: ["cloudflare"], coverage: ["app"], evidence: { scanner: false, blocks: 0 },
    });
    // web_exploit_probing with no scanner / blocks<3 => actionabilityOf = "noise"
    expect(v.actionability).toBe("noise");
    expect(buildRemediation(v, ctx).available).toBe(false);
  });
});
