import { describe, it, expect } from "vitest";
import { baseFindingView } from "./overview.ts";
import type { CoverageLayer, Detection } from "./schema.ts";
import { buildIncidents } from "./incidents.ts";

function fv(detector: string, actor: string, severity: Detection["severity"], coverage: CoverageLayer[]) {
  const v = baseFindingView({ detector, actor, ts: 1, severity, reason: "r", sources: [], coverage, evidence: {} });
  v.actionability = "actionable";
  return v;
}

describe("incident grouping", () => {
  it("collapses multiple detectors on one actor into a single incident with N signals", () => {
    const incidents = buildIncidents([
      fv("web_exploit_probing", "1.2.3.4", "medium", ["app"]),
      fv("enumeration", "1.2.3.4", "high", ["app"]),
      fv("credential_stuffing", "9.9.9.9", "high", ["identity"]),
    ]);
    expect(incidents.length).toBe(2);
    const one = incidents.find((i) => i.actor === "1.2.3.4");
    expect(one?.signals.length).toBe(2);
    expect(one?.severity).toBe("high"); // worst across signals
  });

  it("unions coverage and picks the worst classification", () => {
    const a = fv("identity_chain", "u", "high", ["identity"]);
    a.classification = "foe";
    const b = fv("enumeration", "u", "medium", ["app"]);
    b.classification = "unknown";
    const inc = buildIncidents([a, b])[0];
    expect(inc?.classification).toBe("foe");
    expect([...(inc?.coverage ?? [])].sort()).toEqual(["app", "identity"]);
  });

  it("an incident is recurring only if all its signals are recurring", () => {
    const a = fv("web_exploit_probing", "x", "medium", ["app"]);
    a.recurring = true; a.isNew = false;
    const b = fv("enumeration", "x", "medium", ["app"]);
    b.recurring = false; // still active
    const inc = buildIncidents([a, b])[0];
    expect(inc?.recurring).toBe(false);
  });
});
