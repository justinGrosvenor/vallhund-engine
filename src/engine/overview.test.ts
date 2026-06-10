import { describe, it, expect } from "vitest";
import { normalizeNative } from "../ingest/shims.ts";
import { mergeNative } from "../ingest/native.ts";
import { benignNative, aggregateFixture, attacks } from "./fixtures.ts";
import { buildBaseline, runEngine } from "./aggregate.ts";
import { baseFindingView, buildOverview, deriveMetrics } from "./overview.ts";

describe("overview data layer", () => {
  const benign = normalizeNative(benignNative());
  // benign + distributed recon (G) + a real scanner (B) so all verdict paths show
  const events = normalizeNative(mergeNative(benignNative(), aggregateFixture().native, attacks().B.native));
  const findings = runEngine(events, buildBaseline(benign)).map(baseFindingView);
  const data = buildOverview(deriveMetrics(events), findings, false);

  it("escalates headline to ACTION on an actionable foe (the sqlmap scanner)", () => {
    expect(data.headline).toBe("action");
    expect(data.counts.foe).toBeGreaterThanOrEqual(1);
  });

  it("surfaces actionable detections and counts noise separately", () => {
    expect(data.needsAttention.length).toBeGreaterThan(0);
    expect(data.counts.actionable).toBeGreaterThan(0);
  });

  it("always declares the coverage boundary (never host/kernel)", () => {
    expect(data.coverageNotCovered).toEqual(["host", "kernel"]);
    expect(data.coverageActive).toContain("app");
  });

  it("reports a populated traffic snapshot", () => {
    expect(data.metrics.requests).toBeGreaterThan(0);
    expect(data.metrics.fourOhFourPct).toBeGreaterThan(0);
    expect(data.statusMix.length).toBeGreaterThan(0);
  });
});
