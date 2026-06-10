// Golden-oracle CI test. Run with `npm test` (vitest).
// The TS engine MUST reproduce the Python spike's behavior on the fixtures —
// any divergence fails here (design 3.0 §8, 4.0 §10).
import { describe, it, expect } from "vitest";
import { runOracle } from "./oracle.ts";

describe("golden oracle: TS engine == Python spike", () => {
  const r = runOracle();

  it("catches all attacks A–D (recall = 100%)", () => {
    expect(r.recall).toBe(1);
  });

  it("zero false positives on the benign baseline (incl. E1–E4 controls)", () => {
    expect(r.benignDetections.length).toBe(0);
    expect(r.fpPerWeek).toBeLessThan(1);
  });

  it("cross-source lift on C (only correlated sources catch it)", () => {
    expect(r.lift.cFull).toBe(true);
    expect(r.lift.cNoVc).toBe(false);
    expect(r.lift.cNoSb).toBe(false);
  });

  it("ceiling: F (in-host) is correctly invisible", () => {
    expect(r.ceilingOk).toBe(true);
  });

  it("aggregate edge: catches distributed recon (G) that per-entity rules miss", () => {
    expect(r.aggregateEdgeOk).toBe(true);
  });

  it("overall verdict passes", () => {
    expect(r.pass).toBe(true);
  });
});
