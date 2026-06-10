// Golden oracle — the regression harness. Proves the TS engine reproduces the
// Python spike's behavior on the fixtures (recall A-D, 0 FP on benign, cross-source
// lift on C, F correctly invisible). Ported from spike/eval.py.
// runOracle() is pure (returns results + a report string); printing lives in
// run-oracle.ts so this can be called from a route loader or a test.

import type { Detection, NormalizedEvent } from "./schema.ts";
import { normalizeNative } from "../ingest/shims.ts";
import { mergeNative } from "../ingest/native.ts";
import { aggregateFixture, attacks, benignNative, type Truth } from "./fixtures.ts";
import { runAll } from "./detectors.ts";
import { buildBaseline, runAggregate } from "./aggregate.ts";

const BAR_RECALL = 0.8;
const BAR_FP_PER_WEEK = 1.0;
const MATCH_BUFFER = 1800;

function spanDays(events: NormalizedEvent[]): number {
  if (!events.length) return 1;
  const ts = events.map((e) => e.ts);
  return Math.max(1e-9, (Math.max(...ts) - Math.min(...ts)) / 86400);
}

function matches(d: Detection, truth: Truth): boolean {
  return d.actor === truth.actor &&
    truth.start - MATCH_BUFFER <= d.ts &&
    d.ts <= truth.end + MATCH_BUFFER;
}

export interface OracleResult {
  recall: number;
  fpPerWeek: number;
  liftOk: boolean;
  ceilingOk: boolean;
  aggregateEdgeOk: boolean;
  pass: boolean;
  benignDetections: Detection[];
  recallRows: { key: string; truth: Truth; hit: Detection | null }[];
  lift: { cFull: boolean; cNoVc: boolean; cNoSb: boolean };
  report: string;
}

export function runOracle(): OracleResult {
  const benign = normalizeNative(benignNative());
  const atk = attacks();

  // PRECISION — any detection on pure benign is a false positive
  const benignDetections = runAll(benign);
  const span = spanDays(benign);
  const fpPerWeek = (benignDetections.length / span) * 7;

  // RECALL — each attack injected into the benign baseline
  const recallRows: OracleResult["recallRows"] = [];
  let caught = 0;
  for (const key of ["A", "B", "C", "D"] as const) {
    const { native, truth } = atk[key];
    const events = normalizeNative(mergeNative(benignNative(), native));
    const ds = runAll(events);
    const hit = ds.find((d) => matches(d, truth)) ?? null;
    if (hit !== null) caught++;
    recallRows.push({ key, truth, hit });
  }
  const recall = caught / 4;

  // CROSS-SOURCE LIFT (scenario C)
  const cN = atk.C.native;
  const cT = atk.C.truth;
  const full = normalizeNative(mergeNative(benignNative(), cN));
  const noVc = full.filter((e) => e.source !== "vercel");
  const noSb = full.filter((e) => e.source !== "supabase");
  const cFull = runAll(full).some((d) => matches(d, cT));
  const cNoVc = runAll(noVc).some((d) => matches(d, cT));
  const cNoSb = runAll(noSb).some((d) => matches(d, cT));
  const liftOk = cFull && !cNoVc && !cNoSb;

  // CEILING (scenario F, in-host, unobservable)
  const fEvents = normalizeNative(mergeNative(benignNative(), atk.F.native));
  const fHit = runAll(fEvents).some((d) => matches(d, atk.F.truth));
  const ceilingOk = !fHit;

  // AGGREGATE EDGE — distributed recon that per-Entity rules miss (4.0 §4b)
  const baseline = buildBaseline(benign);
  const g = aggregateFixture();
  const gEvents = normalizeNative(g.native);
  const gPerEntityCaught = runAll(gEvents).some((d) => matches(d, g.truth));
  const gAggregateCaught = runAggregate(gEvents, baseline).some((d) => matches(d, g.truth));
  const aggregateQuietOnBenign = runAggregate(benign, baseline).length === 0;
  const aggregateEdgeOk = !gPerEntityCaught && gAggregateCaught && aggregateQuietOnBenign;

  const recallOk = recall >= BAR_RECALL;
  const fpOk = fpPerWeek < BAR_FP_PER_WEEK;
  const pass = recallOk && fpOk && liftOk && ceilingOk && aggregateEdgeOk;

  const L = "=".repeat(64);
  const lines: string[] = [];
  lines.push(L);
  lines.push("GOLDEN ORACLE — TS engine vs Python spike (fixtures)");
  lines.push(L);
  lines.push(`\nRECALL (target >= ${BAR_RECALL * 100}%)`);
  for (const { key, truth, hit } of recallRows) {
    const via = hit ? hit.sources.join(",") : "-";
    lines.push(`  [${hit ? "CAUGHT" : "MISSED"}] ${key}  ${truth.note}  via ${via}`);
  }
  lines.push(`  => recall = ${Math.round(recall * 100)}%`);
  lines.push(`\nPRECISION (target < ${BAR_FP_PER_WEEK}/week)`);
  lines.push(`  benign false positives: ${benignDetections.length}  => ${fpPerWeek.toFixed(2)}/week`);
  lines.push(`\nCROSS-SOURCE LIFT (C): full=${cFull} dropVercel=${cNoVc} dropSupabase=${cNoSb} => ${liftOk ? "YES" : "NO"}`);
  lines.push(`CEILING (F in-host): detected=${fHit} => ${ceilingOk ? "correctly invisible" : "UNEXPECTED"}`);
  lines.push(`\nAGGREGATE EDGE (G distributed recon):`);
  lines.push(`  per-entity catches G : ${gPerEntityCaught}  (want false)`);
  lines.push(`  aggregate catches G  : ${gAggregateCaught}  (want true)`);
  lines.push(`  aggregate quiet on benign: ${aggregateQuietOnBenign}  (want true)`);
  lines.push(`  => ${aggregateEdgeOk ? "EDGE CONFIRMED" : "FAIL"}`);
  lines.push(`\n${L}`);
  lines.push(`VERDICT: ${pass ? "PASS — TS port matches the spike" : "FAIL — divergence from spike"}`);
  lines.push(L);

  return {
    recall, fpPerWeek, liftOk, ceilingOk, aggregateEdgeOk, pass,
    benignDetections, recallRows,
    lift: { cFull, cNoVc, cNoSb },
    report: lines.join("\n"),
  };
}
