// Aggregate (population-wide) detectors — the differentiating edge (design 4.0 §4b),
// now evaluated against a LEARNED, PERSISTED per-Project Baseline (4.0 §5) instead of
// the current window. EWMA mean+variance, a warming gate (no "change from normal"
// before a normal exists — domain invariant #5), and absolute-vs-relative thresholds.
//
// Two detector kinds:
//   - structural/absolute (distinct_path_fanout): no baseline needed, always on.
//   - baseline-relative (fourohfour_rate, new_asn_surge): muted while warming.

import { A, type Detection, type NormalizedEvent } from "./schema.ts";
import { runAll } from "./detectors.ts";

export interface EwmaStat {
  mean: number;
  var: number;
}

export interface BaselineProfile {
  projectId: string;
  windows: number; // # windows learned (warming gate)
  fourOhFourRate: EwmaStat;
  distinctRoutes: EwmaStat;
  knownAsns: number[];
  updatedAt: number | null;
}

export interface WindowSignals {
  fourOhFourRate: number;
  distinctRoutes: number;
  asns: number[];
  ips: number;
  httpVolume: number;
}

// ---- tunables (config in production) ----
const ALPHA = 0.3; // EWMA weight on the newest window
const MIN_WINDOWS = 3; // warming gate for baseline-relative detectors
const K = 4; // robust std multiplier
const MIN_FLOOR_404 = 0.05; // absolute noise gate so ~0 baselines don't fire on dribbles
const MIN_MARGIN_404 = 0.1; // must exceed learned normal by this much (a chronic rate is normal)
const MIN_VOL_404 = 20; // need enough requests to judge a rate
const FANOUT_ROUTES = 40; // distinct routes in window
const FANOUT_MIN_IPS = 10; // ...spread across many IPs (distributed, not one scanner)
const NEW_ASN_MIN_EVENTS = 50; // events from previously-unseen ASNs

export const AGGREGATE_DETECTOR_NAMES = [
  "fourohfour_rate",
  "distinct_path_fanout",
  "new_asn_surge",
];

function httpEvents(events: NormalizedEvent[]): NormalizedEvent[] {
  // exclude verified friend bots — they are not recon
  return events.filter((e) => e.action === A.HTTP && !e.verifiedBot);
}

function windowStart(events: NormalizedEvent[]): number {
  let m = Infinity;
  for (const e of events) if (e.ts < m) m = e.ts;
  return m === Infinity ? 0 : m;
}

export function isWarming(p: BaselineProfile): boolean {
  return p.windows < MIN_WINDOWS;
}

export function freshProfile(projectId: string): BaselineProfile {
  return {
    projectId,
    windows: 0,
    fourOhFourRate: { mean: 0, var: 0 },
    distinctRoutes: { mean: 0, var: 0 },
    knownAsns: [],
    updatedAt: null,
  };
}

export function observeWindow(events: NormalizedEvent[]): WindowSignals {
  const http = httpEvents(events);
  const total = http.length || 1;
  const n404 = http.filter((e) => e.status === 404).length;
  const asns = new Set<number>();
  for (const e of events) if (e.asn != null) asns.add(e.asn);
  return {
    fourOhFourRate: n404 / total,
    distinctRoutes: new Set(http.map((e) => e.resource)).size,
    asns: [...asns],
    ips: new Set(http.map((e) => e.ip)).size,
    httpVolume: http.length,
  };
}

function ewmaUpdate(stat: EwmaStat, x: number, first: boolean): EwmaStat {
  if (first) return { mean: x, var: 0 };
  const mean = ALPHA * x + (1 - ALPHA) * stat.mean;
  const variance = (1 - ALPHA) * (stat.var + ALPHA * (x - stat.mean) ** 2);
  return { mean, var: variance };
}

export function updateProfile(profile: BaselineProfile, s: WindowSignals): BaselineProfile {
  const first = profile.windows === 0;
  return {
    projectId: profile.projectId,
    windows: profile.windows + 1,
    fourOhFourRate: ewmaUpdate(profile.fourOhFourRate, s.fourOhFourRate, first),
    distinctRoutes: ewmaUpdate(profile.distinctRoutes, s.distinctRoutes, first),
    knownAsns: [...new Set([...profile.knownAsns, ...s.asns])],
    updatedAt: profile.updatedAt,
  };
}

/** A profile trained on a single window (used by the oracle as "established normal"). */
export function buildBaseline(events: NormalizedEvent[], projectId = "oracle"): BaselineProfile {
  const s = observeWindow(events);
  return {
    projectId,
    windows: MIN_WINDOWS, // treat as already-established
    fourOhFourRate: { mean: s.fourOhFourRate, var: 0 },
    distinctRoutes: { mean: s.distinctRoutes, var: 0 },
    knownAsns: s.asns,
    updatedAt: null,
  };
}

export function fourOhFourRate(events: NormalizedEvent[], profile: BaselineProfile, out: Detection[]): void {
  const http = httpEvents(events);
  if (http.length < MIN_VOL_404) return;
  const n404 = http.filter((e) => e.status === 404).length;
  const rate = n404 / http.length;
  const std = Math.sqrt(profile.fourOhFourRate.var);
  const deviation = Math.max(K * std, MIN_MARGIN_404); // need a real jump above normal
  const threshold = Math.max(MIN_FLOOR_404, profile.fourOhFourRate.mean + deviation);
  if (rate >= threshold) {
    out.push({
      detector: "fourohfour_rate",
      actor: "project",
      ts: windowStart(http),
      severity: "medium",
      reason: `404-rate ${(rate * 100).toFixed(0)}% over ${http.length} reqs vs learned ` +
        `baseline ${(profile.fourOhFourRate.mean * 100).toFixed(0)}% — distributed recon`,
      sources: ["cloudflare"],
      coverage: ["app"],
      evidence: { rate, n404, total: http.length, baseline: profile.fourOhFourRate.mean },
    });
  }
}

export function distinctPathFanout(events: NormalizedEvent[], _profile: BaselineProfile, out: Detection[]): void {
  const http = httpEvents(events);
  const routes = new Set(http.map((e) => e.resource));
  const ips = new Set(http.map((e) => e.ip));
  if (routes.size >= FANOUT_ROUTES && ips.size >= FANOUT_MIN_IPS) {
    out.push({
      detector: "distinct_path_fanout",
      actor: "project",
      ts: windowStart(http),
      severity: "medium",
      reason: `${routes.size} distinct routes across ${ips.size} IPs — distributed scanning`,
      sources: ["cloudflare"],
      coverage: ["app"],
      evidence: { routes: routes.size, ips: ips.size },
    });
  }
}

export function newAsnSurge(events: NormalizedEvent[], profile: BaselineProfile, out: Detection[]): void {
  const http = httpEvents(events);
  const known = new Set(profile.knownAsns);
  const fromNew = http.filter((e) => e.asn != null && !known.has(e.asn));
  if (fromNew.length >= NEW_ASN_MIN_EVENTS) {
    const asns = new Set(fromNew.map((e) => e.asn));
    out.push({
      detector: "new_asn_surge",
      actor: "project",
      ts: windowStart(fromNew),
      severity: "medium",
      reason: `${fromNew.length} reqs from ${asns.size} previously-unseen ASNs`,
      sources: ["cloudflare"],
      coverage: ["network"],
      evidence: { count: fromNew.length, asns: [...asns] },
    });
  }
}

export function runAggregate(events: NormalizedEvent[], profile: BaselineProfile): Detection[] {
  const out: Detection[] = [];
  distinctPathFanout(events, profile, out); // structural — always on
  if (!isWarming(profile)) {
    fourOhFourRate(events, profile, out); // baseline-relative — muted while warming
    newAsnSurge(events, profile, out);
  }
  return out;
}

/** Full engine pass: per-Entity Detectors + (if a profile is supplied) Aggregate ones. */
export function runEngine(events: NormalizedEvent[], profile?: BaselineProfile): Detection[] {
  const out = runAll(events);
  if (profile) out.push(...runAggregate(events, profile));
  return out;
}
