// Overview data layer + minimal v1 verdict synthesis (classification + actionability).
// FindingView is the UI/persistence-facing shape (Detection + id + verdict + triage
// state). buildOverview consumes FindingView[] so reputation/suppression adjustments
// made upstream (snapshot) flow straight into the headline, counts, and feed.

import { A, type Detection, type NormalizedEvent } from "./schema.ts";
import type { AsnClass, ScannerVerdict } from "../enrich/asn.ts";
import type { CrawlerVerdict } from "../traffic/rdns.ts";

export type Headline = "calm" | "watching" | "action";
export type Classification = "friend" | "foe" | "unknown";
export type Actionability = "actionable" | "noise" | "informational";

// open_endpoint_automation (a sensitive route open to scripts) and spoofed_crawler (active
// crawler impersonation) are exposure worth paging — classed foe so they ride notify.
// ai_agent_sensitive is informational (visibility), classed unknown → shown, not paged.
const FOE_DETECTORS = new Set(["web_exploit_probing", "credential_stuffing", "identity_chain", "open_endpoint_automation", "spoofed_crawler"]);

export function classificationForDetector(detector: string): Classification {
  return FOE_DETECTORS.has(detector) ? "foe" : "unknown";
}

export function classificationOf(d: Detection): Classification {
  return classificationForDetector(d.detector);
}

export function isFoeDetector(detector: string): boolean {
  return FOE_DETECTORS.has(detector);
}

/** Foe-dominant classification. The previous code let any "crawler"-range ASN flip a finding
 *  to friend — so an exploit-prober on a Microsoft/Bing ASN read as friendly and silenced a
 *  real attack. The fix: an active-attack detector is foe and NOTHING downgrades it; friend is
 *  granted only on a *verified* signal (FCrDNS-confirmed crawler or independently-confirmed
 *  benign), never on ASN ownership. With the FCrDNS gate off, `crawler` is always "unverified",
 *  so this reduces to foe-dominance + GreyNoise — which already fixes the bug. */
export function resolveFindingClassification(
  detector: string,
  detectorDefault: Classification,
  signals: { scanner: ScannerVerdict | null; crawler: CrawlerVerdict },
): Classification {
  // Foe signals first, then friend signals — so nothing hostile can be downgraded.
  if (isFoeDetector(detector)) return "foe"; // active-attack evidence — never downgraded
  if (signals.scanner === "malicious") return "foe";
  if (signals.crawler === "spoofed") return "foe"; // FCrDNS impersonation: UA claims a crawler, DNS says otherwise
  if (signals.crawler === "verified") return "friend"; // FCrDNS-confirmed (Phase 2)
  if (signals.scanner === "benign") return "friend"; // GreyNoise-confirmed benign
  return detectorDefault;
}

const ACTION_THRESHOLD = 2;

// Documented weighted actionability score (rules-based, oracle-testable). The
// strongest escalator is a probe that actually SUCCEEDED (2xx) on a sensitive/exploit
// path — that's exposure, not background radiation. Heavy probing volume is a one-time
// alert (Phase 1 recurrence decays the daily repeats).
export function actionabilityScore(d: Detection): number {
  const ev = d.evidence;
  const n = (k: string): number => (typeof ev[k] === "number" ? ev[k] : 0);
  const b = (k: string): boolean => ev[k] === true;
  switch (d.detector) {
    case "web_exploit_probing": {
      let s = 0;
      if (b("scanner")) s += 2; // a real scanner UA
      if (n("blocks") >= 3) s += 2; // WAF already blocking it
      if (b("sensitiveHit")) s += 3; // 2xx on a probed sensitive/exploit path = exposure
      if (n("sigs") >= 8) s += 2; // heavy probing volume
      return s;
    }
    case "enumeration":
      return 2 + (b("sensitiveHit") ? 2 : 0);
    case "credential_stuffing":
      return b("tookOver") ? 3 : 2;
    case "open_endpoint_automation":
      return 3; // a sensitive route reading as open to scripts — actionable exposure
    case "ai_agent_sensitive":
      return 1; // informational visibility — surfaced in the Traffic view, not the action feed
    default:
      return 2; // identity_chain, aggregate recon, spoofed_crawler, etc. — actionable on first sight
  }
}

export function actionabilityOf(d: Detection): Actionability {
  return actionabilityScore(d) >= ACTION_THRESHOLD ? "actionable" : "noise";
}

export interface FindingView extends Detection {
  id: string;
  classification: Classification;
  actionability: Actionability;
  suppressed: boolean;
  confirmed: boolean;
  isNew: boolean;
  isEscalated: boolean;
  recurring: boolean;
  asnClass: AsnClass;
  scanner: ScannerVerdict | null;
}

/** Pure mapping with no persistence applied (used by tests + as the base in snapshot). */
export function baseFindingView(d: Detection): FindingView {
  return {
    ...d,
    id: `${d.detector}:${d.actor}`,
    classification: classificationOf(d),
    actionability: actionabilityOf(d),
    suppressed: false,
    confirmed: false,
    isNew: true,
    isEscalated: false,
    recurring: false,
    asnClass: "unknown",
    scanner: null,
  };
}

export interface AttentionRow {
  id: string;
  classification: Classification;
  severity: string;
  detector: string;
  actor: string;
  reason: string;
  coverage: string[];
  confirmed: boolean;
}

export interface OverviewData {
  headline: Headline;
  headlineMsg: string;
  counts: { actionable: number; foe: number; friend: number; unknown: number };
  metrics: { requests: number; fourOhFourPct: number; distinctIps: number };
  statusMix: { code: number; count: number }[];
  topRoutes: { route: string; count: number }[];
  coverageActive: string[];
  coverageNotCovered: string[];
  needsAttention: AttentionRow[];
  noiseCount: number;
  warming: boolean;
}

function sevRank(s: string): number {
  return s === "high" ? 0 : s === "medium" ? 1 : 2;
}

// Events-derived signals the worker persists, then DROPS the raw events (derive-and-drop).
// Only distinct IP sets + aggregate counts survive — not the raw telemetry.
export interface SnapshotMetrics {
  requests: number;
  fourOhFourPct: number;
  statusMix: { code: number; count: number }[];
  topRoutes: { route: string; count: number }[];
  allIps: string[]; // distinct actor IPs in the window
  verifiedIps: string[]; // verified-bot IPs
}

/** WORKER side: derive the persistable metrics from the raw events (raw is then dropped). */
export function deriveMetrics(events: NormalizedEvent[]): SnapshotMetrics {
  const http = events.filter((e) => e.action === A.HTTP);
  const requests = http.length;
  const n404 = http.filter((e) => e.status === 404).length;
  const statusMap = new Map<number, number>();
  for (const e of http) if (e.status != null) statusMap.set(e.status, (statusMap.get(e.status) ?? 0) + 1);
  const routeMap = new Map<string, number>();
  for (const e of http) routeMap.set(e.resource, (routeMap.get(e.resource) ?? 0) + 1);
  return {
    requests,
    fourOhFourPct: requests ? Math.round((n404 / requests) * 100) : 0,
    statusMix: [...statusMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([code, count]) => ({ code, count })),
    topRoutes: [...routeMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([route, count]) => ({ route, count })),
    allIps: [...new Set(events.map((e) => e.ip).filter(Boolean))],
    verifiedIps: [...new Set(events.filter((e) => e.verifiedBot).map((e) => e.ip))],
  };
}

/** READ side: combine persisted metrics with the (overlay-applied) findings. Pure. */
export function buildOverview(metrics: SnapshotMetrics, findings: FindingView[], warming: boolean): OverviewData {
  const verifiedIps = new Set(metrics.verifiedIps);
  const foeActors = new Set(findings.filter((f) => f.classification === "foe").map((f) => f.actor));
  let friend = 0;
  let foe = 0;
  let unknown = 0;
  for (const ip of metrics.allIps) {
    if (verifiedIps.has(ip)) friend++;
    else if (foeActors.has(ip)) foe++;
    else unknown++;
  }

  const actionable = findings.filter((f) => f.actionability === "actionable");
  const noiseCount = findings.filter((f) => f.actionability === "noise").length;

  let headline: Headline = "calm";
  if (actionable.some((f) => f.classification === "foe")) headline = "action";
  else if (actionable.length > 0 || foe > 0) headline = "watching";
  const headlineMsg =
    headline === "action" ? "Confirmed foe activity needs attention."
    : headline === "watching" ? "Recon in progress, nothing's broken in."
    : "Quiet. Nothing actionable.";

  const cov = new Set<string>(["network", "app"]);
  for (const f of findings) for (const c of f.coverage) cov.add(c);

  const needsAttention: AttentionRow[] = actionable
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
    .slice(0, 8)
    .map((f) => ({
      id: f.id,
      classification: f.classification,
      severity: f.severity,
      detector: f.detector,
      actor: f.actor,
      reason: f.reason,
      coverage: f.coverage,
      confirmed: f.confirmed,
    }));

  return {
    headline,
    headlineMsg,
    counts: { actionable: actionable.length, foe, friend, unknown },
    metrics: { requests: metrics.requests, fourOhFourPct: metrics.fourOhFourPct, distinctIps: metrics.allIps.length },
    statusMix: metrics.statusMix,
    topRoutes: metrics.topRoutes,
    coverageActive: [...cov],
    coverageNotCovered: ["host", "kernel"],
    needsAttention,
    noiseCount,
    warming,
  };
}
