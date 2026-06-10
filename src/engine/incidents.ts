// Incident grouping (Phase 3) — collapse per-actor findings into one row.
// One IP often trips several detectors (e.g. web_exploit + enumeration); the feed
// should show one incident per actor with its N signals, not N separate rows.
// Pure view-model over FindingView[] — no new aggregate.

import type { Actionability, Classification, FindingView } from "./overview.ts";

export interface IncidentSignal {
  id: string;
  detector: string;
  severity: string;
  reason: string;
  actionability: Actionability;
}

export interface Incident {
  actor: string;
  classification: Classification; // worst across signals (foe > unknown > friend)
  severity: string; // worst
  actionability: Actionability; // worst (actionable > noise > informational)
  coverage: string[]; // union
  confirmed: boolean; // any signal confirmed
  recurring: boolean; // all signals recurring
  isNew: boolean; // any signal new
  isEscalated: boolean; // any signal escalated
  signals: IncidentSignal[];
}

const sevRank = (s: string): number => (s === "high" ? 0 : s === "medium" ? 1 : 2);
const clsRank = (c: Classification): number => (c === "foe" ? 0 : c === "unknown" ? 1 : 2);
const actRank = (a: Actionability): number => (a === "actionable" ? 0 : a === "noise" ? 1 : 2);

const CLS_BY_RANK: Classification[] = ["foe", "unknown", "friend"];
const ACT_BY_RANK: Actionability[] = ["actionable", "noise", "informational"];
const SEV_BY_RANK = ["high", "medium", "low"];

export function buildIncidents(findings: FindingView[]): Incident[] {
  const byActor = new Map<string, FindingView[]>();
  for (const f of findings) {
    const a = byActor.get(f.actor);
    if (a) a.push(f);
    else byActor.set(f.actor, [f]);
  }

  const incidents: Incident[] = [];
  for (const [actor, fs] of byActor) {
    const minCls = Math.min(...fs.map((f) => clsRank(f.classification)));
    const minSev = Math.min(...fs.map((f) => sevRank(f.severity)));
    const minAct = Math.min(...fs.map((f) => actRank(f.actionability)));
    incidents.push({
      actor,
      classification: CLS_BY_RANK[minCls] ?? "unknown",
      severity: SEV_BY_RANK[minSev] ?? "low",
      actionability: ACT_BY_RANK[minAct] ?? "noise",
      coverage: [...new Set(fs.flatMap((f) => f.coverage))],
      confirmed: fs.some((f) => f.confirmed),
      recurring: fs.every((f) => f.recurring),
      isNew: fs.some((f) => f.isNew),
      isEscalated: fs.some((f) => f.isEscalated),
      signals: fs
        .slice()
        .sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
        .map((f) => ({ id: f.id, detector: f.detector, severity: f.severity, reason: f.reason, actionability: f.actionability })),
    });
  }

  return incidents.sort(
    (a, b) =>
      actRank(a.actionability) - actRank(b.actionability) ||
      sevRank(a.severity) - sevRank(b.severity) ||
      b.signals.length - a.signals.length,
  );
}
