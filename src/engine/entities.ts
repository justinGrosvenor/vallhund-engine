// Entity view — actors (ip/user) with friend/foe standing, for the Entities screen.
// Classification is Entity-first-class (domain §11.2): standing lives here; Verdicts
// reference it. v1 derives standing from the current snapshot's findings.

import type { NormalizedEvent } from "./schema.ts";
import type { Classification } from "./overview.ts";
import type { FindingView } from "./overview.ts";
import { type AsnClass, classifyAsn } from "../enrich/asn.ts";

export type EntityKind = "ip" | "user";
export type Reputation = "trusted" | "neutral" | "suspicious" | "hostile";

export interface EntityView {
  key: string;
  kind: EntityKind;
  classification: Classification;
  reputation: Reputation;
  events: number;
  firstSeen: number;
  lastSeen: number;
  detectors: string[];
  asnClass: AsnClass;
}

function reputationFor(c: Classification): Reputation {
  if (c === "foe") return "hostile";
  if (c === "friend") return "trusted";
  return "neutral";
}

export function buildEntities(events: NormalizedEvent[], findings: FindingView[]): EntityView[] {
  const foeActors = new Set(findings.filter((f) => f.classification === "foe").map((f) => f.actor));
  const detectorsByActor = new Map<string, Set<string>>();
  for (const f of findings) {
    const set = detectorsByActor.get(f.actor) ?? new Set<string>();
    set.add(f.detector);
    detectorsByActor.set(f.actor, set);
  }

  interface Acc { kind: EntityKind; count: number; first: number; last: number; verified: boolean; asn: number | null }
  const acc = new Map<string, Acc>();
  for (const e of events) {
    if (e.actor === "") continue;
    const cur = acc.get(e.actor);
    if (cur === undefined) {
      acc.set(e.actor, { kind: e.actor === e.ip ? "ip" : "user", count: 1, first: e.ts, last: e.ts, verified: e.verifiedBot, asn: e.asn });
    } else {
      cur.count++;
      if (e.ts < cur.first) cur.first = e.ts;
      if (e.ts > cur.last) cur.last = e.ts;
      if (e.verifiedBot) cur.verified = true;
      if (cur.asn === null && e.asn !== null) cur.asn = e.asn;
    }
  }

  const out: EntityView[] = [];
  for (const [key, a] of acc) {
    const classification: Classification = a.verified ? "friend" : foeActors.has(key) ? "foe" : "unknown";
    out.push({
      key,
      kind: a.kind,
      classification,
      reputation: reputationFor(classification),
      events: a.count,
      firstSeen: a.first,
      lastSeen: a.last,
      detectors: [...(detectorsByActor.get(key) ?? new Set<string>())],
      asnClass: classifyAsn(a.asn),
    });
  }

  const rank = (c: Classification): number => (c === "foe" ? 0 : c === "unknown" ? 1 : 2);
  out.sort((x, y) => rank(x.classification) - rank(y.classification) || y.events - x.events);
  return out;
}
