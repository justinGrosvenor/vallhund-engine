// Traffic profile — the "watch the door" derivation. From the same normalized HTTP events the
// engine already sees (Vercel drain, Cloudflare http), build an actor-aware map: the top-line
// actor mix (human / crawler / AI agent / automation / unknown) and a per-endpoint table
// crossing route x actor x auth. Persisted on the snapshot; the raw events are then dropped.
//
// Pure + derived OUTSIDE runEngine — never perturbs the engine's detections or the oracle.

import { A, type NormalizedEvent } from "../engine/schema.ts";
import { classifyActor, type ActorClass, ALL_ACTOR_CLASSES } from "./actors.ts";
import { templatePath, isSensitivePath, fileExfilFamily } from "./paths.ts";

export type ActorCounts = Record<ActorClass, number>;

export interface ActorMixRow {
  cls: ActorClass;
  count: number;
  pct: number;
}

export interface EndpointRow {
  /** the proxied gateway/app this route belongs to (Host), or null if unknown. */
  base: string | null;
  path: string; // templated route
  total: number;
  byClass: ActorCounts;
  /** ever returned 401/403 here — i.e. the route challenges callers (else it reads as open). */
  challenged: boolean;
  /** ever actually served a 2xx here — "open to scripts" requires a real success, not a 404/500. */
  served2xx: boolean;
  /** ever served a 2xx that was NOT an HTML page — distinguishes a real file from the app's
   *  catch-all/marketing fallthrough (an exposed .git/config is plain/json, never html). */
  served2xxNonHtml: boolean;
  sensitive: boolean;
  /** most-seen named bot/agent on this route (for display), if any. */
  topAgent: string | null;
  /** the authoritative "reads as open to scripts" verdict (deriveTrafficBarks → readsAsOpen):
   *  sensitive + a real 2xx + not challenged (this window or remembered) + not a soft-200 catch-all
   *  + non-HTML where the plan exposes it. Set at derivation time so the persisted profile is
   *  self-contained — the Traffic UI and the bark agree by construction. Optional for back-compat. */
  open?: boolean;
}

/** Per-gateway (Host) rollup — for a proxy, "which app is being called". */
export interface BaseRow {
  host: string | null;
  total: number;
  byClass: ActorCounts;
}

export interface NamedAgentRow {
  name: string;
  cls: ActorClass;
  count: number;
}

export interface TrafficProfile {
  total: number; // HTTP requests considered
  mix: ActorMixRow[]; // actor-class breakdown, desc
  bases: BaseRow[]; // per-gateway (Host) rollup, desc; empty/[{host:null}] when no Host captured
  endpoints: EndpointRow[]; // top routes by volume (carry their base)
  agents: NamedAgentRow[]; // named bots/agents seen, desc
  spoofed: number; // requests whose UA impersonated a verifiable crawler
  /** hosts (base; "" = no Host) that served a 2xx for ≥2 distinct file-exfil families — a soft-200
   *  catch-all (e.g. marketing fallthrough), so their file-exfil "exposures" are not real. Optional:
   *  absent on profiles persisted before this field existed (barks tolerates that). */
  softCatchAllHosts?: string[];
  /** endpoint keys (see endpointKey) that returned 401/403 this window — feed the sticky-challenge
   *  memory so a guarded endpoint stays "challenged" across windows. Optional for back-compat. */
  challengedEndpoints?: string[];
  window: { from: number; to: number } | null;
}

const CATCHALL_FAMILIES = 2; // distinct file-exfil families 2xx'd on one host => it 200s everything

const EMPTY_COUNTS = (): ActorCounts => ({ human: 0, search_crawler: 0, ai_agent: 0, automation: 0, unknown: 0 });

/** Stable key for an endpoint row: host + templated path ("" host = no Host captured). The same
 *  path on two gateways is two endpoints. Shared by the profile, the sticky-challenge set, and the
 *  barks lookup so they never drift. */
export function endpointKey(base: string | null, path: string): string {
  return `${base ?? ""} ${path}`;
}

interface EndpointAcc {
  base: string | null;
  path: string;
  total: number;
  byClass: ActorCounts;
  challenged: boolean;
  served2xx: boolean;
  served2xxNonHtml: boolean;
  sensitive: boolean;
  agents: Map<string, number>;
}

interface BaseAcc {
  host: string | null;
  total: number;
  byClass: ActorCounts;
}

const MAX_ENDPOINTS = 50; // higher: rows are now split per gateway
const MAX_BASES = 25;
const MAX_AGENTS = 25;

/** The proxied gateway/app (Host) for an event, or null if not captured. */
function hostOf(e: NormalizedEvent): string | null {
  const h = e.meta["host"];
  return typeof h === "string" && h !== "" ? h : null;
}

/** WORKER side: derive the traffic profile from HTTP events (raw events are then dropped). */
export function deriveTrafficProfile(events: NormalizedEvent[]): TrafficProfile {
  const http = events.filter((e) => e.action === A.HTTP);
  const mix = EMPTY_COUNTS();
  const endpoints = new Map<string, EndpointAcc>();
  const bases = new Map<string, BaseAcc>();
  const agents = new Map<string, NamedAgentRow>();
  const exfil2xxByHost = new Map<string, Set<string>>(); // host -> file-exfil families that 2xx'd
  let spoofed = 0;
  let from = Infinity;
  let to = -Infinity;

  for (const e of http) {
    const v = classifyActor(e.userAgent, e.asn);
    mix[v.cls]++;
    if (v.spoofed) spoofed++;
    if (e.ts < from) from = e.ts;
    if (e.ts > to) to = e.ts;

    const host = hostOf(e);
    const path = templatePath(e.resource);
    const key = endpointKey(host, path); // same path on two gateways = two rows
    let acc = endpoints.get(key);
    if (acc === undefined) {
      acc = { base: host, path, total: 0, byClass: EMPTY_COUNTS(), challenged: false, served2xx: false, served2xxNonHtml: false, sensitive: isSensitivePath(path), agents: new Map() };
      endpoints.set(key, acc);
    }
    acc.total++;
    acc.byClass[v.cls]++;
    if (e.status === 401 || e.status === 403) acc.challenged = true;
    if (e.status !== null && e.status >= 200 && e.status < 300) {
      acc.served2xx = true;
      // contentType absent (non-Cloudflare / older data) counts as non-HTML — we don't assume a
      // catch-all we can't see, so detection is preserved until the field is actually present.
      if (e.contentType !== "html") acc.served2xxNonHtml = true;
      // record which secret-file families this host actually served a 2xx for (catch-all signal)
      const fam = fileExfilFamily(path);
      if (fam !== null) {
        const fams = exfil2xxByHost.get(host ?? "") ?? new Set<string>();
        fams.add(fam);
        exfil2xxByHost.set(host ?? "", fams);
      }
    }
    if (v.name !== null) acc.agents.set(v.name, (acc.agents.get(v.name) ?? 0) + 1);

    const bkey = host ?? "";
    let b = bases.get(bkey);
    if (b === undefined) { b = { host, total: 0, byClass: EMPTY_COUNTS() }; bases.set(bkey, b); }
    b.total++;
    b.byClass[v.cls]++;

    if (v.name !== null) {
      const cur = agents.get(v.name);
      if (cur === undefined) agents.set(v.name, { name: v.name, cls: v.cls, count: 1 });
      else cur.count++;
    }
  }

  const total = http.length;
  const mixRows: ActorMixRow[] = ALL_ACTOR_CLASSES.map((cls) => ({
    cls,
    count: mix[cls],
    pct: total > 0 ? Math.round((mix[cls] / total) * 100) : 0,
  }))
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count);

  const baseRows: BaseRow[] = [...bases.values()]
    .map((b): BaseRow => ({ host: b.host, total: b.total, byClass: b.byClass }))
    .sort((a, b) => b.total - a.total)
    .slice(0, MAX_BASES);

  const endpointRows: EndpointRow[] = [...endpoints.values()]
    .map((acc): EndpointRow => ({
      base: acc.base,
      path: acc.path,
      total: acc.total,
      byClass: acc.byClass,
      challenged: acc.challenged,
      served2xx: acc.served2xx,
      served2xxNonHtml: acc.served2xxNonHtml,
      sensitive: acc.sensitive,
      topAgent: topOf(acc.agents),
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, MAX_ENDPOINTS);

  const agentRows = [...agents.values()].sort((a, b) => b.count - a.count).slice(0, MAX_AGENTS);

  const softCatchAllHosts = [...exfil2xxByHost.entries()]
    .filter(([, fams]) => fams.size >= CATCHALL_FAMILIES)
    .map(([host]) => host);

  // computed over the FULL endpoint map (before the top-N slice) so a challenged route outside the
  // displayed rows still feeds the sticky-challenge memory.
  const challengedEndpoints = [...endpoints.values()]
    .filter((a) => a.challenged)
    .map((a) => endpointKey(a.base, a.path));

  return {
    total,
    mix: mixRows,
    bases: baseRows,
    endpoints: endpointRows,
    agents: agentRows,
    spoofed,
    softCatchAllHosts,
    challengedEndpoints,
    window: total > 0 ? { from, to } : null,
  };
}

function topOf(counts: Map<string, number>): string | null {
  let best: string | null = null;
  let bestN = 0;
  for (const [name, n] of counts) if (n > bestN) { best = name; bestN = n; }
  return best;
}
