// Traffic barks — the security findings derived from the traffic profile. These are the
// "watch the door" alerts: a sensitive endpoint that reads as open to scripts, an AI agent
// reaching an open sensitive route, and crawler impersonation. Emitted as engine Detections so
// they ride the existing occurrence + notify + findings pipeline (keyed detector:actor, where
// actor is the templated endpoint — stable across windows so recurrence dedups them).
//
// Derived OUTSIDE runEngine (in evaluateProjectSnapshot, after the engine), so the oracle is
// untouched. classificationForDetector / actionabilityScore in overview.ts decide which page.

import type { Detection } from "../engine/schema.ts";
import { endpointKey, type EndpointRow, type TrafficProfile } from "./profile.ts";
import { isFileExfilPath } from "./paths.ts";

const MIN_AUTOMATION = 5; // below this it's background noise, not an exposure signal

interface OpenContext {
  catchAllHosts: Set<string>; // hosts that 2xx many secret families — soft-200 catch-alls
  challenged: Set<string>; // endpoints known to challenge (this window OR a remembered prior 401/403)
}

/** Does a sensitive endpoint actually read as OPEN to scripts? "Open" requires a real success
 *  (a 2xx — not a 404/500 error page, which never challenges either) AND no evidence it challenges
 *  callers: a 401/403 this window, or a *remembered* one from a prior window (the sticky-challenge
 *  set — sampling means a guarded service endpoint's 401 isn't in every window). For file-exfil
 *  paths (.git/config, .env, key files) two more guards reject a soft-200:
 *   - the host must NOT be a catch-all (one that 2xx'd several distinct secret-file families is
 *     200-ing everything — none of its "exposures" are real), and
 *   - where the plan exposes content-type, that 2xx must be NON-HTML (an HTML 200 on a secret
 *     file is the marketing fallthrough, not the file).
 *  App-surface routes (/admin) legitimately return HTML, so these apply ONLY to file-exfil. */
function readsAsOpen(e: EndpointRow, ctx: OpenContext): boolean {
  const challenged = e.challenged || ctx.challenged.has(endpointKey(e.base, e.path));
  if (!e.sensitive || challenged || !e.served2xx) return false;
  if (isFileExfilPath(e.path)) {
    if (ctx.catchAllHosts.has(e.base ?? "")) return false;
    return e.served2xxNonHtml;
  }
  return true;
}

/** Turn a derived traffic profile into barks. Also annotates each endpoint row with its `open`
 *  verdict (the one authoritative gate) so the persisted profile drives the Traffic UI directly.
 *  `nowSec` is the fallback timestamp; `knownChallenged` is the sticky-challenge set. */
export function deriveTrafficBarks(profile: TrafficProfile, nowSec: number, knownChallenged = new Set<string>()): Detection[] {
  const ts = profile.window?.to ?? nowSec;
  const ctx: OpenContext = {
    catchAllHosts: new Set(profile.softCatchAllHosts ?? []), // tolerate older persisted profiles
    challenged: knownChallenged,
  };
  const out: Detection[] = [];

  for (const e of profile.endpoints) {
    const automated = e.byClass.automation + e.byClass.unknown;
    const ai = e.byClass.ai_agent;
    // disambiguate findings by gateway: the same /pay on two proxied apps are different routes
    const ref = e.base !== null ? `${e.base}${e.path}` : e.path;
    const onGw = e.base !== null ? ` on gateway ${e.base}` : "";

    const open = readsAsOpen(e, ctx);
    e.open = open; // persist the verdict on the row so the Traffic UI reflects the same gate, not a stale heuristic

    // a sensitive route that never challenges (no 401/403) yet serves scripts a real 2xx = open
    if (open && automated >= MIN_AUTOMATION) {
      out.push({
        detector: "open_endpoint_automation",
        actor: ref,
        ts,
        severity: "high",
        reason: `${e.path}${onGw} is a sensitive route that never challenges callers (no 401/403) yet served ${automated} automated request${automated === 1 ? "" : "s"} — it reads as open to scripts.`,
        sources: ["traffic"],
        coverage: ["app"],
        evidence: { base: e.base, path: e.path, automation: e.byClass.automation, unknown: e.byClass.unknown, total: e.total, sensitive: true, challenged: false },
      });
    }

    // an AI agent reaching an open sensitive endpoint (the timely, differentiated bark)
    if (open && ai > 0) {
      const who = e.topAgent ?? "An AI agent";
      out.push({
        detector: "ai_agent_sensitive",
        actor: ref,
        ts,
        severity: "medium",
        reason: `${who} reached open sensitive endpoint ${e.path}${onGw} (${ai} request${ai === 1 ? "" : "s"}, no 401/403).`,
        sources: ["traffic"],
        coverage: ["app"],
        evidence: { base: e.base, path: e.path, aiAgent: ai, topAgent: e.topAgent, challenged: false },
      });
    }
  }

  // crawler impersonation anywhere in the window (UA claims Googlebot/Bingbot/Yandex, ASN says no)
  if (profile.spoofed > 0) {
    out.push({
      detector: "spoofed_crawler",
      actor: "spoofed-crawler",
      ts,
      severity: "medium",
      reason: `${profile.spoofed} request${profile.spoofed === 1 ? "" : "s"} impersonated a verified search crawler (declared e.g. Googlebot from a non-matching network).`,
      sources: ["traffic"],
      coverage: ["app"],
      evidence: { count: profile.spoofed },
    });
  }

  return out;
}
