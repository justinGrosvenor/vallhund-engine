// Detection engine — "dumb-first" rule + (source-agnostic) enumeration detectors.
// Ported verbatim from spike/detect.py so the golden oracle stays behavior-identical.
// Pure functions of (events) -> Detection[]; no wall-clock, no randomness.

import { A, type Detection, type NormalizedEvent } from "./schema.ts";

// ---- tunables (config, not code, in production) ----
const CRED_WINDOW = 600;
const CRED_FAILS = 8;
const CRED_ACCTS = 5;
const CRED_SUCCESS_WINDOW = 900;

const WAF_BLOCKS = 3;
const WAF_SIGS = 2;
const SIG_PATTERNS = [
  "union select", "' or '1'='1", "or '1'='1", "../",
  "/etc/passwd", "<script", "wp-login", ".env",
];
// Oracle-pinned: this MUST stay identical to spike/detect.py:SCANNER_UAS so the TS engine and the
// golden oracle agree. Deliberately NOT sourced from traffic/actors.ts — that registry grows freely
// for UA classification, and feeding a growing list into a pinned detector would silently change
// web_exploit_probing's behavior (and break engine==spike) with no fixture to catch it.
const SCANNER_UAS = ["sqlmap", "nikto", "nmap", "masscan", "acunetix"];
const ENUM_WINDOW = 300;
const ENUM_DISTINCT = 30;
const ENUM_AUTHERR = 15;

const GEO_FOLLOW = 1800;
const SENSITIVE_ROUTES = ["/api/env", "/api/admin", "/settings/secrets", "/api/keys"];

function groupByIp(events: NormalizedEvent[]): Map<string, NormalizedEvent[]> {
  const g = new Map<string, NormalizedEvent[]>();
  for (const e of events) {
    const bucket = g.get(e.ip);
    if (bucket) bucket.push(e);
    else g.set(e.ip, [e]);
  }
  return g;
}

export function credentialStuffing(events: NormalizedEvent[], out: Detection[]): void {
  // source-agnostic: any identity source (Supabase, Zitadel, ...) with auth events
  const logins = events.filter(
    (e) => e.action === A.LOGIN_FAIL || e.action === A.LOGIN_OK || e.action === A.TOKEN,
  );
  for (const [ip, evs] of groupByIp(logins)) {
    const fails = evs.filter((e) => e.action === A.LOGIN_FAIL).sort((a, b) => a.ts - b.ts);
    let i = 0;
    let burstTs: number | null = null;
    for (let j = 0; j < fails.length; j++) {
      const fj = fails[j];
      if (fj === undefined) continue;
      let fi = fails[i];
      while (fi !== undefined && fj.ts - fi.ts > CRED_WINDOW) {
        i++;
        fi = fails[i];
      }
      const window = fails.slice(i, j + 1);
      const accts = new Set(window.map((e) => e.actor));
      if (window.length >= CRED_FAILS && accts.size >= CRED_ACCTS) {
        burstTs = fj.ts;
        break;
      }
    }
    if (burstTs === null) continue;
    const burst = burstTs;
    const success = evs.find(
      (e) => e.action === A.LOGIN_OK && e.ts >= burst && e.ts <= burst + CRED_SUCCESS_WINDOW,
    );
    out.push({
      detector: "credential_stuffing",
      actor: ip,
      ts: burst,
      severity: success ? "high" : "medium",
      reason: `${String(CRED_FAILS)}+ failed logins across ${String(CRED_ACCTS)}+ accounts from one IP` +
        (success ? " followed by a SUCCESS (likely ATO)" : ""),
      sources: [...new Set(evs.map((e) => e.source))],
      coverage: ["identity"],
      evidence: { ip, tookOver: success !== undefined },
    });
  }
}

export function webExploitProbing(events: NormalizedEvent[], out: Detection[]): void {
  const waf = events.filter((e) => e.source === "cloudflare" && !e.verifiedBot);
  for (const [ip, evs] of groupByIp(waf)) {
    const blocks = evs.filter((e) => e.outcome === "block").length;
    const sigs = evs.filter((e) =>
      SIG_PATTERNS.some((p) => (e.resource + " " + e.query).toLowerCase().includes(p)),
    ).length;
    const scanner = evs.some((e) => {
      const ua = e.userAgent;
      return ua !== null && SCANNER_UAS.some((s) => ua.toLowerCase().includes(s));
    });
    // did a probe to an exploit/sensitive path actually succeed (2xx)? = real exposure
    const sensitiveHit = evs.some(
      (e) => e.status !== null && e.status >= 200 && e.status < 300 &&
        (SIG_PATTERNS.some((p) => (e.resource + " " + e.query).toLowerCase().includes(p)) ||
          SENSITIVE_ROUTES.some((r) => e.resource.startsWith(r))),
    );
    if (blocks >= WAF_BLOCKS || sigs >= WAF_SIGS || scanner) {
      out.push({
        detector: "web_exploit_probing",
        actor: ip,
        ts: Math.min(...evs.map((e) => e.ts)),
        severity: scanner || sensitiveHit ? "high" : "medium",
        reason: `WAF blocks=${String(blocks)}, exploit-signatures=${String(sigs)}, scanner_ua=${String(scanner)}` +
          (sensitiveHit ? ", 2xx on a probed sensitive path" : ""),
        sources: ["cloudflare"],
        coverage: ["app"],
        evidence: { ip, blocks, sigs, scanner, sensitiveHit },
      });
    }
  }
}

export function identityChain(events: NormalizedEvent[], out: Detection[]): void {
  const known = new Map<string, Set<string>>();
  const pending = new Map<string, { ts: number; country: string; src: string }>();
  const fired = new Set<string>();
  for (const e of [...events].sort((a, b) => a.ts - b.ts)) {
    if (e.action === A.LOGIN_OK || e.action === A.OAUTH) {
      const u = e.actor;
      const set = known.get(u);
      if (set !== undefined && set.size > 0 && e.country !== null && !set.has(e.country)) {
        pending.set(u, { ts: e.ts, country: e.country, src: e.source });
      }
      if (e.country !== null) {
        let seen = known.get(u);
        if (seen === undefined) {
          seen = new Set<string>();
          known.set(u, seen);
        }
        seen.add(e.country);
      }
      continue;
    }
    const sensitive = e.action === A.ENV_READ ||
      (e.action === A.HTTP && SENSITIVE_ROUTES.some((r) => e.resource.startsWith(r)));
    const p = pending.get(e.actor);
    if (sensitive && p !== undefined && !fired.has(e.actor) && e.ts - p.ts >= 0 && e.ts - p.ts <= GEO_FOLLOW) {
      fired.add(e.actor);
      const what = e.resource === "" ? e.action : e.resource;
      out.push({
        detector: "identity_chain",
        actor: e.actor,
        ts: e.ts,
        severity: "high",
        reason: `new-geo login (${p.country}) then sensitive action (${what}) within ${String(Math.round(e.ts - p.ts))}s`,
        sources: [p.src, e.source],
        coverage: ["identity", "app"],
        evidence: { user: e.actor, newCountry: p.country, sensitive: what },
      });
    }
  }
}

export function enumeration(events: NormalizedEvent[], out: Detection[]): void {
  // source-agnostic: any HTTP request stream (Vercel, Cloudflare, ...) qualifies
  const http = events.filter((e) => e.action === A.HTTP && !e.verifiedBot);
  for (const [ip, evs] of groupByIp(http)) {
    evs.sort((a, b) => a.ts - b.ts);
    let i = 0;
    for (let j = 0; j < evs.length; j++) {
      const ej = evs[j];
      if (ej === undefined) continue;
      let ei = evs[i];
      while (ei !== undefined && ej.ts - ei.ts > ENUM_WINDOW) {
        i++;
        ei = evs[i];
      }
      const window = evs.slice(i, j + 1);
      const w0 = window[0];
      if (w0 === undefined) continue;
      const distinct = new Set(window.map((e) => e.resource)).size;
      const autherr = window.filter((e) => e.status === 401 || e.status === 403).length;
      const sensitiveHit = window.some(
        (e) => e.status !== null && e.status >= 200 && e.status < 300 && SENSITIVE_ROUTES.some((r) => e.resource.startsWith(r)),
      );
      if (distinct >= ENUM_DISTINCT || autherr >= ENUM_AUTHERR) {
        out.push({
          detector: "enumeration",
          actor: ip,
          ts: w0.ts,
          severity: sensitiveHit ? "high" : "medium",
          reason: `${String(distinct)} distinct routes / ${String(autherr)} auth-errors in ${String(ENUM_WINDOW)}s from one IP` +
            (sensitiveHit ? ", 2xx on a sensitive route" : ""),
          sources: [w0.source],
          coverage: ["app"],
          evidence: { ip, distinct, autherr, sensitiveHit },
        });
        break; // one alert per IP is enough
      }
    }
  }
}

// Supply-chain / identity governance (GitHub). Third-party access grants, app
// installs and membership changes are low-frequency, high-impact events worth
// surfacing for review on first sight — the entry vector behind the Vercel-breach
// class. Not inherently hostile (classification stays "unknown" = needs review);
// Phase-1 recurrence decays repeats per actor so steady-state membership churn quiets.
const SUPPLY_ACTIONS = new Set<string>([A.OAUTH, A.MEMBER]);

export function supplyChain(events: NormalizedEvent[], out: Detection[]): void {
  for (const e of events) {
    if (e.source !== "github" || !SUPPLY_ACTIONS.has(e.action)) continue;
    const raw = typeof e.meta["githubAction"] === "string" ? e.meta["githubAction"] : e.action;
    const isGrant = e.action === A.OAUTH;
    out.push({
      detector: "supply_chain",
      actor: e.actor,
      ts: e.ts,
      severity: isGrant ? "high" : "medium",
      reason: isGrant
        ? `third-party access granted (${raw})`
        : `org membership change (${raw})`,
      sources: ["github"],
      coverage: ["identity", "config"],
      evidence: { actor: e.actor, githubAction: raw, target: e.resource },
    });
  }
}

// Control-plane governance (AWS CloudTrail + GCP Cloud Audit Logs). Sensitive cloud
// management actions — new credentials/keys/users, IAM grants, and logging tamper — are
// the privilege-escalation and persistence steps that follow an account compromise.
// Surfaced for review (classification "unknown"); logging-tamper carries config coverage.
// Quiet unless a cloud source is connected; Phase-1 recurrence decays routine ops churn.
const CLOUD_CONTROL_SOURCES = new Set<string>(["aws", "gcp"]);
const CONTROL_PLANE_HIGH = new Set<string>([
  // AWS
  "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile",
  "DeleteTrail", "StopLogging", "UpdateAssumeRolePolicy", "CreateRole",
  // GCP
  "google.iam.admin.v1.CreateServiceAccountKey", "google.iam.admin.v1.CreateServiceAccount",
  "google.iam.admin.v1.CreateRole", "SetIamPolicy",
  "google.logging.v2.ConfigServiceV2.DeleteSink",
]);
const CONTROL_PLANE_MED = new Set<string>([
  // AWS
  "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
  "AddUserToGroup", "AuthorizeSecurityGroupIngress", "PutBucketPolicy",
  // GCP
  "google.iam.admin.v1.UpdateRole", "google.iam.admin.v1.SetIamPolicy",
]);

export function controlPlane(events: NormalizedEvent[], out: Detection[]): void {
  for (const e of events) {
    if (!CLOUD_CONTROL_SOURCES.has(e.source)) continue;
    const name = typeof e.meta["eventName"] === "string" ? e.meta["eventName"] : e.action;
    const high = CONTROL_PLANE_HIGH.has(name);
    if (!high && !CONTROL_PLANE_MED.has(name)) continue;
    const tamper = name === "DeleteTrail" || name === "StopLogging" || name.includes("DeleteSink");
    out.push({
      detector: "control_plane",
      actor: e.actor,
      ts: e.ts,
      severity: high ? "high" : "medium",
      reason: tamper
        ? `audit-logging tampered (${name})`
        : `sensitive control-plane action (${name})`,
      sources: [e.source],
      coverage: tamper ? ["identity", "config"] : ["identity"],
      evidence: { actor: e.actor, eventName: name, ip: e.ip },
    });
  }
}

export const ALL_DETECTORS = [
  credentialStuffing,
  webExploitProbing,
  identityChain,
  enumeration,
  supplyChain,
  controlPlane,
];

export function runAll(events: NormalizedEvent[]): Detection[] {
  const out: Detection[] = [];
  for (const det of ALL_DETECTORS) det(events, out);
  return out;
}
