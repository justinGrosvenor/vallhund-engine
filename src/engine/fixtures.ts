// Golden-oracle fixtures — benign baseline + negative controls E1-E4 + attacks
// A-D + kernel-blind control F + distributed-recon G, in each Source's native shape.
// The regression corpus the TS engine is diffed against the Python spike on.

import type {
  CloudflareHttpNative,
  CloudflareWafNative,
  NativeBatch,
  SupabaseNative,
  VercelNative,
} from "../ingest/native.ts";

export const BASE = 1748822400; // 2025-06-02 00:00:00 UTC
export const DAY = 86400;

const ns = (tsSec: number): number => Math.round(tsSec * 1e9);

function cf(ts: number, ip: string, o: {
  action?: string; path?: string; query?: string; ua?: string;
  asn?: number; country?: string; ruleset?: string;
} = {}): CloudflareWafNative {
  return {
    datetime: ts,
    clientIP: ip,
    action: o.action ?? "allow",
    clientRequestPath: o.path ?? "/",
    clientRequestQuery: o.query ?? "",
    userAgent: o.ua ?? "Mozilla/5.0",
    clientAsn: o.asn ?? 64500,
    clientCountryName: o.country ?? "US",
    source: o.ruleset ?? "",
  };
}

function cfh(ts: number, ip: string, o: {
  path?: string; status?: number; asn?: number; country?: string; ua?: string;
} = {}): CloudflareHttpNative {
  return {
    datetime: ts,
    clientIP: ip,
    clientAsn: o.asn ?? 64500,
    clientCountryName: o.country ?? "US",
    clientRequestPath: o.path ?? "/",
    clientRequestQuery: "",
    edgeResponseStatus: o.status ?? 200,
    userAgent: o.ua ?? "Mozilla/5.0",
  };
}

function sb(ts: number, user: string, action: string, o: {
  ip?: string; country?: string; ua?: string; username?: string;
} = {}): SupabaseNative {
  return {
    created_at: ts,
    ip_address: o.ip ?? "198.51.100.5",
    payload: {
      action,
      actor_id: user,
      actor_username: o.username ?? "user@example.com",
      traits: { country: o.country ?? "US", user_agent: o.ua ?? "Mozilla/5.0" },
    },
  };
}

function vc(ts: number, ip: string, o: {
  route?: string; status?: number; ua?: string; user?: string;
  envRead?: boolean; country?: string;
} = {}): VercelNative {
  const attributes: VercelNative["attributes"] = {
    "http.method": "GET",
    "http.route": o.route ?? "/",
    "http.status_code": o.status ?? 200,
    "client.address": ip,
    "user_agent.original": o.ua ?? "Mozilla/5.0",
    "client.country": o.country ?? "US",
  };
  if (o.user !== undefined) attributes["user.id"] = o.user;
  if (o.envRead === true) attributes["vercel.env_var_read"] = true;
  return { startTimeUnixNano: ns(ts), traceId: `t${String(Math.trunc(ts))}`, attributes };
}

export function benignNative(): NativeBatch {
  const cloudflare: CloudflareWafNative[] = [];
  const supabase: SupabaseNative[] = [];
  const vercel: VercelNative[] = [];

  const normal: [string, string, string, string][] = [
    ["alice", "alice@x.co", "US", "198.51.100.10"],
    ["bob", "bob@x.co", "US", "198.51.100.11"],
    ["carol", "carol@x.co", "GB", "198.51.100.12"],
  ];
  for (const [uid, uname, ctry, ip] of normal) {
    for (const d of [0, 2, 4, 5]) {
      const t = BASE + d * DAY + 9 * 3600;
      supabase.push(sb(t, uid, "login_success", { ip, country: ctry, username: uname }));
      ["/", "/dashboard", "/"].forEach((route, k) => {
        vercel.push(vc(t + 60 + k * 30, ip, { route, user: uid, country: ctry }));
        cloudflare.push(cf(t + 60 + k * 30, ip, { path: route, country: ctry }));
      });
    }
  }
  // one benign failed login then success (single account) — under thresholds
  supabase.push(sb(BASE + 3 * DAY, "alice", "login_failure", { ip: "198.51.100.10", username: "alice@x.co" }));
  supabase.push(sb(BASE + 3 * DAY + 30, "alice", "login_success", { ip: "198.51.100.10", username: "alice@x.co" }));
  // isolated WAF blocks (1 each — below threshold)
  cloudflare.push(cf(BASE + 1 * DAY, "203.0.113.99", { action: "block", path: "/wp-login.php" }));
  cloudflare.push(cf(BASE + 2 * DAY, "203.0.113.98", { action: "block", path: "/.env" }));

  // victim & traveler establish KNOWN home geo (US)
  for (const [uid, ip] of [["u_victim", "198.51.100.20"], ["u_travel", "198.51.100.21"]] as const) {
    for (const d of [0, 3, 5]) {
      supabase.push(sb(BASE + d * DAY + 8 * 3600, uid, "login_success", { ip, country: "US", username: `${uid}@x.co` }));
    }
  }

  // precision probe: alice reads env from her KNOWN geo -> must NOT alert
  vercel.push(vc(BASE + 6 * DAY + 3600, "198.51.100.10", { route: "/api/env", user: "alice", envRead: true, country: "US" }));

  // E1: launch / HN traffic spike (high volume, few paths, 200)
  let t = BASE + 5 * DAY + 12 * 3600;
  for (let i = 0; i < 50; i++) {
    const ip = `192.0.2.${String(i + 1)}`;
    ["/", "/pricing", "/product"].forEach((route, k) => {
      vercel.push(vc(t + k, ip, { route, country: "US" }));
      cloudflare.push(cf(t + k, ip, { path: route }));
    });
  }

  // E2: real user logs in from a NEW country (travel), no sensitive action
  t = BASE + 6 * DAY + 2 * 3600;
  supabase.push(sb(t, "u_travel", "login_success", { ip: "203.0.113.77", country: "FR", username: "u_travel@x.co" }));
  vercel.push(vc(t + 120, "203.0.113.77", { route: "/dashboard", user: "u_travel", country: "FR" }));

  // E3: a FRIEND bot we want (verified) — high volume, many paths
  for (let i = 0; i < 80; i++) {
    const tb = BASE + (i % 6) * DAY + ((i * 137) % 80000);
    vercel.push(vc(tb, "66.249.66.1", { route: `/blog/${String(i)}`, ua: "GoodBot/1.0", country: "US" }));
  }

  // E4: deploy causes a 5xx error spike (not 401/403)
  t = BASE + 6 * DAY + 5 * 3600;
  for (let i = 0; i < 40; i++) {
    vercel.push(vc(t + i, `198.51.100.${String(40 + (i % 8))}`, { route: "/api/checkout", status: 500, country: "US" }));
  }

  return { cloudflare, supabase, vercel };
}

export interface Truth {
  actor: string;
  start: number;
  end: number;
  observable: boolean;
  sourcesNeeded?: string[];
  note: string;
}

export interface Attack {
  native: NativeBatch;
  truth: Truth;
}

export interface AttackSet {
  A: Attack;
  B: Attack;
  C: Attack;
  D: Attack;
  F: Attack;
}

export function attacks(): AttackSet {
  // A — credential stuffing -> account takeover (Supabase)
  const aIp = "203.0.113.10";
  const aT0 = BASE + 6 * DAY + 20 * 3600;
  const aEvents: SupabaseNative[] = [];
  for (let i = 0; i < 12; i++) {
    const acct = `victim${String(i % 6)}`;
    aEvents.push(sb(aT0 + i * 30, acct, "login_failure", { ip: aIp, username: `${acct}@x.co` }));
  }
  aEvents.push(sb(aT0 + 12 * 30, "victim0", "login_success", { ip: aIp, username: "victim0@x.co" }));
  aEvents.push(sb(aT0 + 13 * 30, "victim0", "token_refresh", { ip: aIp, username: "victim0@x.co" }));

  // B — web exploit probing (Cloudflare WAF)
  const bIp = "203.0.113.20";
  const bT0 = BASE + 6 * DAY + 21 * 3600;
  const bEvents: CloudflareWafNative[] = [
    cf(bT0 + 0, bIp, { action: "block", path: "/.env", ua: "sqlmap/1.7", country: "RU" }),
    cf(bT0 + 5, bIp, { action: "block", path: "/wp-login.php", ua: "sqlmap/1.7", country: "RU" }),
    cf(bT0 + 9, bIp, { action: "block", path: "/index.php", query: "id=1' OR '1'='1", ua: "sqlmap/1.7", country: "RU" }),
    cf(bT0 + 14, bIp, { action: "block", path: "/../../../etc/passwd", ua: "sqlmap/1.7", country: "RU" }),
    cf(bT0 + 20, bIp, { action: "allow", path: "/search", query: "q=<script>alert(1)</script>", ua: "sqlmap/1.7", country: "RU" }),
  ];

  // C — identity chain: new-geo login -> env var read (Supabase + Vercel)
  const cT0 = BASE + 6 * DAY + 22 * 3600;
  const cSb: SupabaseNative[] = [sb(cT0, "u_victim", "login_success", { ip: "203.0.113.30", country: "RU", username: "u_victim@x.co" })];
  const cVc: VercelNative[] = [vc(cT0 + 300, "203.0.113.30", { route: "/api/env", user: "u_victim", envRead: true, country: "RU" })];

  // D — enumeration / scanning (Vercel traces)
  const dIp = "203.0.113.40";
  const dT0 = BASE + 6 * DAY + 23 * 3600;
  const dEvents: VercelNative[] = [];
  for (let i = 0; i < 60; i++) {
    dEvents.push(vc(dT0 + i * 2, dIp, { route: `/api/admin/${String(i)}`, status: i % 3 === 0 ? 403 : 404, country: "RU" }));
  }

  return {
    A: { native: { supabase: aEvents }, truth: { actor: aIp, start: aT0, end: aT0 + 400, observable: true, note: "credential stuffing -> ATO" } },
    B: { native: { cloudflare: bEvents }, truth: { actor: bIp, start: bT0, end: bT0 + 60, observable: true, note: "SQLi / path traversal / scanner" } },
    C: { native: { supabase: cSb, vercel: cVc }, truth: { actor: "u_victim", start: cT0, end: cT0 + 400, observable: true, sourcesNeeded: ["supabase", "vercel"], note: "ATO -> secret exfil (Vercel-breach shape)" } },
    D: { native: { vercel: dEvents }, truth: { actor: dIp, start: dT0, end: dT0 + 200, observable: true, note: "endpoint enumeration / scanning" } },
    F: { native: {}, truth: { actor: "host-1", start: BASE + 6 * DAY, end: BASE + 7 * DAY, observable: false, note: "in-host runtime (expected blind spot)" } },
  };
}

// Scenario G — DISTRIBUTED RECON. ~40 IPs, 5 distinct 404 paths each, from 2
// previously-unseen ASNs, in a short window. NO single IP trips a per-Entity rule;
// the aggregate detectors must catch it. (The "38% zone-wide 404s across 221 IPs".)
export function aggregateFixture(): Attack {
  const t0 = BASE + 6 * DAY + 23 * 3600 + 1800; // 23:30, after D (23:00)
  const events: CloudflareHttpNative[] = [];
  for (let i = 0; i < 40; i++) {
    const ip = `45.135.${String(Math.floor(i / 8))}.${String((i % 8) + 1)}`;
    const asn = i % 2 === 0 ? 213371 : 60068;
    for (let k = 0; k < 5; k++) {
      events.push(cfh(t0 + i * 3 + k, ip, { path: `/products/${String(i * 5 + k)}`, status: 404, asn, country: "NL" }));
    }
  }
  return {
    native: { cloudflare_http: events },
    truth: { actor: "project", start: t0, end: t0 + 200, observable: true, note: "distributed recon (aggregate edge)" },
  };
}
