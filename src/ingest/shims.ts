// Ingestion shims — one normalizer per Source native shape -> NormalizedEvent.
// Going live = replace the fetch (see sources/*); normalize() stays identical.

import { A, type NormalizedEvent } from "../engine/schema.ts";
import type {
  CloudTrailNative,
  CloudflareHttpNative,
  CloudflareWafNative,
  GcpAuditNative,
  GithubAuditNative,
  NativeBatch,
  SupabaseNative,
  VercelDrainNative,
  VercelNative,
  ZitadelNative,
} from "./native.ts";

const KNOWN_GOOD_BOT_UA = ["goodbot", "googlebot", "bingbot"];
const VERIFIED_ASNS = new Set<number>([15169]); // e.g. Google

export function isVerifiedBot(ua: string | null, asn: number | null): boolean {
  if (ua !== null && KNOWN_GOOD_BOT_UA.some((s) => ua.toLowerCase().includes(s))) return true;
  if (asn !== null && VERIFIED_ASNS.has(asn)) return true;
  return false;
}

const CF_ACTION_OUTCOME: Record<string, string> = {
  block: "block",
  managed_challenge: "block",
  allow: "allow",
  log: "allow",
  skip: "allow",
};

export function normalizeCloudflare(raw: CloudflareWafNative): NormalizedEvent {
  return {
    ts: raw.datetime,
    source: "cloudflare",
    action: A.WAF,
    actor: raw.clientIP,
    ip: raw.clientIP,
    asn: raw.clientAsn,
    country: raw.clientCountryName,
    userAgent: raw.userAgent,
    resource: raw.clientRequestPath,
    query: raw.clientRequestQuery,
    status: null,
    outcome: CF_ACTION_OUTCOME[raw.action] ?? "allow",
    verifiedBot: isVerifiedBot(raw.userAgent, raw.clientAsn),
    meta: { ruleset: raw.source },
  };
}

// All-traffic dataset (Cloudflare httpRequestsAdaptive) — HTTP requests with a
// status, where the friend/foe + aggregate-recon signal actually lives.
export function normalizeCloudflareHttp(raw: CloudflareHttpNative): NormalizedEvent {
  return {
    ts: raw.datetime,
    source: "cloudflare",
    action: A.HTTP,
    actor: raw.clientIP,
    ip: raw.clientIP,
    asn: raw.clientAsn,
    country: raw.clientCountryName,
    userAgent: raw.userAgent,
    resource: raw.clientRequestPath,
    query: raw.clientRequestQuery,
    status: raw.edgeResponseStatus,
    outcome: "allow",
    contentType: raw.contentType ?? null,
    verifiedBot: isVerifiedBot(raw.userAgent, raw.clientAsn),
    meta: { host: raw.host ?? null }, // the proxied gateway/app — the traffic "base"
  };
}

// Supabase GoTrue audit actions -> our action vocabulary. (Fixtures already use the
// vocabulary directly, so they fall through unchanged.)
export const SUPABASE_ACTION: Record<string, string> = {
  login: A.LOGIN_OK,
  user_signedup: A.LOGIN_OK,
  token_refreshed: A.TOKEN,
};

export function normalizeSupabase(raw: SupabaseNative): NormalizedEvent {
  const p = raw.payload;
  const action = SUPABASE_ACTION[p.action] ?? p.action;
  return {
    ts: raw.created_at,
    source: "supabase",
    action,
    actor: p.actor_id,
    ip: raw.ip_address, // caveat: empty without Sb-Forwarded-For
    asn: null,
    country: p.traits.country,
    userAgent: p.traits.user_agent,
    resource: "auth.audit_log_entries",
    query: "",
    status: null,
    outcome: action === A.LOGIN_FAIL ? "failure" : "success",
    verifiedBot: false,
    meta: { username: p.actor_username },
  };
}

export function normalizeVercel(raw: VercelNative): NormalizedEvent {
  const a = raw.attributes;
  const user = a["user.id"];
  const ip = a["client.address"];
  const isEnv = a["vercel.env_var_read"] ?? false;
  return {
    ts: raw.startTimeUnixNano / 1e9,
    source: "vercel",
    action: isEnv ? A.ENV_READ : A.HTTP,
    actor: user ?? ip,
    ip,
    asn: null,
    country: a["client.country"],
    userAgent: a["user_agent.original"],
    resource: a["http.route"],
    query: "",
    status: a["http.status_code"],
    outcome: null,
    verifiedBot: isVerifiedBot(a["user_agent.original"], null),
    meta: { traceId: raw.traceId },
  };
}

// Vercel log-drain request entry (the PUSH path) -> NormalizedEvent. Request logs carry
// a `proxy` block with the client IP / path / status — an HTTP stream like Cloudflare,
// so it feeds enumeration + the aggregate recon detectors for Vercel-hosted apps.
export function normalizeVercelDrain(raw: VercelDrainNative): NormalizedEvent {
  const px = raw.proxy ?? {};
  const ua = Array.isArray(px.userAgent) ? (px.userAgent[0] ?? null) : (px.userAgent ?? null);
  const ip = px.clientIp ?? "";
  return {
    ts: raw.timestamp !== undefined ? Math.floor(raw.timestamp / 1000) : 0,
    source: "vercel",
    action: A.HTTP,
    actor: ip,
    ip,
    asn: null,
    country: null,
    userAgent: ua,
    resource: px.path ?? raw.path ?? "",
    query: "",
    status: px.statusCode ?? raw.statusCode ?? null,
    outcome: "allow",
    verifiedBot: isVerifiedBot(ua, null),
    meta: { region: px.region ?? null, host: raw.host ?? null },
  };
}

// Zitadel auth events. event-type -> our action vocabulary.
export const ZITADEL_ACTION: Record<string, string> = {
  "user.human.password.check.succeeded": A.LOGIN_OK,
  "user.human.passwordless.check.succeeded": A.LOGIN_OK,
  "user.human.otp.check.succeeded": A.LOGIN_OK,
  "user.human.password.check.failed": A.LOGIN_FAIL,
  "user.token.added": A.TOKEN,
  "user.token.v2.added": A.TOKEN,
  "user.grant.added": A.OAUTH,
};

export function normalizeZitadel(raw: ZitadelNative): NormalizedEvent {
  const action = ZITADEL_ACTION[raw.eventType] ?? raw.eventType;
  return {
    ts: raw.creationDate,
    source: "zitadel",
    action,
    actor: raw.userId,
    ip: raw.ip,
    asn: null,
    country: raw.country,
    userAgent: raw.userAgent,
    resource: "zitadel.events",
    query: "",
    status: null,
    outcome: action === A.LOGIN_FAIL ? "failure" : action === A.LOGIN_OK ? "success" : null,
    verifiedBot: false,
    meta: { eventType: raw.eventType, username: raw.userName },
  };
}

// GitHub audit-log actions -> our action vocabulary. The supply-chain/identity
// signal lives in third-party access grants, app installs, and membership changes —
// the entry vector behind the Vercel breach class.
export const GITHUB_ACTION: Record<string, string> = {
  "oauth_authorization.create": A.OAUTH,
  "oauth_application.create": A.OAUTH,
  "integration_installation.create": A.OAUTH, // a GitHub App granted access
  "integration_installation_request.create": A.OAUTH,
  "personal_access_token.create": A.TOKEN,
  "personal_access_token.request_created": A.TOKEN,
  "org.add_member": A.MEMBER,
  "org.invite_member": A.MEMBER,
  "org.update_member": A.MEMBER, // role change (e.g. promoted to admin)
};

export function normalizeGithub(raw: GithubAuditNative): NormalizedEvent {
  const action = GITHUB_ACTION[raw.action] ?? raw.action;
  return {
    ts: raw.timestamp,
    source: "github",
    action,
    actor: raw.actor,
    ip: raw.ip,
    asn: null,
    country: raw.country,
    userAgent: null,
    resource: raw.repo ?? "",
    query: "",
    status: null,
    outcome: null,
    verifiedBot: false,
    meta: { githubAction: raw.action },
  };
}

// AWS CloudTrail control-plane events. Console logins feed credential_stuffing; sensitive
// management actions (kept as the raw event name) feed the control_plane detector.
export function normalizeCloudTrail(raw: CloudTrailNative): NormalizedEvent {
  const isLogin = raw.eventName === "ConsoleLogin";
  const action = isLogin ? (raw.errorCode !== null ? A.LOGIN_FAIL : A.LOGIN_OK) : raw.eventName;
  return {
    ts: raw.time,
    source: "aws",
    action,
    actor: raw.username !== "" ? raw.username : raw.sourceIp,
    ip: raw.sourceIp,
    asn: null,
    country: null,
    userAgent: null,
    resource: raw.eventSource,
    query: "",
    status: null,
    outcome: isLogin ? (raw.errorCode !== null ? "failure" : "success") : null,
    verifiedBot: false,
    meta: { eventName: raw.eventName, errorCode: raw.errorCode },
  };
}

// GCP Cloud Audit Logs (admin activity). The method name is kept as the action so the
// (cloud-source-agnostic) control_plane detector can flag sensitive IAM / admin calls.
export function normalizeGcp(raw: GcpAuditNative): NormalizedEvent {
  return {
    ts: raw.time,
    source: "gcp",
    action: raw.methodName,
    actor: raw.principal !== "" ? raw.principal : raw.callerIp,
    ip: raw.callerIp,
    asn: null,
    country: null,
    userAgent: null,
    resource: raw.resource !== "" ? raw.resource : raw.serviceName,
    query: "",
    status: raw.statusCode,
    outcome: raw.statusCode !== null && raw.statusCode !== 0 ? "failure" : "success",
    verifiedBot: false,
    meta: { eventName: raw.methodName, serviceName: raw.serviceName },
  };
}

/** Normalize a typed batch of native records, sorted by time. */
export function normalizeNative(batch: NativeBatch): NormalizedEvent[] {
  const out: NormalizedEvent[] = [];
  for (const r of batch.cloudflare ?? []) out.push(normalizeCloudflare(r));
  for (const r of batch.cloudflare_http ?? []) out.push(normalizeCloudflareHttp(r));
  for (const r of batch.supabase ?? []) out.push(normalizeSupabase(r));
  for (const r of batch.vercel ?? []) out.push(normalizeVercel(r));
  for (const r of batch.zitadel ?? []) out.push(normalizeZitadel(r));
  for (const r of batch.github ?? []) out.push(normalizeGithub(r));
  for (const r of batch.aws ?? []) out.push(normalizeCloudTrail(r));
  for (const r of batch.gcp ?? []) out.push(normalizeGcp(r));
  out.sort((x, y) => x.ts - y.ts);
  return out;
}
