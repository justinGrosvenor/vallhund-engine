// "Front door" scan — a lightweight, non-intrusive external check of a public URL the user owns
// (their app's front door). No credentials. We read response headers + probe a small fixed set of
// well-known sensitive paths (content-signature checked to avoid SPA false positives) and emit
// PostureFindings. NOT a vuln scanner: a few timed requests, no fuzzing/exploitation. The URL is
// SSRF-guarded (public https only) so this can never be aimed at internal/metadata hosts.

import { assertPublicHttpsUrl } from "../util/ssrf-guard.ts";
import type { PostureFinding } from "./types.ts";

const TIMEOUT_MS = 8000;
const enc = (s: string): string => encodeURIComponent(s);

async function fetchT(url: string, init?: RequestInit): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => { ctrl.abort(); }, TIMEOUT_MS);
  try {
    return await fetch(url, { redirect: "manual", headers: { "User-Agent": "Vallhund-frontdoor/1" }, ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

interface HeaderRule { header: string; label: string; severity: "low" | "medium"; fix: string }
const SECURITY_HEADERS: HeaderRule[] = [
  { header: "strict-transport-security", label: "HSTS", severity: "medium", fix: "Send Strict-Transport-Security: max-age=63072000; includeSubDomains" },
  { header: "content-security-policy", label: "Content-Security-Policy", severity: "medium", fix: "Add a Content-Security-Policy restricting script/connect sources" },
  { header: "x-content-type-options", label: "X-Content-Type-Options", severity: "low", fix: "Send X-Content-Type-Options: nosniff" },
  { header: "x-frame-options", label: "clickjacking protection", severity: "low", fix: "Send X-Frame-Options: DENY (or CSP frame-ancestors)" },
  { header: "referrer-policy", label: "Referrer-Policy", severity: "low", fix: "Send Referrer-Policy: strict-origin-when-cross-origin" },
];

function disclosure(host: string, name: string, value: string): PostureFinding {
  return {
    id: enc(`frontdoor:disclosure:${host}:${name}`),
    rule: "version-disclosure",
    severity: "low",
    resource: host,
    detail: `The ${name} response header reveals "${value}" — version/stack disclosure helps an attacker target known CVEs.`,
    fix: `Remove or genericize the ${name} header.`,
    coverage: ["app", "config"],
    status: "open",
  };
}

function noSecurityTxt(host: string): PostureFinding {
  return {
    id: enc(`frontdoor:no-security-txt:${host}`),
    rule: "no-security-txt",
    severity: "low",
    resource: host,
    detail: `${host} has no /.well-known/security.txt — researchers have no published channel to report a vulnerability.`,
    fix: "Publish /.well-known/security.txt (RFC 9116) with a contact + policy URL.",
    coverage: ["app", "config"],
    status: "open",
  };
}

/** Pure: turn a root response's headers into header/disclosure findings. */
export function analyzeHeaders(url: string, headers: Headers): PostureFinding[] {
  const host = new URL(url).host;
  const out: PostureFinding[] = [];
  // X-Frame-Options OR CSP frame-ancestors satisfies clickjacking protection
  const hasFrameAncestors = (headers.get("content-security-policy") ?? "").includes("frame-ancestors");
  for (const r of SECURITY_HEADERS) {
    if (r.header === "x-frame-options" && hasFrameAncestors) continue;
    if (headers.has(r.header)) continue;
    out.push({
      id: enc(`frontdoor:header:${host}:${r.header}`),
      rule: "missing-security-header",
      severity: r.severity,
      resource: host,
      detail: `${r.label} is not set on ${host}.`,
      fix: r.fix,
      coverage: ["app", "config"],
      status: "open",
    });
  }
  const powered = headers.get("x-powered-by");
  if (powered !== null && powered !== "") out.push(disclosure(host, "X-Powered-By", powered));
  const server = headers.get("server");
  if (server !== null && /\d/.test(server)) out.push(disclosure(host, "Server", server)); // only when it leaks a version
  return out;
}

/** Pure: flag Set-Cookie values missing hardening flags. One finding per cookie (lists what's
 *  missing). Missing Secure is medium (interceptable over http); HttpOnly/SameSite alone is low. */
export function analyzeCookies(host: string, cookies: string[]): PostureFinding[] {
  const out: PostureFinding[] = [];
  for (const c of cookies) {
    const name = (c.split("=")[0] ?? "cookie").trim() || "cookie";
    const lc = c.toLowerCase();
    const missing: string[] = [];
    if (!lc.includes("secure")) missing.push("Secure");
    if (!lc.includes("httponly")) missing.push("HttpOnly");
    if (!lc.includes("samesite")) missing.push("SameSite");
    if (missing.length === 0) continue;
    out.push({
      id: enc(`frontdoor:cookie:${host}:${name}`),
      rule: "insecure-cookie",
      severity: missing.includes("Secure") ? "medium" : "low",
      resource: `${host} (${name})`,
      detail: `The ${name} cookie is set without ${missing.join(", ")} — session cookies should carry all three.`,
      fix: `Set ${missing.join(", ")} on the ${name} cookie.`,
      coverage: ["app", "config"],
      status: "open",
    });
  }
  return out;
}

interface Probe { path: string; label: string; looksExposed: (body: string) => boolean }
const PROBES: Probe[] = [
  { path: "/.env", label: ".env file", looksExposed: (b) => /^[A-Z][A-Z0-9_]*=/m.test(b) && !/<html/i.test(b) },
  { path: "/.git/HEAD", label: ".git repository", looksExposed: (b) => b.trimStart().startsWith("ref:") },
  { path: "/.git/config", label: ".git config", looksExposed: (b) => b.includes("[core]") },
  { path: "/.aws/credentials", label: "AWS credentials", looksExposed: (b) => /aws_access_key_id/i.test(b) },
  { path: "/docker-compose.yml", label: "docker-compose.yml", looksExposed: (b) => /^services:/m.test(b) && !/<html/i.test(b) },
  { path: "/.npmrc", label: ".npmrc (registry auth)", looksExposed: (b) => /_authToken=|_auth=|\/\/.*\/:_/.test(b) && !/<html/i.test(b) },
  { path: "/server-status", label: "Apache mod_status page", looksExposed: (b) => /Apache Server Status|Server uptime:/i.test(b) },
];

/** Pure: a directly-served (200) path whose body matches the file's signature is exposed. */
export function analyzeProbe(host: string, probe: Probe, status: number, body: string): PostureFinding | null {
  if (status !== 200 || !probe.looksExposed(body)) return null;
  return {
    id: enc(`frontdoor:exposed:${host}:${probe.path}`),
    rule: "exposed-file",
    severity: "high",
    resource: `${host}${probe.path}`,
    detail: `${probe.label} is publicly served at ${probe.path} on ${host} — this can leak secrets or source.`,
    fix: `Block ${probe.path} at the edge/web root and rotate any credentials it exposed.`,
    coverage: ["app", "config"],
    status: "open",
  };
}

/** Scan a public front-door URL. Best-effort; returns [] (not throws) on unreachable/invalid. */
export async function scanFrontDoor(url: string): Promise<PostureFinding[]> {
  try {
    await assertPublicHttpsUrl(url); // public https only — never scan internal/metadata hosts
  } catch {
    return [{
      id: enc(`frontdoor:invalid:${url}`),
      rule: "front-door-url",
      severity: "low",
      resource: url,
      detail: "The front-door URL must be a public https:// address.",
      fix: "Set the connection's URL to your app's public https origin.",
      coverage: ["app"],
      status: "open",
    }];
  }
  const host = new URL(url).host;
  const base = url.replace(/\/+$/, "");
  const out: PostureFinding[] = [];

  try {
    const res = await fetchT(url, { redirect: "follow" });
    out.push(...analyzeHeaders(url, res.headers));
    out.push(...analyzeCookies(host, res.headers.getSetCookie()));
  } catch {
    return out; // unreachable — nothing to assess
  }

  // security.txt (RFC 9116) — a missing one means researchers have no clear way to report issues
  try {
    const res = await fetchT(`https://${host}/.well-known/security.txt`, { redirect: "follow" });
    if (res.status !== 200) out.push(noSecurityTxt(host));
  } catch {
    out.push(noSecurityTxt(host));
  }

  // HTTP must redirect to HTTPS (a 200 over plain http means it's served unencrypted)
  try {
    const res = await fetchT(url.replace(/^https:/i, "http:"), { redirect: "manual" });
    if (res.status === 200) {
      out.push({
        id: enc(`frontdoor:no-https:${host}`),
        rule: "no-https-redirect",
        severity: "medium",
        resource: host,
        detail: `${host} serves content over plain HTTP without redirecting to HTTPS.`,
        fix: "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.",
        coverage: ["network", "app"],
        status: "open",
      });
    }
  } catch { /* http not served — fine */ }

  for (const p of PROBES) {
    try {
      const res = await fetchT(`${base}${p.path}`, { redirect: "manual" });
      const body = res.status === 200 ? (await res.text()).slice(0, 4096) : "";
      const finding = analyzeProbe(host, p, res.status, body);
      if (finding !== null) out.push(finding);
    } catch { /* skip this probe */ }
  }
  return out;
}
