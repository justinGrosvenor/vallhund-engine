// SSRF guard for tenant-supplied outbound URLs (webhook notification channels). A customer
// controls the webhook URL the worker POSTs to, so without this they could point it at cloud
// metadata (169.254.169.254), loopback, or RFC1918 hosts to probe our internal network. We
// require https and reject any URL whose host — literal IP or every DNS-resolved address —
// falls in a non-public range (checking all resolved addresses also defeats DNS rebinding at
// validation time). Callers must additionally fetch with redirects disabled.

import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

function ipv4Blocked(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const o = parts.map((p) => Number(p));
  if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = o as [number, number, number, number];
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 127) return true; // loopback
  if (a === 0) return true; // "this" network / unspecified
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // multicast / reserved (224.0.0.0+)
  return false;
}

function ipv6Blocked(ip: string): boolean {
  const v = ip.toLowerCase();
  if (v === "::1" || v === "::") return true; // loopback / unspecified
  if (v.startsWith("fe80") || v.startsWith("fe9") || v.startsWith("fea") || v.startsWith("feb")) return true; // fe80::/10 link-local
  if (v.startsWith("fc") || v.startsWith("fd")) return true; // fc00::/7 unique-local
  if (v.startsWith("ff")) return true; // multicast
  const mapped = /^(?:::ffff:)(\d+\.\d+\.\d+\.\d+)$/.exec(v); // IPv4-mapped ::ffff:a.b.c.d
  if (mapped?.[1] !== undefined) return ipv4Blocked(mapped[1]);
  return false;
}

/** True if an IP literal is in a non-public (private/loopback/link-local/metadata) range. */
export function isBlockedIp(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) return ipv4Blocked(ip);
  if (kind === 6) return ipv6Blocked(ip);
  return false;
}

/** Throw unless `raw` is an https URL whose host resolves only to public addresses. */
export async function assertPublicHttpsUrl(raw: string): Promise<void> {
  let u: URL;
  try { u = new URL(raw); } catch { throw new Error("invalid webhook URL"); }
  if (u.protocol !== "https:") throw new Error("webhook URL must use https");
  const host = u.hostname.replace(/^\[|\]$/g, ""); // URL.hostname brackets IPv6 literals

  if (isIP(host) !== 0) {
    if (isBlockedIp(host)) throw new Error("webhook URL host is not a public address");
    return;
  }
  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new Error("webhook host did not resolve");
  }
  if (addrs.length === 0) throw new Error("webhook host did not resolve");
  for (const a of addrs) {
    if (isBlockedIp(a.address)) throw new Error("webhook URL resolves to a non-public address");
  }
}
