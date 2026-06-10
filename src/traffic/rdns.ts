// Forward-confirmed reverse DNS (FCrDNS) — the standard way to prove a request that *claims*
// to be Googlebot/Bingbot/etc. actually comes from that operator's network (and to catch
// impersonators). PTR the IP → hostname must end in the operator's official suffix → forward-
// resolve that hostname → must include the original IP.
//
// This is a NETWORK enrichment (two DNS lookups per crawler-claiming IP). It is GATED behind
// VALLHUND_RDNS_VERIFY (default off) and bounded by a hard per-lookup timeout, so it can be
// vetted on real traffic before being enabled. Like GreyNoise, it runs at WRITE time only
// (snapshot enrichment), never on the read path, and caches per IP.

import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import { classifyActor } from "./actors.ts";
import { BoundedCache } from "../util/bounded-cache.ts";

/** "verified" = FCrDNS confirmed the claimed crawler. "spoofed" = it claims a verifiable
 *  crawler but DNS says otherwise. "unverified" = not checked / not conclusive (the default,
 *  and what every actor gets when the gate is off). */
export type CrawlerVerdict = "verified" | "spoofed" | "unverified";

/** Official rDNS suffixes per verifiable search crawler. Keyed by the crawler `name` that
 *  classifyActor() returns. Only crawlers with stable, documented reverse DNS belong here —
 *  AI agents publish CIDR lists, not rDNS, so they stay UA-recognized (never reach here). */
const CRAWLER_SUFFIXES: Record<string, string[]> = {
  Googlebot: ["googlebot.com", "google.com"],
  Bingbot: ["search.msn.com"],
  YandexBot: ["yandex.com", "yandex.net", "yandex.ru"],
  Applebot: ["applebot.apple.com"],
};

export function isVerifiableCrawler(name: string | null): boolean {
  return name !== null && name in CRAWLER_SUFFIXES;
}

/** Does this UA *claim* to be a crawler we can FCrDNS-verify (Googlebot/Bingbot/…)? ASN-independent
 *  — we want the claim regardless of network, so verifyCrawler can confirm or refute it. Lives here
 *  next to the crawler registry it keys off, not in the engine. */
export function claimsVerifiableCrawler(ua: string): boolean {
  return isVerifiableCrawler(classifyActor(ua, null).name);
}

/** Process-wide gate. Off unless VALLHUND_RDNS_VERIFY is a truthy ("1"/"true") env value. */
export function rdnsEnabled(): boolean {
  const v = process.env["VALLHUND_RDNS_VERIFY"];
  return v === "1" || v === "true";
}

const TIMEOUT_MS = 2000;

function withTimeout<T>(p: Promise<T>, fallback: T): Promise<T> {
  return new Promise<T>((resolve) => {
    let settled = false;
    const t = setTimeout(() => { if (!settled) { settled = true; resolve(fallback); } }, TIMEOUT_MS);
    p.then((v) => { if (!settled) { settled = true; clearTimeout(t); resolve(v); } },
           () => { if (!settled) { settled = true; clearTimeout(t); resolve(fallback); } });
  });
}

const cache = new BoundedCache<string, CrawlerVerdict>(20000);

/** Verify that `ip` is the crawler named by `crawlerName` via forward-confirmed reverse DNS.
 *  Returns "unverified" when the gate is off, the name isn't a verifiable crawler, or DNS is
 *  inconclusive/times out — i.e. it only ever *upgrades* trust, never fabricates a foe. */
export async function verifyCrawler(ip: string, crawlerName: string | null): Promise<CrawlerVerdict> {
  if (crawlerName === null || !rdnsEnabled() || !isVerifiableCrawler(crawlerName)) return "unverified";
  const key = `${ip}|${crawlerName}`;
  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  const verdict = await computeVerdict(ip, crawlerName);
  cache.set(key, verdict);
  return verdict;
}

async function computeVerdict(ip: string, crawlerName: string): Promise<CrawlerVerdict> {
  const suffixes = CRAWLER_SUFFIXES[crawlerName] ?? [];
  const hostnames = await withTimeout(dns.reverse(ip), [] as string[]);
  const match = hostnames.find((h) => suffixes.some((s) => h.toLowerCase() === s || h.toLowerCase().endsWith(`.${s}`)));
  if (match === undefined) {
    // It claims a verifiable crawler but PTR doesn't land in the operator's domain — a spoof
    // signal only if rDNS actually resolved to something; an empty/timed-out lookup is inconclusive.
    return hostnames.length > 0 ? "spoofed" : "unverified";
  }
  const forward = await withTimeout(resolveBoth(match), [] as string[]);
  if (forward.length === 0) return "unverified";
  // Compare by normalized form: Cloudflare's clientIP and dns.resolve6() can express the same IPv6
  // address in different textual shapes (::-compression, zero-padding, case). A raw includes() would
  // misread a genuine IPv6 crawler as spoofed.
  return forward.some((f) => sameIp(f, ip)) ? "verified" : "spoofed";
}

/** Fully expand an IPv6 address (resolve "::", pad each group to 4 hex) for textual equality.
 *  Leaves IPv4-embedded forms and anything malformed lowercased-but-unexpanded (so we never
 *  fabricate equality between two different addresses). */
function expandIpv6(addr: string): string {
  const s = (addr.split("%")[0] ?? addr).toLowerCase(); // drop any zone id
  if (s.includes(".")) return s; // IPv4-mapped/embedded — rare for crawler rDNS; compare as-is
  const dbl = s.indexOf("::");
  let groups: string[];
  if (dbl === -1) {
    groups = s.split(":");
  } else {
    const left = s.slice(0, dbl).split(":").filter((g) => g !== "");
    const right = s.slice(dbl + 2).split(":").filter((g) => g !== "");
    const fill = new Array<string>(8 - left.length - right.length).fill("0");
    groups = [...left, ...fill, ...right];
  }
  if (groups.length !== 8) return s; // malformed — don't fabricate an expansion
  return groups.map((g) => g.padStart(4, "0")).join(":");
}

/** IP equality that survives textual differences (IPv4 exact/lowercased; IPv6 expanded). */
function sameIp(a: string, b: string): boolean {
  if (a === b) return true;
  const na = isIP(a) === 6 ? expandIpv6(a) : a.trim().toLowerCase();
  const nb = isIP(b) === 6 ? expandIpv6(b) : b.trim().toLowerCase();
  return na === nb;
}

async function resolveBoth(host: string): Promise<string[]> {
  const [a, aaaa] = await Promise.all([
    dns.resolve4(host).catch(() => [] as string[]),
    dns.resolve6(host).catch(() => [] as string[]),
  ]);
  return [...a, ...aaaa];
}

/** Test-only: reset the per-IP cache between cases. */
export function _resetRdnsCache(): void {
  cache.clear();
}
