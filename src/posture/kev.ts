// CISA Known Exploited Vulnerabilities (KEV) enrichment. KEV answers a narrower, more actionable
// question than raw CVE volume — "is this exploited in the wild?" — so we use it to PRIORITIZE
// existing GitHub posture findings (raise to high + a calm note), not as a CVE scanner. Best-effort
// + fail-open: if CISA is unreachable, posture scanning works unchanged with no enrichment.

import type { PostureFinding } from "./types.ts";

const KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CACHE_TTL_MS = 6 * 3600 * 1000;
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

export interface KevEntry {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  knownRansomwareCampaignUse?: string;
  requiredAction?: string;
  dueDate?: string;
}

export interface KevCatalog {
  has(cve: string): boolean;
  get(cve: string): KevEntry | undefined;
  size: number;
}

/** All distinct CVE ids in a blob of text, normalized uppercase. */
export function extractCves(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(CVE_RE)) out.add(m[0].toUpperCase());
  return [...out];
}

/** Pure: parse the CISA KEV JSON into a CVE-keyed lookup. Tolerates malformed input (empty). */
export function parseKevCatalog(json: unknown): KevCatalog {
  const map = new Map<string, KevEntry>();
  const vulns = (json as { vulnerabilities?: unknown } | null)?.vulnerabilities;
  if (Array.isArray(vulns)) {
    const OPT = ["vendorProject", "product", "vulnerabilityName", "dateAdded", "knownRansomwareCampaignUse", "requiredAction", "dueDate"] as const;
    for (const v of vulns) {
      const r = v as Record<string, unknown>;
      const cveRaw = r["cveID"];
      if (typeof cveRaw !== "string") continue;
      const cve = cveRaw.toUpperCase();
      const entry: KevEntry = { cveID: cve };
      for (const k of OPT) { const val = r[k]; if (typeof val === "string") entry[k] = val; }
      map.set(cve, entry);
    }
  }
  return { has: (c) => map.has(c.toUpperCase()), get: (c) => map.get(c.toUpperCase()), size: map.size };
}

const EMPTY: KevCatalog = { has: () => false, get: () => undefined, size: 0 };
let cache: { catalog: KevCatalog; exp: number } | null = null;

/** Fetch + cache (6h, process-local) the KEV catalog. Network failure → empty catalog (fail open). */
export async function getKevCatalog(): Promise<KevCatalog> {
  const now = Date.now();
  if (cache !== null && cache.exp > now) return cache.catalog;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => { ctrl.abort(); }, 8000);
    let json: unknown;
    try {
      const res = await fetch(KEV_FEED_URL, { signal: ctrl.signal });
      if (!res.ok) return EMPTY;
      json = await res.json();
    } finally {
      clearTimeout(t);
    }
    const catalog = parseKevCatalog(json);
    cache = { catalog, exp: now + CACHE_TTL_MS };
    return catalog;
  } catch {
    return EMPTY; // fail open — posture scanning continues without enrichment
  }
}

/** Pure: if any CVE in `cveText` is in KEV, raise the finding to high and add a calm KEV note.
 *  Returns the finding unchanged when nothing matches. */
export function kevEnrich(finding: PostureFinding, cveText: string, catalog: KevCatalog): PostureFinding {
  const matched = extractCves(cveText).filter((c) => catalog.has(c));
  if (matched.length === 0) return finding;

  const ransomware = matched.some((c) => catalog.get(c)?.knownRansomwareCampaignUse === "Known");
  const shown = matched.slice(0, 3).join(", ");
  const more = matched.length > 3 ? ` (+${String(matched.length - 3)} more)` : "";
  const ransomNote = ransomware ? " It has been used in ransomware campaigns." : "";

  return {
    ...finding,
    severity: "high",
    kev: true,
    detail: `CISA lists ${shown}${more} as known exploited.${ransomNote} That doesn't mean your app was exploited, but it should be patched ahead of ordinary dependency noise. ${finding.detail}`,
    fix: `${finding.fix} Prioritize: CISA KEV marks this exploited in the wild — patch or mitigate before other dependency updates.`,
  };
}
