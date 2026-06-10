// Actor classification — "who is at the door." Turns a request's user-agent (+ ASN where we
// have it) into a coarse actor class: human, search crawler, AI agent, generic automation, or
// unknown. This is the maintained asset behind the traffic pillar — the UA registry (esp. the
// AI-agent list) and the ASN-consistency spoof check compound over time.
//
// Deliberately standalone and pure: it is derived OUTSIDE runEngine (in the traffic profile),
// so it never perturbs the engine's detections or the golden oracle. In particular it does NOT
// touch isVerifiedBot (ingest/shims.ts), which stays the engine's narrow friend-leaning signal.

export type ActorClass = "human" | "search_crawler" | "ai_agent" | "automation" | "unknown";

export interface ActorVerdict {
  /** Coarse class. A spoofed crawler/agent is reported as "automation" (it isn't who it claims). */
  cls: ActorClass;
  /** Recognized bot/agent name when known (e.g. "GPTBot"); the *claimed* name when spoofed. */
  name: string | null;
  /** UA claim is ASN-consistent (only provable for crawlers we have an ASN for). */
  verified: boolean;
  /** UA claims a known crawler but the ASN says otherwise — impersonation. */
  spoofed: boolean;
}

interface Sig {
  name: string;
  /** lowercased UA substrings — any match assigns this signature. */
  needles: string[];
  cls: ActorClass;
  /** ASNs that legitimately operate this bot. Present only where a UA claim is ASN-verifiable. */
  verifyAsns?: number[];
}

// AI agents — LLM/AI-company crawlers, on-demand fetchers, and training scrapers. The timely,
// differentiated class. These run from cloud ASNs (often published as CIDR lists, not a single
// ASN), so we generally can't ASN-verify them — recognition is by UA. Extend freely.
const AI_AGENTS: Sig[] = [
  { name: "GPTBot", needles: ["gptbot"], cls: "ai_agent" },
  { name: "OAI-SearchBot", needles: ["oai-searchbot"], cls: "ai_agent" },
  { name: "ChatGPT-User", needles: ["chatgpt-user"], cls: "ai_agent" },
  { name: "ClaudeBot", needles: ["claudebot"], cls: "ai_agent" },
  { name: "Claude-User", needles: ["claude-user", "claude-web"], cls: "ai_agent" },
  { name: "anthropic-ai", needles: ["anthropic-ai"], cls: "ai_agent" },
  { name: "PerplexityBot", needles: ["perplexitybot"], cls: "ai_agent" },
  { name: "Perplexity-User", needles: ["perplexity-user"], cls: "ai_agent" },
  { name: "CCBot", needles: ["ccbot"], cls: "ai_agent" }, // Common Crawl — feeds most LLM training sets
  { name: "Bytespider", needles: ["bytespider"], cls: "ai_agent" }, // ByteDance
  { name: "Amazonbot", needles: ["amazonbot"], cls: "ai_agent" }, // Alexa / AI answers
  { name: "Meta-ExternalAgent", needles: ["meta-externalagent", "meta-externalfetcher"], cls: "ai_agent" },
  { name: "Applebot-Extended", needles: ["applebot-extended"], cls: "ai_agent" }, // AI-training variant (before plain Applebot)
  { name: "Google-CloudVertexBot", needles: ["google-cloudvertexbot"], cls: "ai_agent" },
  { name: "cohere-ai", needles: ["cohere-ai", "cohere-training-data-crawler"], cls: "ai_agent" },
  { name: "Diffbot", needles: ["diffbot"], cls: "ai_agent" },
  { name: "YouBot", needles: ["youbot"], cls: "ai_agent" }, // You.com
  { name: "DuckAssistBot", needles: ["duckassistbot"], cls: "ai_agent" },
  { name: "MistralAI-User", needles: ["mistralai-user"], cls: "ai_agent" },
  { name: "Timpibot", needles: ["timpibot"], cls: "ai_agent" },
];

// Declared search/index crawlers (search engines + SEO/archival indexers). The big three carry
// known ASNs, so a UA claiming them from elsewhere is a strong spoof signal.
const CRAWLERS: Sig[] = [
  { name: "Googlebot", needles: ["googlebot"], cls: "search_crawler", verifyAsns: [15169] },
  { name: "Bingbot", needles: ["bingbot", "bingpreview", "msnbot"], cls: "search_crawler", verifyAsns: [8075] },
  { name: "YandexBot", needles: ["yandexbot", "yandex.com/bots"], cls: "search_crawler", verifyAsns: [13238] },
  { name: "DuckDuckBot", needles: ["duckduckbot", "duckduckgo-favicons-bot"], cls: "search_crawler" },
  { name: "Baiduspider", needles: ["baiduspider"], cls: "search_crawler" },
  { name: "Slurp", needles: ["slurp"], cls: "search_crawler" }, // Yahoo
  { name: "Sogou", needles: ["sogou"], cls: "search_crawler" },
  { name: "Applebot", needles: ["applebot"], cls: "search_crawler" }, // plain — after Applebot-Extended
  { name: "ia_archiver", needles: ["ia_archiver", "archive.org_bot"], cls: "search_crawler" },
  { name: "SemrushBot", needles: ["semrushbot"], cls: "search_crawler" },
  { name: "AhrefsBot", needles: ["ahrefsbot"], cls: "search_crawler" },
  { name: "MJ12bot", needles: ["mj12bot"], cls: "search_crawler" },
  { name: "DotBot", needles: ["dotbot"], cls: "search_crawler" },
  { name: "PetalBot", needles: ["petalbot"], cls: "search_crawler" }, // Huawei
];

// Offensive-security / vulnerability scanners. These announce themselves in the UA and are almost
// never a human in a browser — recognizing them rescues the request from "unknown" for the traffic
// pillar. This list grows freely; it is intentionally NOT the engine's oracle-pinned scanner list
// (that lives in engine/detectors.ts), so adding a scanner here never perturbs web_exploit_probing.
const SCANNERS: Sig[] = [
  { name: "sqlmap", needles: ["sqlmap"], cls: "automation" },
  { name: "Nikto", needles: ["nikto"], cls: "automation" },
  { name: "Nmap", needles: ["nmap", "masscan", "zmap"], cls: "automation" },
  { name: "Acunetix", needles: ["acunetix"], cls: "automation" },
  { name: "Nuclei", needles: ["nuclei"], cls: "automation" },
  { name: "zgrab", needles: ["zgrab"], cls: "automation" },
  { name: "WPScan", needles: ["wpscan"], cls: "automation" },
  { name: "Gobuster", needles: ["gobuster", "dirbuster", "feroxbuster", "ffuf"], cls: "automation" },
  { name: "Nessus", needles: ["nessus", "openvas", "qualys"], cls: "automation" },
];

// Generic automation — scripts, HTTP libraries, API clients, and headless browsers. Not lying
// about who they are; just not a human in a browser.
const AUTOMATION: Sig[] = [
  { name: "curl", needles: ["curl/"], cls: "automation" },
  { name: "Wget", needles: ["wget"], cls: "automation" },
  { name: "python-requests", needles: ["python-requests", "python-urllib", "python-httpx", "aiohttp"], cls: "automation" },
  { name: "axios", needles: ["axios/"], cls: "automation" },
  { name: "node-fetch", needles: ["node-fetch", "undici", "got ("], cls: "automation" },
  { name: "Go-http-client", needles: ["go-http-client"], cls: "automation" },
  { name: "Java", needles: ["java/", "apache-httpclient", "okhttp", "jakarta"], cls: "automation" },
  { name: "libwww-perl", needles: ["libwww-perl", "lwp::"], cls: "automation" },
  { name: "Ruby", needles: ["ruby", "faraday"], cls: "automation" },
  { name: "PHP", needles: ["guzzlehttp", "symfony httpclient"], cls: "automation" },
  { name: "Rust", needles: ["reqwest", "rust-reqwest"], cls: "automation" },
  { name: "HTTPie", needles: ["httpie"], cls: "automation" },
  { name: "PostmanRuntime", needles: ["postmanruntime", "insomnia"], cls: "automation" },
  { name: "Scrapy", needles: ["scrapy"], cls: "automation" },
  { name: "HeadlessChrome", needles: ["headlesschrome", "puppeteer", "playwright", "phantomjs", "selenium"], cls: "automation" },
  { name: ".NET", needles: [".net clr", "dotnet", "restsharp", "winhttp"], cls: "automation" },
];

// Order matters: AI agents before crawlers (Applebot-Extended must beat plain Applebot),
// crawlers before scanners/automation. First matching signature wins.
const SIGS: Sig[] = [...AI_AGENTS, ...CRAWLERS, ...SCANNERS, ...AUTOMATION];

const BROWSER_TOKENS = ["chrome", "safari", "firefox", "edg", "opr", "gecko", "trident", "crios", "fxios", "samsungbrowser"];

/** A browser-looking UA that didn't match any bot/automation signature reads as a human. */
function looksHuman(lc: string): boolean {
  if (!lc.includes("mozilla")) return false;
  return BROWSER_TOKENS.some((t) => lc.includes(t));
}

/** Classify a request's actor from its user-agent (+ ASN when available). Pure + deterministic. */
export function classifyActor(ua: string | null, asn: number | null): ActorVerdict {
  if (ua === null || ua.trim() === "") return { cls: "unknown", name: null, verified: false, spoofed: false };
  const lc = ua.toLowerCase();
  for (const sig of SIGS) {
    if (!sig.needles.some((n) => lc.includes(n))) continue;
    if (sig.verifyAsns !== undefined && asn !== null) {
      if (sig.verifyAsns.includes(asn)) return { cls: sig.cls, name: sig.name, verified: true, spoofed: false };
      // claims a verifiable crawler from the wrong network — an impersonator, not who it says
      return { cls: "automation", name: sig.name, verified: false, spoofed: true };
    }
    return { cls: sig.cls, name: sig.name, verified: false, spoofed: false };
  }
  if (looksHuman(lc)) return { cls: "human", name: null, verified: false, spoofed: false };
  return { cls: "unknown", name: null, verified: false, spoofed: false };
}

export const ALL_ACTOR_CLASSES: readonly ActorClass[] = ["human", "search_crawler", "ai_agent", "automation", "unknown"];

const ACTOR_LABELS: Record<ActorClass, string> = {
  human: "Human",
  search_crawler: "Search crawler",
  ai_agent: "AI agent",
  automation: "Automation",
  unknown: "Unknown",
};

export function actorLabel(cls: ActorClass): string {
  return ACTOR_LABELS[cls];
}
