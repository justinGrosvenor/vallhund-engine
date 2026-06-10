import { describe, it, expect } from "vitest";
import { classifyActor, actorLabel, ALL_ACTOR_CLASSES } from "./actors.ts";

const CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot";
const CLAUDEBOT = "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)";
const GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

describe("classifyActor — classes", () => {
  it("recognizes a real browser as human", () => {
    const v = classifyActor(CHROME, null);
    expect(v.cls).toBe("human");
    expect(v.spoofed).toBe(false);
  });

  it("recognizes AI agents (GPTBot, ClaudeBot, Perplexity) even with a Mozilla prefix", () => {
    expect(classifyActor(GPTBOT, null).cls).toBe("ai_agent");
    expect(classifyActor(GPTBOT, null).name).toBe("GPTBot");
    expect(classifyActor(CLAUDEBOT, null).cls).toBe("ai_agent");
    expect(classifyActor("PerplexityBot/1.0 (+https://perplexity.ai/bot)", null).cls).toBe("ai_agent");
    expect(classifyActor("CCBot/2.0 (https://commoncrawl.org/faq/)", null).cls).toBe("ai_agent");
  });

  it("classifies declared search crawlers", () => {
    expect(classifyActor(GOOGLEBOT, null).cls).toBe("search_crawler");
    expect(classifyActor("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", null).cls).toBe("search_crawler");
    expect(classifyActor("Mozilla/5.0 (compatible; DuckDuckBot/1.1)", null).cls).toBe("search_crawler");
  });

  it("classifies scripts and HTTP libraries as automation", () => {
    expect(classifyActor("curl/8.4.0", null).cls).toBe("automation");
    expect(classifyActor("python-requests/2.31.0", null).cls).toBe("automation");
    expect(classifyActor("Go-http-client/2.0", null).cls).toBe("automation");
    expect(classifyActor("axios/1.6.2", null).cls).toBe("automation");
    expect(classifyActor("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/124.0.0.0", null).cls).toBe("automation");
  });

  it("classifies vuln scanners as named automation (rescued from unknown)", () => {
    const sqlmap = classifyActor("sqlmap/1.7.2#stable (http://sqlmap.org)", null);
    expect(sqlmap.cls).toBe("automation");
    expect(sqlmap.name).toBe("sqlmap");
    expect(classifyActor("Nikto/2.5.0", null).cls).toBe("automation");
    expect(classifyActor("Mozilla/5.0 (Nuclei - Open-source project)", null).cls).toBe("automation");
    expect(classifyActor("masscan/1.3", null).cls).toBe("automation");
  });

  it("recognizes additional HTTP-client libraries (httpie, reqwest, got)", () => {
    expect(classifyActor("HTTPie/3.2.1", null).cls).toBe("automation");
    expect(classifyActor("reqwest/0.11", null).cls).toBe("automation");
    expect(classifyActor("got (https://github.com/sindresorhus/got)", null).cls).toBe("automation");
  });

  it("treats blank / unrecognized non-browser UAs as unknown", () => {
    expect(classifyActor(null, null).cls).toBe("unknown");
    expect(classifyActor("", null).cls).toBe("unknown");
    expect(classifyActor("   ", null).cls).toBe("unknown");
    expect(classifyActor("SomeRandomToken/9", null).cls).toBe("unknown");
  });
});

describe("classifyActor — AI-vs-crawler ordering", () => {
  it("Applebot-Extended (AI) beats plain Applebot (crawler)", () => {
    expect(classifyActor("Mozilla/5.0 (compatible; Applebot-Extended/0.1)", null).cls).toBe("ai_agent");
    expect(classifyActor("Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)", null).cls).toBe("search_crawler");
  });
});

describe("classifyActor — ASN spoof check", () => {
  it("verifies Googlebot from Google's ASN", () => {
    const v = classifyActor(GOOGLEBOT, 15169);
    expect(v.cls).toBe("search_crawler");
    expect(v.verified).toBe(true);
    expect(v.spoofed).toBe(false);
  });

  it("flags Googlebot from a non-Google ASN as a spoof (downgraded to automation)", () => {
    const v = classifyActor(GOOGLEBOT, 14061); // DigitalOcean
    expect(v.cls).toBe("automation");
    expect(v.spoofed).toBe(true);
    expect(v.verified).toBe(false);
    expect(v.name).toBe("Googlebot"); // retains the claimed name for the bark
  });

  it("does not accuse of spoofing when ASN is unknown (Vercel drain has no ASN)", () => {
    const v = classifyActor(GOOGLEBOT, null);
    expect(v.cls).toBe("search_crawler");
    expect(v.spoofed).toBe(false);
    expect(v.verified).toBe(false);
  });

  it("does not ASN-verify AI agents (cloud-hosted, no single ASN) — never false-spoofs them", () => {
    const v = classifyActor(GPTBOT, 14061);
    expect(v.cls).toBe("ai_agent");
    expect(v.spoofed).toBe(false);
  });
});

describe("labels", () => {
  it("has a label for every class", () => {
    for (const c of ALL_ACTOR_CLASSES) expect(actorLabel(c).length).toBeGreaterThan(0);
  });
});
