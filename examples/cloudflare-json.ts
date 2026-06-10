// Feed Cloudflare-shaped HTTP records through the engine — the shape you get from the
// Cloudflare GraphQL httpRequestsAdaptive dataset (synthetic data here, no account needed):
//   npm run example:cloudflare
//
// Shows the actor map and the impostor catch: a "Googlebot" claim from a hosting ASN is
// classified as automation/spoofed, while the real one (Google ASN 15169) verifies.

import type { CloudflareHttpNative } from "../src/index.ts";
import {
  actorLabel,
  baseFindingView,
  classifyActor,
  deriveTrafficProfile,
  normalizeNative,
  runAllDetectors,
} from "../src/index.ts";

const NOW = 1_760_000_000; // fixed so the example is deterministic

function req(o: Partial<CloudflareHttpNative> & { clientIP: string; clientRequestPath: string }): CloudflareHttpNative {
  return {
    datetime: NOW, clientAsn: null, clientCountryName: "US", clientRequestQuery: "",
    edgeResponseStatus: 200, userAgent: "Mozilla/5.0 (Macintosh) Chrome/125 Safari/537.36",
    host: "api.example.dev", contentType: "html",
    ...o,
  };
}

const records: CloudflareHttpNative[] = [
  // a human browsing
  req({ clientIP: "203.0.113.7", clientRequestPath: "/pricing" }),
  // the real Googlebot (Google ASN)
  req({ clientIP: "66.249.66.1", clientAsn: 15169, clientRequestPath: "/docs/api", userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" }),
  // an AI agent reading docs
  req({ clientIP: "20.171.206.10", clientRequestPath: "/docs/quickstart", userAgent: "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)" }),
  // an impostor: claims Googlebot from a DigitalOcean ASN
  req({ clientIP: "198.51.100.9", clientAsn: 14061, clientRequestPath: "/wp-login.php", edgeResponseStatus: 404, userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" }),
  // a scanner probing for secrets
  ...["/.env", "/.git/config", "/.aws/credentials", "/wp-login.php", "/phpmyadmin/index.php"].map((p, i) =>
    req({ clientIP: "198.51.100.50", clientAsn: 14061, clientRequestPath: p, edgeResponseStatus: 404, userAgent: "sqlmap/1.8", datetime: NOW + i * 30 })),
];

const events = normalizeNative({ cloudflare_http: records });
console.log(`events: ${events.length}\n`);

console.log("actor map:");
for (const e of events.slice(0, 4)) {
  const v = classifyActor(e.userAgent, e.asn);
  const flag = v.spoofed ? "  ← SPOOFED (claims a crawler from the wrong network)" : v.verified ? "  (ASN-verified)" : "";
  console.log(`  ${e.ip.padEnd(15)} ${actorLabel(v.cls).padEnd(15)} ${v.name ?? "-"}${flag}`);
}

const findings = runAllDetectors(events).map(baseFindingView);
console.log("\nfindings:");
for (const f of findings) {
  console.log(`  [${f.severity}] ${f.detector} actor=${f.actor} → ${f.classification}`);
}

const profile = deriveTrafficProfile(events);
console.log(`\nendpoints profiled: ${profile.endpoints.length}`);
