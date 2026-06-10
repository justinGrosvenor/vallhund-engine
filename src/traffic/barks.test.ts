import { describe, it, expect } from "vitest";
import { deriveTrafficBarks } from "./barks.ts";
import { deriveTrafficProfile } from "./profile.ts";
import { A, type NormalizedEvent } from "../engine/schema.ts";

function ev(p: Partial<NormalizedEvent> & { resource: string; userAgent: string | null }): NormalizedEvent {
  return {
    ts: 1000, source: "vercel", action: A.HTTP, actor: "1.2.3.4", ip: "1.2.3.4",
    asn: null, country: null, query: "", status: 200, outcome: "allow", verifiedBot: false, meta: {},
    ...p,
  };
}

function many(n: number, p: Partial<NormalizedEvent> & { resource: string; userAgent: string | null }): NormalizedEvent[] {
  return Array.from({ length: n }, () => ev(p));
}

const NOW = 9999;

describe("deriveTrafficBarks", () => {
  it("barks open_endpoint_automation on a sensitive, never-challenged route hit by scripts", () => {
    const profile = deriveTrafficProfile(many(6, { resource: "/api/users/1", userAgent: "curl/8.4.0", status: 200 }));
    const barks = deriveTrafficBarks(profile, NOW);
    const b = barks.find((d) => d.detector === "open_endpoint_automation");
    expect(b).toBeDefined();
    expect(b?.severity).toBe("high");
    expect(b?.actor).toBe("/api/users/:id");
  });

  it("annotates each endpoint row with the authoritative `open` verdict (so the UI can't drift)", () => {
    // an open sensitive route, and a challenged one — deriveTrafficBarks sets e.open on both.
    const profile = deriveTrafficProfile([
      ...many(6, { resource: "/api/open", userAgent: "curl/8", status: 200 }),
      ...many(6, { resource: "/api/guard", userAgent: "curl/8", status: 200 }),
      ...many(2, { resource: "/api/guard", userAgent: "curl/8", status: 401 }),
    ]);
    deriveTrafficBarks(profile, NOW);
    const open = profile.endpoints.find((e) => e.path === "/api/open");
    const guard = profile.endpoints.find((e) => e.path === "/api/guard");
    expect(open?.open).toBe(true);
    expect(guard?.open).toBe(false); // challenged → not open, matching the suppressed bark
  });

  it("does NOT bark when the sensitive route challenges (returns 401/403)", () => {
    const evs = [...many(6, { resource: "/api/users/1", userAgent: "curl/8.4.0", status: 200 }), ev({ resource: "/api/users/2", userAgent: "curl/8", status: 401 })];
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(false);
  });

  it("does NOT bark on a file-exfil path that 200s with HTML (the marketing catch-all FP)", () => {
    // /.git/config 200s to the marketing page — a soft-200, not a leaked git config.
    const evs = many(8, { resource: "/.git/config", userAgent: "curl/8", status: 200, contentType: "html" });
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(false);
  });

  it("DOES bark on a file-exfil path that 200s with a non-HTML body (a real leak)", () => {
    const evs = many(8, { resource: "/.git/config", userAgent: "curl/8", status: 200, contentType: "plain" });
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(true);
  });

  it("does NOT bark on file-exfil paths when the host is a soft-200 catch-all (≥2 secret families 2xx)", () => {
    // A marketing catch-all 200s every probed dotfile — .git/config AND .env both succeed, which no
    // real host does. The whole host's file-exfil barks are suppressed. (No content-type on this zone.)
    const host = { host: "pay.example.net" };
    const evs = [
      ...many(8, { resource: "/.git/config", userAgent: "curl/8", status: 200, meta: host }),
      ...many(8, { resource: "/.env", userAgent: "curl/8", status: 200, meta: host }),
    ];
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(false);
  });

  it("DOES bark on a single file-exfil family (one secret 2xx, not a catch-all)", () => {
    // Only /.git/* succeeds (siblings would 404) — one family, so it reads as a real leak, not a catch-all.
    const host = { host: "pay.example.net" };
    const evs = [
      ...many(5, { resource: "/.git/config", userAgent: "curl/8", status: 200, meta: host }),
      ...many(5, { resource: "/.git/HEAD", userAgent: "curl/8", status: 200, meta: host }),
    ];
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(true);
  });

  it("does NOT bark on a sensitive route that only errors (404 — no real 2xx)", () => {
    const evs = many(8, { resource: "/api/secrets", userAgent: "curl/8", status: 404, contentType: "html" });
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(false);
  });

  it("STILL barks on an app-surface route open with HTML (open admin panel preserved)", () => {
    // /admin is sensitive but NOT file-exfil — HTML is expected there, so an open 200 still flags.
    const evs = many(8, { resource: "/admin", userAgent: "curl/8", status: 200, contentType: "html" });
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(true);
  });

  it("does NOT bark when the endpoint is in the sticky-challenge set (guarded route, all-200 sample)", () => {
    // /v1/admin/config 200s to authenticated services this window, but a prior window saw its 401.
    const host = { host: "api.example.net" };
    const profile = deriveTrafficProfile(many(8, { resource: "/v1/admin/config", userAgent: "curl/8", status: 200, meta: host }));
    const known = new Set(["api.example.net /v1/admin/config"]);
    expect(deriveTrafficBarks(profile, NOW, known).some((d) => d.detector === "open_endpoint_automation")).toBe(false);
    // ...and WOULD bark without that memory (proves the suppression is what's doing the work)
    expect(deriveTrafficBarks(profile, NOW).some((d) => d.detector === "open_endpoint_automation")).toBe(true);
  });

  it("does NOT bark below the automation threshold", () => {
    const barks = deriveTrafficBarks(deriveTrafficProfile(many(2, { resource: "/api/users/1", userAgent: "curl/8", status: 200 })), NOW);
    expect(barks.some((d) => d.detector === "open_endpoint_automation")).toBe(false);
  });

  it("does NOT bark on a non-sensitive route open to scripts", () => {
    const barks = deriveTrafficBarks(deriveTrafficProfile(many(20, { resource: "/blog/hello", userAgent: "curl/8", status: 200 })), NOW);
    expect(barks).toHaveLength(0);
  });

  it("barks ai_agent_sensitive when an AI agent reaches an open sensitive endpoint", () => {
    const barks = deriveTrafficBarks(deriveTrafficProfile(many(3, { resource: "/api/internal", userAgent: "GPTBot/1.2", status: 200 })), NOW);
    const b = barks.find((d) => d.detector === "ai_agent_sensitive");
    expect(b).toBeDefined();
    expect(b?.reason).toContain("GPTBot");
    expect(b?.actor).toBe("/api/internal");
  });

  it("barks spoofed_crawler when a UA impersonates a verified crawler", () => {
    const evs = many(2, { resource: "/", userAgent: "Googlebot/2.1", asn: 14061, status: 200 }); // DigitalOcean ASN
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW);
    const b = barks.find((d) => d.detector === "spoofed_crawler");
    expect(b).toBeDefined();
    expect(b?.evidence["count"]).toBe(2);
  });

  it("uses the window's last ts (not now) when events are present", () => {
    const profile = deriveTrafficProfile(many(6, { resource: "/api/x", userAgent: "curl/8", status: 200, ts: 5000 }));
    const barks = deriveTrafficBarks(profile, NOW);
    expect(barks[0]?.ts).toBe(5000);
  });

  it("disambiguates barks by gateway host (same path, two proxied apps)", () => {
    const evs = [
      ...many(6, { resource: "/api/keys", userAgent: "curl/8.4.0", status: 200, meta: { host: "a--gw.example.net" } }),
      ...many(6, { resource: "/api/keys", userAgent: "curl/8.4.0", status: 200, meta: { host: "b--gw.example.net" } }),
    ];
    const barks = deriveTrafficBarks(deriveTrafficProfile(evs), NOW).filter((b) => b.detector === "open_endpoint_automation");
    expect(barks).toHaveLength(2);
    expect(barks.map((b) => b.actor).sort()).toEqual(["a--gw.example.net/api/keys", "b--gw.example.net/api/keys"]);
  });

  it("is quiet on a clean human-only profile", () => {
    const chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";
    expect(deriveTrafficBarks(deriveTrafficProfile(many(10, { resource: "/api/users/1", userAgent: chrome, status: 200 })), NOW)).toHaveLength(0);
  });
});
