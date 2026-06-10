import { describe, it, expect } from "vitest";
import { deriveTrafficProfile } from "./profile.ts";
import { A, type NormalizedEvent } from "../engine/schema.ts";

function ev(p: Partial<NormalizedEvent> & { resource: string; userAgent: string | null }): NormalizedEvent {
  return {
    ts: 1000, source: "vercel", action: A.HTTP, actor: "1.2.3.4", ip: "1.2.3.4",
    asn: null, country: null, query: "", status: 200, outcome: "allow", verifiedBot: false, meta: {},
    ...p,
  };
}

const CHROME = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";

describe("deriveTrafficProfile", () => {
  it("returns an empty profile for no HTTP events", () => {
    const p = deriveTrafficProfile([]);
    expect(p.total).toBe(0);
    expect(p.mix).toHaveLength(0);
    expect(p.window).toBeNull();
  });

  it("computes the actor mix with percentages", () => {
    const p = deriveTrafficProfile([
      ev({ resource: "/", userAgent: CHROME }),
      ev({ resource: "/", userAgent: CHROME }),
      ev({ resource: "/api/data", userAgent: "GPTBot/1.2" }),
      ev({ resource: "/api/data", userAgent: "curl/8.4.0" }),
    ]);
    expect(p.total).toBe(4);
    const human = p.mix.find((m) => m.cls === "human");
    expect(human?.count).toBe(2);
    expect(human?.pct).toBe(50);
    expect(p.mix.find((m) => m.cls === "ai_agent")?.count).toBe(1);
    expect(p.mix.find((m) => m.cls === "automation")?.count).toBe(1);
  });

  it("groups endpoints by template and crosses route x actor", () => {
    const p = deriveTrafficProfile([
      ev({ resource: "/users/1", userAgent: "GPTBot/1.2" }),
      ev({ resource: "/users/2", userAgent: "GPTBot/1.2" }),
      ev({ resource: "/users/3", userAgent: CHROME }),
    ]);
    expect(p.endpoints).toHaveLength(1);
    const row = p.endpoints[0];
    expect(row?.path).toBe("/users/:id");
    expect(row?.total).toBe(3);
    expect(row?.byClass.ai_agent).toBe(2);
    expect(row?.byClass.human).toBe(1);
    expect(row?.sensitive).toBe(true); // /users matches sensitivity
    expect(row?.topAgent).toBe("GPTBot");
  });

  it("marks an endpoint challenged only when it returns 401/403", () => {
    const open = deriveTrafficProfile([ev({ resource: "/api/open", userAgent: "curl/8", status: 200 })]);
    expect(open.endpoints[0]?.challenged).toBe(false);
    const guarded = deriveTrafficProfile([
      ev({ resource: "/api/guard", userAgent: "curl/8", status: 200 }),
      ev({ resource: "/api/guard", userAgent: "curl/8", status: 401 }),
    ]);
    expect(guarded.endpoints[0]?.challenged).toBe(true);
  });

  it("flags a host as a soft-200 catch-all only when ≥2 distinct secret families 2xx", () => {
    const h = { host: "pay.example.net" };
    // one secret family that 2xx'd → not a catch-all (could be a real leak)
    const single = deriveTrafficProfile([
      ev({ resource: "/.git/config", userAgent: "curl/8", status: 200, meta: h }),
      ev({ resource: "/.git/HEAD", userAgent: "curl/8", status: 200, meta: h }),
    ]);
    expect(single.softCatchAllHosts ?? []).not.toContain("pay.example.net");
    // two distinct families 2xx'd on the same host → catch-all
    const many2 = deriveTrafficProfile([
      ev({ resource: "/.git/config", userAgent: "curl/8", status: 200, meta: h }),
      ev({ resource: "/.env", userAgent: "curl/8", status: 200, meta: h }),
    ]);
    expect(many2.softCatchAllHosts ?? []).toContain("pay.example.net");
  });

  it("collects challenged endpoint keys (401/403) for the sticky-challenge memory", () => {
    const h = { host: "api.example.net" };
    const p = deriveTrafficProfile([
      ev({ resource: "/v1/admin/config", userAgent: "curl/8", status: 200, meta: h }),
      ev({ resource: "/v1/admin/config", userAgent: "curl/8", status: 401, meta: h }),
      ev({ resource: "/v1/open", userAgent: "curl/8", status: 200, meta: h }),
    ]);
    expect(p.challengedEndpoints ?? []).toContain("api.example.net /v1/admin/config");
    expect(p.challengedEndpoints ?? []).not.toContain("api.example.net /v1/open");
  });

  it("does not count secret families that only 404 (a host that properly rejects them)", () => {
    const h = { host: "real.example" };
    const p = deriveTrafficProfile([
      ev({ resource: "/.git/config", userAgent: "curl/8", status: 404, meta: h }),
      ev({ resource: "/.env", userAgent: "curl/8", status: 404, meta: h }),
    ]);
    expect(p.softCatchAllHosts ?? []).not.toContain("real.example");
  });

  it("counts named agents and spoofs", () => {
    const p = deriveTrafficProfile([
      ev({ resource: "/", userAgent: "ClaudeBot/1.0" }),
      ev({ resource: "/", userAgent: "ClaudeBot/1.0" }),
      ev({ resource: "/", userAgent: "Googlebot/2.1", asn: 14061 }), // spoofed (DigitalOcean ASN)
    ]);
    expect(p.agents.find((a) => a.name === "ClaudeBot")?.count).toBe(2);
    expect(p.spoofed).toBe(1);
  });

  it("splits endpoints per gateway host and rolls up bases", () => {
    const p = deriveTrafficProfile([
      ev({ resource: "/pay", userAgent: "curl/8", meta: { host: "a--gw.example.net" } }),
      ev({ resource: "/pay", userAgent: "curl/8", meta: { host: "a--gw.example.net" } }),
      ev({ resource: "/pay", userAgent: "curl/8", meta: { host: "b--gw.example.net" } }),
    ]);
    const aPay = p.endpoints.find((e) => e.base === "a--gw.example.net" && e.path === "/pay");
    const bPay = p.endpoints.find((e) => e.base === "b--gw.example.net" && e.path === "/pay");
    expect(aPay?.total).toBe(2); // same /pay on two gateways => two rows
    expect(bPay?.total).toBe(1);
    expect(p.bases.find((x) => x.host === "a--gw.example.net")?.total).toBe(2);
    expect(p.bases.find((x) => x.host === "b--gw.example.net")?.total).toBe(1);
  });

  it("base is null when no Host is captured", () => {
    const p = deriveTrafficProfile([ev({ resource: "/x", userAgent: "curl/8" })]);
    expect(p.endpoints[0]?.base).toBeNull();
    expect(p.bases[0]?.host).toBeNull();
  });

  it("ignores non-HTTP events (logins, token grants)", () => {
    const p = deriveTrafficProfile([
      ev({ resource: "auth", userAgent: CHROME, action: A.LOGIN_OK }),
      ev({ resource: "/", userAgent: CHROME, action: A.HTTP }),
    ]);
    expect(p.total).toBe(1);
  });
});
