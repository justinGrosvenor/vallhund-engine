// FCrDNS verification — gated, network-mocked. Verifies the verdict logic (verified / spoofed /
// unverified) and that the gate keeps it inert (and silent on the network) when disabled.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const { reverse, resolve4, resolve6 } = vi.hoisted(() => ({
  reverse: vi.fn(), resolve4: vi.fn(), resolve6: vi.fn(),
}));
vi.mock("node:dns", () => ({ promises: { reverse, resolve4, resolve6 } }));

import { verifyCrawler, isVerifiableCrawler, _resetRdnsCache } from "./rdns.ts";

beforeEach(() => {
  process.env["VALLHUND_RDNS_VERIFY"] = "1";
  _resetRdnsCache();
  reverse.mockReset(); resolve4.mockReset(); resolve6.mockReset();
  resolve4.mockResolvedValue([]); resolve6.mockResolvedValue([]);
});
afterEach(() => { delete process.env["VALLHUND_RDNS_VERIFY"]; });

describe("verifyCrawler — gate", () => {
  it("is inert and makes NO dns calls when VALLHUND_RDNS_VERIFY is off", async () => {
    delete process.env["VALLHUND_RDNS_VERIFY"];
    const v = await verifyCrawler("66.249.66.1", "Googlebot");
    expect(v).toBe("unverified");
    expect(reverse).not.toHaveBeenCalled();
  });

  it("returns unverified for a non-verifiable crawler (AI agents publish CIDRs, not rDNS)", async () => {
    expect(isVerifiableCrawler("GPTBot")).toBe(false);
    const v = await verifyCrawler("1.2.3.4", "GPTBot");
    expect(v).toBe("unverified");
    expect(reverse).not.toHaveBeenCalled();
  });
});

describe("verifyCrawler — verdict", () => {
  it("verifies a real Googlebot (PTR in googlebot.com that forward-resolves back to the IP)", async () => {
    reverse.mockResolvedValue(["crawl-66-249-66-1.googlebot.com"]);
    resolve4.mockResolvedValue(["66.249.66.1"]);
    expect(await verifyCrawler("66.249.66.1", "Googlebot")).toBe("verified");
  });

  it("flags a spoof when PTR lands outside the operator's domain", async () => {
    reverse.mockResolvedValue(["host.attacker-vps.example"]);
    expect(await verifyCrawler("203.0.113.9", "Googlebot")).toBe("spoofed");
  });

  it("flags a spoof when the PTR hostname does NOT forward-resolve back to the IP", async () => {
    reverse.mockResolvedValue(["crawl-1.googlebot.com"]);
    resolve4.mockResolvedValue(["8.8.8.8"]); // forward points elsewhere
    expect(await verifyCrawler("203.0.113.9", "Googlebot")).toBe("spoofed");
  });

  it("is inconclusive (unverified), not a spoof, when reverse DNS returns nothing", async () => {
    reverse.mockResolvedValue([]);
    expect(await verifyCrawler("203.0.113.9", "Googlebot")).toBe("unverified");
  });

  it("verifies an IPv6 crawler despite textual-form differences (compressed vs expanded)", async () => {
    // clientIP compressed; resolve6 returns the fully-expanded form — must still match (not spoof).
    reverse.mockResolvedValue(["crawl-001.googlebot.com"]);
    resolve6.mockResolvedValue(["2001:4860:4801:0010:0000:0000:0000:006a"]);
    expect(await verifyCrawler("2001:4860:4801:10::6a", "Googlebot")).toBe("verified");
  });

  it("still flags a genuine IPv6 mismatch as spoofed", async () => {
    reverse.mockResolvedValue(["crawl-x.googlebot.com"]);
    resolve6.mockResolvedValue(["2001:4860:4801:10::6b"]); // different address
    expect(await verifyCrawler("2001:4860:4801:10::6a", "Googlebot")).toBe("spoofed");
  });

  it("caches per IP — a second call does not re-hit DNS", async () => {
    reverse.mockResolvedValue(["crawl.search.msn.com"]);
    resolve4.mockResolvedValue(["157.55.39.1"]);
    expect(await verifyCrawler("157.55.39.1", "Bingbot")).toBe("verified");
    expect(await verifyCrawler("157.55.39.1", "Bingbot")).toBe("verified");
    expect(reverse).toHaveBeenCalledTimes(1);
  });
});
