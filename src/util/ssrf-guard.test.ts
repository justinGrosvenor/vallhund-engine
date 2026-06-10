import { describe, it, expect } from "vitest";
import { isBlockedIp, assertPublicHttpsUrl } from "./ssrf-guard.ts";

describe("isBlockedIp", () => {
  it("blocks loopback, private, link-local/metadata, CGNAT, multicast", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
      "169.254.169.254", "0.0.0.0", "100.64.0.1", "224.0.0.1"]) {
      expect(isBlockedIp(ip)).toBe(true);
    }
  });
  it("allows public IPv4", () => {
    for (const ip of ["1.1.1.1", "8.8.8.8", "203.0.113.10", "172.32.0.1", "172.15.0.1"]) {
      expect(isBlockedIp(ip)).toBe(false);
    }
  });
  it("blocks IPv6 loopback, ULA, link-local, mapped-private", () => {
    for (const ip of ["::1", "::", "fe80::1", "fc00::1", "fd12::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"]) {
      expect(isBlockedIp(ip)).toBe(true);
    }
  });
  it("allows public IPv6 / mapped-public", () => {
    expect(isBlockedIp("2606:4700:4700::1111")).toBe(false);
    expect(isBlockedIp("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("assertPublicHttpsUrl", () => {
  it("rejects non-https", async () => {
    await expect(assertPublicHttpsUrl("http://example.com/hook")).rejects.toThrow(/https/);
  });
  it("rejects an invalid URL", async () => {
    await expect(assertPublicHttpsUrl("not a url")).rejects.toThrow(/invalid/);
  });
  it("rejects literal private / metadata IP hosts", async () => {
    await expect(assertPublicHttpsUrl("https://169.254.169.254/latest/meta-data/")).rejects.toThrow(/public/);
    await expect(assertPublicHttpsUrl("https://127.0.0.1/hook")).rejects.toThrow(/public/);
    await expect(assertPublicHttpsUrl("https://[::1]/hook")).rejects.toThrow(/public/);
  });
  it("accepts an https URL with a literal public IP", async () => {
    await expect(assertPublicHttpsUrl("https://1.1.1.1/hook")).resolves.toBeUndefined();
  });
});
