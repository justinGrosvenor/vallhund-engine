import { describe, it, expect } from "vitest";
import { extractCves, parseKevCatalog, kevEnrich } from "./kev.ts";
import type { PostureFinding } from "./types.ts";

const FEED = {
  vulnerabilities: [
    { cveID: "CVE-2024-12345", vendorProject: "foo", product: "bar", knownRansomwareCampaignUse: "Known" },
    { cveID: "CVE-2021-44228", vendorProject: "apache", product: "log4j", knownRansomwareCampaignUse: "Unknown" },
    { notACve: true },
  ],
};

function finding(detail: string): PostureFinding {
  return { id: "x", rule: "dependency-vulnerability", severity: "medium", resource: "owner/repo:foo", detail, fix: "Upgrade foo.", coverage: ["config"], status: "open" };
}

describe("extractCves", () => {
  it("pulls distinct, uppercased CVE ids", () => {
    expect(extractCves("cve-2021-44228 and CVE-2024-12345, again cve-2021-44228")).toEqual(["CVE-2021-44228", "CVE-2024-12345"]);
    expect(extractCves("no cves here")).toEqual([]);
  });
});

describe("parseKevCatalog", () => {
  it("indexes by CVE (case-insensitive), skips malformed, tolerates junk", () => {
    const cat = parseKevCatalog(FEED);
    expect(cat.size).toBe(2);
    expect(cat.has("cve-2024-12345")).toBe(true);
    expect(cat.get("CVE-2021-44228")?.product).toBe("log4j");
    expect(cat.has("CVE-2000-0001")).toBe(false);
    expect(parseKevCatalog(null).size).toBe(0);
    expect(parseKevCatalog({}).size).toBe(0);
  });
});

describe("kevEnrich", () => {
  const cat = parseKevCatalog(FEED);
  it("raises severity to high, flags kev + adds a KEV note when a CVE matches", () => {
    const out = kevEnrich(finding("Vulnerable dependency foo (CVE-2024-12345)."), "CVE-2024-12345", cat);
    expect(out.severity).toBe("high");
    expect(out.kev).toBe(true);
    expect(out.detail).toContain("known exploited");
    expect(out.detail).toContain("ransomware"); // CVE-2024-12345 is flagged Known
    expect(out.fix).toContain("KEV");
  });
  it("leaves non-KEV findings unchanged (no kev flag)", () => {
    const f = finding("Vulnerable dependency (CVE-2099-0001).");
    const out = kevEnrich(f, "CVE-2099-0001", cat);
    expect(out).toEqual(f);
    expect(out.kev).toBeUndefined();
  });
  it("does not add a ransomware note when not flagged", () => {
    const out = kevEnrich(finding("log4shell"), "CVE-2021-44228", cat);
    expect(out.severity).toBe("high");
    expect(out.detail).not.toContain("ransomware");
  });
});
