// Lock-in for foe-dominant classification. Regression target: a high-severity web_exploit_probing
// finding on a Microsoft/Bing ("crawler"-range) ASN was being flipped to "friend", silencing a real
// attack. Friend must require a *verified* signal; an active-attack detector is foe and nothing
// (ASN class or benign-scanner reputation) downgrades it. (The hosted platform's read-time triage
// overlay enforces the same dominance for user-set "trusted" standings; that lives upstream.)

import { describe, it, expect } from "vitest";
import { resolveFindingClassification } from "./overview.ts";

describe("resolveFindingClassification — foe dominance", () => {
  it("keeps a foe-detector finding foe even when the scanner reputation says benign", () => {
    expect(resolveFindingClassification("web_exploit_probing", "foe", { scanner: "benign", crawler: "unverified" })).toBe("foe");
  });

  it("keeps a foe-detector finding foe even when the actor sits on a crawler ASN (the original bug)", () => {
    // asnClass no longer feeds classification at all — crawler stays "unverified" unless FCrDNS confirms.
    expect(resolveFindingClassification("web_exploit_probing", "foe", { scanner: null, crawler: "unverified" })).toBe("foe");
  });

  it("only grants friend on a verified signal (FCrDNS-confirmed crawler) for non-foe detectors", () => {
    expect(resolveFindingClassification("ai_agent_sensitive", "unknown", { scanner: null, crawler: "verified" })).toBe("friend");
    expect(resolveFindingClassification("ai_agent_sensitive", "unknown", { scanner: "benign", crawler: "unverified" })).toBe("friend");
  });

  it("malicious scanner reputation makes a non-foe detector foe", () => {
    expect(resolveFindingClassification("ai_agent_sensitive", "unknown", { scanner: "malicious", crawler: "unverified" })).toBe("foe");
  });

  it("a forged crawler (FCrDNS 'spoofed') escalates a non-foe detector to foe", () => {
    expect(resolveFindingClassification("ai_agent_sensitive", "unknown", { scanner: null, crawler: "spoofed" })).toBe("foe");
    // foe-dominant: a spoof verdict beats a benign-scanner friend signal
    expect(resolveFindingClassification("ai_agent_sensitive", "unknown", { scanner: "benign", crawler: "spoofed" })).toBe("foe");
  });

  it("falls back to the detector default when no signal fires", () => {
    expect(resolveFindingClassification("ai_agent_sensitive", "unknown", { scanner: null, crawler: "unverified" })).toBe("unknown");
  });
});

