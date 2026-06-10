// Posture finding — a config/exposure problem (vs. an engine Detection, which is behavior).
// Producers in this package are pure or credential-free (front-door, KEV); hosted Vallhund
// adds credentialed posture collectors on the same shape.

export interface PostureFinding {
  id: string;
  rule: string;
  severity: "low" | "medium" | "high";
  resource: string;
  detail: string;
  fix: string;
  coverage: string[];
  status: "open" | "resolved";
  /** Set when CISA KEV lists a referenced CVE as exploited in the wild (prioritization). */
  kev?: boolean;
}
