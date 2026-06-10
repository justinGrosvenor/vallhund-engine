// Engine contract — the common shapes every Source normalizes into and the
// Detection the engine emits. Ported from the Python spike (the golden oracle).
// Domain language: Detection (not "Alert"); CoverageBoundary on every Detection.

export const A = {
  WAF: "waf_event",
  LOGIN_OK: "login_success",
  LOGIN_FAIL: "login_failure",
  OAUTH: "oauth_grant",
  TOKEN: "token_refresh",
  MEMBER: "member_change", // org membership / role change (supply-chain governance)
  HTTP: "http_request",
  ENV_READ: "env_var_read",
} as const;

export type SourceKind = "cloudflare" | "supabase" | "vercel" | "zitadel" | "github" | (string & {});
export type Severity = "low" | "medium" | "high";
export type CoverageLayer = "network" | "app" | "identity" | "config";

export interface NormalizedEvent {
  ts: number; // epoch seconds
  source: SourceKind;
  action: string;
  actor: string; // canonical entity: user when known, else ip
  ip: string;
  asn: number | null;
  country: string | null;
  userAgent: string | null;
  resource: string;
  query: string;
  status: number | null;
  outcome: string | null; // allow | block | success | failure
  contentType?: string | null; // response content-type short name (Cloudflare "html"/"json"/...); absent elsewhere
  verifiedBot: boolean;
  meta: Record<string, unknown>;
}

export interface Detection {
  detector: string;
  actor: string;
  ts: number;
  severity: Severity;
  reason: string;
  sources: string[];
  coverage: CoverageLayer[]; // the honesty boundary — never host/kernel
  evidence: Record<string, unknown>;
}
