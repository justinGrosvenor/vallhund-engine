// Native record shapes — the exact wire shapes each Source emits, before
// normalization. Typed (no `any`) so the normalizers and fixtures are checkable.

export interface CloudflareWafNative {
  datetime: number;
  clientIP: string;
  action: string;
  clientRequestPath: string;
  clientRequestQuery: string;
  userAgent: string;
  clientAsn: number;
  clientCountryName: string;
  source: string;
}

export interface CloudflareHttpNative {
  datetime: number;
  clientIP: string;
  clientAsn: number | null;
  clientCountryName: string;
  clientRequestPath: string;
  clientRequestQuery: string;
  edgeResponseStatus: number | null;
  userAgent: string;
  host?: string; // clientRequestHTTPHost — the proxied gateway/app (the "base"); optional for back-compat
  contentType?: string | null; // edgeResponseContentTypeName (e.g. "html", "json", "plain"); optional for back-compat
}

export interface SupabaseTraits {
  country: string;
  user_agent: string;
}

export interface SupabasePayload {
  action: string;
  actor_id: string;
  actor_username: string;
  traits: SupabaseTraits;
}

export interface SupabaseNative {
  created_at: number;
  ip_address: string;
  payload: SupabasePayload;
}

export interface VercelAttrs {
  "http.method": string;
  "http.route": string;
  "http.status_code": number;
  "client.address": string;
  "user_agent.original": string;
  "client.country": string;
  "user.id"?: string;
  "vercel.env_var_read"?: boolean;
}

export interface VercelNative {
  startTimeUnixNano: number;
  traceId: string;
  attributes: VercelAttrs;
}

export interface ZitadelNative {
  creationDate: number; // epoch seconds (adapter converts ISO -> epoch)
  eventType: string; // raw Zitadel event type
  userId: string;
  userName: string;
  ip: string; // often empty: admin events may not carry client IP
  country: string | null;
  userAgent: string | null;
}

export interface GithubAuditNative {
  timestamp: number; // epoch seconds (adapter converts @timestamp ms -> epoch)
  action: string; // raw GitHub audit action, e.g. "oauth_authorization.create"
  actor: string; // the GitHub login that performed the action
  ip: string; // actor_ip if present, else ""
  country: string | null; // actor_location.country_code if present
  repo: string | null; // affected repo, if any
}

export interface CloudTrailNative {
  time: number; // epoch seconds
  eventName: string; // raw CloudTrail event name, e.g. "CreateAccessKey", "ConsoleLogin"
  eventSource: string; // e.g. "iam.amazonaws.com"
  username: string; // userIdentity userName/arn
  sourceIp: string; // sourceIPAddress (may be an AWS service principal string)
  errorCode: string | null; // present on failures (e.g. ConsoleLogin "Failed authentication")
}

export interface VercelDrainProxy {
  method?: string;
  path?: string;
  statusCode?: number;
  clientIp?: string;
  userAgent?: string | string[];
  region?: string;
}

// Vercel JSON log-drain entry (push, not pull). Request logs carry a `proxy` block.
export interface VercelDrainNative {
  timestamp?: number; // epoch ms
  source?: string; // "lambda" | "edge" | "static" | "build" | "external"
  host?: string;
  path?: string;
  statusCode?: number;
  proxy?: VercelDrainProxy;
}

export interface GcpAuditNative {
  time: number; // epoch seconds (adapter converts the entry timestamp)
  methodName: string; // protoPayload.methodName, e.g. "SetIamPolicy"
  principal: string; // protoPayload.authenticationInfo.principalEmail
  callerIp: string; // protoPayload.requestMetadata.callerIp
  serviceName: string; // protoPayload.serviceName, e.g. "iam.googleapis.com"
  resource: string; // protoPayload.resourceName
  statusCode: number | null; // protoPayload.status.code (0/absent = ok)
}

export interface NativeBatch {
  cloudflare?: CloudflareWafNative[];
  cloudflare_http?: CloudflareHttpNative[];
  supabase?: SupabaseNative[];
  vercel?: VercelNative[];
  zitadel?: ZitadelNative[];
  github?: GithubAuditNative[];
  aws?: CloudTrailNative[];
  gcp?: GcpAuditNative[];
}

export function mergeNative(...batches: NativeBatch[]): NativeBatch {
  const out: NativeBatch = {};
  for (const b of batches) {
    if (b.cloudflare) out.cloudflare = [...(out.cloudflare ?? []), ...b.cloudflare];
    if (b.cloudflare_http) out.cloudflare_http = [...(out.cloudflare_http ?? []), ...b.cloudflare_http];
    if (b.supabase) out.supabase = [...(out.supabase ?? []), ...b.supabase];
    if (b.vercel) out.vercel = [...(out.vercel ?? []), ...b.vercel];
    if (b.zitadel) out.zitadel = [...(out.zitadel ?? []), ...b.zitadel];
    if (b.github) out.github = [...(out.github ?? []), ...b.github];
    if (b.aws) out.aws = [...(out.aws ?? []), ...b.aws];
    if (b.gcp) out.gcp = [...(out.gcp ?? []), ...b.gcp];
  }
  return out;
}
