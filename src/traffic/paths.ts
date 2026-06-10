// Path utilities for the traffic profile. templatePath folds per-record identifiers
// (/users/123 -> /users/:id) so the endpoint map groups by route instead of exploding into
// one row per id. isSensitivePath flags routes where automated/unauthenticated access matters.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEXISH = /^[0-9a-f]{12,}$/i;

function templateSegment(seg: string): string {
  if (seg === "") return seg;
  if (/^\d+$/.test(seg)) return ":id"; // 123
  if (UUID.test(seg)) return ":uuid"; // 550e8400-e29b-41d4-a716-446655440000
  if (HEXISH.test(seg) && /\d/.test(seg)) return ":hash"; // long hex digest
  // mixed long alnum tokens (hashed asset names, slugged ids) — collapse to avoid row explosion
  if (seg.length >= 12 && /\d/.test(seg) && /[a-z]/i.test(seg)) return ":id";
  return seg;
}

/** Group a raw request path into a route template. Drops the query string. Pure. */
export function templatePath(raw: string): string {
  const path = (raw.split("?")[0] ?? "").trim();
  if (path === "" || path === "/") return "/";
  const joined = path.split("/").map(templateSegment).join("/");
  return joined.length > 1 ? joined.replace(/\/+$/, "") : joined;
}

// Routes where who-is-calling and whether-it's-authenticated actually matter. Tested against
// the templated path (so /users/:id still matches). Conservative, extend as needed.
const SENSITIVE =
  /(^|\/)(admin|internal|api|auth|login|logout|signin|signup|oauth|token|session|account|accounts|billing|payment|payments|invoice|user|users|me|graphql|debug|actuator|metrics|config|secret|secrets|webhook|webhooks|backup|export|download|upload|key|keys|password|reset)(\/|$|:)/i;

export function isSensitivePath(templated: string): boolean {
  return SENSITIVE.test(templated);
}

// File-exfil paths — scanner targets that fetch a STATIC secret/config file, not an app route.
// For these a genuine exposure returns the file itself (plain/json/octet-stream); an HTML 200 is
// the app's catch-all/marketing fallthrough, NOT a leak. (App-surface sensitive routes like
// /admin legitimately return HTML, so this narrower set — not isSensitivePath — drives the
// "must be non-HTML" gate in barks.) Matched against the templated path.
const FILE_EXFIL =
  /(^|\/)(\.git|\.env|\.aws|\.ssh|\.svn|\.hg|\.htpasswd|\.htaccess|\.ds_store|\.npmrc|\.dockercfg|\.bash_history|wp-config\.php|id_rsa|id_dsa|web\.config|composer\.lock|package-lock\.json|docker-compose\.ya?ml)(\/|$)/i;
const SECRET_EXT = /\.(env|pem|key|p12|pfx|crt|sql|sqlite|db|bak|backup|old|swp|conf|ini|log|tar|tar\.gz|tgz|zip)(\/|$)/i;

export function isFileExfilPath(templated: string): boolean {
  return FILE_EXFIL.test(templated) || SECRET_EXT.test(templated);
}

// The "family" a file-exfil path belongs to — the secret it's trying to read (".git", ".env",
// "wp-config.php", ".sql", ...). Used to detect a soft-200 catch-all: a host that serves 2xx for
// SEVERAL distinct families is 200-ing everything (no host legitimately exposes .git AND .env AND
// wp-config at once), whereas one family alone may be a real leak. Grouping by family means a
// genuinely wide-open .git directory (/.git/config + /.git/HEAD + ...) stays ONE family, so it
// isn't mistaken for a catch-all. Returns null for non-file-exfil paths.
export function fileExfilFamily(templated: string): string | null {
  const m = FILE_EXFIL.exec(templated);
  if (m !== null) return m[2]?.toLowerCase() ?? null; // the matched dir/file token
  const e = SECRET_EXT.exec(templated);
  if (e !== null) return `.${e[1]?.toLowerCase() ?? ""}`; // the secret extension
  return null;
}
