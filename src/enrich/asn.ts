// ASN classification — deterministic, always on. "Where does this IP live?" matters for
// judgment: a cloud/hosting-origin actor doing recon is more suspicious than a residential
// one, and a known crawler ASN supports (but never proves) a crawler claim.
//
// This is the open, local-evaluable half of reputation. Hosted Vallhund layers optional
// network enrichments (e.g. GreyNoise) on top; the engine's verdicts never require them.

export type AsnClass = "cloud" | "crawler" | "hosting" | "isp" | "unknown";

/** GreyNoise-style scanner verdict. The open engine treats this as an optional input signal —
 *  callers may supply one from their own enrichment; nothing in this package looks it up. */
export type ScannerVerdict = "malicious" | "benign" | "unknown";

// Curated map of well-known ASNs. Not exhaustive — extend as needed.
const ASN_CLASS: Record<number, AsnClass> = {
  15169: "crawler", // Google (Googlebot)
  8075: "crawler", // Microsoft / Bing
  13238: "crawler", // Yandex
  16509: "cloud", // Amazon AWS
  14618: "cloud", // Amazon AWS
  8987: "cloud", // Amazon AWS
  396982: "cloud", // Google Cloud
  8068: "cloud", // Microsoft Azure
  8069: "cloud", // Microsoft Azure
  13335: "cloud", // Cloudflare
  14061: "hosting", // DigitalOcean
  16276: "hosting", // OVH
  24940: "hosting", // Hetzner
  63949: "hosting", // Akamai/Linode
  20473: "hosting", // Vultr/Choopa
  14421: "hosting", // generic hosting
};

export function classifyAsn(asn: number | null): AsnClass {
  if (asn === null) return "unknown";
  return ASN_CLASS[asn] ?? "unknown";
}
