// Remediation prompts — a paste-ready "agent handoff" generated from a Finding.
// Framing: CONTEXT HANDOFF, not "we fix your code". Vallhund supplies the judgment +
// stack context only it has; the user's own coding agent investigates/patches.
// Guardrails (agreed): actionable-only; Explain/Investigate are safe defaults, Patch
// is opt-in; every prompt carries the Coverage Boundary + "what we can't prove"; and
// output is run through secret redaction (this text leaves the boundary when pasted).
// Deterministic templates (no LLM) so it stays oracle-testable.

import type { FindingView } from "../engine/overview.ts";

export type RemediationMode = "explain" | "investigate" | "patch";

export interface RemediationContext {
  project: string;
  connectedSources: string[];
}

export interface Remediation {
  available: boolean;
  explain: string;
  investigate: string;
  patch: string;
}

// --- secret redaction (hard gate; the prompt is copy-pasted into external agents) ---
const SECRET_PATTERNS: RegExp[] = [
  /sk_(?:live|test)_[A-Za-z0-9]+/g,
  /whsec_[A-Za-z0-9]+/g,
  /AKIA[0-9A-Z]{16}/g,
  /AIza[0-9A-Za-z_-]{20,}/g,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, // JWT
  /postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@/g, // db url with inline password
  /\b[A-Fa-f0-9]{40,}\b/g, // long hex
  /\b[A-Za-z0-9_-]{40,}\b/g, // long opaque token (catch-all; over-redacts on purpose)
];

export function redactSecrets(text: string): string {
  let out = text;
  for (const re of SECRET_PATTERNS) out = out.replace(re, "[redacted]");
  return out;
}

interface Pack {
  matters: string;
  indicates: string;
  benign: string;
  task: string;
  steps: string[];
  fix: string[];
  constraints: string[];
  verify: string[];
}

const RECON: Pack = {
  matters: "a population-wide spike of probes (high 404s / many distinct paths / new ASNs) — distributed reconnaissance.",
  indicates: "automated recon across many IPs hunting for exposed routes.",
  benign: "internet background noise, a broken-link wave, or a new legitimate integration.",
  task: "Review whether any commonly-probed paths, debug endpoints, generated docs, or config routes are accidentally exposed.",
  steps: [
    "Search the repo for handlers matching the top probed paths in the evidence.",
    "Confirm sensitive / admin / debug / generated-doc / config routes require auth or aren't public.",
    "Confirm /.env, /debug, admin, and generated API docs are not served unintentionally.",
  ],
  fix: [
    "Gate or remove any genuinely exposed route you find.",
    "Add tests for the routes you secure.",
    "If it's only noise with nothing exposed, make no change and explain why.",
  ],
  constraints: [
    "Do not add broad blocking logic in app code unless such a layer already exists.",
    "Do not hide 404s behind misleading 200 responses.",
  ],
  verify: [
    "No sensitive route is publicly exposed.",
    "Tests added for anything secured.",
    "The aggregate probe rate is treated as noise or mitigated at the edge.",
  ],
};

const PACKS: Record<string, Pack> = {
  identity_chain: {
    matters: "an established account signed in from a new location and then reached a sensitive route — the shape of account takeover followed by data access.",
    indicates: "a stolen credential or session being used to read privileged data.",
    benign: "the real user travelled or used a VPN, then did legitimate sensitive work.",
    task: "Determine whether the sensitive route(s) this user reached can expose secrets or data to an account that shouldn't have them.",
    steps: [
      "Inspect the handler(s) for the sensitive route(s) named in the evidence.",
      "Inspect the auth / session / role checks guarding them.",
      "Check whether a non-admin authenticated user can read secrets or privileged data.",
      "Check whether step-up / MFA is required for sensitive actions.",
    ],
    fix: [
      "Require the correct role (and step-up / MFA) on the sensitive route(s).",
      "Invalidate or rotate sessions for the affected user.",
      "Add a regression test proving an ordinary user is denied.",
    ],
    constraints: [
      "Do not broaden auth on unrelated routes.",
      "Do not remove audit logging.",
      "Do not print secret values in tests or logs.",
    ],
    verify: [
      "The sensitive route requires the intended role / session / MFA.",
      "A regression test is added and passing.",
      "Vallhund stops correlating this new-geo → sensitive pattern.",
    ],
  },
  credential_stuffing: {
    matters: "many failed logins across multiple accounts from one source, then a success — the shape of credential stuffing / account takeover.",
    indicates: "leaked-password reuse being tried at scale.",
    benign: "a misconfigured client retrying, or many users behind one NAT / office IP.",
    task: "Confirm login throttling and account protections are adequate, and secure any taken-over account.",
    steps: [
      "Review rate-limiting on the auth endpoint.",
      "Check lockout / anomaly handling after repeated failures.",
      "Confirm MFA availability and enforcement for sensitive accounts.",
    ],
    fix: [
      "Add or tighten per-IP and per-account login rate limits.",
      "Force a reset and notify the account that was taken over.",
      "Require MFA for the affected account(s).",
    ],
    constraints: ["Do not lock out all users globally.", "Do not log raw passwords or tokens."],
    verify: [
      "Rate limits are enforced on the auth path.",
      "The affected account is secured (reset + MFA).",
      "Vallhund stops seeing the stuffing burst from this source.",
    ],
  },
  web_exploit_probing: {
    matters: "a source sent requests matching known exploit/probe patterns (SQLi, traversal, scanner UAs) at your edge.",
    indicates: "automated vulnerability scanning; occasionally a targeted attempt.",
    benign: "internet background-radiation scanning that hits every public host.",
    task: "Confirm none of the probed paths are live/exposed and that inputs are validated.",
    steps: [
      "Check whether the probed paths resolve to real handlers.",
      "Review input validation / query parameterization on any that do.",
      "Confirm WAF managed rules cover the probed CVE classes.",
    ],
    fix: [
      "Patch or validate any genuinely exposed handler.",
      "Enable or tune the relevant WAF managed ruleset.",
      "Add a test for the input-validation fix.",
    ],
    constraints: [
      "Do not add ad-hoc blocking in app code if a WAF layer exists.",
      "Do not weaken existing validation.",
    ],
    verify: [
      "Probed paths 404 or are properly guarded.",
      "An input-validation test is added.",
      "The source is challenged/blocked at the edge if abusive.",
    ],
  },
  enumeration: {
    matters: "one source walked many distinct endpoints quickly — endpoint enumeration / scanning.",
    indicates: "someone mapping your API surface for weak spots.",
    benign: "a misbehaving client or an aggressive but legitimate crawler.",
    task: "Confirm enumerated endpoints don't leak structure or data and are rate-limited.",
    steps: [
      "Review which endpoints the source hit (see evidence).",
      "Confirm sensitive / admin endpoints require auth + role.",
      "Check for per-source rate limiting.",
    ],
    fix: [
      "Gate or remove any exposed sensitive endpoint.",
      "Add rate limiting for high-distinct-path sources.",
      "Add a test for the gated endpoint.",
    ],
    constraints: [
      "Do not return misleading 200s to hide 404s.",
      "Do not broaden access to make tests pass.",
    ],
    verify: ["Sensitive endpoints are gated.", "Rate limiting is in place.", "The enumeration pattern subsides."],
  },
  fourohfour_rate: RECON,
  distinct_path_fanout: RECON,
  new_asn_surge: RECON,
};

const DEFAULT_PACK: Pack = {
  matters: "behavior that deviates from your normal at the app/identity layer.",
  indicates: "possible probing or misuse worth a look.",
  benign: "an unusual but legitimate client or traffic pattern.",
  task: "Investigate whether the involved route(s) or identity can be misused.",
  steps: [
    "Inspect the routes / handlers referenced in the evidence.",
    "Confirm auth, validation, and rate-limiting are adequate.",
  ],
  fix: ["Fix any confirmed exposure and add a test.", "Otherwise document why it's safe."],
  constraints: ["Do not broaden auth.", "Do not weaken existing controls.", "Do not log secrets."],
  verify: ["Confirmed issue fixed with a test, or documented as benign."],
};

function evidenceLines(ev: Record<string, unknown>): string {
  return Object.entries(ev).map(([k, v]) => `- ${k}: ${JSON.stringify(v)}`).join("\n");
}

export function buildRemediation(f: FindingView, ctx: RemediationContext): Remediation {
  if (f.actionability !== "actionable") {
    return { available: false, explain: "", investigate: "", patch: "" };
  }
  const pack = PACKS[f.detector] ?? DEFAULT_PACK;
  const cannot = `Vallhund cannot see host/kernel activity and cannot prove code execution or compromise — it observed ${f.coverage.join(" / ")} only.`;
  const stack = ctx.connectedSources.map((s) => `- ${s}`).join("\n");
  const observed = [
    `- Detector: ${f.detector}`,
    `- Entity: ${f.actor}`,
    `- Classification: ${f.classification}`,
    `- Coverage: ${f.coverage.join(" + ")}`,
    evidenceLines(f.evidence),
    `- ${cannot}`,
  ].join("\n");

  const explain = redactSecrets(
    [
      `What we saw (${f.detector} on ${f.actor}):`,
      f.reason,
      ``,
      `What it can mean: ${pack.indicates}`,
      `Benign explanation: ${pack.benign}`,
      `What we can't prove: ${cannot}`,
    ].join("\n"),
  );

  const investigateBody = [
    `You are working in a project monitored by Vallhund.`,
    ``,
    `Connected services:`,
    stack,
    ``,
    `Vallhund observed:`,
    observed,
    ``,
    `Task (investigate only — do not change code yet):`,
    pack.task,
    ``,
    `Steps:`,
    pack.steps.map((s, i) => `${String(i + 1)}. ${s}`).join("\n"),
    ``,
    `Return: what you inspected, whether the issue is real, and anything needing manual review.`,
  ].join("\n");
  const investigate = redactSecrets(investigateBody);

  const patch = redactSecrets(
    [
      investigateBody,
      ``,
      `If — and only if — you confirm the issue:`,
      pack.fix.map((s, i) => `${String(i + 1)}. ${s}`).join("\n"),
      ``,
      `Constraints:`,
      pack.constraints.map((c) => `- ${c}`).join("\n"),
      ``,
      `Done means:`,
      pack.verify.map((v) => `- ${v}`).join("\n"),
      ``,
      `Return: files changed, tests added, and anything still needing manual review.`,
    ].join("\n"),
  );

  return { available: true, explain, investigate, patch };
}
