# Vallhund Engine

Vallhund Engine is the open detection and remediation core behind [Vallhund](https://vallhund.org).

It turns normalized telemetry and config-derived signals into findings, actor
classification, coverage boundaries, actionability, and agent-ready remediation
prompts.

It does **not** collect credentials, store customer data, run a SaaS worker, or
connect to your cloud accounts.

## Why this repo is public

Vallhund Cloud asks for read-only credentials to sources like Cloudflare, GitHub,
and AWS. You should not have to take our word for what runs on that telemetry.
This repo is the judgment logic, inspectable and runnable locally:

- What does Vallhund detect, and how?
- What evidence does it retain?
- What does it explicitly not claim to see?
- How are classification, actionability, and remediation prompts produced?

Vallhund Cloud is proprietary hosted software that runs this same engine
continuously, with managed connectors, encrypted credential handling, scheduled
jobs, retention, notifications, team workflow, and hosted triage.

## Quick start

Use it as a package:

```bash
npm install @vallhund/engine
```

Or run it from source (Node >= 22.6; the repo runs TypeScript directly via type stripping):

```bash
npm install
npm test               # 119 tests, including the golden oracle
npm run example:basic  # full pipeline on bundled fixtures: events -> findings -> prompt
npm run example:cloudflare  # Cloudflare-shaped JSON in, actor map + findings out
```

No env vars, no credentials, no network access needed for any of the above.

## What it does

```ts
import {
  runAllDetectors,
  baseFindingView,
  deriveTrafficProfile,
  deriveTrafficBarks,
  buildOverview,
  deriveMetrics,
  buildRemediation,
  normalizeNative,
} from "@vallhund/engine";

const events = normalizeNative(nativeBatch);            // per-source shapes -> NormalizedEvent[]
const findings = runAllDetectors(events).map(baseFindingView);
const traffic = deriveTrafficProfile(events);           // who is at the door, per endpoint
const barks = deriveTrafficBarks(traffic, nowSec);
const overview = buildOverview(deriveMetrics(events), findings, false);
const fix = buildRemediation(findings[0], { project: "local", connectedSources: ["Cloudflare"] });
```

Core ideas, each enforced in code and locked by tests:

- **Friend or foe, foe-dominant.** Every finding is classified friend, foe, or
  unknown. Reputation can never silence an active attack: a foe detector stays
  foe regardless of ASN class, benign scanner reputation, or trust standing.
- **Verified, not trusted.** A user agent claiming Googlebot is checked against
  the operator's network (ASN, and optionally forward-confirmed reverse DNS).
  Impostors are flagged, not greeted.
- **Derive and drop.** The engine computes signals from events and keeps
  findings. Raw traffic is input, never storage.
- **An honest boundary.** Every finding carries the coverage layers it was
  observed on (network, app, identity, config) and the engine states what it
  cannot see (host, kernel). The oracle includes a scenario that must remain
  invisible, and fails if the engine ever claims to catch it.
- **Agent-ready remediation.** Actionable findings produce paste-ready,
  stack-aware prompts for a coding agent, with explicit scope and a
  cannot-prove disclaimer.

## What lives here vs. hosted Vallhund

| Here (AGPL) | Hosted (proprietary) |
|---|---|
| Normalized event schema | Credentialed fetchers and push receivers |
| Detectors (per-entity + aggregate) | Connector authorization flows |
| Actor classification + FCrDNS verification | Encrypted secret storage |
| Traffic profiling + barks | Scheduling, retention, persistence |
| Actionability, incidents, overview | Notifications (Slack, webhooks) |
| Remediation prompt builder | Team workflow and hosted triage |
| Credential-free posture (front door, KEV) | Cross-project reputation graph |
| Fixtures + golden oracle | Multi-tenant platform and billing |

## The oracle

`src/engine/oracle.ts` is the engine's regression harness: a fixed corpus of
benign multi-source traffic plus attack scenarios, with hard bars for recall
(>= 80%), precision (< 1 false positive per week on benign traffic),
cross-source lift, and the honesty ceiling (an in-host attack the engine must
NOT claim to see). `npm test` runs it; changes that move judgment must move the
oracle consciously.

## License

AGPL-3.0-only. You can inspect it, run it, and build on it; improvements to
hosted derivatives must be shared. See [LICENSE](LICENSE) and
[CONTRIBUTING.md](CONTRIBUTING.md).
