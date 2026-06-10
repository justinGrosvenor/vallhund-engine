// Run the full judgment pipeline on the bundled fixtures — no credentials, no network, no setup:
//   npm run example:basic
//
// This is the same code path hosted Vallhund runs on your live telemetry: normalize native
// events, run the detectors, classify findings, derive the traffic profile + barks, and build
// an agent-ready remediation prompt for the top actionable finding.

import { attacks, benignNative } from "../src/engine/fixtures.ts";
import {
  baseFindingView,
  buildOverview,
  buildRemediation,
  deriveMetrics,
  deriveTrafficBarks,
  deriveTrafficProfile,
  mergeNative,
  normalizeNative,
  runEngine,
} from "../src/index.ts";

// 1. Events: a week of benign multi-source traffic + attack scenario A injected into it.
const atk = attacks();
const events = normalizeNative(mergeNative(benignNative(), atk.A.native));
console.log(`normalized events : ${events.length}`);

// 2. Detection: per-entity rules + aggregate detectors over the same events.
const detections = runEngine(events);
const findings = detections.map(baseFindingView);
console.log(`findings          : ${findings.length}`);
for (const f of findings) {
  console.log(`  [${f.severity}] ${f.detector} actor=${f.actor} → ${f.classification} (${f.actionability})`);
}

// 3. Traffic pillar: who is at the door, endpoint by endpoint — plus traffic-derived barks.
const profile = deriveTrafficProfile(events);
const lastTs = events.reduce((m, e) => Math.max(m, e.ts), 0);
const barks = deriveTrafficBarks(profile, lastTs);
console.log(`traffic           : ${profile.endpoints.length} endpoints, ${barks.length} traffic barks`);

// 4. Overview: friend/foe split + what deserves attention, with the coverage boundary attached.
const overview = buildOverview(deriveMetrics(events), findings, false);
console.log(`actors            : ${overview.counts.friend} friend · ${overview.counts.foe} foe · ${overview.counts.unknown} unknown`);
console.log(`coverage boundary : observed=${overview.coverageActive.join(",")} blind=${overview.coverageNotCovered.join(",")}`);

// 5. Remediation: a paste-ready prompt for the first actionable finding.
const actionable = findings.find((f) => f.actionability === "actionable");
if (actionable !== undefined) {
  const r = buildRemediation(actionable, { project: "local-example", connectedSources: ["Cloudflare"] });
  console.log(`\n--- remediation prompt for ${actionable.detector} ---\n`);
  console.log(r.patch);
}
