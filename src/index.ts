// @vallhund/engine — the open judgment core behind Vallhund.
//
// Deliberately small public surface: normalized events in, findings / traffic intelligence /
// remediation prompts out. Internal helpers and per-detector functions are NOT exported here;
// import depth is a signal that something belongs in the API, so open an issue instead of
// deep-importing.

// ── schema ────────────────────────────────────────────────
export { A } from "./engine/schema.ts";
export type {
  NormalizedEvent,
  Detection,
  Severity,
  SourceKind,
  CoverageLayer,
} from "./engine/schema.ts";

// ── native shapes + pure normalizers (data-in/data-out, no fetch/auth) ──
export type {
  NativeBatch,
  CloudflareHttpNative,
  CloudflareWafNative,
  CloudTrailNative,
  GcpAuditNative,
  GithubAuditNative,
  SupabaseNative,
  VercelDrainNative,
  VercelNative,
  ZitadelNative,
} from "./ingest/native.ts";
export { mergeNative } from "./ingest/native.ts";
export { normalizeNative, isVerifiedBot } from "./ingest/shims.ts";

// ── detection ─────────────────────────────────────────────
export { runAll, runAll as runAllDetectors, ALL_DETECTORS } from "./engine/detectors.ts";
export { runEngine, runAggregate, buildBaseline, AGGREGATE_DETECTOR_NAMES } from "./engine/aggregate.ts";
export type { BaselineProfile, WindowSignals } from "./engine/aggregate.ts";

// ── judgment: classification, actionability, overview ─────
export {
  baseFindingView,
  buildOverview,
  deriveMetrics,
  classificationOf,
  classificationForDetector,
  resolveFindingClassification,
  isFoeDetector,
  actionabilityOf,
  actionabilityScore,
} from "./engine/overview.ts";
export type {
  FindingView,
  Classification,
  Actionability,
  OverviewData,
  SnapshotMetrics,
  AttentionRow,
  Headline,
} from "./engine/overview.ts";
export { buildEntities } from "./engine/entities.ts";
export type { EntityView, EntityKind, Reputation } from "./engine/entities.ts";
export { buildIncidents } from "./engine/incidents.ts";
export type { Incident, IncidentSignal } from "./engine/incidents.ts";

// ── traffic pillar: actors, profile, barks ────────────────
export { classifyActor, actorLabel, ALL_ACTOR_CLASSES } from "./traffic/actors.ts";
export type { ActorClass, ActorVerdict } from "./traffic/actors.ts";
export { deriveTrafficProfile, endpointKey } from "./traffic/profile.ts";
export type { TrafficProfile, EndpointRow, ActorMixRow, BaseRow, NamedAgentRow, ActorCounts } from "./traffic/profile.ts";
export { deriveTrafficBarks } from "./traffic/barks.ts";
export { isSensitivePath, isFileExfilPath, fileExfilFamily, templatePath } from "./traffic/paths.ts";
export { verifyCrawler, claimsVerifiableCrawler, isVerifiableCrawler, rdnsEnabled } from "./traffic/rdns.ts";
export type { CrawlerVerdict } from "./traffic/rdns.ts";

// ── enrichment (deterministic, local) ─────────────────────
export { classifyAsn } from "./enrich/asn.ts";
export type { AsnClass, ScannerVerdict } from "./enrich/asn.ts";

// ── remediation ───────────────────────────────────────────
export { buildRemediation, redactSecrets } from "./remediation/remediation.ts";
export type { Remediation, RemediationContext, RemediationMode } from "./remediation/remediation.ts";

// ── posture (credential-free) ─────────────────────────────
export type { PostureFinding } from "./posture/types.ts";
export { extractCves, parseKevCatalog, getKevCatalog, kevEnrich } from "./posture/kev.ts";
export type { KevEntry, KevCatalog } from "./posture/kev.ts";
export { scanFrontDoor, analyzeHeaders, analyzeCookies, analyzeProbe } from "./posture/front-door.ts";

// ── oracle (the engine's own regression harness) ──────────
export { runOracle } from "./engine/oracle.ts";
export type { OracleResult } from "./engine/oracle.ts";
