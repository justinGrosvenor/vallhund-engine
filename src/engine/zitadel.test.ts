// Proves the source-agnostic generalization: Zitadel-sourced auth events flow
// through normalize -> detectors and trigger credential_stuffing, with the
// detection attributed to the "zitadel" source. (Uses events that carry an IP, as a
// Zitadel instance emitting login source IPs would.)
import { describe, it, expect } from "vitest";
import { normalizeNative } from "../ingest/shims.ts";
import type { ZitadelNative } from "../ingest/native.ts";
import { runAll } from "./detectors.ts";

function zEvent(ts: number, user: string, eventType: string, ip: string): ZitadelNative {
  return { creationDate: ts, eventType, userId: user, userName: `${user}@x.co`, ip, country: null, userAgent: null };
}

describe("zitadel adapter: source-agnostic identity detection", () => {
  const base = 1_748_822_400;
  const ip = "203.0.113.55";
  const events: ZitadelNative[] = [];
  for (let i = 0; i < 12; i++) {
    events.push(zEvent(base + i * 30, `victim${String(i % 6)}`, "user.human.password.check.failed", ip));
  }
  events.push(zEvent(base + 12 * 30, "victim0", "user.human.password.check.succeeded", ip));

  const normalized = normalizeNative({ zitadel: events });
  const detections = runAll(normalized);

  it("normalizes Zitadel events to the common action vocabulary", () => {
    expect(normalized.some((e) => e.source === "zitadel" && e.action === "login_failure")).toBe(true);
    expect(normalized.some((e) => e.source === "zitadel" && e.action === "login_success")).toBe(true);
  });

  it("fires credential_stuffing on Zitadel events, attributed to the zitadel source", () => {
    const cs = detections.find((d) => d.detector === "credential_stuffing");
    expect(cs).toBeDefined();
    expect(cs?.sources).toContain("zitadel");
    expect(cs?.severity).toBe("high"); // burst followed by a success = likely ATO
  });
});
