import { describe, it, expect } from "vitest";
import { BoundedCache } from "./bounded-cache.ts";

describe("BoundedCache", () => {
  it("stores and retrieves values", () => {
    const c = new BoundedCache<string, number>(3);
    c.set("a", 1);
    expect(c.get("a")).toBe(1);
    expect(c.get("missing")).toBeUndefined();
  });

  it("evicts the oldest entry once the cap is exceeded", () => {
    const c = new BoundedCache<string, number>(2);
    c.set("a", 1);
    c.set("b", 2);
    c.set("c", 3); // evicts "a"
    expect(c.size).toBe(2);
    expect(c.get("a")).toBeUndefined();
    expect(c.get("b")).toBe(2);
    expect(c.get("c")).toBe(3);
  });

  it("re-setting an existing key updates in place without evicting", () => {
    const c = new BoundedCache<string, number>(2);
    c.set("a", 1);
    c.set("b", 2);
    c.set("a", 99); // existing key — no eviction
    expect(c.size).toBe(2);
    expect(c.get("a")).toBe(99);
    expect(c.get("b")).toBe(2);
  });
});
