// A Map with a hard size cap. Evicts the oldest entry (insertion order) when full, bounding
// memory in long-lived processes (the worker) where per-IP enrichment caches — GreyNoise scanner
// verdicts, FCrDNS crawler verdicts — would otherwise grow without limit. FIFO, not strict LRU:
// the goal is a memory ceiling, not recency optimality, and verdicts are cheap to recompute.

export class BoundedCache<K, V> {
  private readonly map = new Map<K, V>();
  private readonly max: number;

  // Note: an explicit field + assignment, NOT a constructor parameter property — these .ts files
  // run under Node's strip-only mode, which doesn't support `constructor(private max: number)`.
  constructor(max: number) {
    this.max = max;
  }

  get(key: K): V | undefined {
    return this.map.get(key);
  }

  set(key: K, value: V): void {
    if (this.map.size >= this.max && !this.map.has(key)) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    this.map.set(key, value);
  }

  delete(key: K): void {
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}
