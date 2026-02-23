import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SecretCache } from "../src/secrets/cache.js";

describe("SecretCache", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("stores and retrieves a value", () => {
    const cache = new SecretCache(5000);
    cache.set("k1", "v1");
    expect(cache.get("k1")).toBe("v1");
  });

  it("returns null for unknown key", () => {
    const cache = new SecretCache(5000);
    expect(cache.get("nope")).toBeNull();
  });

  it("evicts expired entries lazily on get", () => {
    const cache = new SecretCache(1000);
    cache.set("k1", "v1");
    expect(cache.get("k1")).toBe("v1");

    vi.advanceTimersByTime(1001);
    expect(cache.get("k1")).toBeNull();
  });

  it("supports custom TTL per entry", () => {
    const cache = new SecretCache(10000);
    cache.set("short", "val", 500);

    vi.advanceTimersByTime(501);
    expect(cache.get("short")).toBeNull();
  });

  it("clears all entries", () => {
    const cache = new SecretCache(5000);
    cache.set("a", "1");
    cache.set("b", "2");
    expect(cache.size).toBe(2);
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get("a")).toBeNull();
  });

  it("reports size including expired (not yet evicted)", () => {
    const cache = new SecretCache(1000);
    cache.set("a", "1");
    cache.set("b", "2");
    vi.advanceTimersByTime(1001);
    // size still 2 until accessed
    expect(cache.size).toBe(2);
    // accessing triggers eviction
    cache.get("a");
    expect(cache.size).toBe(1);
  });
});
