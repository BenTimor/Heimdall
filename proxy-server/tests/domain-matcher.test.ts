import { describe, it, expect } from "vitest";
import {
  matchesDomain,
  matchesAnyDomain,
} from "../src/utils/domain-matcher.js";

describe("matchesDomain", () => {
  describe("exact match", () => {
    it("matches identical hostnames", () => {
      expect(matchesDomain("api.openai.com", "api.openai.com")).toBe(true);
    });

    it("is case-insensitive", () => {
      expect(matchesDomain("API.OpenAI.COM", "api.openai.com")).toBe(true);
      expect(matchesDomain("api.openai.com", "API.OPENAI.COM")).toBe(true);
    });

    it("does not match different hostnames", () => {
      expect(matchesDomain("evil.com", "api.openai.com")).toBe(false);
    });
  });

  describe("wildcard domain", () => {
    it("matches subdomain", () => {
      expect(matchesDomain("foo.example.com", "*.example.com")).toBe(true);
    });

    it("matches deep subdomain", () => {
      expect(matchesDomain("a.b.example.com", "*.example.com")).toBe(true);
    });

    it("does not match bare domain", () => {
      expect(matchesDomain("example.com", "*.example.com")).toBe(false);
    });

    it("does not match unrelated domain", () => {
      expect(matchesDomain("evil.com", "*.example.com")).toBe(false);
    });
  });

  describe("IP glob", () => {
    it("matches 10.*", () => {
      expect(matchesDomain("10.0.0.1", "10.*")).toBe(true);
      expect(matchesDomain("10.255.0.99", "10.*")).toBe(true);
    });

    it("does not match different prefix", () => {
      expect(matchesDomain("192.168.0.1", "10.*")).toBe(false);
    });

    it("matches more specific glob 192.168.*", () => {
      expect(matchesDomain("192.168.1.1", "192.168.*")).toBe(true);
      expect(matchesDomain("192.169.1.1", "192.168.*")).toBe(false);
    });
  });

  describe("CIDR", () => {
    it("matches 10.0.0.0/8", () => {
      expect(matchesDomain("10.0.0.1", "10.0.0.0/8")).toBe(true);
      expect(matchesDomain("10.255.255.255", "10.0.0.0/8")).toBe(true);
    });

    it("does not match outside range", () => {
      expect(matchesDomain("11.0.0.1", "10.0.0.0/8")).toBe(false);
    });

    it("matches /32 exact", () => {
      expect(matchesDomain("1.2.3.4", "1.2.3.4/32")).toBe(true);
      expect(matchesDomain("1.2.3.5", "1.2.3.4/32")).toBe(false);
    });
  });
});

describe("matchesAnyDomain", () => {
  it("returns true if any pattern matches", () => {
    expect(
      matchesAnyDomain("foo.corp.com", ["*.corp.com", "10.*"])
    ).toBe(true);
  });

  it("returns false if no pattern matches", () => {
    expect(matchesAnyDomain("evil.com", ["*.corp.com", "10.*"])).toBe(false);
  });

  it("returns false for empty patterns", () => {
    expect(matchesAnyDomain("anything.com", [])).toBe(false);
  });
});
