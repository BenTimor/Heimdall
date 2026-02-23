import { describe, it, expect } from "vitest";
import { scanHeaders } from "../src/injection/scanner.js";

describe("scanHeaders", () => {
  it("detects a single placeholder", () => {
    const result = scanHeaders({
      Authorization: "Bearer __OPENAI_API_KEY__",
    });
    expect(result.placeholders).toHaveLength(1);
    expect(result.placeholders[0]).toEqual({
      headerName: "Authorization",
      placeholder: "__OPENAI_API_KEY__",
      secretName: "OPENAI_API_KEY",
    });
    expect(result.warnings).toHaveLength(0);
  });

  it("detects multiple placeholders in one header", () => {
    const result = scanHeaders({
      "X-Combo": "__KEY_A__ and __KEY_B__",
    });
    expect(result.placeholders).toHaveLength(2);
    expect(result.placeholders[0].secretName).toBe("KEY_A");
    expect(result.placeholders[1].secretName).toBe("KEY_B");
  });

  it("detects placeholders across multiple headers", () => {
    const result = scanHeaders({
      Authorization: "Bearer __TOKEN_A__",
      "X-Api-Key": "__TOKEN_B__",
    });
    expect(result.placeholders).toHaveLength(2);
    expect(result.placeholders[0].headerName).toBe("Authorization");
    expect(result.placeholders[1].headerName).toBe("X-Api-Key");
  });

  it("returns empty for no placeholders", () => {
    const result = scanHeaders({
      Authorization: "Bearer sk-some-token",
      "Content-Type": "application/json",
    });
    expect(result.placeholders).toHaveLength(0);
  });

  it("warns on near-miss single-underscore patterns", () => {
    const result = scanHeaders({
      Authorization: "Bearer _OPENAI_KEY_",
    });
    expect(result.placeholders).toHaveLength(0);
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.warnings[0]).toContain("Possible malformed placeholder");
    expect(result.warnings[0]).toContain("_OPENAI_KEY_");
  });
});
