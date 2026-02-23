export interface ScanResult {
  placeholders: Array<{
    headerName: string;
    placeholder: string;
    secretName: string;
  }>;
  warnings: string[];
}

const PLACEHOLDER_RE = /__([A-Z][A-Z0-9_]{1,63})__/g;
const NEAR_MISS_RE = /_([A-Z][A-Z0-9_]{1,63})_/g;

export function scanHeaders(headers: Record<string, string>): ScanResult {
  const placeholders: ScanResult["placeholders"] = [];
  const warnings: string[] = [];
  const foundPlaceholders = new Set<string>();

  for (const [headerName, value] of Object.entries(headers)) {
    // Find valid placeholders
    for (const match of value.matchAll(PLACEHOLDER_RE)) {
      const placeholder = match[0];
      const secretName = match[1];
      placeholders.push({ headerName, placeholder, secretName });
      foundPlaceholders.add(placeholder);
    }

    // Find near-miss patterns (single underscore instead of double)
    for (const match of value.matchAll(NEAR_MISS_RE)) {
      const nearMiss = match[0];
      // Skip if this is actually part of a valid __XX__ placeholder
      if (!foundPlaceholders.has(`_${nearMiss}_`)) {
        // Check it's truly a single-underscore pattern (not a substring of __)
        const idx = value.indexOf(nearMiss);
        const before = idx > 0 ? value[idx - 1] : "";
        const after = idx + nearMiss.length < value.length ? value[idx + nearMiss.length] : "";
        if (before !== "_" && after !== "_") {
          warnings.push(
            `Possible malformed placeholder "${nearMiss}" in header "${headerName}" — did you mean "__${match[1]}__"?`
          );
        }
      }
    }
  }

  return { placeholders, warnings };
}
