import { matchesDomain } from "../utils/domain-matcher.js";

export function normalizeSourceIp(sourceIp?: string): string | undefined {
  if (!sourceIp) return undefined;

  let normalized = sourceIp.trim();
  const zoneIdx = normalized.indexOf("%");
  if (zoneIdx !== -1) {
    normalized = normalized.slice(0, zoneIdx);
  }
  if (normalized.startsWith("::ffff:")) {
    normalized = normalized.slice("::ffff:".length);
  }

  return normalized || undefined;
}

export function isSourceIpAllowed(sourceIp: string | undefined, sourceCidrs: string[]): boolean {
  if (sourceCidrs.length === 0) {
    return true;
  }

  const normalized = normalizeSourceIp(sourceIp);
  if (!normalized) {
    return false;
  }

  return sourceCidrs.some((pattern) => {
    const trimmed = pattern.trim();
    return trimmed.length > 0 && matchesDomain(normalized, trimmed);
  });
}
