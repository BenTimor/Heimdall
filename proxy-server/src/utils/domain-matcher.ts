import { Buffer } from "node:buffer";

function parseIPv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    nums.push(n);
  }
  return nums;
}

function ipToUint32(octets: number[]): number {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function matchesCIDR(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split("/");
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;

  const ipOctets = parseIPv4(ip);
  const netOctets = parseIPv4(network);
  if (!ipOctets || !netOctets) return false;

  const ipNum = ipToUint32(ipOctets);
  const netNum = ipToUint32(netOctets);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;

  return (ipNum & mask) === (netNum & mask);
}

function isIPGlobPattern(pattern: string): boolean {
  const parts = pattern.split(".");
  if (parts.length < 1 || parts.length > 4) return false;
  return parts.every(
    (p) => p === "*" || (Number.isInteger(Number(p)) && Number(p) >= 0 && Number(p) <= 255)
  );
}

function matchesIPGlob(ip: string, pattern: string): boolean {
  const ipParts = ip.split(".");
  const patParts = pattern.split(".");
  if (ipParts.length !== 4) return false;

  for (let i = 0; i < patParts.length; i++) {
    if (patParts[i] === "*") continue;
    if (ipParts[i] !== patParts[i]) return false;
  }
  return true;
}

export function matchesDomain(hostname: string, pattern: string): boolean {
  const host = hostname.toLowerCase();
  const pat = pattern.toLowerCase();

  // CIDR notation
  if (pat.includes("/")) {
    return matchesCIDR(host, pat);
  }

  // IP glob (e.g. "10.*")
  if (isIPGlobPattern(pat)) {
    return matchesIPGlob(host, pat);
  }

  // Wildcard domain (e.g. "*.example.com")
  if (pat.startsWith("*.")) {
    const suffix = pat.slice(1); // ".example.com"
    // Must have at least one subdomain level — host !== bare domain
    return host.endsWith(suffix) && host.length > suffix.length;
  }

  // Exact match
  return host === pat;
}

export function matchesAnyDomain(
  hostname: string,
  patterns: string[]
): boolean {
  return patterns.some((p) => matchesDomain(hostname, p));
}
