import { describe, it, expect, beforeAll, afterAll } from "vitest";
import forge from "node-forge";
import * as fs from "node:fs";
import * as path from "node:path";
import * as child_process from "node:child_process";
import { CertManager } from "../src/proxy/cert-manager.js";

// Generate an in-memory CA for unit tests
function createTestCA() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(
    now.getFullYear() + 10,
    now.getMonth(),
    now.getDate(),
  );
  const attrs = [
    { name: "commonName", value: "Test CA" },
    { name: "organizationName", value: "Test" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    cert,
  };
}

describe("CertManager", () => {
  const ca = createTestCA();
  let manager: CertManager;

  beforeAll(() => {
    manager = new CertManager(ca.certPem, ca.keyPem);
  });

  it("generates a valid PEM certificate for a hostname", () => {
    const result = manager.getCertificate("example.com");

    expect(result.cert).toContain("-----BEGIN CERTIFICATE-----");
    expect(result.cert).toContain("-----END CERTIFICATE-----");
    expect(result.key).toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(result.key).toContain("-----END RSA PRIVATE KEY-----");
  });

  it("generates a cert signed by the CA", () => {
    const result = manager.getCertificate("signed-test.com");
    const generated = forge.pki.certificateFromPem(result.cert);

    // Verify the issuer matches the CA subject
    expect(generated.issuer.getField("CN")?.value).toBe("Test CA");
    expect(generated.issuer.getField("O")?.value).toBe("Test");

    // Verify the CA can validate the generated cert
    const caStore = forge.pki.createCaStore([ca.certPem]);
    const verified = forge.pki.verifyCertificateChain(caStore, [generated]);
    expect(verified).toBe(true);
  });

  it("sets the Subject Alternative Name with the hostname", () => {
    const result = manager.getCertificate("san-test.example.org");
    const generated = forge.pki.certificateFromPem(result.cert);

    const sanExt = generated.getExtension("subjectAltName") as {
      altNames: { type: number; value?: string; ip?: string }[];
    } | null;
    expect(sanExt).not.toBeNull();
    expect(sanExt!.altNames).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 2, value: "san-test.example.org" }),
      ]),
    );
  });

  it("generates a cert with iPAddress SAN for IP addresses", () => {
    const result = manager.getCertificate("10.0.0.1");
    const generated = forge.pki.certificateFromPem(result.cert);

    const sanExt = generated.getExtension("subjectAltName") as {
      altNames: { type: number; value?: string; ip?: string }[];
    } | null;
    expect(sanExt).not.toBeNull();
    expect(sanExt!.altNames).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 7, ip: "10.0.0.1" }),
      ]),
    );
  });

  it("caches certificates and returns the same one for repeat calls", () => {
    const fresh = new CertManager(ca.certPem, ca.keyPem);
    const first = fresh.getCertificate("cached.example.com");
    const second = fresh.getCertificate("cached.example.com");

    expect(fresh.cacheSize).toBe(1);
    expect(first.cert).toBe(second.cert);
    expect(first.key).toBe(second.key);
  });

  it("clears the cache", () => {
    const fresh = new CertManager(ca.certPem, ca.keyPem);
    fresh.getCertificate("a.com");
    fresh.getCertificate("b.com");
    expect(fresh.cacheSize).toBe(2);

    fresh.clearCache();
    expect(fresh.cacheSize).toBe(0);
  });
});

describe("generate-ca.ts script", () => {
  const projectRoot = path.resolve(import.meta.dirname ?? __dirname, "..");
  const certsDir = path.join(projectRoot, "certs");
  const certPath = path.join(certsDir, "ca.crt");
  const keyPath = path.join(certsDir, "ca.key");

  // Clean up any existing certs before the test
  beforeAll(() => {
    if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
    if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
  });

  afterAll(() => {
    // Clean up generated files
    if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
    if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
    if (fs.existsSync(certsDir)) {
      try {
        fs.rmdirSync(certsDir);
      } catch {
        // directory not empty, that's fine
      }
    }
  });

  it("generates CA cert and key files", () => {
    const result = child_process.execSync("npx tsx scripts/generate-ca.ts", {
      cwd: projectRoot,
      encoding: "utf-8",
      timeout: 60000,
    });

    expect(result).toContain("CA certificate and key generated successfully");
    expect(fs.existsSync(certPath)).toBe(true);
    expect(fs.existsSync(keyPath)).toBe(true);
  });

  it("generates a valid CA cert with basicConstraints cA=true", () => {
    // The previous test must have run first
    expect(fs.existsSync(certPath)).toBe(true);

    const certPem = fs.readFileSync(certPath, "utf-8");
    const cert = forge.pki.certificateFromPem(certPem);

    expect(cert.subject.getField("CN")?.value).toBe("Guardian Proxy CA");
    expect(cert.subject.getField("O")?.value).toBe("Guardian");

    const bc = cert.getExtension("basicConstraints") as {
      cA: boolean;
    } | null;
    expect(bc).not.toBeNull();
    expect(bc!.cA).toBe(true);
  });
});
