import { describe, it, expect } from "vitest";
import forge from "node-forge";
import { generateOcspResponse } from "../src/proxy/ocsp-response.js";

function createTestCA() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getFullYear() + 10, now.getMonth(), now.getDate());
  const attrs = [
    { name: "commonName", value: "Test CA" },
    { name: "organizationName", value: "Test" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, key: keys.privateKey, certPem: forge.pki.certificateToPem(cert), keyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

function createLeafCert(caCert: forge.pki.Certificate, caKey: forge.pki.rsa.PrivateKey, hostname: string) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate());
  cert.setSubject([{ name: "commonName", value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "subjectAltName", altNames: [{ type: 2, value: hostname }] },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  return cert;
}

describe("OCSP Response Generator", () => {
  const ca = createTestCA();
  const leafCert = createLeafCert(ca.cert, ca.key, "example.com");

  it("returns a Buffer", () => {
    const resp = generateOcspResponse(ca.cert, ca.key, leafCert);
    expect(resp).toBeInstanceOf(Buffer);
    expect(resp.length).toBeGreaterThan(0);
  });

  it("produces valid DER-encoded ASN.1", () => {
    const resp = generateOcspResponse(ca.cert, ca.key, leafCert);
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(resp.toString("binary")));
    // OCSPResponse is a SEQUENCE
    expect(asn1.type).toBe(forge.asn1.Type.SEQUENCE);
  });

  it("has responseStatus = successful (0)", () => {
    const resp = generateOcspResponse(ca.cert, ca.key, leafCert);
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(resp.toString("binary")));
    // First element is ENUMERATED with value 0
    const statusValue = asn1.value[0] as forge.asn1.Asn1;
    expect(statusValue.type).toBe(forge.asn1.Type.ENUMERATED);
    expect(statusValue.value).toBe(String.fromCharCode(0));
  });

  it("contains id-pkix-ocsp-basic OID", () => {
    const resp = generateOcspResponse(ca.cert, ca.key, leafCert);
    const derHex = resp.toString("hex");
    // OID 1.3.6.1.5.5.7.48.1.1 DER encoding
    const oidDer = forge.asn1.oidToDer("1.3.6.1.5.5.7.48.1.1").toHex();
    expect(derHex).toContain(oidDer);
  });

  it("contains the leaf cert serial number", () => {
    const resp = generateOcspResponse(ca.cert, ca.key, leafCert);
    const derHex = resp.toString("hex");
    expect(derHex).toContain(leafCert.serialNumber.toLowerCase());
  });

  it("generates different responses for different leaf certs", () => {
    const leaf2 = createLeafCert(ca.cert, ca.key, "other.com");
    const resp1 = generateOcspResponse(ca.cert, ca.key, leafCert);
    const resp2 = generateOcspResponse(ca.cert, ca.key, leaf2);
    expect(resp1.equals(resp2)).toBe(false);
  });
});
