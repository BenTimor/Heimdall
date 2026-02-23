import forge from "node-forge";
import * as fs from "node:fs";
import * as net from "node:net";

export class CertManager {
  private caCert: forge.pki.Certificate;
  private caKey: forge.pki.rsa.PrivateKey;
  private cache: Map<string, { cert: string; key: string }>;

  constructor(caCertPem: string, caKeyPem: string) {
    this.caCert = forge.pki.certificateFromPem(caCertPem);
    this.caKey = forge.pki.privateKeyFromPem(caKeyPem);
    this.cache = new Map();
  }

  getCertificate(hostname: string): { cert: string; key: string } {
    const cached = this.cache.get(hostname);
    if (cached) {
      return cached;
    }

    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));

    const now = new Date();
    cert.validity.notBefore = now;
    cert.validity.notAfter = new Date(
      now.getFullYear() + 1,
      now.getMonth(),
      now.getDate(),
    );

    cert.setSubject([{ name: "commonName", value: hostname }]);
    cert.setIssuer(this.caCert.subject.attributes);

    const sanExtension: { type: number; value?: string; ip?: string }[] = [];
    if (net.isIP(hostname)) {
      sanExtension.push({ type: 7, ip: hostname });
    } else {
      sanExtension.push({ type: 2, value: hostname });
    }

    cert.setExtensions([
      {
        name: "basicConstraints",
        cA: false,
      },
      {
        name: "subjectAltName",
        altNames: sanExtension,
      },
    ]);

    cert.sign(this.caKey, forge.md.sha256.create());

    const result = {
      cert: forge.pki.certificateToPem(cert),
      key: forge.pki.privateKeyToPem(keys.privateKey),
    };

    this.cache.set(hostname, result);
    return result;
  }

  clearCache(): void {
    this.cache.clear();
  }

  get cacheSize(): number {
    return this.cache.size;
  }
}

export function loadCertManager(
  certFile: string,
  keyFile: string,
): CertManager {
  const caCertPem = fs.readFileSync(certFile, "utf-8");
  const caKeyPem = fs.readFileSync(keyFile, "utf-8");
  return new CertManager(caCertPem, caKeyPem);
}
