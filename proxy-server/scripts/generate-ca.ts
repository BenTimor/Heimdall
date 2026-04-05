import forge from "node-forge";
import * as fs from "node:fs";
import * as path from "node:path";

const CERTS_DIR = path.resolve(import.meta.dirname ?? __dirname, "..", "certs");

function generateCA(): void {
  // Generate RSA 4096-bit key pair
  const keys = forge.pki.rsa.generateKeyPair(4096);

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";

  // 10-year validity
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(
    now.getFullYear() + 10,
    now.getMonth(),
    now.getDate(),
  );

  const attrs = [
    { name: "commonName", value: "Heimdall Proxy CA" },
    { name: "organizationName", value: "Heimdall" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
      critical: true,
    },
    {
      name: "keyUsage",
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
    {
      name: "subjectKeyIdentifier",
    },
  ]);

  // Self-sign with the CA private key
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  // Create certs directory if it doesn't exist
  if (!fs.existsSync(CERTS_DIR)) {
    fs.mkdirSync(CERTS_DIR, { recursive: true });
  }

  const certPath = path.join(CERTS_DIR, "ca.crt");
  const keyPath = path.join(CERTS_DIR, "ca.key");

  fs.writeFileSync(certPath, certPem);
  fs.writeFileSync(keyPath, keyPem);

  console.log("CA certificate and key generated successfully:");
  console.log(`  Certificate: ${certPath}`);
  console.log(`  Private key: ${keyPath}`);
}

generateCA();
