import forge from "node-forge";
import * as fs from "node:fs";
import * as path from "node:path";

const CERTS_DIR = path.resolve(import.meta.dirname ?? __dirname, "..", "certs");

function generateTunnelCert(): void {
  const certPath = path.join(CERTS_DIR, "ca.crt");
  const keyPath = path.join(CERTS_DIR, "ca.key");

  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    console.error(
      "CA certificate not found. Run `pnpm run generate-ca` first.",
    );
    process.exit(1);
  }

  const caCert = forge.pki.certificateFromPem(
    fs.readFileSync(certPath, "utf-8"),
  );
  const caKey = forge.pki.privateKeyFromPem(
    fs.readFileSync(keyPath, "utf-8"),
  );

  // Accept server address as CLI argument (IP or hostname)
  const serverAddress = process.argv[2];
  if (!serverAddress) {
    console.error("Usage: pnpm run generate-tunnel-cert <server-ip-or-hostname>");
    console.error("Example: pnpm run generate-tunnel-cert 46.62.221.2");
    console.error("Example: pnpm run generate-tunnel-cert proxy.example.com");
    process.exit(1);
  }

  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(serverAddress);

  // Generate RSA 2048-bit key pair for tunnel server
  const keys = forge.pki.rsa.generateKeyPair(2048);

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(
    now.getFullYear() + 1,
    now.getMonth(),
    now.getDate(),
  );

  const attrs = [{ name: "commonName", value: serverAddress }];
  cert.setSubject(attrs);
  cert.setIssuer(caCert.subject.attributes);

  const altName = isIP
    ? { type: 7, ip: serverAddress }
    : { type: 2, value: serverAddress };

  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: false,
      critical: true,
    },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    {
      name: "extKeyUsage",
      serverAuth: true,
    },
    {
      name: "subjectAltName",
      altNames: [altName],
    },
  ]);

  // Sign with the CA private key
  cert.sign(caKey, forge.md.sha256.create());

  const tunnelCertPem = forge.pki.certificateToPem(cert);
  const tunnelKeyPem = forge.pki.privateKeyToPem(keys.privateKey);

  const tunnelCertPath = path.join(CERTS_DIR, "tunnel.crt");
  const tunnelKeyPath = path.join(CERTS_DIR, "tunnel.key");

  fs.writeFileSync(tunnelCertPath, tunnelCertPem);
  fs.writeFileSync(tunnelKeyPath, tunnelKeyPem);

  console.log("Tunnel certificate generated successfully:");
  console.log(`  Certificate: ${tunnelCertPath}`);
  console.log(`  Private key: ${tunnelKeyPath}`);
  console.log(`  Server address: ${serverAddress} (${isIP ? "IP" : "hostname"})`);
  console.log(`  Signed by: ${caCert.subject.getField("CN").value}`);
  console.log(`  Valid for: 1 year`);
}

generateTunnelCert();
