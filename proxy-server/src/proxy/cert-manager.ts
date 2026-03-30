import forge from "node-forge";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import { generateOcspResponse } from "./ocsp-response.js";

interface CachedCertificate {
  cert: string;
  key: string;
  ocspResponse: Buffer;
}

interface LeafKeyPairPem {
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface CertificateResult extends CachedCertificate {
  fromCache: boolean;
  keySource: "cache" | "prebuilt" | "sync-generated";
}

export class CertManager {
  private caCert: forge.pki.Certificate;
  private caKey: forge.pki.rsa.PrivateKey;
  private cache: Map<string, CachedCertificate>;
  private maxCacheSize: number;

  private caKeyId: string;
  private ocspUrl: string | undefined;
  private warmKeyPairPoolSize: number;
  private keyPairPool: LeafKeyPairPem[] = [];
  private pendingKeyPairBuilds = 0;

  constructor(
    caCertPem: string,
    caKeyPem: string,
    ocspUrl?: string,
    maxCacheSize: number = 10_000,
    warmKeyPairPoolSize: number = 4,
  ) {
    this.caCert = forge.pki.certificateFromPem(caCertPem);
    this.caKey = forge.pki.privateKeyFromPem(caKeyPem);
    this.cache = new Map();
    this.maxCacheSize = maxCacheSize;
    this.ocspUrl = ocspUrl;
    this.warmKeyPairPoolSize = Math.max(0, warmKeyPairPoolSize);

    // Pre-compute the CA's subject key identifier (raw binary) for use in
    // leaf cert authorityKeyIdentifier extensions.  Forge v1.3.3 doesn't
    // hex-decode the string automatically, so we convert once here.
    const skiExt = this.caCert.getExtension("subjectKeyIdentifier") as
      { subjectKeyIdentifier?: string } | null;
    this.caKeyId = skiExt?.subjectKeyIdentifier
      ? forge.util.hexToBytes(skiExt.subjectKeyIdentifier)
      : forge.pki.getPublicKeyFingerprint(this.caCert.publicKey, {
          md: forge.md.sha1.create(),
        }).getBytes();

    this.fillKeyPairPool();
  }

  getCertificate(hostname: string): CertificateResult {
    const cached = this.cache.get(hostname);
    if (cached) {
      // Move to end of Map iteration order (most recently used)
      this.cache.delete(hostname);
      this.cache.set(hostname, cached);
      return {
        ...cached,
        fromCache: true,
        keySource: "cache",
      };
    }

    const { publicKeyPem, privateKeyPem, keySource } = this.getLeafKeyPair();
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

    const cert = forge.pki.createCertificate();

    cert.publicKey = publicKey;
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

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const extensions: any[] = [
      {
        name: "basicConstraints",
        cA: false,
      },
      {
        name: "subjectAltName",
        altNames: sanExtension,
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
        name: "subjectKeyIdentifier",
      },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: this.caKeyId,
      },
    ];

    // Add Authority Information Access (AIA) extension pointing to our OCSP
    // responder so that clients (e.g. Windows schannel) can verify revocation
    // status of MITM leaf certs.  Forge v1.3.3 doesn't support AIA by name,
    // so we build the raw extension value manually.
    if (this.ocspUrl) {
      const aiaValue = forge.asn1.create(
        forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
              // accessMethod: id-ad-ocsp (1.3.6.1.5.5.7.48.1)
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                forge.asn1.oidToDer("1.3.6.1.5.5.7.48.1").getBytes(),
              ),
              // accessLocation: [6] IMPLICIT IA5String (uniformResourceIdentifier)
              forge.asn1.create(
                forge.asn1.Class.CONTEXT_SPECIFIC, 6, false,
                this.ocspUrl,
              ),
            ],
          ),
        ],
      );
      extensions.push({
        id: "1.3.6.1.5.5.7.1.1",
        value: forge.asn1.toDer(aiaValue).getBytes(),
      });
    }

    cert.setExtensions(extensions);

    cert.sign(this.caKey, forge.md.sha256.create());

    const ocspResponse = generateOcspResponse(this.caCert, this.caKey, cert);

    const result: CachedCertificate = {
      cert: forge.pki.certificateToPem(cert),
      key: forge.pki.privateKeyToPem(privateKey),
      ocspResponse,
    };

    // LRU eviction: remove oldest entries if cache is at capacity
    if (this.cache.size >= this.maxCacheSize) {
      const keysToDelete = this.cache.size - this.maxCacheSize + 1;
      const iter = this.cache.keys();
      for (let i = 0; i < keysToDelete; i++) {
        const oldest = iter.next().value;
        if (oldest !== undefined) {
          this.cache.delete(oldest);
        }
      }
    }

    this.cache.set(hostname, result);
    return {
      ...result,
      fromCache: false,
      keySource,
    };
  }

  clearCache(): void {
    this.cache.clear();
  }

  get cacheSize(): number {
    return this.cache.size;
  }

  private getLeafKeyPair(): LeafKeyPairPem & { keySource: "prebuilt" | "sync-generated" } {
    const pooled = this.keyPairPool.pop();
    if (pooled) {
      this.fillKeyPairPool();
      return {
        ...pooled,
        keySource: "prebuilt",
      };
    }

    // Fallback to synchronous generation when the warm pool is empty.
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    return {
      publicKeyPem: publicKey,
      privateKeyPem: privateKey,
      keySource: "sync-generated",
    };
  }

  private fillKeyPairPool(): void {
    while (this.keyPairPool.length + this.pendingKeyPairBuilds < this.warmKeyPairPoolSize) {
      this.pendingKeyPairBuilds++;
      crypto.generateKeyPair(
        "rsa",
        {
          modulusLength: 2048,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        },
        (err, publicKey, privateKey) => {
          this.pendingKeyPairBuilds--;

          if (!err) {
            this.keyPairPool.push({
              publicKeyPem: publicKey as string,
              privateKeyPem: privateKey as string,
            });
          }

          this.fillKeyPairPool();
        },
      );
    }
  }
}

export function loadCertManager(
  certFile: string,
  keyFile: string,
  ocspUrl?: string,
  maxCacheSize?: number,
  warmKeyPairPoolSize?: number,
): CertManager {
  const caCertPem = fs.readFileSync(certFile, "utf-8");
  const caKeyPem = fs.readFileSync(keyFile, "utf-8");
  return new CertManager(caCertPem, caKeyPem, ocspUrl, maxCacheSize, warmKeyPairPoolSize);
}
