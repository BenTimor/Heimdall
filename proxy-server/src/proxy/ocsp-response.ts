import forge from "node-forge";

/**
 * Internal helper: builds a signed "good" OCSPResponse from a pre-built CertID
 * ASN.1 node.  Used by both `generateOcspResponse` (stapling) and
 * `handleOcspHttpRequest` (AIA responder).
 */
function buildOcspResponseFromCertId(
  certId: forge.asn1.Asn1,
  caCert: forge.pki.Certificate,
  caKey: forge.pki.rsa.PrivateKey,
): Buffer {
  // --- Time values ---
  const now = new Date();
  const nextUpdateDate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  const thisUpdateStr = formatGeneralizedTime(now);
  const nextUpdateStr = formatGeneralizedTime(nextUpdateDate);

  // --- SingleResponse ---
  const singleResponse = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      certId,
      // certStatus: [0] IMPLICIT NULL (good)
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, false, ""),
      // thisUpdate: GeneralizedTime
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.GENERALIZEDTIME,
        false,
        thisUpdateStr,
      ),
      // nextUpdate: [0] EXPLICIT GeneralizedTime
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.GENERALIZEDTIME,
          false,
          nextUpdateStr,
        ),
      ]),
    ],
  );

  // --- ResponseData ---
  const tbsResponseData = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      // responderID: [1] EXPLICIT (byName — CA's subject DN)
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 1, true, [
        forge.pki.distinguishedNameToAsn1(caCert.subject),
      ]),
      // producedAt: GeneralizedTime
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.GENERALIZEDTIME,
        false,
        thisUpdateStr,
      ),
      // responses: SEQUENCE OF SingleResponse
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        singleResponse,
      ]),
    ],
  );

  // --- Signature ---
  const tbsDer = forge.asn1.toDer(tbsResponseData).getBytes();
  const md = forge.md.sha256.create().update(tbsDer);
  const signatureBytes = caKey.sign(md);
  // BIT STRING: leading 0x00 byte = unused bits count
  const bitString = "\x00" + signatureBytes;

  // --- BasicOCSPResponse ---
  const basicOcspResponse = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      tbsResponseData,
      // signatureAlgorithm: SHA-256 with RSA
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer("1.2.840.113549.1.1.11").getBytes(),
        ),
      ]),
      // signature: BIT STRING
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.BITSTRING,
        false,
        bitString,
      ),
    ],
  );

  // --- OCSPResponse ---
  const basicOcspResponseDer = forge.asn1.toDer(basicOcspResponse).getBytes();

  const ocspResponse = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      // responseStatus: ENUMERATED = 0 (successful)
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.ENUMERATED,
        false,
        String.fromCharCode(0),
      ),
      // responseBytes: [0] EXPLICIT SEQUENCE
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          // responseType: OID id-pkix-ocsp-basic
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer("1.3.6.1.5.5.7.48.1.1").getBytes(),
          ),
          // response: OCTET STRING containing DER-encoded BasicOCSPResponse
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OCTETSTRING,
            false,
            basicOcspResponseDer,
          ),
        ]),
      ]),
    ],
  );

  return Buffer.from(forge.asn1.toDer(ocspResponse).getBytes(), "binary");
}

/**
 * Generates a DER-encoded OCSP response (RFC 6960) indicating the leaf
 * certificate's revocation status is "good", signed by the CA key.
 */
export function generateOcspResponse(
  caCert: forge.pki.Certificate,
  caKey: forge.pki.rsa.PrivateKey,
  leafCert: forge.pki.Certificate,
): Buffer {
  // --- CertID ---
  const issuerNameDer = forge.asn1.toDer(
    forge.pki.distinguishedNameToAsn1(caCert.subject),
  );
  const issuerNameHash = forge.md.sha1.create().update(issuerNameDer.getBytes()).digest().getBytes();

  // Extract the BIT STRING value from SubjectPublicKeyInfo for issuerKeyHash.
  // SubjectPublicKeyInfo = SEQUENCE { AlgorithmIdentifier, BIT STRING }.
  // We need the raw key bits inside the BIT STRING (skip the unused-bits byte).
  // forge.asn1.fromDer parses the BIT STRING contents into child ASN.1 nodes,
  // so we DER-encode the BIT STRING node, strip the tag+length wrapper, then
  // skip the leading unused-bits byte to get the actual public key bits.
  const spkiAsn1 = forge.pki.publicKeyToAsn1(caCert.publicKey);
  const spkiDer = forge.asn1.toDer(spkiAsn1).getBytes();
  const spkiParsed = forge.asn1.fromDer(forge.util.createBuffer(spkiDer));
  const bitStringAsn1 = (spkiParsed.value as forge.asn1.Asn1[])[1];
  const bitStringFullDer = forge.asn1.toDer(bitStringAsn1).getBytes();
  // Skip DER tag (0x03) + length encoding to reach the BIT STRING content
  let contentOffset = 1;
  const lenByte = bitStringFullDer.charCodeAt(contentOffset);
  if (lenByte < 0x80) {
    contentOffset = 2;
  } else {
    contentOffset = 2 + (lenByte & 0x7f);
  }
  // First byte of content is unused-bits count (0x00), skip it to get raw key bits
  const keyBits = bitStringFullDer.substring(contentOffset + 1);
  const issuerKeyHash = forge.md.sha1.create().update(keyBits).digest().getBytes();

  const serialBytes = forge.util.hexToBytes(leafCert.serialNumber);

  const certId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    // hashAlgorithm: AlgorithmIdentifier for SHA-1
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer("1.3.14.3.2.26").getBytes(),
      ),
    ]),
    // issuerNameHash
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      issuerNameHash,
    ),
    // issuerKeyHash
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      issuerKeyHash,
    ),
    // serialNumber
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.INTEGER,
      false,
      serialBytes,
    ),
  ]);

  return buildOcspResponseFromCertId(certId, caCert, caKey);
}

/**
 * Handles an HTTP OCSP request (POST /ocsp).
 *
 * Parses the DER-encoded OCSPRequest body, extracts the CertID from the first
 * request entry, and returns a signed "good" OCSPResponse.  This is called by
 * clients that discover the OCSP responder URL via the AIA extension in our
 * MITM leaf certificates.
 */
export function handleOcspHttpRequest(
  reqBody: Buffer,
  caCert: forge.pki.Certificate,
  caKey: forge.pki.rsa.PrivateKey,
): Buffer {
  // Parse the DER-encoded OCSPRequest (convert Buffer to binary string for forge)
  const asn1 = forge.asn1.fromDer(forge.util.createBuffer(reqBody.toString("binary")));

  // OCSPRequest ::= SEQUENCE {
  //   tbsRequest    TBSRequest,
  //   optionalSignature [0] EXPLICIT Signature OPTIONAL
  // }
  const tbsRequest = (asn1.value as forge.asn1.Asn1[])[0];

  // TBSRequest ::= SEQUENCE {
  //   version       [0] EXPLICIT Version DEFAULT v1,
  //   requestorName [1] EXPLICIT GeneralName OPTIONAL,
  //   requestList   SEQUENCE OF Request,
  //   requestExtensions [2] EXPLICIT Extensions OPTIONAL
  // }
  // Skip context-specific tagged elements ([0] version, [1] requestorName)
  // to find the first UNIVERSAL SEQUENCE child — that's the requestList.
  const tbsChildren = tbsRequest.value as forge.asn1.Asn1[];
  let requestList: forge.asn1.Asn1 | undefined;
  for (const child of tbsChildren) {
    if (
      child.tagClass === forge.asn1.Class.UNIVERSAL &&
      child.type === forge.asn1.Type.SEQUENCE
    ) {
      requestList = child;
      break;
    }
  }
  if (!requestList) {
    throw new Error("OCSP request: could not find requestList SEQUENCE");
  }

  // requestList is SEQUENCE OF Request
  // Request ::= SEQUENCE { reqCert CertID, ... }
  const firstRequest = (requestList.value as forge.asn1.Asn1[])[0];
  // reqCert is the first element of the Request SEQUENCE — it's a CertID SEQUENCE
  const certId = (firstRequest.value as forge.asn1.Asn1[])[0];

  return buildOcspResponseFromCertId(certId, caCert, caKey);
}

function formatGeneralizedTime(date: Date): string {
  const y = date.getUTCFullYear().toString();
  const m = (date.getUTCMonth() + 1).toString().padStart(2, "0");
  const d = date.getUTCDate().toString().padStart(2, "0");
  const h = date.getUTCHours().toString().padStart(2, "0");
  const min = date.getUTCMinutes().toString().padStart(2, "0");
  const s = date.getUTCSeconds().toString().padStart(2, "0");
  return `${y}${m}${d}${h}${min}${s}Z`;
}
