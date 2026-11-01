// Builds a CAdES-B-B signature (ETSI EN 319 122-1 baseline, CMS SignedData, RFC 5652)
// in the browser. Flow:
//   1. buildSignedAttributes() -> bytes the card must sign (hash them, send the hash to the card)
//   2. buildCms() -> wraps the card's signature, the signer certificate and the attributes.
// Detached (.p7s) and attached (.p7m) forms share the same signature, because the
// signature covers the signed attributes, which contain the document digest.
import { bytesToB64 } from "./der.js";

const OID = {
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingTime: "1.2.840.113549.1.9.5",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
};
const HASH_OID = {
  "SHA-256": "2.16.840.1.101.3.4.2.1",
  "SHA-384": "2.16.840.1.101.3.4.2.2",
  "SHA-512": "2.16.840.1.101.3.4.2.3",
};
const RSA_SIG_OID = {
  "SHA-256": "1.2.840.113549.1.1.11",
  "SHA-384": "1.2.840.113549.1.1.12",
  "SHA-512": "1.2.840.113549.1.1.13",
};
const ECDSA_SIG_OID = {
  "SHA-256": "1.2.840.10045.4.3.2",
  "SHA-384": "1.2.840.10045.4.3.3",
  "SHA-512": "1.2.840.10045.4.3.4",
};

// ---- minimal DER encoder ---------------------------------------------------
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function lengthBytes(n) {
  if (n < 128) return [n];
  const b = [];
  for (; n > 0; n = Math.floor(n / 256)) b.unshift(n % 256);
  return [0x80 | b.length, ...b];
}

const enc = (tag, ...parts) => {
  const body = concat(...parts);
  return concat(Uint8Array.of(tag, ...lengthBytes(body.length)), body);
};
const SEQ = (...p) => enc(0x30, ...p);
const SET = (...p) => enc(0x31, ...p);
const OCT = (b) => enc(0x04, b);
const NULL = Uint8Array.of(0x05, 0x00);
const INT1 = Uint8Array.of(0x02, 0x01, 0x01);

function OID_(dotted) {
  const n = dotted.split(".").map(Number);
  const body = [40 * n[0] + n[1]];
  for (const v of n.slice(2)) {
    const chunk = [v & 0x7f];
    for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) chunk.unshift(0x80 | (x & 0x7f));
    body.push(...chunk);
  }
  return enc(0x06, Uint8Array.from(body));
}

function utcTime(d) {
  const p = (x) => String(x).padStart(2, "0");
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return enc(0x17, new TextEncoder().encode(s));
}

// DER SET OF: elements sorted by their encodings, as octet strings (X.690 11.6)
function sortedForSet(items) {
  return [...items].sort((a, b) => {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const d = (a[i] ?? 0) - (b[i] ?? 0);
      if (d) return d;
    }
    return 0;
  });
}

const attribute = (oid, value) => SEQ(OID_(oid), SET(value));

// ---- public API --------------------------------------------------------------
/**
 * @param {Uint8Array} docDigest   digest of the document (same hash function as `hashFunction`)
 * @param {Uint8Array} certDer     signer certificate
 * @param {{issuerDer: Uint8Array, serialDer: Uint8Array}} info  from parseCertificate()
 * @param {Date} signingTime       taken from the browser clock (not trusted time)
 * @returns {Promise<{toBeSigned: Uint8Array, embedded: Uint8Array}>}
 *   toBeSigned = DER SET of attributes: hash this and have the card sign the hash.
 *   embedded   = the same attributes with the [0] IMPLICIT tag used inside SignerInfo.
 */
export async function buildSignedAttributes(docDigest, certDer, info, signingTime) {
  const certHash = new Uint8Array(await crypto.subtle.digest("SHA-256", certDer));
  // ESSCertIDv2: hashAlgorithm omitted = id-sha256 (the DEFAULT)
  const essCertIdV2 = SEQ(OCT(certHash), SEQ(SEQ(enc(0xa4, info.issuerDer)), info.serialDer));
  const attrs = sortedForSet([
    attribute(OID.contentType, OID_(OID.data)),
    attribute(OID.messageDigest, OCT(docDigest)),
    attribute(OID.signingTime, utcTime(signingTime)),
    attribute(OID.signingCertificateV2, SEQ(SEQ(essCertIdV2))),
  ]);
  return { toBeSigned: enc(0x31, ...attrs), embedded: enc(0xa0, ...attrs) };
}

function signatureAlgorithmId(hashFunction, cryptoAlgorithm) {
  if (cryptoAlgorithm === "ECC") return SEQ(OID_(ECDSA_SIG_OID[hashFunction]));
  return SEQ(OID_(RSA_SIG_OID[hashFunction]), NULL);
}

/**
 * @param {object} p
 * @param {Uint8Array} p.certDer
 * @param {{issuerDer: Uint8Array, serialDer: Uint8Array}} p.info
 * @param {string} p.hashFunction        "SHA-256" | "SHA-384" | "SHA-512"
 * @param {"RSA"|"ECC"} p.cryptoAlgorithm
 * @param {Uint8Array} p.signedAttrs     `embedded` from buildSignedAttributes()
 * @param {Uint8Array} p.signature       RSA: raw value; ECC: DER ECDSA-Sig-Value
 * @param {Uint8Array} [p.content]       given = attached (.p7m), omitted = detached (.p7s)
 */
export function buildCms({ certDer, info, hashFunction, cryptoAlgorithm, signedAttrs, signature, content }) {
  const digestAlg = SEQ(OID_(HASH_OID[hashFunction]));
  const encapContent = content ? SEQ(OID_(OID.data), enc(0xa0, OCT(content))) : SEQ(OID_(OID.data));
  const signerInfo = SEQ(
    INT1, // version 1: sid is IssuerAndSerialNumber
    SEQ(info.issuerDer, info.serialDer),
    digestAlg,
    signedAttrs,
    signatureAlgorithmId(hashFunction, cryptoAlgorithm),
    OCT(signature),
  );
  const signedData = SEQ(INT1, SET(digestAlg), encapContent, enc(0xa0, certDer), SET(signerInfo));
  return SEQ(OID_(OID.signedData), enc(0xa0, signedData));
}

export function toPem(label, bytes) {
  const body = bytesToB64(bytes).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}
