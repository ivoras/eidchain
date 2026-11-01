// Tiny DER helpers: just enough to read an X.509 certificate and to convert
// ECDSA signatures between raw (r||s) and DER.

export const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

export function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

function tlv(buf, pos) {
  const tag = buf[pos];
  let len = buf[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  if (p + len > buf.length) throw new Error("Malformed DER");
  return { tag, start: pos, vstart: p, end: p + len };
}

function children(buf, node) {
  const out = [];
  for (let p = node.vstart; p < node.end;) {
    const c = tlv(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

function oid(buf, node) {
  const b = buf.subarray(node.vstart, node.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  for (let i = 1, v = 0; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

function str(buf, node) {
  const b = buf.subarray(node.vstart, node.end);
  return new TextDecoder(node.tag === 0x1e ? "utf-16be" : "utf-8").decode(b);
}

function time(buf, node) {
  const s = str(buf, node);
  const m = node.tag === 0x17
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) throw new Error("Unsupported time format");
  let y = +m[1];
  if (node.tag === 0x17) y += y >= 50 ? 1900 : 2000;
  return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

const NAME_OIDS = {
  "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.42": "GN", "2.5.4.5": "serialNumber",
  "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.97": "organizationIdentifier",
};

function name(buf, node) {
  const out = [];
  for (const rdn of children(buf, node)) {
    for (const atv of children(buf, rdn)) {
      const [o, v] = children(buf, atv);
      const label = NAME_OIDS[oid(buf, o)];
      if (label) out.push(`${label}=${str(buf, v)}`);
    }
  }
  return out.join(", ");
}

/** Parses a DER X.509 certificate (Uint8Array). */
export function parseCertificate(der) {
  const root = tlv(der, 0);
  const tbs = children(der, root)[0];
  const f = children(der, tbs);
  const i = f[0].tag === 0xa0 ? 1 : 0; // skip optional [0] version
  const [serial, , issuer, validity, subject, spki] = f.slice(i); // serial, sigAlg, issuer, validity, subject, spki
  const [notBefore, notAfter] = children(der, validity);

  let nonRepudiation = null;
  const ext = f.find((n) => n.tag === 0xa3);
  if (ext) {
    nonRepudiation = false;
    for (const e of children(der, children(der, ext)[0])) {
      const parts = children(der, e);
      if (oid(der, parts[0]) !== "2.5.29.15") continue;
      const octets = parts[parts.length - 1];
      const bits = tlv(der, octets.vstart); // BIT STRING inside the OCTET STRING
      nonRepudiation = !!(der[bits.vstart + 1] & 0x40); // bit 1 = nonRepudiation / contentCommitment
    }
  }
  return {
    subject: name(der, subject),
    issuer: name(der, issuer),
    notBefore: time(der, notBefore),
    notAfter: time(der, notAfter),
    nonRepudiation, // null = no extensions, false = keyUsage lacks the bit or is absent
    spki: der.slice(spki.start, spki.end),
    issuerDer: der.slice(issuer.start, issuer.end), // Name, as DER
    serialDer: der.slice(serial.start, serial.end), // INTEGER, as DER
  };
}

const derInt = (b) => {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  return b[0] & 0x80 ? Uint8Array.of(0, ...b) : b;
};

function derSeq(...parts) {
  const len = parts.reduce((n, p) => n + 2 + (p.length > 127 ? 1 : 0) + p.length, 0);
  const out = [0x30, ...(len > 127 ? [0x81, len] : [len])];
  for (const p of parts) out.push(0x02, ...(p.length > 127 ? [0x81, p.length] : [p.length]), ...p);
  return Uint8Array.from(out);
}

/** Raw ECDSA signature (r||s) -> DER ECDSA-Sig-Value, the format OpenSSL expects. */
export function ecdsaRawToDer(raw) {
  const n = raw.length / 2;
  return derSeq(derInt(raw.subarray(0, n)), derInt(raw.subarray(n)));
}

/** DER ECDSA-Sig-Value -> raw r||s of n bytes each. */
export function ecdsaDerToRaw(der, n) {
  const [r, s] = children(der, tlv(der, 0));
  const out = new Uint8Array(2 * n);
  for (const [node, off] of [[r, 0], [s, n]]) {
    let v = der.subarray(node.vstart, node.end);
    while (v.length > n && v[0] === 0) v = v.subarray(1);
    out.set(v, off + n - v.length);
  }
  return out;
}

const EC_RAW_LENGTHS = [64, 96, 132]; // P-256, P-384, P-521

/** Accepts an ECDSA signature either raw (r||s) or already DER; returns DER. */
export function ecdsaToDer(sig) {
  const isDer = sig[0] === 0x30 && sig[1] === sig.length - 2;
  return EC_RAW_LENGTHS.includes(sig.length) && !isDer ? ecdsaRawToDer(sig) : sig;
}
