import { getSigningCertificate, sign, onTrace, WebEidError } from "./webeid-client.js";
import {
  b64ToBytes, bytesToB64, bytesToHex, parseCertificate, ecdsaToDer, ecdsaDerToRaw,
} from "./der.js";
import { buildSignedAttributes, buildCms, toPem } from "./cades.js";

const MAX_BYTES = 256 * 1024 * 1024; // the whole file is held in memory for hashing
const MAX_ATTACHED_BYTES = 32 * 1024 * 1024; // .p7m embeds a copy of the document
const LANG = (navigator.language || "en").slice(0, 2); // for the Web eID dialogs
const HASH_PREFERENCE = ["SHA-256", "SHA-384", "SHA-512"]; // what WebCrypto can compute
const HASH_BYTES = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };
const CURVES = [["P-256", 32], ["P-384", 48], ["P-521", 66]];

const $ = (id) => document.getElementById(id);
const fileInput = $("file");
const signButton = $("sign");
const statusEl = $("status");
const signerEl = $("signer");
const resultEl = $("result");
const linksEl = $("links");
let objectUrls = [];

const traceEl = $("trace");
const tracePanel = $("diagnostics");
onTrace((line) => {
  traceEl.textContent += `${new Date().toISOString().slice(11, 23)}  ${line}\n`;
});
function resetTrace() {
  traceEl.textContent = "";
  onTraceHeader();
}
function onTraceHeader() {
  traceEl.textContent +=
    `page: ${location.href}\nsecure context: ${window.isSecureContext}\n` +
    `browser: ${navigator.userAgent}\n`;
}
onTraceHeader();

const ERRORS = {
  ERR_WEBEID_EXTENSION_UNAVAILABLE:
    "The Web eID browser extension did not answer. Check that it is enabled and allowed to read this site (extension settings: site access), then reload the page. Details are in the browser console (filter: web-eid).",
  ERR_WEBEID_NATIVE_UNAVAILABLE:
    "The Web eID extension is installed but its native application is not. Install the Web eID app from https://web-eid.eu.",
  ERR_WEBEID_USER_CANCELLED: "Signing was cancelled.",
  ERR_WEBEID_USER_TIMEOUT: "The PIN dialog timed out.",
  ERR_WEBEID_CONTEXT_INSECURE: "This page must be opened over HTTPS.",
  ERR_WEBEID_ACTION_PENDING: "A previous request is still running; wait for it or reload the page.",
  ERR_WEBEID_VERSION_MISMATCH: "The Web eID extension and app versions do not match; update both.",
  ERR_WEBEID_VERSION_INVALID: "The Web eID extension or app is too old; update it.",
};

const setStatus = (text, kind = "") => {
  statusEl.textContent = text;
  statusEl.className = kind;
};

function resetOutput() {
  for (const u of objectUrls) URL.revokeObjectURL(u);
  objectUrls = [];
  linksEl.replaceChildren();
  resultEl.hidden = true;
  signerEl.hidden = true;
}

function downloadGroup(title, note) {
  const h = document.createElement("h3");
  h.textContent = title;
  const ul = document.createElement("ul");
  linksEl.append(h);
  if (note) {
    const p = document.createElement("p");
    p.className = "note";
    p.textContent = note;
    linksEl.append(p);
  }
  linksEl.append(ul);
  return ul;
}

function addDownload(list, bytesOrText, filename, type, description) {
  const url = URL.createObjectURL(new Blob([bytesOrText], { type }));
  objectUrls.push(url);
  const li = document.createElement("li");
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.textContent = filename;
  li.append(a, ` – ${description}`);
  list.append(li);
}

function showSigner(info, warnings) {
  const rows = [
    ["Subject", info.subject],
    ["Issuer", info.issuer],
    ["Valid", `${info.notBefore.toISOString().slice(0, 10)} to ${info.notAfter.toISOString().slice(0, 10)}`],
  ];
  signerEl.replaceChildren();
  const dl = document.createElement("dl");
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = k;
    dd.textContent = v;
    dl.append(dt, dd);
  }
  signerEl.append(dl);
  for (const w of warnings) {
    const p = document.createElement("p");
    p.className = "warn";
    p.textContent = w;
    signerEl.append(p);
  }
  signerEl.hidden = false;
}

async function verifySignature(spki, hashFunction, alg, sig, data) {
  const subtle = crypto.subtle;
  if (alg.cryptoAlgorithm === "RSA") {
    if (alg.paddingScheme === "PSS") {
      const key = await subtle.importKey("spki", spki, { name: "RSA-PSS", hash: hashFunction }, false, ["verify"]);
      return subtle.verify({ name: "RSA-PSS", saltLength: HASH_BYTES[hashFunction] }, key, sig, data);
    }
    const key = await subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: hashFunction }, false, ["verify"]);
    return subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
  }
  for (const [namedCurve, n] of CURVES) {
    let key;
    try {
      key = await subtle.importKey("spki", spki, { name: "ECDSA", namedCurve }, false, ["verify"]);
    } catch {
      continue; // wrong curve for this key
    }
    const raw = ecdsaDerToRaw(ecdsaToDer(sig), n);
    return subtle.verify({ name: "ECDSA", hash: hashFunction }, key, raw, data);
  }
  throw new Error("Unsupported public key type");
}

async function run() {
  const file = fileInput.files[0];
  const wantCades = $("fmt-cades").checked;
  const wantPlain = $("fmt-plain").checked;
  if (!file) return setStatus("Choose a document first.", "error");
  if (!wantCades && !wantPlain) return setStatus("Select at least one signature type.", "error");
  if (file.size > MAX_BYTES) return setStatus(`The file is larger than ${MAX_BYTES >> 20} MiB.`, "error");

  signButton.disabled = true;
  resetOutput();
  resetTrace();
  try {
    setStatus("Reading the document…");
    const data = new Uint8Array(await file.arrayBuffer());

    setStatus("Reading the signing certificate from the card…");
    const { certificate, supportedSignatureAlgorithms } = await getSigningCertificate({ lang: LANG });
    const certDer = b64ToBytes(certificate);
    const info = parseCertificate(certDer);

    const warnings = [];
    const now = new Date();
    if (now < info.notBefore || now > info.notAfter) warnings.push("This certificate is outside its validity period.");
    if (info.nonRepudiation === false) {
      warnings.push("This certificate does not have the non-repudiation key usage; it may be the authentication certificate, not the signing one.");
    }
    showSigner(info, warnings);

    const supported = new Set((supportedSignatureAlgorithms ?? []).map((a) => a.hashFunction));
    const hashFunction = supported.size ? HASH_PREFERENCE.find((h) => supported.has(h)) : "SHA-256";
    if (!hashFunction) throw new Error(`The card supports no usable hash function (${[...supported].join(", ")}).`);

    setStatus(`Hashing the document (${hashFunction})…`);
    const digest = new Uint8Array(await crypto.subtle.digest(hashFunction, data));
    const base = file.name;
    const meta = {
      file: base, size: file.size, hashFunction, hash: bytesToHex(digest),
      certificate, signedAtUnverified: new Date().toISOString(), signatures: {},
    };
    const outputs = []; // [group title, note, [bytes, filename, type, description][]]
    let step = 0;
    const total = Number(wantCades) + Number(wantPlain);
    const pinPrompt = () => setStatus(`Enter your signing PIN (PIN2) in the Web eID window (${++step} of ${total})…`);

    if (wantCades) {
      pinPrompt();
      const attrs = await buildSignedAttributes(digest, certDer, info, new Date());
      const attrsHash = new Uint8Array(await crypto.subtle.digest(hashFunction, attrs.toBeSigned));
      const { signature, signatureAlgorithm } = await sign(certificate, bytesToB64(attrsHash), hashFunction, { lang: LANG });
      if (signatureAlgorithm.paddingScheme === "PSS") throw new Error("The card used RSA-PSS, which this page does not put into CAdES.");

      setStatus("Checking the signature against the certificate…");
      const sigBytes = b64ToBytes(signature);
      if (!(await verifySignature(info.spki, hashFunction, signatureAlgorithm, sigBytes, attrs.toBeSigned))) {
        throw new Error("The card returned a CAdES signature that does not verify against its certificate. Nothing was saved.");
      }
      const cmsArgs = {
        certDer, info, hashFunction, cryptoAlgorithm: signatureAlgorithm.cryptoAlgorithm,
        signedAttrs: attrs.embedded,
        signature: signatureAlgorithm.cryptoAlgorithm === "ECC" ? ecdsaToDer(sigBytes) : sigBytes,
      };
      const p7s = buildCms(cmsArgs);
      const files = [
        [p7s, `${base}.p7s`, "application/pkcs7-signature", "detached CAdES signature, DER (the standard format)"],
        [toPem("CMS", p7s), `${base}.p7s.pem`, "application/x-pem-file", "same signature, PEM text"],
        [bytesToB64(p7s), `${base}.p7s.b64`, "text/plain", "same signature, Base64 text on one line"],
      ];
      if (file.size <= MAX_ATTACHED_BYTES) {
        files.push([buildCms({ ...cmsArgs, content: data }), `${base}.p7m`, "application/pkcs7-mime", "attached form: the signature with a copy of the document inside"]);
      }
      outputs.push(["CAdES-B-B signature", "One signature, several formats. The detached ones go next to the original file.", files]);
      meta.signatures.cades = { signatureAlgorithm, signature, signedAttributes: bytesToB64(attrs.embedded) };
    }

    if (wantPlain) {
      pinPrompt();
      const { signature, signatureAlgorithm } = await sign(certificate, bytesToB64(digest), hashFunction, { lang: LANG });
      setStatus("Checking the signature against the certificate…");
      const sigBytes = b64ToBytes(signature);
      if (!(await verifySignature(info.spki, hashFunction, signatureAlgorithm, sigBytes, data))) {
        throw new Error("The card returned a plain signature that does not verify against its certificate. Nothing was saved.");
      }
      const out = signatureAlgorithm.cryptoAlgorithm === "ECC" ? ecdsaToDer(sigBytes) : sigBytes; // OpenSSL wants DER for ECDSA
      outputs.push(["Plain signature", "A bare signature over the file's hash; no container.",
        [[out, `${base}.sig`, "application/octet-stream", "raw signature value"]]]);
      meta.signatures.plain = { signatureAlgorithm, signature };
    }

    for (const [title, note, files] of outputs) {
      const list = downloadGroup(title, note);
      for (const [bytes, name, type, desc] of files) addDownload(list, bytes, name, type, desc);
    }
    const common = downloadGroup("Signer and details");
    addDownload(common, toPem("CERTIFICATE", certDer), `${base}.signer.pem`, "application/x-pem-file", "signer certificate");
    addDownload(common, JSON.stringify(meta, null, 2), `${base}.sig.json`, "application/json", "hash, algorithms and signature values");

    const h = hashFunction.replace("-", "").toLowerCase();
    // The file name comes from whoever supplied the document and these commands get
    // pasted into a shell: quote it fully, and keep a leading "-" from being an option.
    const q = (name) => `'./${name.replaceAll("'", `'\\''`)}'`;
    const cmds = [];
    if (wantCades) {
      cmds.push(`# CAdES: signature and document match (does not check the certificate chain)`,
        `openssl cms -verify -inform DER -in ${q(`${base}.p7s`)} -content ${q(base)} -binary -noverify -out /dev/null`,
        `# ... and the chain to AKDCA Root / HRIDCA (hr-eid-ca.pem from this site; revocation is not checked)`,
        `openssl cms -verify -inform DER -in ${q(`${base}.p7s`)} -content ${q(base)} -binary -CAfile hr-eid-ca.pem -purpose any -out /dev/null`);
    }
    if (wantPlain) {
      cmds.push(`# plain signature`,
        `openssl x509 -in ${q(`${base}.signer.pem`)} -pubkey -noout > pub.pem`,
        `openssl dgst -${h} -verify pub.pem -signature ${q(`${base}.sig`)} ${q(base)}`);
    }
    $("verify-cmd").textContent = cmds.join("\n");
    resultEl.hidden = false;
    setStatus("Signed. Each signature was verified against the card's certificate.", "ok");
  } catch (e) {
    const msg = e instanceof WebEidError ? (ERRORS[e.code] ?? `${e.code}: ${e.message}`) : e.message;
    setStatus(msg, "error");
    tracePanel.open = true;
  } finally {
    signButton.disabled = false;
  }
}

signButton.addEventListener("click", run);
fileInput.addEventListener("change", () => { resetOutput(); setStatus(""); });
