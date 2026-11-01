import { getSigningCertificate, sign, onTrace, WebEidError } from "./webeid-client.js";
import { b64ToBytes, bytesToB64, parseCertificate, ecdsaToDer } from "./der.js";
import { buildSignedAttributes, buildCms } from "./cades.js";
import { setTicker } from "./nav.js";

const $ = (id) => document.getElementById(id);
const HASH_PREFERENCE = ["SHA-256", "SHA-384", "SHA-512"];
let maxBytes = 10 * 1024;
let chainId = ""; // the genesis hash: records name their chain, so they cannot be replayed on another

const ERRORS = {
  ERR_WEBEID_EXTENSION_UNAVAILABLE: "The Web eID extension did not answer. Check that it is enabled for this site, then reload the page.",
  ERR_WEBEID_NATIVE_UNAVAILABLE: "The Web eID app is not installed (or not reachable). Install it from https://web-eid.eu.",
  ERR_WEBEID_USER_CANCELLED: "Signing was cancelled.",
  ERR_WEBEID_USER_TIMEOUT: "The PIN dialog timed out.",
  ERR_WEBEID_CONTEXT_INSECURE: "Web eID needs an HTTPS page or localhost.",
};

const setStatus = (text, kind = "") => { $("status").textContent = text; $("status").className = kind; };
const utf8 = (s) => new TextEncoder().encode(s);

onTrace((line) => { $("trace").textContent += `${new Date().toISOString().slice(11, 23)}  ${line}\n`; });

function record(text) {
  return JSON.stringify({ type: "message", chain: chainId, text, created: new Date().toISOString() });
}

function updateCount() {
  const bytes = utf8(record($("text").value)).length;
  $("count").textContent = `${bytes} / ${maxBytes} bytes`;
  $("submit").disabled = bytes > maxBytes || !$("text").value.trim() || !chainId;
  $("count").style.color = bytes > maxBytes ? "var(--err)" : "";
}

async function getJSON(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

function fmtTime(unix) { return new Date(unix * 1000).toLocaleString(); }

async function refresh() {
  try {
    const info = await getJSON("api/v1/info");
    maxBytes = info.maxPayloadBytes;
    chainId = info.genesisHash;
    $("chain").textContent = `“${info.message}”`;
    setTicker(info.message);
    const next = info.pending > 0 ? fmtTime(info.nextBlockAt) : `every ${info.blockIntervalSeconds / 60} min`;
    const stats = $("stats");
    stats.replaceChildren();
    for (const [label, value] of [["blocks", info.height], ["pending", info.pending], ["next block", next], ["authorities", info.authorities.length]]) {
      const box = document.createElement("div");
      box.className = "stat";
      const l = document.createElement("span");
      l.className = "label";
      l.textContent = label;
      const b = document.createElement("b");
      b.textContent = value;
      box.append(l, b);
      stats.append(box);
    }
    updateCount();
    const msgs = await getJSON("api/v1/messages?limit=10");
    const ul = $("messages");
    ul.replaceChildren();
    for (const m of msgs) {
      let text = m.payload;
      try { text = JSON.parse(m.payload).text ?? m.payload; } catch { /* show raw */ }
      const li = document.createElement("li");
      const badge = document.createElement("span");
      badge.className = `badge ${m.status}`;
      badge.textContent = m.status === "pending" ? "pending" : `block ${m.height}`;
      const body = document.createElement("div");
      body.className = "text";
      body.textContent = text;
      const meta = document.createElement("div");
      meta.className = "meta";
      const link = document.createElement("a");
      link.href = `explorer.html#/tx/${m.id}`;
      link.textContent = "details";
      meta.append(`${m.subject} · ${fmtTime(m.time)}${m.ocsp ? " · OCSP checked" : ""} · `, link);
      li.append(badge, body, meta);
      ul.append(li);
    }
  } catch (e) {
    $("chain").textContent = `Cannot reach the node: ${e.message}`;
  }
}

async function run() {
  const text = $("text").value;
  const payload = record(text);
  const data = utf8(payload);
  if (data.length > maxBytes) return setStatus(`The record is ${data.length} bytes; the limit is ${maxBytes}.`, "error");
  $("submit").disabled = true;
  $("trace").textContent = "";
  try {
    setStatus("Reading the signing certificate from the card…");
    const { certificate, supportedSignatureAlgorithms } = await getSigningCertificate({ lang: "hr" });
    const certDer = b64ToBytes(certificate);
    const info = parseCertificate(certDer);
    if (info.nonRepudiation === false) throw new Error("This is not the card's signing certificate (no non-repudiation key usage).");
    const supported = new Set((supportedSignatureAlgorithms ?? []).map((a) => a.hashFunction));
    const hashFunction = supported.size ? HASH_PREFERENCE.find((h) => supported.has(h)) : "SHA-256";
    if (!hashFunction) throw new Error("The card supports no usable hash function.");

    const digest = new Uint8Array(await crypto.subtle.digest(hashFunction, data));
    const attrs = await buildSignedAttributes(digest, certDer, info, new Date());
    const attrsHash = new Uint8Array(await crypto.subtle.digest(hashFunction, attrs.toBeSigned));

    setStatus("Enter your signing PIN (PIN2) in the Web eID window…");
    const { signature, signatureAlgorithm } = await sign(certificate, bytesToB64(attrsHash), hashFunction, { lang: "hr" });
    if (signatureAlgorithm.paddingScheme === "PSS") throw new Error("The card used RSA-PSS, which is not supported.");
    const sigBytes = b64ToBytes(signature);
    const cms = buildCms({
      certDer, info, hashFunction, cryptoAlgorithm: signatureAlgorithm.cryptoAlgorithm,
      signedAttrs: attrs.embedded,
      signature: signatureAlgorithm.cryptoAlgorithm === "ECC" ? ecdsaToDer(sigBytes) : sigBytes,
    });

    setStatus("Submitting to the node (it checks the signature and the certificate's revocation status)…");
    const r = await fetch("api/v1/payloads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload, signature: bytesToB64(cms) }),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error ?? `HTTP ${r.status}`);
    $("text").value = "";
    setStatus(body.status === "known" ? "You have already submitted that exact message." : "Accepted: it will be in the next block.", "ok");
    refresh();
  } catch (e) {
    setStatus(e instanceof WebEidError ? (ERRORS[e.code] ?? `${e.code}: ${e.message}`) : e.message, "error");
    $("diagnostics").open = true;
  } finally {
    updateCount();
  }
}

$("text").addEventListener("input", updateCount);
$("submit").addEventListener("click", run);
updateCount();
refresh();
setInterval(refresh, 15000);
