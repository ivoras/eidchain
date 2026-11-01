// Minimal client for the Web eID browser extension (protocol of web-eid.js v2.1.0,
// https://github.com/web-eid/web-eid.js, MIT). Implements only what /signer needs:
// getSigningCertificate() and sign(). The page talks to the extension through
// window.postMessage; the extension relays to the native Web eID app, which talks
// to the card and shows the PIN dialog.
const LIBRARY_VERSION = "2.1.0";
const EXTENSION_HANDSHAKE_TIMEOUT = 1000;
const NATIVE_APP_HANDSHAKE_TIMEOUT = 5000;
const USER_INTERACTION_TIMEOUT = 2 * 60 * 1000;
const MAX_EXTENSION_LOAD_DELAY = 1000;

const loadedAt = Date.now();

// Diagnostics: everything is written to the console and to any registered listener
// (signer.js shows it in the page, so the browser console is not needed).
const traceListeners = [];
export const onTrace = (fn) => traceListeners.push(fn);
function trace(text) {
  console.log("[web-eid]", text);
  for (const fn of traceListeners) fn(text);
}
const pending = new Map(); // action -> {resolve, reject, ackTimer, replyTimer}

export class WebEidError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "WebEidError";
    this.code = code;
  }
}

// Like the official library, accept replies whatever event.source says: some browsers do not
// report the page's own window for messages relayed by an extension's content script.
// The certificate and signature are verified against each other afterwards in signer.js.
window.addEventListener("message", (event) => {
  const data = event.data;
  if (typeof data?.action !== "string" || !data.action.startsWith("web-eid:")) return;
  trace(`received ${data.action} (origin ${event.origin || "?"}, source is this window: ${event.source === window})`);
  const m = /^(.*?)(?:-(ack|success|failure))?$/.exec(data.action);
  const initial = m[1], suffix = m[2];
  const p = pending.get(initial);
  if (!p || !suffix) return;
  if (suffix === "ack") { clearTimeout(p.ackTimer); return; }
  clearTimeout(p.ackTimer);
  clearTimeout(p.replyTimer);
  pending.delete(initial);
  if (suffix === "success") p.resolve(data);
  else p.reject(new WebEidError(data.error?.code || "ERR_WEBEID_UNKNOWN_ERROR", data.error?.message));
});

function send(message, replyTimeout) {
  if (!window.isSecureContext) {
    return Promise.reject(new WebEidError("ERR_WEBEID_CONTEXT_INSECURE", "The page is not served over HTTPS"));
  }
  if (pending.has(message.action)) {
    return Promise.reject(new WebEidError("ERR_WEBEID_ACTION_PENDING", "Another request is already in progress"));
  }
  return new Promise((resolve, reject) => {
    const p = { resolve, reject };
    p.ackTimer = setTimeout(() => {
      trace(`no acknowledgement for ${message.action} within ${EXTENSION_HANDSHAKE_TIMEOUT} ms`);
      clearTimeout(p.replyTimer);
      pending.delete(message.action);
      reject(new WebEidError("ERR_WEBEID_EXTENSION_UNAVAILABLE", "No answer from the Web eID extension"));
    }, EXTENSION_HANDSHAKE_TIMEOUT);
    p.replyTimer = setTimeout(() => {
      clearTimeout(p.ackTimer);
      pending.delete(message.action);
      reject(new WebEidError("ERR_WEBEID_ACTION_TIMEOUT", "Timed out"));
    }, replyTimeout);
    pending.set(message.action, p);
    trace(`sending ${message.action}`);
    window.postMessage(message, window.location.origin);
  });
}

// Give the extension's content script a moment to load after page load.
async function extensionLoadDelay() {
  const wait = loadedAt + MAX_EXTENSION_LOAD_DELAY - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
}

const replyTimeout = (options) =>
  EXTENSION_HANDSHAKE_TIMEOUT + NATIVE_APP_HANDSHAKE_TIMEOUT +
  (options?.userInteractionTimeout ?? USER_INTERACTION_TIMEOUT) * 2;

/** @returns {Promise<{certificate: string, supportedSignatureAlgorithms: Array}>} certificate is base64 DER */
export async function getSigningCertificate(options) {
  await extensionLoadDelay();
  const r = await send(
    { action: "web-eid:get-signing-certificate", libraryVersion: LIBRARY_VERSION, options },
    replyTimeout(options),
  );
  return { certificate: r.certificate, supportedSignatureAlgorithms: r.supportedSignatureAlgorithms };
}

/** @returns {Promise<{signature: string, signatureAlgorithm: object}>} signature is base64 */
export async function sign(certificate, hash, hashFunction, options) {
  await extensionLoadDelay();
  const r = await send(
    { action: "web-eid:sign", libraryVersion: LIBRARY_VERSION, certificate, hash, hashFunction, options },
    replyTimeout(options),
  );
  return { signature: r.signature, signatureAlgorithm: r.signatureAlgorithm };
}
