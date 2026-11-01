// Blockchain explorer: blocks, messages (transactions), authorities and node
// status, read from this node's API. Hash-routed single page; everything is
// built with DOM calls and textContent, never innerHTML, because the data on
// the chain is written by arbitrary users.
import { setTicker } from "./nav.js";

const view = document.getElementById("view");

// ---- helpers ----

async function api(path) {
  const r = await fetch("api/v1/" + path);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error ?? `HTTP ${r.status}`);
  return body;
}

/** h("div", {class: "x", href: "#"}, child, "text", ...) */
function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v);
  for (const k of kids.flat(Infinity)) if (k !== undefined && k !== null && k !== false) e.append(k);
  return e;
}

const time = (unix) => (unix ? new Date(unix * 1000).toLocaleString() : "–");
const short = (hash, a = 8, b = 6) => (hash.length > a + b + 1 ? `${hash.slice(0, a)}…${hash.slice(-b)}` : hash);
const link = (href, text, props = {}) => h("a", { href, ...props }, text);
const blockLink = (ref, text) => link(`#/block/${ref}`, text ?? String(ref));
const hashLink = (hash) => link(`#/block/${hash}`, short(hash), { class: "hash", title: hash });
const keyLink = (id) => link(`#/authority/${id}`, short(id, 8, 4), { class: "hash", title: id });
const txLink = (id, text) => link(`#/tx/${id}`, text ?? short(id), { class: "hash", title: id });
const bytes = (n) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KiB`);

function heading(eyebrow, title, lead) {
  return h("section", { class: "hero" }, h("p", { class: "eyebrow" }, eyebrow), h("h1", {}, title), lead ? h("p", { class: "lead" }, lead) : null);
}

function kv(rows) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of rows) if (v !== undefined && v !== null) dl.append(h("dt", {}, k), h("dd", {}, v));
  return dl;
}

function table(head, rows, numeric = []) {
  return h("div", { class: "table-scroll" }, h("table", { class: "data" },
    h("thead", {}, h("tr", {}, head.map((t, i) => h("th", { class: numeric.includes(i) ? "num" : "" }, t)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c, i) => h("td", { class: numeric.includes(i) ? "num" : "" }, c)))))));
}

function stat(label, value) {
  return h("div", { class: "stat" }, h("span", { class: "label" }, label), h("b", {}, String(value)));
}

function crumbs(...parts) {
  const nodes = [];
  parts.forEach((p, i) => { if (i) nodes.push(" / "); nodes.push(p); });
  return h("p", { class: "crumbs small" }, nodes);
}

function show(...nodes) {
  view.replaceChildren(...nodes.flat(Infinity).filter(Boolean));
  window.scrollTo(0, 0);
}

function failure(message, back = "#/blocks") {
  document.title = "eidchain – explorer";
  show(heading("not found", "Nothing here."), h("div", { class: "card" }, h("p", { class: "status error" }, message), link(back, "Back to the blocks", { class: "btn" })));
}

const messageText = (payload) => {
  try { const t = JSON.parse(payload).text; if (typeof t === "string") return t; } catch { /* not a message record */ }
  return payload;
};

// ---- views ----

async function viewBlocks(before) {
  const [list, info] = await Promise.all([api(`explorer/blocks?limit=20${before ? `&before=${before}` : ""}`), api("info")]);
  setTicker(info.message);
  document.title = "eidchain – blocks";
  const rows = list.blocks.map((b) => [
    blockLink(b.height), hashLink(b.hash), time(b.time), keyLink(b.signer), String(b.payloads), String(b.rotations || ""), bytes(b.size),
  ]);
  show(
    heading("explorer", "Blocks.", `“${info.message}”`),
    h("div", { class: "stats" }, stat("height", info.height), stat("pending", info.pending), stat("authorities", info.authorities.length), stat("rotations", info.rotationSeq)),
    list.blocks.length
      ? h("div", { class: "card" }, table(["Height", "Hash", "Time", "Signer", "Msgs", "Rot.", "Size"], rows, [4, 5, 6]),
        list.older ? h("div", { class: "pager" }, link(`#/blocks/${list.older}`, "Older blocks", { class: "btn" })) : null)
      : h("div", { class: "card empty" }, "No blocks yet. Messages are put into a block every ", String(info.blockIntervalSeconds / 60), " minutes."),
    before ? h("div", { class: "pager" }, link("#/blocks", "Latest blocks", { class: "btn" })) : null,
  );
}

async function viewBlock(ref) {
  const b = await api(`explorer/block/${encodeURIComponent(ref)}`);
  document.title = `eidchain – block ${b.height}`;
  const hd = b.header;
  show(
    crumbs(link("#/blocks", "Blocks"), `Block ${b.height}`),
    heading("block", `#${b.height}`),
    h("div", { class: "card" }, kv([
      ["status", h("span", { class: `badge ${b.canonical ? "confirmed" : "bad"}` }, b.canonical ? `canonical · ${b.confirmations} confirmation${b.confirmations === 1 ? "" : "s"}` : "side branch")],
      ["hash", h("span", { class: "hash" }, b.hash)],
      ["time", time(hd.time)],
      ["previous", b.prevIsGenesis ? h("span", {}, "genesis ", link("#/node", short(b.prev), { class: "hash", title: b.prev })) : hashLink(b.prev)],
      ["next", b.next ? hashLink(b.next) : "–"],
      ["signed by", keyLink(hd.signer)],
      ["messages", `${hd.payloadCount} (Merkle root ${short(hd.payloadsRoot)})`],
      ["rotations", `${hd.rotationCount}${hd.rotationCount ? ` (root ${short(hd.rotationsRoot)})` : ""}`],
      ["size", bytes(b.size)],
      ["signature", h("span", { class: "hash", title: "ECDSA over the block hash" }, short(b.signature, 20, 8))],
      ["raw", link(`api/v1/blocks/${b.hash}`, "block JSON")],
    ])),
    h("h2", {}, "Messages"),
    b.transactions.length
      ? h("ul", { class: "messages" }, b.transactions.map((t) => h("li", {},
        h("span", { class: "badge confirmed" }, `#${t.index}`), " ", t.ocsp ? h("span", { class: "badge good" }, "ocsp") : null,
        h("div", { class: "text" }, t.preview),
        h("div", { class: "meta" }, `${t.subject} · ${bytes(t.bytes)} · `, txLink(t.id)))))
      : h("p", { class: "small" }, "This block carries no messages."),
    b.rotationList.length ? [h("h2", {}, "Key rotations"), ...b.rotationList.map((r) => h("div", { class: "card" }, kv([
      ["replaces", keyLink(r.change.old)],
      ["new key", h("span", { class: "hash" }, short(r.change.newKey, 16, 8))],
      ["sequence", String(r.change.seq)],
      ["approved by", r.signatures.map((s, i) => [i ? ", " : "", keyLink(s.signer)])],
    ])))] : null,
    h("div", { class: "pager" },
      b.height > 1 ? link(`#/block/${b.height - 1}`, "← Previous block", { class: "btn" }) : null,
      b.next ? link(`#/block/${b.height + 1}`, "Next block →", { class: "btn" }) : null),
  );
}

function certCard(c) {
  const now = Date.now() / 1000;
  return h("div", { class: "card" }, h("h2", {}, "Signer certificate"), kv([
    ["subject", c.subject],
    ["issuer", c.issuer],
    ["serial", h("span", { class: "hash" }, c.serial)],
    ["valid", `${time(c.notBefore)} → ${time(c.notAfter)}`, now > c.notAfter ? h("span", { class: "badge bad" }, "expired now") : null],
    ["key usage", c.keyUsage.join(", ") || "–"],
    ["algorithm", c.signatureAlgorithm],
    ["sha-256", h("span", { class: "hash" }, c.sha256)],
    ["ocsp responder", c.ocspServer?.join(", ") || "–"],
  ].map(([k, v, extra]) => [k, extra ? [v, " ", extra] : v])));
}

async function viewTx(id) {
  const t = await api(`explorer/tx/${encodeURIComponent(id)}`);
  document.title = "eidchain – message";
  show(
    crumbs(link("#/messages", "Messages"), short(t.id)),
    heading("message", t.status === "pending" ? "Waiting for a block." : `In block ${t.height}.`),
    h("div", { class: "card" },
      h("p", { class: "big-quote" }, messageText(t.payload)),
      h("p", {}, h("span", { class: `badge ${t.status}` }, t.status), " ",
        h("span", { class: `badge ${t.valid ? "good" : "bad"}` }, t.valid ? "signature and certificate valid" : "invalid"),
        t.ocsp ? [" ", h("span", { class: `badge ${t.ocsp.status === "good" ? "good" : "bad"}` }, `ocsp ${t.ocsp.status}`)] : null),
      t.error ? h("p", { class: "status error" }, t.error) : null),
    h("div", { class: "card" }, h("h2", {}, "Details"), kv([
      ["id", h("span", { class: "hash" }, t.id)],
      ["block", t.block ? [blockLink(t.block, `#${t.height}`), " ", h("span", { class: "hash small" }, short(t.block)), `, message ${t.index}`] : "not in a block yet"],
      ["time", time(t.time)],
      ["signing time", t.claimedSigningTime ? `${time(t.claimedSigningTime)} (claimed by the signer)` : "–"],
      ["hash function", t.hashFunction],
      ["payload", bytes(new TextEncoder().encode(t.payload).length)],
      ["signature", t.signatureBytes ? `CAdES-B-B, ${bytes(t.signatureBytes)}` : "–"],
    ])),
    t.certificate ? certCard(t.certificate) : null,
    t.ocsp ? h("div", { class: "card" }, h("h2", {}, "Revocation check (OCSP)"), kv([
      ["status", h("span", { class: `badge ${t.ocsp.status === "good" ? "good" : "bad"}` }, t.ocsp.status)],
      ["responder signature", t.ocsp.signatureVerified ? "verified against the issuing CA" : "not verified"],
      ["produced", time(t.ocsp.producedAt)],
      ["this update", time(t.ocsp.thisUpdate)],
      ["next update", time(t.ocsp.nextUpdate)],
      ["response", bytes(t.ocsp.bytes)],
      t.ocspError ? ["note", h("span", { class: "status error" }, t.ocspError)] : null,
    ].filter(Boolean)), h("p", { class: "small" }, "Taken once, when the message was submitted. It is stored in the block but is not a rule blocks are validated by.")) : null,
    h("div", { class: "card" }, h("h2", {}, "Payload, verbatim"), h("pre", {}, t.payload),
      h("p", { class: "small" }, "These exact bytes are what the eID signature covers.")),
  );
}

async function viewMessages(before) {
  const { messages: msgs, older } = await api(`explorer/messages${before ? `?before=${before}` : ""}`);
  document.title = "eidchain – messages";
  show(
    heading("explorer", "Messages.", "Every message is a JSON record signed with an eID card."),
    msgs.length
      ? h("ul", { class: "messages" }, msgs.map((m) => h("li", {},
        h("span", { class: `badge ${m.status}` }, m.status === "pending" ? "pending" : `block ${m.height}`),
        h("div", { class: "text" }, messageText(m.payload)),
        h("div", { class: "meta" }, `${m.subject} · ${time(m.time)} · `, txLink(m.id, "details")))))
      : h("div", { class: "card empty" }, "No messages yet."),
    h("div", { class: "pager" },
      older ? link(`#/messages/${older}`, "Older messages", { class: "btn" }) : null,
      before ? link("#/messages", "Latest messages", { class: "btn" }) : null),
  );
}

async function viewAuthorities(highlight) {
  const a = await api("explorer/authorities");
  a.history ??= []; a.pending ??= []; a.canSign ??= [];
  document.title = "eidchain – authorities";
  const mine = new Set(a.canSign);
  const row = (id, i) => [
    String(i + 1),
    h("span", { class: highlight === id ? "badge pending" : "" }, keyLink(id)),
    mine.has(id) ? h("span", { class: "badge good" }, "key held by this node") : "",
  ];
  show(
    heading("explorer", "Authorities.", `Blocks are signed by one of ${a.current.length} keys. A key may not sign again within ${a.window} block${a.window === 1 ? "" : "s"} of its last one, and replacing a key needs ${a.quorum} approval${a.quorum === 1 ? "" : "s"}.`),
    h("div", { class: "stats" }, stat("authorities", a.current.length), stat("rotation quorum", a.quorum), stat("rotations so far", a.seq), stat("signer cooldown", `${a.window} block${a.window === 1 ? "" : "s"}`)),
    h("div", { class: "card" }, h("h2", {}, "Current keys"), table(["#", "Key id", ""], a.current.map(row))),
    h("div", { class: "card" }, h("h2", {}, "Rotation history"),
      a.history.length
        ? table(["Block", "Time", "Replaced", "Approved by"], a.history.map((e) => [
          blockLink(e.height), time(e.time), keyLink(e.old), e.approvers.map((s, i) => [i ? ", " : "", keyLink(s)])]))
        : h("p", { class: "small" }, "No key has been rotated.")),
    (a.pending ?? []).length ? h("div", { class: "card" }, h("h2", {}, "Proposals waiting for approvals"),
      table(["Replaces", "Approvals"], a.pending.map((p) => [keyLink(p.change.old), `${p.signatures.length} of ${a.quorum}`]))) : null,
  );
}

async function viewNode() {
  const [info, g, peers] = await Promise.all([api("info"), api("genesis"), api("peers").catch(() => null)]);
  setTicker(info.message);
  document.title = "eidchain – node";
  show(
    heading("explorer", "This node.", `“${info.message}”`),
    h("div", { class: "stats" }, stat("height", info.height), stat("pending messages", info.pending), stat("pending rotations", info.pendingRotations), stat("authorities", info.authorities.length)),
    h("div", { class: "card" }, h("h2", {}, "Chain"), kv([
      ["genesis hash", h("span", { class: "hash" }, info.genesisHash)],
      ["head", info.height ? blockLink(info.head, `#${info.height}`) : "genesis (no blocks yet)"],
      ["created", time(g.created)],
      ["block interval", `${info.blockIntervalSeconds / 60} min, only when messages are waiting`],
      ["next block", time(info.nextBlockAt)],
      ["this node can sign now", info.canProduce ? "yes" : "no"],
      ["message size limit", bytes(info.maxPayloadBytes)],
      ["genesis", link("api/v1/genesis", "genesis JSON")],
    ])),
    peers ? h("div", { class: "card" }, h("h2", {}, "Peers"),
      h("p", {}, "Nodes this one shares with others. It gossips with these and with the peers it was configured with."),
      peers.peers.length ? h("ul", {}, peers.peers.map((u) => h("li", { class: "mono" }, u))) : h("p", { class: "small" }, "No public peers to show.")) : null,
    h("div", { class: "card" }, h("h2", {}, "Trusted eID CAs"),
      h("p", {}, "Message signatures are only accepted from certificates issued under these CAs. They are fixed in the genesis block."),
      h("ul", {}, info.trustAnchors.map((n) => h("li", {}, n)))),
  );
}

async function viewSearch(q) {
  try {
    const r = await api(`explorer/search?q=${encodeURIComponent(q)}`);
    const target = { block: `#/block/${r.ref}`, tx: `#/tx/${r.ref}`, authority: `#/authority/${r.ref}`, node: "#/node" }[r.kind];
    location.replace(target);
  } catch (e) {
    failure(e.message);
  }
}

// ---- router ----

async function route() {
  const [name, arg] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  show(h("p", { class: "empty" }, "Loading…"));
  try {
    switch (name) {
      case "": case "blocks": return await viewBlocks(Number(arg) || 0);
      case "block": return await viewBlock(arg);
      case "tx": return await viewTx(arg);
      case "messages": return await viewMessages(Number(arg) || 0);
      case "authorities": return await viewAuthorities();
      case "authority": return await viewAuthorities(arg);
      case "node": return await viewNode();
      case "search": return await viewSearch(arg ?? "");
      default: return failure("There is no such page.");
    }
  } catch (e) {
    failure(e.message, name === "tx" ? "#/messages" : "#/blocks");
  }
}

addEventListener("hashchange", route);
route();
