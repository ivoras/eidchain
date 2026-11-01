// The pending messages page: records waiting for a block on this node. Everything
// is built with DOM calls and textContent, because the text is written by users.
import { setTicker } from "./nav.js";

const view = document.getElementById("view");

async function api(path) {
  const r = await fetch("api/v1/" + path);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error ?? `HTTP ${r.status}`);
  return body;
}

function el(tag, className, ...kids) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  e.append(...kids);
  return e;
}

function link(href, text, className = "") {
  const a = el("a", className, text);
  a.href = href;
  return a;
}

const time = (unix) => (unix ? new Date(unix * 1000).toLocaleString() : "–");

function stat(label, value) {
  return el("div", "stat", el("span", "label", label), el("b", "", String(value)));
}

const messageText = (payload) => {
  try { const t = JSON.parse(payload).text; if (typeof t === "string") return t; } catch { /* not a message record */ }
  return payload;
};

function item(m) {
  const badges = [el("span", "badge pending", "pending")];
  if (m.ocsp) badges.push(" ", el("span", "badge good", "ocsp"));
  return el("li", "", ...badges,
    el("div", "text", messageText(m.payload)),
    el("div", "meta", `${m.subject} · received ${time(m.time)} · `, link(`explorer.html#/tx/${m.id}`, "details")));
}

async function show() {
  const offset = Number(new URLSearchParams(location.search).get("offset")) || 0;
  const [p, info] = await Promise.all([api(`explorer/pending?offset=${offset}`), api("info")]);
  setTicker(info.message);
  const lead = !p.total ? "Nothing is waiting for a block."
    : info.canProduce ? `Next block: ${time(info.nextBlockAt)}.`
      : "This node cannot sign the next block itself: it waits for another authority.";
  const pager = el("div", "pager");
  if (offset) pager.append(link("pending.html", "First page", "btn"));
  if (p.next) pager.append(link(`pending.html?offset=${p.next}`, "More", "btn"));
  view.replaceChildren(
    el("section", "hero", el("p", "eyebrow", "explorer"), el("h1", "", "Pending messages."), el("p", "lead", lead)),
    el("div", "stats", stat("pending", p.total), stat("next block", p.total ? time(info.nextBlockAt) : "–")),
    p.messages.length ? el("ul", "messages", ...p.messages.map(item)) : el("div", "card empty", "No messages are pending."),
    pager,
  );
}

show().catch((e) => view.replaceChildren(el("div", "card", el("p", "status error", e.message))));
