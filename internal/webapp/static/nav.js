// Shared navigation bar and ticker for the eidchain website and the node's
// embedded web app. Mounts itself from <body data-nav="site|app" data-ticker="...">.
// DOM construction only (no innerHTML); loads nothing and fetches nothing.
// Source of truth: www/nav.js. scripts/sync-webapp.sh copies it into the app.

const SITE_ITEMS = [
  ["home", "/", (p) => p === "/" || p === "/index.html"],
  ["signer", "/signer/", (p) => p.startsWith("/signer")],
  ["card login", "/login/", (p) => p.startsWith("/login")],
  ["chain", "/chain/", (p) => p === "/chain/" || p === "/chain/index.html"],
  ["explorer", "/chain/explorer.html#/blocks", (p) => p.endsWith("/explorer.html")],
];

// In the web app all links are relative, so it works at / and under a prefix such as /chain/.
const APP_ITEMS = [
  ["post a message", "index.html", (p, h) => !p.endsWith("/explorer.html")],
  ["blocks", "explorer.html#/blocks", (p, h) => p.endsWith("/explorer.html") && /^#\/(blocks|block)?(\/|$)/.test(h || "#/")],
  ["messages", "explorer.html#/messages", (p, h) => p.endsWith("/explorer.html") && /^#\/(messages|tx)(\/|$)/.test(h)],
  ["authorities", "explorer.html#/authorities", (p, h) => p.endsWith("/explorer.html") && /^#\/(authorities|authority)(\/|$)/.test(h)],
  ["node", "explorer.html#/node", (p, h) => p.endsWith("/explorer.html") && /^#\/node(\/|$)/.test(h)],
];

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  e.append(...kids);
  return e;
}

function build(mode) {
  const items = mode === "site" ? SITE_ITEMS : APP_ITEMS;
  const list = el("ul");
  const links = items.map(([label, href, active]) => {
    const a = el("a", { href }, label);
    list.append(el("li", {}, a));
    return [a, active];
  });
  // The app is often mounted under the website (/chain/): offer the way back.
  if (mode === "app" && location.pathname.startsWith("/chain/")) {
    list.append(el("li", {}, el("a", { href: "../" }, "website")));
  }
  const nav = el("nav", { class: "nav", "aria-label": "Main" },
    el("a", { class: "brand", href: mode === "site" ? "/" : "index.html" }, "eidchain"), list);
  if (mode === "app") {
    const input = el("input", { type: "search", placeholder: "height, hash or id", "aria-label": "Search the chain", autocomplete: "off", spellcheck: "false" });
    const form = el("form", { role: "search" }, input);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const q = input.value.trim();
      if (q) location.href = "explorer.html#/search/" + encodeURIComponent(q);
    });
    nav.append(form);
  }
  const mark = () => {
    for (const [a, active] of links) {
      if (active(location.pathname, location.hash)) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  };
  mark();
  addEventListener("hashchange", mark);
  return el("header", { class: "nav-wrap" }, nav);
}

let ticker;

/** Sets (or creates) the scrolling banner under the nav bar. */
export function setTicker(text) {
  if (!text) return;
  const unit = `${text} ✦`;
  const track = el("div", { class: "ticker-track" });
  // Two identical halves so the -50% animation loops seamlessly.
  for (let i = 0; i < 2; i++) for (let j = 0; j < 4; j++) track.append(el("span", {}, unit));
  if (!ticker) {
    ticker = el("div", { class: "ticker", "aria-hidden": "true" });
    document.querySelector(".nav-wrap")?.after(ticker);
  }
  ticker.replaceChildren(track);
}

function mount() {
  const mode = document.body.dataset.nav;
  if (!mode) return;
  document.body.prepend(build(mode));
  setTicker(document.body.dataset.ticker);
}

if (document.readyState === "loading") addEventListener("DOMContentLoaded", mount);
else mount();
