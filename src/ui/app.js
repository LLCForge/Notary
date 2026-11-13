// Notary web UI. Talks only to this origin; every value is inserted with
// textContent (never innerHTML). The optional API token lives in memory only.
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const form = $("check");

  function headers() {
    const t = form.elements.token.value.trim();
    return t ? { Authorization: "Bearer " + t } : {};
  }

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  }

  function table(head, rows) {
    const wrap = el("div", undefined, "scroll");
    const t = el("table");
    const tr = el("tr");
    head.forEach((h) => { const th = el("th", h); th.scope = "col"; tr.appendChild(th); });
    const thead = el("thead"); thead.appendChild(tr); t.appendChild(thead);
    const tb = el("tbody");
    rows.forEach((r) => {
      const row = el("tr");
      r.forEach((c) => row.appendChild(el("td", c)));
      tb.appendChild(row);
    });
    t.appendChild(tb);
    wrap.appendChild(t);
    return wrap;
  }

  async function getJson(url) {
    const r = await fetch(url, { headers: headers(), credentials: "omit" });
    let body = null;
    try { body = await r.json(); } catch (_) { body = null; }
    if (!r.ok) {
      const msg = body && typeof body.error === "string" ? body.error : "HTTP " + r.status;
      throw new Error(msg);
    }
    return body;
  }

  async function loadStatus() {
    try {
      const s = await getJson("/v1/status");
      $("status").textContent =
        s.vrp_count + " VRPs (" + s.ipv4_vrps + " v4 / " + s.ipv6_vrps + " v6), " +
        s.aspa_count + " ASPA, serial " + (s.serial === null ? "-" : s.serial) +
        ", source " + s.source + (s.stale ? " - STALE" : "");
    } catch (e) {
      $("status").textContent = "Status unavailable: " + e.message;
    }
  }

  const LABEL = { valid: "VALID", invalid: "INVALID", not_found: "NOT FOUND" };

  async function check(ev) {
    ev.preventDefault();
    const prefix = form.elements.prefix.value.trim();
    const asn = form.elements.asn.value.trim();
    const out = $("result");
    out.replaceChildren(el("p", "Checking...", "muted"));
    const q = "prefix=" + encodeURIComponent(prefix) + "&asn=" + encodeURIComponent(asn);
    try {
      const v = await getJson("/v1/validity?" + q);
      const verdict = el("p", (LABEL[v.state] || v.state) + (v.reason ? " (" + v.reason.replaceAll("_", " ") + ")" : ""), "verdict " + v.state);
      const nodes = [verdict];
      if (v.stale) nodes.push(el("p", "Warning: VRP data is stale.", "invalid"));
      if (v.covering.length === 0) {
        nodes.push(el("p", "No VRP covers this prefix, so RPKI has no opinion on it.", "muted"));
      } else {
        nodes.push(table(["Covering VRP", "maxLength", "Origin"],
          v.covering.map((c) => [c.prefix, "/" + c.max_length, "AS" + c.asn])));
      }
      out.replaceChildren(...nodes);
    } catch (e) {
      out.replaceChildren(el("p", "Error: " + e.message, "invalid"));
    }
    loadHistory(prefix);
  }

  async function loadHistory(prefix) {
    const box = $("history");
    try {
      const h = await getJson("/v1/history?limit=20&prefix=" + encodeURIComponent(prefix));
      if (!h.events.length) {
        box.replaceChildren(el("p", "No recorded VRP changes overlap this prefix.", "muted"));
        return;
      }
      const rows = [];
      h.events.forEach((e) => {
        e.added.forEach((v) => rows.push([e.time, "added", v.prefix, "/" + v.max_length, "AS" + v.asn]));
        e.removed.forEach((v) => rows.push([e.time, "removed", v.prefix, "/" + v.max_length, "AS" + v.asn]));
      });
      box.replaceChildren(table(["Time", "Change", "Prefix", "maxLength", "Origin"], rows));
    } catch (e) {
      box.replaceChildren(el("p", "History unavailable: " + e.message, "muted"));
    }
  }

  form.addEventListener("submit", check);
  loadStatus();
  setInterval(loadStatus, 30000);
})();
