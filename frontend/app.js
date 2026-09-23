/* ══════════════════════════════════════════════════════════════════════
   SENTRA-IIoT console — client logic
   ----------------------------------------------------------------------
   No framework and no build step, deliberately: the whole thing is one
   file a marker can read top to bottom, and it runs by opening the server.

   The important departure from v1: this connects to the WebSocket the
   backend has always exposed. v1 shipped /ws/live and then polled every
   four seconds anyway, so alerts could sit invisible for four seconds.
   Here the socket is primary and polling is the fallback for when it
   cannot be established.
   ══════════════════════════════════════════════════════════════════════ */

const API = "";                       // same origin — the server hosts this page
const KEY_STORAGE = "sentra.apikey";
const THEME_STORAGE = "sentra.theme";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const STATUS_FLOW = [
  ["new", "New"],
  ["investigating", "Investigating"],
  ["contained", "Contained"],
  ["closed", "Closed"],
];

const state = {
  view: "floor",
  alerts: [],                 // newest first, capped client-side
  byId: new Map(),
  assets: [],
  taxonomy: null,
  modelCard: null,
  filters: { severity: new Set(), search: "", onlyReview: false, hideNormal: true },
  selected: null,
  feedLimit: 60,
  stream: { running: true, interval_ms: 1400, attack_ratio: 0.18 },
  sound: false,
  socket: null,
  pollTimer: null,
  unseen: 0,
  apiKey: localStorage.getItem(KEY_STORAGE) || "sentra-dev-key",
};

/* ───────────────────────────── helpers ───────────────────────────── */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const pretty = (s) => String(s ?? "").replace(/_/g, " ");
const pct = (n) => `${Math.round((n ?? 0) * 100)}%`;
const num = (n) => (n ?? 0).toLocaleString();

function clockTime(iso) {
  const d = iso ? new Date(iso) : new Date();
  return d.toLocaleTimeString([], { hour12: false });
}

function sevColour(sev) {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(`--sev-${sev}`).trim() || "#888";
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") headers["X-API-Key"] = state.apiKey;
  const res = await fetch(API + path, { ...options, headers });
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try { detail = (await res.json()).detail || detail; } catch { /* keep default */ }
    throw new Error(detail);
  }
  return res.json();
}

function toast(title, body, tone = "neutral") {
  const el = document.createElement("div");
  el.className = "toast";
  el.dataset.tone = tone;
  el.innerHTML = `<b>${esc(title)}</b>${esc(body)}`;
  $("#toasts").append(el);
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 4600);
}

/* Plays a bundled sound file for critical events. */
const alertAudio = new Audio("/static/sounds/alert.mp3");
alertAudio.preload = "auto";
alertAudio.volume = 0.5;

function beep() {
  if (!state.sound) return;
  alertAudio.currentTime = 0;              // restart if it's still playing
  alertAudio.play().catch(() => {
    /* blocked or failed to load; audio is a nicety, never a failure */
  });
}


/* ───────────────────────────── connection ───────────────────────────── */

function setConn(stateName, label) {
  const pill = $("#connPill");
  pill.dataset.state = stateName;
  $("#connLabel").textContent = label;
}

function connectSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${location.host}/ws/live`;
  let socket;
  try { socket = new WebSocket(url); } catch { return startPolling(); }
  state.socket = socket;

  socket.addEventListener("open", () => {
    setConn(state.stream.running ? "live" : "paused",
            state.stream.running ? "Live" : "Feed paused");
    stopPolling();
    setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.send("ping");
    }, 25000);
  });

  socket.addEventListener("message", (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }
    if (msg.type === "alert") ingest(msg.data);
  });

  socket.addEventListener("close", () => {
    setConn("offline", "Reconnecting");
    startPolling();
    setTimeout(connectSocket, 4000);
  });

  socket.addEventListener("error", () => socket.close());
}

function startPolling() {
  if (state.pollTimer) return;
  state.pollTimer = setInterval(async () => {
    try {
      const body = await api("/api/alerts?limit=25");
      body.items.reverse().forEach(ingest);
      setConn("live", "Live (polling)");
    } catch {
      setConn("offline", "Backend unreachable");
    }
  }, 3000);
}

function stopPolling() {
  if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
}

/* ───────────────────────────── ingest ───────────────────────────── */

function ingest(alert) {
  if (!alert || state.byId.has(alert.id)) return;
  state.byId.set(alert.id, alert);
  state.alerts.unshift(alert);
  if (state.alerts.length > 600) {
    const dropped = state.alerts.pop();
    state.byId.delete(dropped.id);
  }

  if (alert.severity === "critical") {
    beep();
    if (state.view !== "feed") {
      toast(
        alert.narrative?.headline || pretty(alert.attack_type),
        `${alert.asset?.name || alert.source_ip} — ${alert.narrative?.confidence_word || ""}`,
        "critical",
      );
    }
  }

  if (state.view !== "feed" && alert.attack_type !== "Normal") {
    state.unseen += 1;
    const badge = $("#feedBadge");
    badge.textContent = state.unseen > 99 ? "99+" : state.unseen;
    badge.hidden = false;
  }

  flashTile(alert);
  if (state.view === "feed") renderFeed();
  if (state.view === "floor") scheduleFloorRefresh();
}

let floorTimer = null;
function scheduleFloorRefresh() {
  if (floorTimer) return;
  floorTimer = setTimeout(() => { floorTimer = null; refreshFloor(); }, 1200);
}

function flashTile(alert) {
  const id = alert.asset?.id;
  if (!id) return;
  const tile = $(`.tile[data-asset="${CSS.escape(id)}"]`);
  if (!tile) return;
  tile.classList.remove("flash");
  void tile.offsetWidth;                 // restart the animation
  tile.classList.add("flash");
  if (SEV_ORDER[alert.severity] >= SEV_ORDER[tile.dataset.worst || "info"]) {
    tile.dataset.worst = alert.severity;
  }
}

/* ───────────────────────────── view routing ───────────────────────────── */

function showView(name) {
  state.view = name;
  $$(".rail-item").forEach((b) => b.classList.toggle("is-active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("is-active", v.id === `view-${name}`));

  if (name === "feed") {
    state.unseen = 0;
    $("#feedBadge").hidden = true;
    renderFeed();
  }
  if (name === "floor") refreshFloor();
  if (name === "triage") renderBoard();
  if (name === "model") renderModel();
}

/* ═══════════════════════════ VIEW: THE FLOOR ═══════════════════════════ */

async function refreshFloor() {
  try {
    const [stats, timeline, assetBody] = await Promise.all([
      api("/api/stats?window=60"),
      api("/api/timeline?minutes=30&buckets=30"),
      api("/api/assets"),
    ]);
    state.assets = assetBody.assets;
    renderKpis(stats);
    renderBrief(stats);
    renderChart(timeline.series);
    renderFloorTiles(stats);
    renderBarList("#familyBars", stats.by_family, { colour: "var(--brass)" });
    renderAssetBars(stats.by_asset);
    $("#railEvents").textContent = num(stats.events_all_time);
    if (stats.stream) {
      state.stream = { ...state.stream, ...stats.stream };
      $("#railAcc").textContent =
        stats.stream.live_accuracy != null ? pct(stats.stream.live_accuracy) : "—";
      syncStreamControls();
    }
  } catch (err) {
    setConn("offline", "Backend unreachable");
  }
}

function bump(el, value) {
  if (el.textContent === value) return;
  el.textContent = value;
  el.classList.remove("tick");
  void el.offsetWidth;
  el.classList.add("tick");
}

function renderKpis(stats) {
  const sev = stats.by_severity || {};
  const urgent = (sev.critical || 0) + (sev.high || 0);
  bump($("#kpiEvents"), num(stats.events_in_window));
  bump($("#kpiCritical"), num(urgent));
  bump($("#kpiReview"), num(stats.needs_review_count));
  bump($("#kpiLatency"), `${(stats.avg_latency_ms || 0).toFixed(1)} ms`);

  $("#kpiEventsNote").textContent =
    `${num(stats.attack_count)} of them hostile · ${num(stats.events_all_time)} held in total`;
  $("#kpiCriticalNote").textContent =
    urgent === 0 ? "nothing urgent in the last hour" : `${num(stats.open_alerts)} alerts still open`;
  $("#kpiReviewNote").textContent =
    `${num(stats.novel_count)} looked unlike anything in training`;
  $("#kpiLatencyNote").textContent =
    `budget is 2,000 ms · average confidence ${pct(stats.avg_confidence)}`;

  $("[data-tone='critical']").dataset.tone = urgent > 0 ? "critical" : "good";
}

/* The brief is the one piece of writing on the page that changes with the
   data. It is assembled from real counts only -- no invented adjectives. */
function renderBrief(stats) {
  const sev = stats.by_severity || {};
  const urgent = (sev.critical || 0) + (sev.high || 0);
  const worstAsset = Object.entries(stats.by_asset || {})
    .sort((a, b) => b[1] - a[1])[0];
  const topType = Object.entries(stats.by_attack_type || {})
    .filter(([k]) => k !== "Normal")
    .sort((a, b) => b[1] - a[1])[0];

  let line;
  if (stats.events_in_window === 0) {
    line = "No traffic has been classified in the last hour.";
  } else if (urgent === 0) {
    line = "Nothing on the floor needs you right now.";
  } else if (urgent === 1) {
    line = "One thing on the floor needs a look.";
  } else {
    line = `${urgent} flows in the last hour are worth your attention.`;
  }

  const bits = [];
  if (topType) {
    bits.push(`Most of it is ${pretty(topType[0]).toLowerCase()} (${topType[1]} flows)`);
  }
  if (worstAsset) {
    const asset = state.assets.find((a) => a.id === worstAsset[0]);
    if (asset) bits.push(`the loudest asset is ${asset.name.toLowerCase()}`);
  }
  if (stats.needs_review_count > 0) {
    bits.push(`${stats.needs_review_count} the model would not commit to`);
  }

  $("#briefLine").textContent = line;
  $("#briefSub").textContent = bits.length ? `${bits.join(", ")}.` : "";
}

function renderChart(series) {
  const svg = $("#activityChart");
  const W = 900, H = 210, pad = { t: 10, r: 8, b: 22, l: 34 };
  const innerW = W - pad.l - pad.r;
  const innerH = H - pad.t - pad.b;
  const max = Math.max(4, ...series.map((s) => s.total));
  const bw = innerW / series.length;

  const parts = [];

  // horizontal guides
  for (let i = 0; i <= 3; i++) {
    const y = pad.t + (innerH / 3) * i;
    const value = Math.round(max - (max / 3) * i);
    parts.push(
      `<line x1="${pad.l}" y1="${y}" x2="${W - pad.r}" y2="${y}" stroke="var(--rule-soft)" stroke-width="1"/>`,
      `<text x="${pad.l - 7}" y="${y + 3.5}" text-anchor="end" font-size="9"
             fill="var(--ink-dim)" font-family="var(--mono)">${value}</text>`,
    );
  }

  series.forEach((bucket, i) => {
    const x = pad.l + i * bw;
    let y = pad.t + innerH;
    SEVERITIES.slice().reverse().forEach((sev) => {
      const count = bucket[sev] || 0;
      if (!count) return;
      const h = (count / max) * innerH;
      y -= h;
      parts.push(
        `<rect x="${x + 1}" y="${y}" width="${Math.max(1, bw - 2)}" height="${h}"
               fill="${sevColour(sev)}" opacity=".9" rx="1"></rect>`,
      );
    });
    parts.push(
      `<rect x="${x}" y="${pad.t}" width="${bw}" height="${innerH}" fill="transparent"
             data-i="${i}" class="hit"></rect>`,
    );
  });

  const first = new Date(series[0].t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const last = new Date(series[series.length - 1].t)
    .toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  parts.push(
    `<text x="${pad.l}" y="${H - 6}" font-size="9.5" fill="var(--ink-dim)" font-family="var(--mono)">${first}</text>`,
    `<text x="${W - pad.r}" y="${H - 6}" font-size="9.5" fill="var(--ink-dim)"
           text-anchor="end" font-family="var(--mono)">${last}</text>`,
  );

  svg.innerHTML = parts.join("");

  const tip = $("#chartTip");
  svg.onmousemove = (event) => {
    const hit = event.target.closest(".hit");
    if (!hit) { tip.hidden = true; return; }
    const bucket = series[+hit.dataset.i];
    const lines = SEVERITIES
      .filter((s) => bucket[s])
      .map((s) => `${s} <b>${bucket[s]}</b>`)
      .join(" · ");
    tip.innerHTML = `${clockTime(bucket.t)} — <b>${bucket.total}</b> flows${lines ? `<br>${lines}` : ""}`;
    tip.hidden = false;
    const rect = svg.getBoundingClientRect();
    tip.style.left = `${Math.min(event.clientX - rect.left + 12, rect.width - 170)}px`;
    tip.style.top = `${event.clientY - rect.top - 44}px`;
  };
  svg.onmouseleave = () => { tip.hidden = true; };

  $("#chartLegend").innerHTML = SEVERITIES.map(
    (s) => `<span class="legend-item"><i class="legend-swatch" style="background:${sevColour(s)}"></i>${s}</span>`,
  ).join("");
}

function renderFloorTiles(stats) {
  const counts = stats.by_asset || {};
  const worstBy = {};
  state.alerts.forEach((a) => {
    const id = a.asset?.id;
    if (!id) return;
    if (!worstBy[id] || SEV_ORDER[a.severity] > SEV_ORDER[worstBy[id].severity]) {
      worstBy[id] = a;
    }
  });

  $("#floorGrid").innerHTML = state.assets.map((asset) => {
    const worst = worstBy[asset.id];
    const sev = worst ? worst.severity : "info";
    const count = counts[asset.id] || 0;
    const line = worst && worst.attack_type !== "Normal"
      ? `${worst.narrative?.headline || pretty(worst.attack_type)}.`
      : count
        ? "Traffic looks like it always does."
        : "Quiet — nothing classified this hour.";
    const pips = [1, 2, 3, 4, 5]
      .map((i) => `<i class="${i <= asset.criticality ? "on" : ""}"></i>`).join("");
    return `
      <button class="tile" data-asset="${esc(asset.id)}" data-worst="${sev}"
              title="${esc(asset.consequence)}">
        <div class="tile-name">${esc(asset.name)}</div>
        <div class="tile-role">${esc(asset.ip)} · ${esc(asset.protocol)}</div>
        <div class="tile-state">${esc(line)}</div>
        <div class="tile-foot">
          <span class="tile-count">${count} flow${count === 1 ? "" : "s"}</span>
          <span class="tile-crit" title="Criticality ${asset.criticality} of 5">${pips}</span>
        </div>
      </button>`;
  }).join("");

  $$("#floorGrid .tile").forEach((tile) => {
    tile.onclick = () => {
      state.filters.search = "";
      $("#feedSearch").value = "";
      showView("feed");
      const hit = state.alerts.find((a) => a.asset?.id === tile.dataset.asset);
      if (hit) openDrawer(hit.id);
    };
  });
}

function renderBarList(selector, counts, { colour = "var(--brass)", format = num } = {}) {
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = Math.max(1, ...entries.map((e) => e[1]));
  const host = $(selector);
  if (!entries.length) {
    host.innerHTML = `<p class="column-empty">Nothing recorded in this window yet.</p>`;
    return;
  }
  host.innerHTML = entries.map(([label, value]) => `
    <div class="bar-row">
      <span class="bar-label" title="${esc(label)}">${esc(pretty(label))}</span>
      <span class="bar-track"><span class="bar-fill"
            style="width:${(value / max) * 100}%;background:${colour}"></span></span>
      <span class="bar-value">${format(value)}</span>
    </div>`).join("");
}

function renderAssetBars(counts) {
  const named = {};
  Object.entries(counts || {}).forEach(([id, n]) => {
    const asset = state.assets.find((a) => a.id === id);
    named[asset ? asset.name : id] = n;
  });
  renderBarList("#assetBars", named, { colour: "var(--sev-low)" });
}

/* ═══════════════════════════ VIEW: LIVE FEED ═══════════════════════════ */

function visibleAlerts() {
  const f = state.filters;
  const needle = f.search.trim().toLowerCase();
  return state.alerts.filter((a) => {
    if (f.hideNormal && a.attack_type === "Normal" && !a.needs_review) return false;
    if (f.severity.size && !f.severity.has(a.severity)) return false;
    if (f.onlyReview && !a.needs_review) return false;
    if (needle) {
      const hay = `${a.attack_type} ${a.source_ip} ${a.asset?.name || ""} ${a.family}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
}

function renderFeed() {
  const rows = visibleAlerts().slice(0, state.feedLimit);
  const host = $("#feed");
  $("#feedEmpty").hidden = rows.length > 0;
  $("#feedCount").textContent =
    `${rows.length} shown of ${visibleAlerts().length} matching · ${state.alerts.length} held`;

  host.innerHTML = rows.map((a) => {
    const missed = a.ground_truth && a.ground_truth !== a.attack_type;
    const tags = [
      a.needs_review ? `<span class="tag review">needs a human</span>` : "",
      a.is_novel ? `<span class="tag novel">unfamiliar</span>` : "",
      missed ? `<span class="tag wrong">truth: ${esc(pretty(a.ground_truth))}</span>` : "",
    ].join("");
    return `
      <button class="row ${state.selected === a.id ? "is-selected" : ""}" role="listitem" data-id="${a.id}">
        <span class="row-tick" style="background:${sevColour(a.severity)}"></span>
        <span class="row-time">${clockTime(a.timestamp)}</span>
        <span class="row-main">
          <span class="row-head">
            <span class="row-class">${esc(pretty(a.attack_type))}</span>${tags}
          </span>
          <span class="row-story">${esc(a.narrative?.headline || a.family)}</span>
        </span>
        <span class="row-asset">
          ${esc(a.asset?.name || "Unmapped device")}
          <span class="row-ip">${esc(a.source_ip)}</span>
        </span>
        <span class="conf">
          <span class="conf-word">${esc(a.narrative?.confidence_word || "")}</span>
          <span class="conf-track"><span class="conf-fill"
                style="width:${(a.confidence * 100).toFixed(0)}%;background:${sevColour(a.severity)}"></span></span>
        </span>
        <span class="row-status">${esc(a.status)}</span>
      </button>`;
  }).join("");

  $$("#feed .row").forEach((row, i) => {
    if (i === 0) row.classList.add("enter");
    row.onclick = () => openDrawer(row.dataset.id);
  });
}

/* ───────────────────────────── drawer ───────────────────────────── */

async function openDrawer(id) {
  let alert = state.byId.get(id);
  try { alert = await api(`/api/alerts/${id}`); state.byId.set(id, alert); } catch { /* use cached */ }
  if (!alert) return;

  state.selected = id;
  const n = alert.narrative || {};

  $("#drawerFamily").textContent =
    `${alert.family} · ${alert.mitre || "--"} · ${clockTime(alert.timestamp)}`;
  $("#drawerTitle").textContent = n.headline || pretty(alert.attack_type);

  const probs = Object.entries(alert.probabilities || {});
  const maxProb = Math.max(...probs.map((p) => p[1]), 0.0001);

  $("#drawerBody").innerHTML = `
    <div class="verdict">
      <div class="verdict-top">
        <span class="verdict-sev" style="color:${sevColour(alert.severity)}">
          ${esc(alert.severity)} severity
        </span>
        <span class="verdict-conf">${esc(n.confidence_word || "")} · ${pct(alert.confidence)}</span>
      </div>
      <p class="verdict-note">${esc(n.confidence_note || "")}</p>
    </div>

    <div class="dsec">
      <h3>What is happening</h3>
      <p>${esc(n.story || "")}</p>
      ${n.second_opinion ? `<p style="margin-top:8px">${esc(n.second_opinion)}</p>` : ""}
    </div>

    ${alert.asset ? `
    <div class="dsec">
      <h3>Affected equipment</h3>
      <p><strong>${esc(alert.asset.name)}</strong> — ${esc(alert.asset.role)},
         ${esc(alert.asset.zone)}.</p>
      <p style="margin-top:6px;color:var(--ink-dim)">If this goes down: ${esc(alert.asset.consequence)}</p>
    </div>` : ""}

    ${(n.evidence || []).length ? `
    <div class="dsec">
      <h3>What the model noticed</h3>
      <div class="evidence">
        ${n.evidence.map((e) => `<p class="evi">${esc(e)}</p>`).join("")}
      </div>
    </div>` : ""}

    <div class="dsec">
      <h3>Do this next</h3>
      <div class="checklist">
        ${(n.actions || []).map((a, i) => `
          <label class="check">
            <input type="checkbox" data-step="${i}">
            <span>${esc(a)}</span>
          </label>`).join("")}
      </div>
    </div>

    <div class="dsec">
      <h3>How the call was split</h3>
      <div class="probs">
        ${probs.map(([cls, p], i) => `
          <div class="prob-row ${i === 0 ? "lead" : ""}">
            <span>${esc(pretty(cls))}</span>
            <span class="prob-track"><span class="prob-fill" style="width:${(p / maxProb) * 100}%"></span></span>
            <span>${pct(p)}</span>
          </div>`).join("")}
      </div>
    </div>

    <div class="dsec">
      <h3>Triage</h3>
      <div class="statusbar">
        ${STATUS_FLOW.map(([value, label]) => `
          <button class="ghost ${alert.status === value ? "on" : ""}" data-status="${value}">${label}</button>`).join("")}
        <button class="ghost ${alert.status === "false_positive" ? "on" : ""}"
                data-status="false_positive">Not a threat</button>
      </div>
    </div>

    <div class="dsec">
      <h3>Notes</h3>
      <div class="notes" id="noteList">
        ${(alert.notes || []).length
          ? alert.notes.map((note) => `
              <div class="note">
                <div class="note-meta">${esc(note.author)} · ${clockTime(note.created)}</div>
                <div class="note-body">${esc(note.body)}</div>
              </div>`).join("")
          : `<p style="font-size:12.5px;color:var(--ink-dim)">
               Nothing written yet. What you type here becomes the incident record.</p>`}
      </div>
      <div class="note-form" style="margin-top:9px">
        <textarea id="noteBody" placeholder="What did you find, and what did you do?"></textarea>
        <button class="primary" id="noteSave">Save note</button>
      </div>
    </div>

    <div class="dsec">
      <h3>Raw record</h3>
      <dl class="kv">
        <dt>Alert id</dt><dd>${esc(alert.id)}</dd>
        <dt>Source</dt><dd>${esc(alert.source_ip)}</dd>
        <dt>Origin</dt><dd>${esc(alert.origin)}</dd>
        <dt>Decision time</dt><dd>${alert.latency_ms} ms</dd>
        ${alert.novelty_score != null ? `<dt>Novelty score</dt><dd>${alert.novelty_score}</dd>` : ""}
        ${alert.ground_truth ? `<dt>True label</dt><dd>${esc(alert.ground_truth)}</dd>` : ""}
      </dl>
    </div>`;

  $$("#drawerBody [data-status]").forEach((btn) => {
    btn.onclick = async () => {
      try {
        const updated = await api(`/api/alerts/${id}/status`, {
          method: "PATCH",
          body: JSON.stringify({ status: btn.dataset.status }),
        });
        state.byId.set(id, updated);
        const cached = state.alerts.find((a) => a.id === id);
        if (cached) cached.status = updated.status;
        toast("Status saved", `Marked ${pretty(updated.status)}.`, "good");
        openDrawer(id);
        if (state.view === "feed") renderFeed();
        if (state.view === "triage") renderBoard();
      } catch (err) { toast("Could not save", err.message); }
    };
  });

  $("#noteSave").onclick = async () => {
    const body = $("#noteBody").value.trim();
    if (!body) { toast("Nothing to save", "Write something first."); return; }
    try {
      await api(`/api/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ body }) });
      toast("Note saved", "Added to the incident record.", "good");
      openDrawer(id);
    } catch (err) { toast("Could not save the note", err.message); }
  };

  $("#drawer").classList.add("is-open");
  $("#drawer").setAttribute("aria-hidden", "false");
  if (state.view === "feed") renderFeed();
}

function closeDrawer() {
  state.selected = null;
  $("#drawer").classList.remove("is-open");
  $("#drawer").setAttribute("aria-hidden", "true");
  if (state.view === "feed") renderFeed();
}

/* ═══════════════════════════ VIEW: TRIAGE ═══════════════════════════ */

async function renderBoard() {
  let items = [];
  try {
    const body = await api("/api/alerts?limit=200");
    items = body.items.filter((a) => a.attack_type !== "Normal" || a.needs_review);
  } catch { items = state.alerts; }

  const openCount = items.filter((a) => ["new", "investigating"].includes(a.status)).length;
  const badge = $("#triageBadge");
  badge.textContent = openCount;
  badge.hidden = openCount === 0;

  const columns = [
    ["new", "New", "Nothing waiting. The feed is being watched."],
    ["investigating", "Investigating", "Nothing being worked right now."],
    ["contained", "Contained", "Nothing contained in this window."],
    ["closed", "Closed", "Closed items will collect here."],
  ];

  const weight = (a) =>
    SEV_ORDER[a.severity] * 10 + (a.asset?.criticality || 0);

  $("#board").innerHTML = columns.map(([status, label, emptyText]) => {
    const group = items.filter((a) => a.status === status).sort((x, y) => weight(y) - weight(x));
    return `
      <section class="column">
        <header class="column-head">
          <h3>${label}</h3><span class="column-count">${group.length}</span>
        </header>
        ${group.length ? group.slice(0, 20).map((a) => `
          <article class="card" data-sev="${a.severity}" data-id="${a.id}">
            <div class="card-class">${esc(pretty(a.attack_type))}</div>
            <div class="card-asset">${esc(a.asset?.name || a.source_ip)}</div>
            <p class="card-why">${esc(a.narrative?.headline || "")}</p>
            <div class="card-actions">
              <button class="ghost" data-open="${a.id}">Open</button>
              ${nextStatus(status)
                ? `<button class="ghost" data-move="${a.id}" data-to="${nextStatus(status)}">
                     ${esc(nextLabel(status))}</button>`
                : ""}
            </div>
          </article>`).join("")
          : `<p class="column-empty">${emptyText}</p>`}
      </section>`;
  }).join("");

  $$("#board [data-open]").forEach((b) => { b.onclick = () => openDrawer(b.dataset.open); });
  $$("#board [data-move]").forEach((b) => {
    b.onclick = async () => {
      try {
        await api(`/api/alerts/${b.dataset.move}/status`, {
          method: "PATCH",
          body: JSON.stringify({ status: b.dataset.to }),
        });
        renderBoard();
      } catch (err) { toast("Could not move that", err.message); }
    };
  });
}

const nextStatus = (s) =>
  ({ new: "investigating", investigating: "contained", contained: "closed" }[s] || null);
const nextLabel = (s) =>
  ({ new: "Start work", investigating: "Mark contained", contained: "Close" }[s] || "");

/* ═══════════════════════════ VIEW: DRILL RANGE ═══════════════════════════ */

function renderLibrary() {
  if (!state.taxonomy) return;
  const { profiles, families, attack_types: types } = state.taxonomy;
  const groups = families.map((family) => ({
    family,
    members: types.filter((t) => profiles[t].family === family),
  })).filter((g) => g.members.length);

  $("#library").innerHTML = groups.map((g) => `
    <div class="lib-group">
      <h3>${esc(g.family)}</h3>
      <div class="lib-row">
        ${g.members.map((t) => {
          const p = profiles[t];
          return `
            <button class="lib-btn" data-attack="${esc(t)}">
              <strong><span class="lib-sev" style="background:${sevColour(p.severity)}"></span>${esc(pretty(t))}</strong>
              <em>${esc(p.headline)}</em>
            </button>`;
        }).join("")}
      </div>
    </div>`).join("");

  $$("#library .lib-btn").forEach((btn) => { btn.onclick = () => fireDrill(btn); });
}

async function fireDrill(btn) {
  const attack = btn.dataset.attack;
  const count = +$("#burstCount").value;
  btn.disabled = true;
  try {
    const result = await api("/api/simulate", {
      method: "POST",
      body: JSON.stringify({ attack_type: attack, count }),
    });
    result.alerts.forEach(ingest);
    const hit = result.detected_correctly;
    const ok = hit === result.generated;
    consoleLine(
      `<b>${esc(pretty(attack))}</b> — ${result.generated} flows from ${esc(result.source)}, ` +
      `model called <b>${hit}/${result.generated}</b> correctly.`,
      ok ? "console-ok" : "console-miss",
    );
    toast(
      ok ? "Drill detected in full" : "Drill partially detected",
      `${pretty(attack)}: ${hit} of ${result.generated} identified.`,
      ok ? "good" : "critical",
    );
  } catch (err) {
    consoleLine(`<b>${esc(pretty(attack))}</b> — drill failed: ${esc(err.message)}`, "console-miss");
    toast("Drill failed", err.message);
  } finally {
    btn.disabled = false;
  }
}

function consoleLine(html, cls = "") {
  const host = $("#console");
  $(".console-empty", host)?.remove();
  const el = document.createElement("div");
  el.className = `console-line ${cls}`;
  el.innerHTML = `<span class="console-time">${clockTime()}</span><span class="console-body">${html}</span>`;
  host.prepend(el);
  while (host.children.length > 60) host.lastChild.remove();
}

function syncStreamControls() {
  $("#streamRate").value = state.stream.interval_ms;
  $("#rateOut").textContent = `${(state.stream.interval_ms / 1000).toFixed(1)} s`;
  $("#attackRatio").value = Math.round(state.stream.attack_ratio * 100);
  $("#ratioOut").textContent = `${Math.round(state.stream.attack_ratio * 100)}%`;
  $("#streamToggleLabel").textContent = state.stream.running ? "Pause feed" : "Resume feed";
  if ($("#connPill").dataset.state !== "offline") {
    setConn(state.stream.running ? "live" : "paused",
            state.stream.running ? "Live" : "Feed paused");
  }
}

async function pushStream(patch) {
  try {
    state.stream = await api("/api/stream", { method: "POST", body: JSON.stringify(patch) });
    syncStreamControls();
  } catch (err) { toast("Could not change the feed", err.message); }
}

/* ═══════════════════════════ VIEW: MODEL ═══════════════════════════ */

async function renderModel() {
  if (!state.modelCard) {
    try { state.modelCard = await api("/api/model/card"); }
    catch (err) { $("#modelHeadline").textContent = err.message; return; }
  }
  const card = state.modelCard;
  const synthetic = card.data_source !== "edge-iiotset";

  $("#modelHeadline").textContent =
    `${card.algorithm}, trained on ${num(card.rows_used)} flows.`;
  $("#modelSub").textContent =
    `${card.n_features} features, ${card.classes.length} classes, ` +
    `${num(card.train_size)} for training and ${num(card.test_size)} held back. ` +
    `Last trained ${new Date(card.trained_at).toLocaleString()}.`;

  const cv = card.cv_macro_f1 || {};
  $("#modelKpis").innerHTML = [
    ["Accuracy", pct(card.accuracy), "share of held-out flows called correctly"],
    ["Balanced accuracy", pct(card.balanced_accuracy),
     "the same, with every class weighted equally"],
    ["Attacks caught", pct(card.attack_vs_normal?.detection_rate),
     `${num(card.attack_vs_normal?.false_negative)} hostile flows slipped through`],
    ["False alarms", pct(card.attack_vs_normal?.false_alarm_rate),
     `${num(card.attack_vs_normal?.false_positive)} normal flows raised an alert`],
  ].map(([title, value, note], i) => `
    <article class="kpi" data-tone="${i === 3 ? "review" : "neutral"}">
      <h3>${title}</h3>
      <p class="kpi-value">${value}</p>
      <p class="kpi-note">${esc(note)}</p>
    </article>`).join("");

  $("#sourceWarning").hidden = !synthetic;
  if (synthetic) {
    $("#sourceWarningBody").textContent =
      "No Edge-IIoTset CSV was found at training time, so the model was fitted on generated " +
      "traffic instead. The pipeline is being exercised end to end, but these scores say " +
      "nothing about how the detector would behave on a real plant network. Put " +
      "ML-EdgeIIoT-dataset.csv in data/ and run the trainer again to replace them.";
  }

  renderMatrix(card);
  renderBarList("#importanceBars",
    Object.fromEntries(card.feature_importances.map((f) => [f.label, f.importance])),
    { colour: "var(--sev-low)", format: (v) => v.toFixed(3) });

  const families = state.taxonomy?.profiles || {};
  $("#perClass tbody").innerHTML = card.classes.map((cls) => {
    const row = card.per_class[cls] || {};
    const recall = row.recall ?? 0;
    const precision = row.precision ?? 0;
    let reading;
    if (recall >= 0.95 && precision >= 0.95) reading = "Reliable in both directions.";
    else if (recall < 0.8) reading = "Misses a meaningful share of real cases.";
    else if (precision < 0.8) reading = "Fires on traffic that is not this.";
    else reading = "Usable, with some spill into neighbouring classes.";
    return `
      <tr>
        <td>${esc(pretty(cls))}</td>
        <td>${esc(families[cls]?.family || "")}</td>
        <td class="num">${precision.toFixed(3)}</td>
        <td class="num">${recall.toFixed(3)}</td>
        <td class="num">${(row["f1-score"] ?? 0).toFixed(3)}</td>
        <td class="num">${num(row.support)}</td>
        <td class="reading">${reading}</td>
      </tr>`;
  }).join("");

  const baselines = {
    "This model": card.accuracy,
    ...Object.fromEntries(Object.entries(card.baselines || {})
      .map(([k, v]) => [k, v.accuracy])),
  };
  renderBarList("#baselineBars", baselines,
    { colour: "var(--signal)", format: (v) => pct(v) });

  const lat = card.latency || {};
  $("#latencyStats").innerHTML = [
    ["Average", `${lat.mean_ms} ms`, "per flow, measured over 200 runs"],
    ["Median", `${lat.p50_ms} ms`, "the typical case"],
    ["95th percentile", `${lat.p95_ms} ms`, "one flow in twenty is slower than this"],
    ["Requirement", "2,000 ms", `met with ${(2000 / (lat.mean_ms || 1)).toFixed(0)}x headroom`],
    ["Cross-validated F1", cv.mean != null ? `${cv.mean.toFixed(3)} ± ${cv.std.toFixed(3)}` : "not run",
     "five folds, so the headline is not one lucky split"],
  ].map(([label, value, note]) => `
    <div class="stat-line">
      <span>${label}<em>${esc(note)}</em></span><b>${esc(value)}</b>
    </div>`).join("");
}

function renderMatrix(card) {
  const classes = card.families || [];
  const cm = card.family_confusion_matrix || [];
  if (!cm.length) { $("#matrix").innerHTML = "<p class='column-empty'>No matrix recorded.</p>"; return; }

  const rowTotals = cm.map((r) => r.reduce((a, b) => a + b, 0) || 1);
  const short = (s) => s.replace("Denial of service", "DoS")
                        .replace("Application abuse", "App abuse")
                        .replace("Reconnaissance", "Recon");

  const cells = [`<div class="matrix-head"></div>`];
  classes.forEach((c) => cells.push(`<div class="matrix-head">${esc(short(c))}</div>`));

  cm.forEach((row, i) => {
    cells.push(`<div class="matrix-head row-head">${esc(short(classes[i]))}</div>`);
    row.forEach((value, j) => {
      const share = value / rowTotals[i];
      const correct = i === j;
      const colour = correct ? "var(--signal)" : "var(--sev-critical)";
      const alpha = share === 0 ? 0 : 0.14 + share * 0.72;
      cells.push(`
        <div class="matrix-cell"
             style="background:color-mix(in srgb, ${colour} ${(alpha * 100).toFixed(0)}%, transparent)"
             title="${esc(classes[i])} called ${esc(classes[j])}: ${value} (${pct(share)})">
          ${value || ""}
        </div>`);
    });
  });

  const grid = document.createElement("div");
  grid.className = "matrix";
  grid.style.gridTemplateColumns = `86px repeat(${classes.length}, minmax(30px, 1fr))`;
  grid.innerHTML = cells.join("");
  $("#matrix").replaceChildren(grid);
}

/* ═══════════════════════════ wiring ═══════════════════════════ */

function buildSeverityChips() {
  $("#sevChips").innerHTML = SEVERITIES.map((s) => `
    <button class="chip" data-sev="${s}" aria-pressed="false">
      <i style="background:${sevColour(s)}"></i>${s}
    </button>`).join("");
  $$("#sevChips .chip").forEach((chip) => {
    chip.onclick = () => {
      const s = chip.dataset.sev;
      if (state.filters.severity.has(s)) state.filters.severity.delete(s);
      else state.filters.severity.add(s);
      chip.setAttribute("aria-pressed", state.filters.severity.has(s));
      renderFeed();
    };
  });
}

function wire() {
  $$(".rail-item").forEach((b) => { b.onclick = () => showView(b.dataset.view); });

  $("#feedSearch").oninput = (e) => { state.filters.search = e.target.value; renderFeed(); };
  $("#onlyReview").onchange = (e) => { state.filters.onlyReview = e.target.checked; renderFeed(); };
  $("#hideNormal").onchange = (e) => { state.filters.hideNormal = e.target.checked; renderFeed(); };
  $("#clearFilters").onclick = () => {
    state.filters = { severity: new Set(), search: "", onlyReview: false, hideNormal: true };
    $("#feedSearch").value = "";
    $("#onlyReview").checked = false;
    $("#hideNormal").checked = true;
    $$("#sevChips .chip").forEach((c) => c.setAttribute("aria-pressed", "false"));
    renderFeed();
  };
  $("#loadMore").onclick = () => { state.feedLimit += 50; renderFeed(); };

  $("#drawerClose").onclick = closeDrawer;
  $("#refreshTriage").onclick = renderBoard;
  $("#clearConsole").onclick = () => {
    $("#console").innerHTML = `<p class="console-empty">Drill log cleared.</p>`;
  };

  $("#burstCount").oninput = (e) => { $("#burstOut").textContent = e.target.value; };
  $("#streamRate").onchange = (e) => pushStream({ interval_ms: +e.target.value });
  $("#streamRate").oninput = (e) => {
    $("#rateOut").textContent = `${(+e.target.value / 1000).toFixed(1)} s`;
  };
  $("#attackRatio").onchange = (e) => pushStream({ attack_ratio: +e.target.value / 100 });
  $("#attackRatio").oninput = (e) => { $("#ratioOut").textContent = `${e.target.value}%`; };

  $("#streamToggle").onclick = () => pushStream({ running: !state.stream.running });

  $("#soundToggle").onclick = (e) => {
    state.sound = !state.sound;
    e.currentTarget.setAttribute("aria-pressed", state.sound);
    if (state.sound) beep();
  };

  $("#themeToggle").onclick = () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem(THEME_STORAGE, next);
    if (state.view === "floor") refreshFloor();
    if (state.view === "model") renderModel();
  };

  $("#helpToggle").onclick = () => { $("#helpModal").hidden = false; };
  $("#helpClose").onclick = () => { $("#helpModal").hidden = true; };
  $("#helpModal").onclick = (e) => { if (e.target.id === "helpModal") $("#helpModal").hidden = true; };

  document.addEventListener("keydown", (e) => {
    if (["INPUT", "TEXTAREA"].includes(e.target.tagName)) {
      if (e.key === "Escape") e.target.blur();
      return;
    }
    const views = ["floor", "feed", "triage", "range", "model"];
    if (e.key >= "1" && e.key <= "5") showView(views[+e.key - 1]);
    if (e.key === " ") { e.preventDefault(); pushStream({ running: !state.stream.running }); }
    if (e.key === "/") { e.preventDefault(); showView("feed"); $("#feedSearch").focus(); }
    if (e.key === "Escape") { closeDrawer(); $("#helpModal").hidden = true; }
    if (e.key.toLowerCase() === "r") {
      showView("feed");
      $("#onlyReview").checked = !$("#onlyReview").checked;
      state.filters.onlyReview = $("#onlyReview").checked;
      renderFeed();
    }
  });

  setInterval(() => { $("#clock").textContent = clockTime(); }, 1000);
  setInterval(() => { if (state.view === "floor") refreshFloor(); }, 15000);
}

function shiftLabel() {
  const h = new Date().getHours();
  if (h < 6) return "Night shift";
  if (h < 14) return "Morning shift";
  if (h < 22) return "Afternoon shift";
  return "Night shift";
}

async function boot() {
  document.documentElement.dataset.theme = localStorage.getItem(THEME_STORAGE) || "dark";
  $("#shiftLabel").textContent = shiftLabel();
  $("#clock").textContent = clockTime();

  buildSeverityChips();
  wire();

  try {
    const health = await api("/api/health");
    if (!health.model_loaded) {
      $("#briefLine").textContent = "No model is loaded.";
      $("#briefSub").textContent =
        "Train one first: python -m sentra.ml.train — then refresh this page.";
      setConn("offline", "No model");
      return;
    }
    state.stream = { ...state.stream, ...(health.stream || {}) };
  } catch {
    $("#briefLine").textContent = "The backend is not answering.";
    $("#briefSub").textContent = "Start it with: uvicorn sentra.main:app --reload";
    setConn("offline", "Backend unreachable");
    return;
  }

  try {
    state.taxonomy = await api("/api/taxonomy");
    renderLibrary();
  } catch { /* the library is optional */ }

  try {
    const body = await api("/api/alerts?limit=120");
    body.items.reverse().forEach((a) => {
      state.byId.set(a.id, a);
      state.alerts.unshift(a);
    });
  } catch { /* start empty */ }

  await refreshFloor();
  syncStreamControls();
  connectSocket();
}

boot();
