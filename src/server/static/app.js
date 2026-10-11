/* UniThreat dashboard logic — vanilla JS, no dependencies.
 * Live updates: WebSocket push (flows/alerts) + 1s REST polling (stats). */
"use strict";

(function () {
  // ------------------------------------------------------------------ helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g,
    (c) => ({ "&": "&", "<": "<", ">": ">",
              '"': """, "'": "&#39;" }[c]));
  const fmtInt = (n) => (n ?? 0).toLocaleString("en-US");
  const fmtBytes = (n) => {
    n = n ?? 0;
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  };
  const fmtDur = (us) => {
    us = us ?? 0;
    if (us < 1000) return us + "µs";
    if (us < 1e6) return (us / 1000).toFixed(1) + "ms";
    if (us < 60e6) return (us / 1e6).toFixed(1) + "s";
    return Math.floor(us / 60e6) + "m" + Math.round((us % 60e6) / 1e6) + "s";
  };
  const hhmmss = (ts) => new Date(ts * 1000).toLocaleTimeString("en-GB");

  const CATEGORY = {
    BENIGN: "benign", DDoS: "dos", "DoS Hulk": "dos", "DoS GoldenEye": "dos",
    "DoS slowloris": "dos", "DoS Slowhttptest": "dos", Heartbleed: "exploit",
    PortScan: "reconnaissance", Bot: "botnet", Infiltration: "infiltration",
    "Web Attack - Brute Force": "web-attack", "Web Attack - XSS": "web-attack",
    "Web Attack - SQL Injection": "web-attack", "FTP-Patator": "brute-force",
    "SSH-Patator": "brute-force",
  };
  const catColor = {
    benign: "#10b981", dos: "#ef4444", reconnaissance: "#3b82f6",
    botnet: "#a855f7", "web-attack": "#f97316", "brute-force": "#eab308",
    infiltration: "#ec4899", exploit: "#dc2626", "unknown-threat": "#94a3b8",
  };
  const catOf = (label) => (label && label !== "BENIGN"
    ? (CATEGORY[label] || "unknown-threat") : "benign");

  // ------------------------------------------------------------------ state
  const store = {
    flows: [],                    // newest first
    alerts: new Map(),            // id -> alert
    status: null,
    stats: null,
    threatsOnly: false,
  };

  // ------------------------------------------------------------------ REST
  async function api(path, opts) {
    const res = await fetch(path, opts);
    if (!res.ok) throw new Error(path + " -> " + res.status);
    return res.json();
  }

  async function hydrate() {
    try {
      const [status, stats, alerts, flows] = await Promise.all([
        api("/api/status"), api("/api/stats"),
        api("/api/alerts?limit=100"), api("/api/flows?limit=100"),
      ]);
      store.status = status;
      store.stats = stats;
      (alerts.alerts || []).slice().reverse().forEach((a) => store.alerts.set(a.id, a));
      store.flows = (flows.flows || []).slice().reverse();   // API returns newest first
      renderAll();
    } catch (e) { console.warn("hydrate failed:", e); }
  }

  async function pollStats() {
    try {
      const [status, stats] = await Promise.all([api("/api/status"), api("/api/stats")]);
      store.status = status; store.stats = stats;
      renderStatus(); renderCards(); renderTrafficChart(); renderDonut();
    } catch (e) { /* server restarting */ }
  }

  // ------------------------------------------------------------------ WebSocket
  let ws = null, wsRetryMs = 1000;
  function connectWS() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => { wsRetryMs = 1000; setPill("pill-ws", "WS: live", "ok"); };
    ws.onclose = () => {
      setPill("pill-ws", "WS: retrying", "bad");
      setTimeout(connectWS, wsRetryMs);
      wsRetryMs = Math.min(wsRetryMs * 2, 15000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      handleEvent(msg);
    };
  }

  function handleEvent(msg) {
    switch (msg.type) {
      case "snapshot":
        store.status = msg.status; store.stats = msg.stats;
        (msg.alerts || []).slice().reverse().forEach((a) => store.alerts.set(a.id, a));
        store.flows = (msg.flows || []).slice().reverse();
        renderAll();
        break;
      case "flow": {
        const f = msg.flow;
        store.flows.unshift(f);
        if (store.flows.length > 300) store.flows.length = 300;
        renderFlows();
        if (!store.threatsOnly || (f.verdict && f.verdict.is_threat)) renderFlows();
        break;
      }
      case "alert": {
        const a = msg.alert;
        const isNew = msg.new !== false && !store.alerts.has(a.id);
        store.alerts.set(a.id, a);
        renderAlerts();
        if (isNew && (a.severity === "critical" || a.severity === "high")) toast(a);
        break;
      }
      case "capture_started":
      case "capture_stopped":
      case "source_finished":
      case "capture_error":
        pollStats();
        break;
      default:
        break;
    }
  }

  // ------------------------------------------------------------------ renderers
  function setPill(id, text, cls) {
    const el = $(id);
    el.className = "pill" + (cls ? " " + cls : "");
    el.querySelector("span:last-child").textContent = text;
  }

  function renderStatus() {
    const st = store.status; if (!st) return;
    const running = st.capture && st.capture.running;
    setPill("pill-capture", running ? "CAPTURE LIVE" : "CAPTURE STOPPED",
      running ? "ok" : (st.capture.error ? "bad" : ""));
    $("btn-start").disabled = running;
    $("btn-stop").disabled = !running;

    const model = st.model || {};
    const metrics = model.metrics || {};
    if (model.loaded) {
      setPill("pill-model", `MODEL: ${model.algorithm || "?"} · F1 ${fmtF1(metrics.macro_f1)}`, "ok");
      $("foot-model").textContent =
        `model: ${model.algorithm} · accuracy ${fmtF1(metrics.accuracy)} · ` +
        `macro-F1 ${fmtF1(metrics.macro_f1)} · ${model.n_features} features`;
    } else {
      setPill("pill-model", "MODEL: NOT LOADED", "bad");
      $("foot-model").textContent = "model: NOT LOADED — " + (model.error || "train one via scripts/train.py");
    }
    if (st.capture) {
      $("foot-source").textContent = "source: " + (st.capture.source || st.capture.backend);
      $("foot-dir").textContent = "direction: " + (st.capture.direction || "—");
    }
    if (st.capture && st.capture.error) {
      setPill("pill-capture", "CAPTURE ERROR", "bad");
    }
  }
  const fmtF1 = (v) => (typeof v === "number" ? (100 * v).toFixed(1) + "%" : "—");

  function renderCards() {
    const s = store.stats; if (!s) return;
    const tl = s.timeline || [];
    const last = tl[tl.length - 1] || { packets: 0, bytes: 0 };
    const prev = tl[tl.length - 2] || last;
    $("stat-pps").textContent = fmtInt(last.packets || 0);
    $("stat-pkt-total").textContent = fmtInt(s.packets_total) + " packets total";
    $("stat-flows").textContent = fmtInt(s.flows_total);
    $("stat-active").textContent = fmtInt(s.flows_active);
    $("stat-threats").textContent = fmtInt(s.threats_total);
    $("stat-threat-rate").textContent =
      s.flows_total ? ((100 * s.threats_total) / s.flows_total).toFixed(2) + "% of flows" : "—";
    const alerts = store.status && store.status.alerts ? store.status.alerts : {};
    $("stat-alerts").textContent = fmtInt((alerts.total_created ?? 0));
    const sev = alerts.by_severity || {};
    $("stat-alerts-sev").textContent =
      `crit ${sev.critical || 0} · high ${sev.high || 0} · med ${sev.medium || 0}`;
    $("stat-bps").textContent = fmtBytes(last.bytes || 0) + "/s";
    $("stat-bytes-total").textContent = fmtBytes(s.bytes_total) + " seen";
    void prev;
  }

  // -- traffic chart -----------------------------------------------------------
  function renderTrafficChart() {
    const s = store.stats; if (!s) return;
    const canvas = $("traffic-chart");
    const tl = (s.timeline || []).slice(-120);
    drawTraffic(canvas, tl);
  }

  function drawTraffic(canvas, tl) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 600, h = canvas.height;
    canvas.width = w * dpr; canvas.style.height = h + "px";
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const padL = 38, padR = 6, padT = 8, padB = 18;
    const iw = w - padL - padR, ih = h - padT - padB;
    const n = Math.max(tl.length, 2);
    const maxP = Math.max(10, ...tl.map((d) => d.packets || 0));
    const maxB = Math.max(1000, ...tl.map((d) => d.bytes || 0));

    ctx.strokeStyle = "#1b242e"; ctx.fillStyle = "#55677a";
    ctx.font = "10px Consolas, monospace"; ctx.textAlign = "right";
    for (let i = 0; i <= 4; i++) {
      const y = padT + (ih * i) / 4;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
      ctx.fillText(String(Math.round(maxP * (1 - i / 4))), padL - 6, y + 3);
    }

    if (!tl.length) {
      ctx.textAlign = "center";
      ctx.fillText("waiting for packets…", padL + iw / 2, padT + ih / 2);
      return;
    }
    const step = iw / n;
    // KB/s line (right axis, scaled into same box)
    ctx.beginPath();
    tl.forEach((d, i) => {
      const x = padL + i * step + step / 2;
      const y = padT + ih * (1 - (d.bytes || 0) / maxB);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = "#31465c"; ctx.lineWidth = 1.4; ctx.stroke();
    // pps area
    ctx.beginPath();
    ctx.moveTo(padL, padT + ih);
    tl.forEach((d, i) => {
      const x = padL + i * step + step / 2;
      const y = padT + ih * (1 - (d.packets || 0) / maxP);
      ctx.lineTo(x, y);
    });
    ctx.lineTo(padL + (tl.length - 1) * step + step / 2, padT + ih);
    ctx.closePath();
    ctx.fillStyle = "rgba(34,211,238,.12)"; ctx.fill();
    ctx.beginPath();
    tl.forEach((d, i) => {
      const x = padL + i * step + step / 2;
      const y = padT + ih * (1 - (d.packets || 0) / maxP);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.strokeStyle = "#22d3ee"; ctx.lineWidth = 1.6; ctx.stroke();
  }

  // -- verdict donut ------------------------------------------------------------
  function renderDonut() {
    const s = store.stats; if (!s) return;
    const byLabel = s.flows_by_label || {};
    const buckets = {};
    for (const [label, count] of Object.entries(byLabel)) {
      const cat = catOf(label);
      buckets[cat] = (buckets[cat] || 0) + count;
    }
    const entries = Object.entries(buckets).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((a, [, c]) => a + c, 0) || 1;
    drawDonut($("verdict-donut"), entries.map(([cat, count]) =>
      ({ value: count, color: catColor[cat] || catColor["unknown-threat"] })));

    const threats = total - (buckets.benign || 0);
    $("donut-threat-pct").textContent = Math.round((100 * threats) / total) + "%";

    const list = $("verdict-list");
    list.innerHTML = entries.slice(0, 6).map(([cat, count]) => {
      const pct = (100 * count) / total;
      const color = catColor[cat] || catColor["unknown-threat"];
      return `<li><i class="sw" style="background:${color}"></i>${esc(cat)}
        <span class="vbar"><i style="width:${pct}%;background:${color}"></i></span>
        <span class="vcount">${fmtInt(count)}</span></li>`;
    }).join("");
  }

  function drawDonut(canvas, slices) {
    const dpr = window.devicePixelRatio || 1;
    const size = 220;
    canvas.width = size * dpr; canvas.height = size * dpr;
    canvas.style.width = size + "px"; canvas.style.height = size + "px";
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size, size);
    const total = slices.reduce((a, s) => a + s.value, 0);
    const cx = size / 2, cy = size / 2, rOut = 100, rIn = 70;
    if (!total) {
      ctx.beginPath(); ctx.arc(cx, cy, (rOut + rIn) / 2, 0, Math.PI * 2);
      ctx.strokeStyle = "#1b242e"; ctx.lineWidth = rOut - rIn; ctx.stroke();
      return;
    }
    let angle = -Math.PI / 2;
    for (const s of slices) {
      const sweep = (s.value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, rOut, angle, angle + sweep);
      ctx.arc(cx, cy, rIn, angle + sweep, angle, true);
      ctx.closePath(); ctx.fillStyle = s.color; ctx.fill();
      angle += sweep;
    }
  }

  // -- flows table ----------------------------------------------------------------
  function renderFlows() {
    const body = $("flow-body");
    const rows = store.flows
      .filter((f) => !store.threatsOnly || (f.verdict && f.verdict.is_threat))
      .slice(0, 40);
    if (!rows.length) {
      body.innerHTML = `<tr class="empty-row"><td colspan="7">Waiting for flows…</td></tr>`;
      return;
    }
    body.innerHTML = rows.map((f) => {
      const v = f.verdict;
      let chip = `<span class="verdict-chip none">N/A</span>`;
      if (v) {
        chip = v.is_threat
          ? `<span class="verdict-chip threat">${esc(v.label)} ${(v.confidence * 100).toFixed(0)}%</span>`
          : v.low_confidence
            ? `<span class="verdict-chip lowconf">? ${esc(v.label)}</span>`
            : `<span class="verdict-chip benign">benign</span>`;
      }
      return `<tr>
        <td>${hhmmss(f.ts)}</td>
        <td class="ep"><b>${esc(f.src)}:${f.sport}</b> → <b>${esc(f.dst)}:${f.dport}</b></td>
        <td>${esc(f.proto_name)}</td>
        <td class="num">${fmtInt(f.packets)}</td>
        <td class="num">${fmtBytes(f.bytes)}</td>
        <td class="num">${fmtDur(f.duration_us)}</td>
        <td>${chip}</td>
      </tr>`;
    }).join("");
  }

  // -- alerts feed -----------------------------------------------------------------
  function renderAlerts() {
    const feed = $("alert-feed");
    const alerts = [...store.alerts.values()]
      .sort((a, b) => b.ts_last - a.ts_last).slice(0, 80);
    if (!alerts.length) {
      feed.innerHTML = `<div class="empty">No alerts yet.</div>`;
      return;
    }
    feed.innerHTML = alerts.map((a) => `
      <div class="alert ${a.severity}">
        <div class="alert-top">
          <span class="badge sev-${a.severity}">${esc(a.severity)}</span>
          <span class="alert-label">${esc(a.label)}</span>
          <span class="badge cat">${esc(a.category)}</span>
          ${a.occurrences > 1 ? `<span class="alert-occ">×${fmtInt(a.occurrences)}</span>` : ""}
          <span class="alert-time">${hhmmss(a.ts_last)}</span>
        </div>
        <div class="alert-endpoints">${esc(a.src)}:${a.sport} → ${esc(a.dst)}:${a.dport} · ${esc(a.proto_name)}</div>
        <div class="alert-meta">
          <div class="confbar"><i style="width:${(a.confidence * 100).toFixed(0)}%"></i></div>
          <span class="alert-conf">${(a.confidence * 100).toFixed(1)}%</span>
        </div>
      </div>`).join("");
  }

  function renderAll() {
    renderStatus(); renderCards(); renderTrafficChart(); renderDonut();
    renderFlows(); renderAlerts();
  }

  // ------------------------------------------------------------------ toasts
  function toast(alert) {
    const el = document.createElement("div");
    el.className = "toast";
    el.innerHTML = `
      <div class="t-head"><span class="badge sev-${alert.severity}">${esc(alert.severity)}</span>
        ${esc(alert.label)}</div>
      <div class="t-sub">${esc(alert.src)} → ${esc(alert.dst)}:${alert.dport}
        · confidence ${(alert.confidence * 100).toFixed(0)}%</div>`;
    $("toasts").appendChild(el);
    setTimeout(() => el.classList.add("fading"), 5200);
    setTimeout(() => el.remove(), 5800);
  }

  // ------------------------------------------------------------------ controls
  $("btn-start").addEventListener("click", async () => {
    try { await api("/api/capture/start", { method: "POST" }); pollStats(); }
    catch (e) { toastText(String(e)); }
  });
  $("btn-stop").addEventListener("click", async () => {
    try { await api("/api/capture/stop", { method: "POST" }); pollStats(); }
    catch (e) { toastText(String(e)); }
  });
  $("chk-threats").addEventListener("change", (ev) => {
    store.threatsOnly = ev.target.checked; renderFlows();
  });
  function toastText(text) {
    const el = document.createElement("div");
    el.className = "toast";
    el.innerHTML = `<div class="t-head">action failed</div><div class="t-sub">${esc(text)}</div>`;
    $("toasts").appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }

  // ------------------------------------------------------------------ boot
  window.addEventListener("resize", () => {
    renderTrafficChart(); renderDonut();
  });
  hydrate();
  connectWS();
  setInterval(pollStats, 1500);
})();
