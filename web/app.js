// PhantomScan Dashboard JS
const API = '';
const DEBUG = false;
let socket = null;
let currentScanId = null;
let lastResult = null;
let logLines = [];
let reconnectTimer = null;

const els = {
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  scanBtn: document.getElementById('scanBtn'),
  targetInput: document.getElementById('targetInput'),
  modeSelect: document.getElementById('modeSelect'),
  progressFill: document.getElementById('progressFill'),
  progressPct: document.getElementById('progressPct'),
  progressLabel: document.getElementById('progressLabel'),
  logList: document.getElementById('logLines'),
  statPorts: document.getElementById('statPorts'),
  statCve: document.getElementById('statCve'),
  statSubs: document.getElementById('statSubs'),
  statScore: document.getElementById('statScore'),
  mapInfo: document.getElementById('mapInfo'),
  mapTarget: document.getElementById('mapTarget'),
  ring: document.getElementById('ringFg'),
  ringGrade: document.getElementById('ringGrade'),
  ringScore: document.getElementById('ringScore'),
  dnsList: document.getElementById('dnsList'),
  tlsList: document.getElementById('tlsList'),
  httpList: document.getElementById('httpList'),
  whoisList: document.getElementById('whoisList'),
  recList: document.getElementById('recList'),
  portsTable: document.querySelector('#portsTable tbody'),
  historyGrid: document.getElementById('historyGrid'),
  toast: document.getElementById('toast'),
  cmpA: document.getElementById('cmpA'),
  cmpB: document.getElementById('cmpB'),
  cmpRadar: document.getElementById('cmpRadar'),
  cmpAScore: document.getElementById('cmpAScore'),
  cmpBScore: document.getElementById('cmpBScore'),
  cmpLegend: document.getElementById('cmpLegend'),
  compareBtn: document.getElementById('compareBtn'),
};

// Canvas background
(() => {
  const canvas = document.getElementById('bg-canvas');
  const ctx = canvas.getContext('2d');
  let W, H;
  const nodes = [];
  const resize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
  resize(); window.addEventListener('resize', resize);
  class Node {
    constructor() { this.reset(); }
    reset() { this.x = Math.random() * W; this.y = Math.random() * H; this.vx = (Math.random() - 0.5) * 0.4; this.vy = (Math.random() - 0.5) * 0.4; this.r = Math.random() * 1.6 + 0.4; }
    step() { this.x += this.vx; this.y += this.vy; if (this.x < 0 || this.x > W) this.vx *= -1; if (this.y < 0 || this.y > H) this.vy *= -1; }
  }
  for (let i = 0; i < 80; i++) nodes.push(new Node());
  function draw() {
    ctx.clearRect(0, 0, W, H);
    nodes.forEach(n => {
      n.step();
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0,212,255,0.35)'; ctx.fill();
    });
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
        if (d < 120) {
          ctx.strokeStyle = `rgba(0,212,255,${0.08 * (1 - d / 120)})`;
          ctx.beginPath(); ctx.moveTo(nodes[i].x, nodes[i].y); ctx.lineTo(nodes[j].x, nodes[j].y); ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// Sound effects (Web Audio API)
function tone(seq = []) {
  try {
    const ac = new AudioContext();
    seq.forEach(({ f = 440, d = 120, t = 'sine', v = 0.08 }, idx) => {
      const osc = ac.createOscillator();
      const gain = ac.createGain();
      osc.type = t; osc.frequency.value = f;
      gain.gain.value = v;
      osc.connect(gain); gain.connect(ac.destination);
      const start = ac.currentTime + idx * (d / 1000);
      osc.start(start); osc.stop(start + d / 1000);
    });
  } catch (err) { if (DEBUG) console.warn('Audio unavailable:', err); }
}
const sounds = {
  start: () => tone([{ f: 440 }, { f: 620 }, { f: 760 }]),
  port: () => tone([{ f: 320, d: 60, v: 0.06 }]),
  critical: () => tone([{ f: 160, d: 240, t: 'square', v: 0.12 }, { f: 140, d: 240, t: 'square', v: 0.12 }]),
  success: () => tone([{ f: 520, d: 140 }, { f: 660, d: 140 }, { f: 820, d: 180 }]),
  error: () => tone([{ f: 320, d: 180 }, { f: 260, d: 180 }]),
};

// WebSocket
function initSocket() {
  if (typeof io === 'undefined') {
    setStatus(false, 'Socket.IO unavailable');
    return;
  }
  socket = io({ reconnection: true, reconnectionAttempts: 5 });

  socket.on('connect', () => {
    setStatus(true, 'API ONLINE');
    if (currentScanId) socket.emit('join_scan', { scan_id: currentScanId });
  });

  socket.on('disconnect', () => {
    setStatus(false, 'API OFFLINE');
  });

  socket.on('log_line', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    renderLog(payload.line);
    const pct = Math.max(payload.progress || 0, progressFromLog(payload.line));
    updateProgress(pct, payload.line);
  });

  socket.on('scan_status', payload => {
    if (payload.scan_id !== currentScanId) return;
    updateProgress(payload.progress || 0, 'running');
  });

  socket.on('scan_error', payload => {
    if (payload.scan_id !== currentScanId) return;
    renderLog(`[-] ${payload.error || 'Ошибка'}`, 'log-err');
    sounds.error();
    els.scanBtn.disabled = false;
  });

  socket.on('scan_complete', payload => {
    if (payload.scan_id !== currentScanId) return;
    updateProgress(100, 'done');
    sounds.success();
    if (payload.result) {
      lastResult = payload.result;
      renderAll(payload.result);
      fetchHistory();
    }
    els.scanBtn.disabled = false;
  });
}

// Status indicator
function setStatus(ok, text) {
  if (!els.statusDot || !els.statusText) return;
  els.statusText.textContent = text;
  els.statusDot.classList.toggle('status', ok);
  els.statusDot.style.background = ok ? 'var(--green)' : 'var(--accent)';
  els.statusDot.style.boxShadow = ok ? '0 0 12px var(--green)' : '0 0 12px var(--accent)';
}

// Progress
function updateProgress(pct, label) {
  const v = Math.min(100, Math.max(0, Math.floor(pct)));
  if (els.progressFill) els.progressFill.style.width = `${v}%`;
  if (els.progressPct) els.progressPct.textContent = `${v}%`;
  if (els.progressLabel) els.progressLabel.textContent = label || 'Running...';
}

function progressFromLog(line) {
  const l = line.toLowerCase();
  if (l.includes('завершено') || l.includes('готово')) return 100;
  if (l.includes('сохраняем')) return 95;
  if (l.includes('firewall')) return 80;
  if (l.includes('поддомен')) return 65;
  if (l.includes('cve')) return 45;
  if (l.includes('сканируем порты')) return 20;
  return 10;
}

// Logs
function renderLog(text, cls = '') {
  if (!els.logList) return;
  const li = document.createElement('li');
  li.className = `log-line ${cls || classifyLog(text)}`;
  typewriter(li, text);
  els.logList.appendChild(li);
  logLines.push(li);
  if (logLines.length > 50) {
    const rm = logLines.shift();
    rm.classList.add('fade');
    setTimeout(() => rm.remove(), 200);
  }
  els.logList.scrollTop = els.logList.scrollHeight;
}

function typewriter(el, text) {
  let idx = 0;
  const step = () => {
    el.textContent = text.slice(0, idx);
    idx++;
    if (idx <= text.length) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function classifyLog(text) {
  if (text.startsWith('[+]')) return 'log-ok';
  if (text.startsWith('[-]')) return 'log-err';
  if (text.startsWith('[!]')) return 'log-warn';
  return 'log-info';
}

// Toast
const TOAST_DURATION = 4000;
let toastTimer = null;
function toast(msg) {
  if (!els.toast) return;
  els.toast.textContent = msg;
  els.toast.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.style.display = 'none', TOAST_DURATION);
}

// Stats
function animateNumber(el, to) {
  if (!el) return;
  const from = Number(el.dataset.val || 0);
  const diff = to - from;
  const steps = 30;
  let i = 0;
  const tick = () => {
    i++;
    const val = Math.round(from + diff * (i / steps));
    el.textContent = val;
    el.dataset.val = val;
    if (i < steps) requestAnimationFrame(tick);
  };
  tick();
}

// Render results
function renderAll(data) {
  if (!data) return;
  renderStats(data);
  renderPorts(data.ports || []);
  renderScorecard(data);
  renderMap(data);
}

function renderStats(data) {
  animateNumber(els.statPorts?.querySelector('.stat-value'), (data.ports || []).length);
  animateNumber(els.statSubs?.querySelector('.stat-value'), (data.subdomains || []).length);
  const cves = collectCves(data.ports || []);
  animateNumber(els.statCve?.querySelector('.stat-value'), cves.total);
  if (data.score !== undefined) {
    const valEl = els.statScore?.querySelector('.stat-value');
    if (valEl) { valEl.textContent = data.score; valEl.style.color = '#00ff9d'; }
  }
}

function collectCves(ports) {
  let total = 0, critical = 0;
  ports.forEach(p => {
    if (Array.isArray(p.cves)) {
      total += p.cves.length;
      critical += p.cves.filter(c => c.severity === 'CRITICAL').length;
    }
  });
  return { total, critical };
}

function renderPorts(ports) {
  if (!els.portsTable) return;
  if (!ports.length) {
    els.portsTable.innerHTML = `<tr><td colspan="5" style="color:var(--dim)">Нет данных</td></tr>`;
    return;
  }
  els.portsTable.innerHTML = '';
  ports.forEach((p, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'port-row';
    const cells = [
      p.port,
      p.protocol || 'tcp',
      p.service || '—',
      p.version || '',
      'OPEN',
    ];
    cells.forEach((c, i) => {
      const td = document.createElement('td');
      if (i === 4) td.className = 'badge-open';
      td.textContent = c;
      tr.appendChild(td);
    });
    setTimeout(() => tr.classList.add('visible'), idx * 70);
    els.portsTable.appendChild(tr);
    sounds.port();
    if (p.cves) {
      p.cves.forEach(c => {
        if (c.severity === 'CRITICAL') flashCritical();
      });
    }
  });
}

function renderMap(data) {
  if (!els.mapInfo || !els.mapTarget) return;
  const ip = data.ip || data.target || '—';
  els.mapInfo.innerHTML = '';
  [['TARGET', ip], ['COUNTRY', data.country || '—'], ['ORG', data.isp || '—']]
    .forEach(([label, value]) => {
      const row = document.createElement('div');
      row.textContent = `${label}: `;
      const span = document.createElement('span');
      span.textContent = value;
      row.appendChild(span);
      els.mapInfo.appendChild(row);
    });
  const x = 20 + Math.random() * 60;
  const y = 20 + Math.random() * 50;
  els.mapTarget.style.left = `${x}%`;
  els.mapTarget.style.top = `${y}%`;
}

function renderScorecard(data) {
  if (!els.ring || !els.ringGrade) return;
  const score = data.score || 0;
  const grade = data.grade || 'F';
  const circ = 534;
  const offset = circ - (score / 100) * circ;
  const gradeColors = { 'A+': '#00ff9d', A: '#00ff9d', B: '#00d4ff', C: '#ffd447' };
  const color = gradeColors[grade] || '#ff2d6b';
  els.ring.style.strokeDashoffset = offset;
  els.ring.style.stroke = color;
  els.ringGrade.textContent = grade;
  els.ringScore.textContent = `${score}/100`;

  const setList = (el, items) => {
    if (!el) return;
    el.innerHTML = '';
    items.forEach(i => {
      const li = document.createElement('li');
      li.className = i.state;
      li.innerHTML = `<span>${i.label}</span>`;
      el.appendChild(li);
    });
  };

  setList(els.dnsList, [
    { label: `SPF ${okBad(data.dns?.spf)}`, state: data.dns?.spf ? 'ok' : 'bad' },
    { label: `DMARC ${okBad(data.dns?.dmarc)}`, state: data.dns?.dmarc ? 'ok' : 'bad' },
    { label: `DNSSEC ${okBad(data.dns?.dnssec)}`, state: data.dns?.dnssec ? 'ok' : 'bad' },
    { label: `CAA ${okBad(data.dns?.caa)}`, state: data.dns?.caa ? 'ok' : 'bad' },
    { label: `DKIM ${okBad(data.dns?.dkim)}`, state: data.dns?.dkim ? 'ok' : 'bad' },
    { label: `MX ${okBad(data.dns?.mx)}`, state: data.dns?.mx ? 'ok' : 'bad' },
  ]);

  setList(els.tlsList, [
    { label: `TLS1.0 ${offOn(data.tls?.tls10)}`, state: data.tls?.tls10 ? 'ok' : 'warn' },
    { label: `TLS1.1 ${offOn(data.tls?.tls11)}`, state: data.tls?.tls11 ? 'ok' : 'warn' },
    { label: `TLS1.2 ${okBad(data.tls?.tls12)}`, state: data.tls?.tls12 ? 'ok' : 'bad' },
    { label: `TLS1.3 ${okBad(data.tls?.tls13)}`, state: data.tls?.tls13 ? 'ok' : 'bad' },
    { label: `HSTS ${okBad(data.tls?.hsts)}`, state: data.tls?.hsts ? 'ok' : 'bad' },
    { label: `Cert days: ${data.tls?.days_left ?? '—'}`, state: (data.tls?.days_left ?? 0) > 30 ? 'ok' : 'warn' },
  ]);

  setList(els.httpList, [
    { label: `X-Frame-Options ${okBad(data.http?.x_frame_options)}`, state: data.http?.x_frame_options ? 'ok' : 'bad' },
    { label: `X-Content-Type ${okBad(data.http?.x_content_type_options)}`, state: data.http?.x_content_type_options ? 'ok' : 'bad' },
    { label: `CSP ${okBad(data.http?.csp)}`, state: data.http?.csp ? 'ok' : 'bad' },
    { label: `Referrer-Policy ${okBad(data.http?.referrer_policy)}`, state: data.http?.referrer_policy ? 'ok' : 'bad' },
  ]);

  setList(els.whoisList, [
    { label: `Registrar: ${data.whois?.registrar || '—'}`, state: 'info' },
    { label: `Country: ${data.whois?.country || '—'}`, state: 'info' },
    { label: `Expiry in: ${data.whois?.days_until_expiry ?? '—'} days`, state: 'info' },
  ]);

  if (els.recList) {
    els.recList.innerHTML = '';
    (data.recommendations || []).sort((a, b) => severityRank(a.level) - severityRank(b.level))
      .forEach(r => {
        const div = document.createElement('div');
        div.className = `rec ${r.level.toLowerCase()}`;
        div.textContent = `[${r.level}] ${r.message}`;
        els.recList.appendChild(div);
        if (r.level === 'CRITICAL') flashCritical();
      });
  }
}

function okBad(val) { return val ? '✓' : '✗'; }
function offOn(val) { return val ? '✓ Off' : '✗ On'; }
function severityRank(lvl) {
  return { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 }[lvl] || 5;
}

function flashCritical() {
  document.body.classList.add('flash');
  sounds.critical();
  setTimeout(() => document.body.classList.remove('flash'), 500);
}

// History
function fetchHistory() {
  fetch(`${API}/api/history`).then(r => r.json()).then(rows => {
    if (!Array.isArray(rows) || !els.historyGrid) return;
    els.historyGrid.innerHTML = '';
    rows.slice(0, 20).forEach(row => {
      const div = document.createElement('div');
      div.className = 'history-card';
      const title = document.createElement('div');
      title.className = 'title';
      title.textContent = row.target || '—';
      const meta1 = document.createElement('div');
      meta1.className = 'meta';
      meta1.textContent = `Ports: ${row.ports ?? '—'}`;
      const meta2 = document.createElement('div');
      meta2.className = 'meta';
      meta2.textContent = `Score: ${row.score ?? '—'} ${row.grade || ''}`;
      const meta3 = document.createElement('div');
      meta3.className = 'meta';
      meta3.textContent = row.timestamp ? new Date(row.timestamp).toLocaleString() : '';
      [title, meta1, meta2, meta3].forEach(el => div.appendChild(el));
      els.historyGrid.appendChild(div);
    });
  }).catch(() => {});
}

// Compare
function compareTargets() {
  const a = els.cmpA.value.trim();
  const b = els.cmpB.value.trim();
  if (!a || !b) { toast('Введите оба хоста для сравнения'); return; }
  els.compareBtn?.setAttribute('disabled', 'disabled');
  fetch(`${API}/api/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_a: a, target_b: b }),
  }).then(r => r.json()).then(data => {
    renderCompare(data?.a, data?.b);
  }).catch(() => toast('Ошибка сравнения')).finally(() => {
    els.compareBtn?.removeAttribute('disabled');
  });
}

function renderCompare(a, b) {
  if (els.cmpAScore) els.cmpAScore.textContent = a?.score ?? '—';
  if (els.cmpBScore) els.cmpBScore.textContent = b?.score ?? '—';
  if (els.cmpLegend) {
    els.cmpLegend.innerHTML = '';
    ['DNS', 'TLS', 'HTTP', 'WHOIS'].forEach(item => {
      const li = document.createElement('div');
      li.textContent = item;
      els.cmpLegend.appendChild(li);
    });
  }
  drawRadar(a, b);
}

function drawRadar(a, b) {
  const radarMinScale = 0.3;
  const radarValueRange = 0.7;
  const ctx = els.cmpRadar?.getContext('2d');
  if (!ctx) return;
  const metrics = [
    a?.dns?.spf ? 1 : 0, a?.tls?.tls13 ? 1 : 0, a?.http?.csp ? 1 : 0, a?.whois?.days_until_expiry ? 1 : 0,
  ];
  const metricsB = [
    b?.dns?.spf ? 1 : 0, b?.tls?.tls13 ? 1 : 0, b?.http?.csp ? 1 : 0, b?.whois?.days_until_expiry ? 1 : 0,
  ];
  const cx = 180, cy = 180, r = 120;
  ctx.clearRect(0, 0, 360, 360);
  ctx.strokeStyle = 'rgba(0,212,255,0.25)';
  for (let i = 1; i <= 4; i++) {
    ctx.beginPath(); ctx.arc(cx, cy, (r / 4) * i, 0, Math.PI * 2); ctx.stroke();
  }
  const drawPoly = (vals, color) => {
    ctx.beginPath();
    vals.forEach((v, idx) => {
      const angle = -Math.PI / 2 + (Math.PI * 2 * idx) / vals.length;
      const px = cx + Math.cos(angle) * r * v;
      const py = cy + Math.sin(angle) * r * v;
      if (idx === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    });
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.strokeStyle = color.replace('0.35', '0.8');
    ctx.fill(); ctx.stroke();
  };
  drawPoly(metrics.map(v => radarMinScale + v * radarValueRange), 'rgba(0,212,255,0.35)');
  drawPoly(metricsB.map(v => radarMinScale + v * radarValueRange), 'rgba(255,45,107,0.35)');
}

// Actions
function startScan() {
  const target = els.targetInput.value.trim();
  if (!target) { toast('Введите цель'); return; }
  els.scanBtn.disabled = true;
  updateProgress(5, `Запуск ${target}`);
  renderLog(`[*] Запуск сканирования: ${target}`);
  const title = document.querySelector('.glitch');
  if (title) { title.classList.add('pulse'); setTimeout(() => title.classList.remove('pulse'), 600); }
  sounds.start();

  fetch(`${API}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, mode: els.modeSelect.value }),
  }).then(r => r.json())
    .then(data => {
      if (data.error) { throw new Error(data.error); }
      currentScanId = data.scan_id;
      socket?.emit('join_scan', { scan_id: currentScanId });
      toast('Сканирование запущено');
    })
    .catch(err => { toast(err.message || 'Ошибка запуска'); sounds.error(); els.scanBtn.disabled = false; });
}

// Tabs
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const id = tab.dataset.tab;
    document.getElementById(`tab-${id}`)?.classList.add('active');
  });
});

// Events
if (els.scanBtn) els.scanBtn.addEventListener('click', startScan);
if (els.targetInput) els.targetInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
if (els.compareBtn) els.compareBtn.addEventListener('click', compareTargets);

// Health check
function healthCheck() {
  fetch(`${API}/api/health`).then(r => r.json()).then(data => {
    setStatus(data.binary_exists, data.binary_exists ? 'API ONLINE' : 'BINARY MISSING');
    toast(data.binary_exists ? '✓ API подключён' : '⚠ binary отсутствует');
  }).catch(() => setStatus(false, 'API OFFLINE'));
}

// Clock
setInterval(() => {
  const c = document.getElementById('clock');
  if (c) c.textContent = new Date().toLocaleTimeString();
}, 1000);

// Init
healthCheck();
initSocket();
fetchHistory();
