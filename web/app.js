// PhantomScan Dashboard — Living Neon Terminal
const API = '';
const DEBUG = false;

let socket = null;
let reconnectTimer = null;
let pollTimer = null;
let elapsedTimer = null;
let currentScanId = null;
let currentMode = 'full';
let lastResult = null;
let logBuffer = [];
let startTs = null;
let logSeen = 0;

const els = {
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  scanBtn: document.getElementById('scanBtn'),
  targetInput: document.getElementById('targetInput'),
  progressFill: document.getElementById('progressFill'),
  progressPct: document.getElementById('progressPct'),
  progressLabel: document.getElementById('progressLabel'),
  progressSection: document.getElementById('progressSection'),
  currentAction: document.getElementById('currentAction'),
  elapsedTime: document.getElementById('elapsedTime'),
  logList: document.getElementById('logList'),
  statPorts: document.querySelector('#statPorts .value'),
  statCve: document.querySelector('#statCve .value'),
  statSubs: document.querySelector('#statSubs .value'),
  statScore: document.querySelector('#statScore .value'),
  mapInfo: document.getElementById('mapInfo'),
  mapTarget: document.getElementById('mapTarget'),
  resultTarget: document.getElementById('resultTarget'),
  osInfo: document.getElementById('osInfo'),
  countryInfo: document.getElementById('countryInfo'),
  ispInfo: document.getElementById('ispInfo'),
  fwInfo: document.getElementById('fwInfo'),
  cveSummary: document.getElementById('cveSummary'),
  portsBody: document.getElementById('portsBody'),
  ring: document.getElementById('ringFg'),
  ringGrade: document.getElementById('ringGrade'),
  ringScore: document.getElementById('ringScore'),
  ringVerdict: document.getElementById('ringVerdict'),
  scoreTarget: document.getElementById('scoreTarget'),
  dnsList: document.getElementById('dnsList'),
  tlsList: document.getElementById('tlsList'),
  httpList: document.getElementById('httpList'),
  whoisList: document.getElementById('whoisList'),
  recList: document.getElementById('recList'),
  historyGrid: document.getElementById('historyGrid'),
  toast: document.getElementById('toast'),
  cmpA: document.getElementById('cmpA'),
  cmpB: document.getElementById('cmpB'),
  cmpAScore: document.getElementById('cmpAScore'),
  cmpBScore: document.getElementById('cmpBScore'),
  cmpLegend: document.getElementById('cmpLegend'),
  compareBtn: document.getElementById('compareBtn'),
};

// Background particle network
(() => {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H;
  const nodes = [];
  const resize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
  resize(); window.addEventListener('resize', resize);
  let mouse = { x: W / 2, y: H / 2 };
  window.addEventListener('mousemove', e => { mouse = { x: e.clientX, y: e.clientY }; });
  class Node {
    constructor() { this.reset(); }
    reset() { this.x = Math.random() * W; this.y = Math.random() * H; this.vx = (Math.random() - 0.5) * 0.35; this.vy = (Math.random() - 0.5) * 0.35; this.r = Math.random() * 1.8 + 0.6; }
    step() {
      this.x += this.vx; this.y += this.vy;
      if (this.x < 0 || this.x > W) this.vx *= -1;
      if (this.y < 0 || this.y > H) this.vy *= -1;
    }
  }
  for (let i = 0; i < 90; i++) nodes.push(new Node());
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
        if (d < 140) {
          const mx = (mouse.x / W - 0.5) * 2;
          const my = (mouse.y / H - 0.5) * 2;
          const alpha = 0.09 * (1 - d / 140);
          ctx.strokeStyle = `rgba(0,212,255,${alpha})`;
          ctx.beginPath(); ctx.moveTo(nodes[i].x + mx, nodes[i].y + my); ctx.lineTo(nodes[j].x, nodes[j].y); ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// Helpers
function setStatus(ok, text) {
  if (els.statusDot) {
    els.statusDot.style.background = ok ? 'var(--accent)' : 'var(--secondary)';
    els.statusDot.style.boxShadow = ok ? '0 0 12px var(--accent)' : '0 0 12px var(--secondary)';
  }
  if (els.statusText) els.statusText.textContent = text;
}

function animateNumber(el, to, duration = 800) {
  if (!el) return;
  const from = Number(el.dataset.val || 0);
  const start = performance.now();
  const step = now => {
    const p = Math.min(1, (now - start) / duration);
    const val = Math.round(from + (to - from) * p);
    el.textContent = val;
    el.dataset.val = val;
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function formatTime(ms) {
  const total = Math.floor(ms / 1000);
  const m = String(Math.floor(total / 60)).padStart(2, '0');
  const s = String(total % 60).padStart(2, '0');
  return `${m}:${s}`;
}

// Progress handling
function progressFromLog(line) {
  const l = (line || '').toLowerCase();
  if (l.includes('готово') || l.includes('done')) return { pct: 100, action: 'Готово' };
  if (l.includes('сохраняем')) return { pct: 95, action: 'Сохраняем отчёты' };
  if (l.includes('анализ')) return { pct: 85, action: 'Анализируем' };
  if (l.includes('tls')) return { pct: 75, action: 'Проверяем TLS' };
  if (l.includes('поддомен')) return { pct: 65, action: 'Ищем поддомены' };
  if (l.includes('cve')) return { pct: 45, action: 'Проверяем CVE' };
  if (l.includes('завершено за') || l.includes('ports done')) return { pct: 30, action: 'Порты завершены' };
  if (l.includes('сканируем порты') || l.includes('ports')) return { pct: 15, action: 'Сканируем порты' };
  return { pct: 8, action: 'Инициализация' };
}

function updateProgress(pct, label) {
  const v = Math.max(0, Math.min(100, Math.floor(pct || 0)));
  if (els.progressFill) {
    els.progressFill.style.width = `${v}%`;
    const tip = els.progressFill.querySelector('.glow-tip');
    if (tip) tip.style.right = `${-6 + (100 - v) * 0.12}px`;
  }
  if (els.progressPct) els.progressPct.textContent = `${v}%`;
  if (els.progressLabel) els.progressLabel.textContent = label || 'В работе...';
}

// Logs
function classifyLog(text) {
  if (/^\[\+\]|✓/.test(text)) return 'log-ok';
  if (/^\[-\]|✗/.test(text)) return 'log-err';
  if (/^\[\!\]|⚠/.test(text)) return 'log-warn';
  return 'log-info';
}

function typewriter(el, text) {
  let idx = 0;
  const write = () => {
    el.textContent = text.slice(0, idx);
    idx++;
    if (idx <= text.length) setTimeout(write, 15);
  };
  write();
}

function renderLog(text, cls = '') {
  if (!els.logList || !text) return;
  const li = document.createElement('li');
  const extra = text.toLowerCase().includes('cve') ? 'log-cve' : '';
  li.className = `log-line ${cls || classifyLog(text)} ${extra}`.trim();
  typewriter(li, text);
  els.logList.appendChild(li);
  logBuffer.push(li);
  logSeen += 1;
  if (logBuffer.length > 8) {
    const rm = logBuffer.shift();
    rm.classList.add('fade');
    setTimeout(() => rm.remove(), 200);
  }
}

// UI pieces
const TOAST_DURATION = 4000;
let toastTimer = null;
function toast(msg) {
  if (!els.toast) return;
  els.toast.textContent = msg;
  els.toast.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { if (els.toast) els.toast.style.display = 'none'; }, TOAST_DURATION);
}

function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${tabName}`);
  });
}

// Socket handling
function connectSocket() {
  if (typeof io === 'undefined') {
    setStatus(false, 'Socket.IO unavailable');
    return;
  }
  if (socket) socket.disconnect();
  socket = io({ transports: ['websocket', 'polling'] });

  socket.on('connect', () => {
    setStatus(true, 'API ONLINE');
    if (currentScanId) socket.emit('join_scan', { scan_id: currentScanId });
  });

  socket.on('disconnect', () => {
    setStatus(false, 'API OFFLINE');
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connectSocket, 2000);
  });

  socket.on('log_line', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    handleLog(payload.line, payload.progress, payload.current_action);
  });

  socket.on('scan_status', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    handleStatus(payload.progress, payload.current_action);
  });

  socket.on('scan_error', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    renderLog(`[-] ${payload.error || 'Ошибка'}`, 'log-err');
    stopTimers();
    setStatus(false, 'SCAN ERROR');
    if (els.scanBtn) els.scanBtn.disabled = false;
  });

  socket.on('scan_complete', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    finalizeScan(payload.result);
  });
}

function handleLog(line, pct, action) {
  renderLog(line);
  const derived = progressFromLog(line);
  const progress = Math.max(pct || 0, derived.pct);
  const label = action || derived.action || 'Сканирование';
  updateProgress(progress, label);
  if (els.currentAction) els.currentAction.textContent = label;
}

function handleStatus(pct, action) {
  const label = action || 'Сканирование';
  if (els.currentAction) els.currentAction.textContent = label;
  updateProgress(pct || 0, label);
}

function stopTimers() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

function finalizeScan(result) {
  updateProgress(100, 'Готово');
  if (els.currentAction) els.currentAction.textContent = 'Готово';
  stopTimers();
  if (els.scanBtn) els.scanBtn.disabled = false;
  if (result) {
    lastResult = result;
    renderAll(result);
    fetchHistory();
    switchTab('results');
  }
}

// Polling fallback
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!currentScanId) return;
    try {
      const res = await fetch(`${API}/api/scan/${currentScanId}`);
      const data = await res.json();
      if (data.error) return;
      const logs = Array.isArray(data.log) ? data.log : [];
      const unseen = logs.slice(Math.max(0, logSeen));
      unseen.forEach(line => handleLog(line));
      logSeen = Math.max(logSeen, logs.length);
      handleStatus(data.progress || 0, data.current_action || data.status);
      if (data.status === 'done') {
        finalizeScan(data.result);
      } else if (data.status === 'error') {
        renderLog(`[-] ${data.error || 'Ошибка сканирования'}`, 'log-err');
        stopTimers();
        if (els.scanBtn) els.scanBtn.disabled = false;
      }
    } catch (e) {
      if (DEBUG) console.warn('poll error', e);
    }
  }, 2000);
}

// Rendering
function collectCves(ports) {
  let total = 0, critical = 0;
  (ports || []).forEach(p => {
    if (Array.isArray(p.cves)) {
      total += p.cves.length;
      critical += p.cves.filter(c => c.severity === 'CRITICAL').length;
    }
  });
  return { total, critical };
}

function renderStats(data) {
  animateNumber(els.statPorts, (data.ports || []).length);
  animateNumber(els.statSubs, (data.subdomains || []).length);
  const c = collectCves(data.ports || []);
  animateNumber(els.statCve, c.total);
  animateNumber(els.statScore, data.score || 0);
}

function renderPorts(ports) {
  if (!els.portsBody) return;
  const body = els.portsBody;
  if (!ports.length) {
    body.innerHTML = '<tr><td colspan="5" style="color:var(--muted)">Нет данных</td></tr>';
    return;
  }
  body.innerHTML = '';
  ports.forEach((p, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'port-row';
    const cells = [idx + 1, p.port, p.service || '—', p.version || '—', 'OPEN'];
    cells.forEach((c, i) => {
      const td = document.createElement('td');
      td.textContent = c;
      if (i === 4) td.className = 'badge-open';
      tr.appendChild(td);
    });
    setTimeout(() => tr.classList.add('visible'), idx * 80);
    body.appendChild(tr);
  });
}

function renderMap(data) {
  if (!els.mapInfo || !els.mapTarget) return;
  const info = [
    ['Target', data.ip || data.target || '—'],
    ['Country', data.country || data.city || '—'],
    ['ISP', data.isp || '—'],
  ];
  els.mapInfo.innerHTML = '';
  info.forEach(([k, v]) => {
    const row = document.createElement('div');
    row.textContent = `${k}: `;
    const span = document.createElement('span'); span.textContent = v;
    row.appendChild(span); els.mapInfo.appendChild(row);
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
  const circ = 600;
  const offset = circ - (score / 100) * circ;
  const gradeColors = { 'A+': '#00ff9d', A: '#00ff9d', B: '#00d4ff', C: '#ffd700' };
  els.ring.style.strokeDashoffset = offset;
  els.ring.style.stroke = gradeColors[grade] || '#ff2d6b';
  els.ringGrade.textContent = grade;
  els.ringScore.textContent = `${score}/100`;
  if (els.ringVerdict) els.ringVerdict.textContent = data.verdict || '—';
  if (els.scoreTarget) els.scoreTarget.textContent = data.target || '—';

  const setList = (el, items) => {
    if (!el) return;
    el.innerHTML = '';
    items.forEach(i => {
      const li = document.createElement('li');
      li.className = i.state;
      li.innerHTML = `<span>${i.label}</span><span>${i.badge || ''}</span>`;
      el.appendChild(li);
    });
  };

  setList(els.dnsList, [
    { label: 'SPF', badge: okBad(data.dns?.spf), state: data.dns?.spf ? 'ok' : 'bad' },
    { label: 'DMARC', badge: okBad(data.dns?.dmarc), state: data.dns?.dmarc ? 'ok' : 'bad' },
    { label: 'DNSSEC', badge: okBad(data.dns?.dnssec), state: data.dns?.dnssec ? 'ok' : 'bad' },
    { label: 'CAA', badge: okBad(data.dns?.caa), state: data.dns?.caa ? 'ok' : 'bad' },
    { label: 'DKIM', badge: okBad(data.dns?.dkim), state: data.dns?.dkim ? 'ok' : 'bad' },
    { label: 'MX', badge: okBad(data.dns?.mx), state: data.dns?.mx ? 'ok' : 'bad' },
  ]);

  setList(els.tlsList, [
    { label: 'TLS1.0', badge: offOn(data.tls?.tls10), state: data.tls?.tls10 ? 'warn' : 'ok' },
    { label: 'TLS1.1', badge: offOn(data.tls?.tls11), state: data.tls?.tls11 ? 'warn' : 'ok' },
    { label: 'TLS1.2', badge: okBad(data.tls?.tls12), state: data.tls?.tls12 ? 'ok' : 'bad' },
    { label: 'TLS1.3', badge: okBad(data.tls?.tls13), state: data.tls?.tls13 ? 'ok' : 'bad' },
    { label: 'HSTS', badge: okBad(data.tls?.hsts), state: data.tls?.hsts ? 'ok' : 'bad' },
    { label: 'Cert days', badge: data.tls?.days_left ?? '—', state: (data.tls?.days_left ?? 0) > 30 ? 'ok' : 'warn' },
  ]);

  setList(els.httpList, [
    { label: 'X-Frame-Options', badge: okBad(data.http?.x_frame_options), state: data.http?.x_frame_options ? 'ok' : 'bad' },
    { label: 'X-Content-Type', badge: okBad(data.http?.x_content_type_options), state: data.http?.x_content_type_options ? 'ok' : 'bad' },
    { label: 'CSP', badge: okBad(data.http?.csp), state: data.http?.csp ? 'ok' : 'bad' },
    { label: 'Referrer-Policy', badge: okBad(data.http?.referrer_policy), state: data.http?.referrer_policy ? 'ok' : 'bad' },
  ]);

  setList(els.whoisList, [
    { label: 'Registrar', badge: data.whois?.registrar || '—', state: 'info' },
    { label: 'Country', badge: data.whois?.country || '—', state: 'info' },
    { label: 'Expiry (days)', badge: data.whois?.days_until_expiry ?? '—', state: 'info' },
  ]);

  if (els.recList) {
    els.recList.innerHTML = '';
    (data.recommendations || [])
      .sort((a, b) => severityRank(a.level) - severityRank(b.level))
      .forEach(r => {
        const div = document.createElement('div');
        div.className = `rec ${r.level.toLowerCase()}`;
        div.textContent = `[${r.level}] ${r.message}`;
        els.recList.appendChild(div);
      });
  }
}

function okBad(val) { return val ? '✓' : '✗'; }
function offOn(val) { return val ? '✓ Off' : '✗ On'; }
function severityRank(lvl) { return { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 }[lvl] || 5; }

function renderAll(data) {
  if (!data) return;
  renderStats(data);
  renderPorts(data.ports || []);
  renderMap(data);
  renderScorecard(data);
  if (els.resultTarget) els.resultTarget.textContent = data.target || data.ip || '—';
  if (els.osInfo) els.osInfo.textContent = `OS: ${data.os || '—'}`;
  if (els.countryInfo) els.countryInfo.textContent = `Country: ${data.country || '—'}`;
  if (els.ispInfo) els.ispInfo.textContent = `ISP: ${data.isp || '—'}`;
  if (els.fwInfo) els.fwInfo.textContent = `Firewall: ${data.firewall ? 'Detected' : '—'}`;
  if (els.cveSummary) {
    const c = collectCves(data.ports || []);
    els.cveSummary.textContent = `CVE total: ${c.total} | Critical: ${c.critical}`;
  }
}

// History
async function fetchHistory() {
  try {
    const res = await fetch(`${API}/api/history`);
    const rows = await res.json();
    if (!Array.isArray(rows) || !els.historyGrid) return;
    els.historyGrid.innerHTML = '';
    rows.slice(0, 20).forEach(row => {
      const card = document.createElement('div');
      card.className = 'history-card';
      card.innerHTML = `
        <div class="title">${row.target || '—'}</div>
        <div class="meta">Ports: ${row.ports ?? '—'}</div>
        <div class="meta">Score: ${row.score ?? '—'}</div>
        <div class="meta">${row.timestamp ? new Date(row.timestamp).toLocaleString() : ''}</div>
      `;
      const badge = document.createElement('div');
      badge.className = 'score-badge';
      const grade = (row.grade || '').toUpperCase();
      badge.textContent = grade || '—';
      badge.classList.add(
        grade.startsWith('A') ? 'grade-a' :
        grade === 'B' ? 'grade-b' :
        grade === 'C' ? 'grade-c' : 'grade-d'
      );
      card.appendChild(badge);
      card.addEventListener('click', () => toast(`Выбрано: ${row.target || '—'}`));
      els.historyGrid.appendChild(card);
    });
  } catch (e) {
    if (DEBUG) console.warn('history error', e);
  }
}

// Compare
function renderCompare(a, b) {
  const scoreA = a?.score ?? null;
  const scoreB = b?.score ?? null;
  if (els.cmpAScore) els.cmpAScore.textContent = scoreA ?? '—';
  if (els.cmpBScore) els.cmpBScore.textContent = scoreB ?? '—';
  document.querySelectorAll('.score-sides .side').forEach(el => el.classList.remove('winner'));
  if (scoreA !== null && scoreB !== null) {
    const aSide = document.querySelector('.score-sides .side:nth-child(1)');
    const bSide = document.querySelector('.score-sides .side:nth-child(2)');
    if (scoreA > scoreB && aSide) aSide.classList.add('winner');
    if (scoreB > scoreA && bSide) bSide.classList.add('winner');
  }
  if (els.cmpLegend) {
    els.cmpLegend.innerHTML = '';
    ['DNS', 'TLS', 'HTTP', 'WHOIS'].forEach(item => {
      const div = document.createElement('div');
      div.textContent = item;
      els.cmpLegend.appendChild(div);
    });
  }
}

async function compareTargets() {
  const a = (els.cmpA?.value || '').trim();
  const b = (els.cmpB?.value || '').trim();
  if (!a || !b) { toast('Введите оба хоста для сравнения'); return; }
  els.compareBtn?.setAttribute('disabled', 'disabled');
  try {
    const res = await fetch(`${API}/api/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_a: a, target_b: b }),
    });
    const data = await res.json();
    renderCompare(data?.a, data?.b);
    toast('Сравнение завершено');
  } catch (e) {
    toast('Ошибка сравнения');
  } finally {
    els.compareBtn?.removeAttribute('disabled');
  }
}

// Scan actions
async function startScan() {
  const target = (els.targetInput?.value || '').trim();
  if (!target) { toast('Введите цель'); return; }
  if (els.scanBtn) els.scanBtn.disabled = true;
  logBuffer = [];
  logSeen = 0;
  if (els.logList) els.logList.innerHTML = '';
  if (els.progressSection) els.progressSection.style.opacity = 1;
  startTs = Date.now();
  if (els.elapsedTime) els.elapsedTime.textContent = '00:00';
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = setInterval(() => {
    if (els.elapsedTime && startTs) els.elapsedTime.textContent = formatTime(Date.now() - startTs);
  }, 1000);
  renderLog(`[*] Запуск сканирования: ${target}`);
  updateProgress(5, 'Запуск');
  if (els.currentAction) els.currentAction.textContent = 'Инициализация';
  switchTab('scan');

  const body = { target, mode: currentMode };
  try {
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    currentScanId = data.scan_id;
    if (socket) socket.emit('join_scan', { scan_id: currentScanId });
    startPolling();
    toast('Сканирование запущено');
  } catch (err) {
    toast(err.message || 'Ошибка запуска');
    if (els.scanBtn) els.scanBtn.disabled = false;
  }
}

// Health check
async function healthCheck() {
  try {
    const res = await fetch(`${API}/api/health`);
    const data = await res.json();
    setStatus(data.binary_exists, data.binary_exists ? 'API ONLINE' : 'BINARY MISSING');
  } catch (e) {
    setStatus(false, 'API OFFLINE');
  }
}

// Clock
setInterval(() => {
  const c = document.getElementById('clock');
  if (c) c.textContent = new Date().toLocaleTimeString();
}, 1000);

// Tabs
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// Mode chips
document.querySelectorAll('#modeChips .chip').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('#modeChips .chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    currentMode = chip.dataset.mode;
  });
});

// Events
els.scanBtn?.addEventListener('click', startScan);
els.targetInput?.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
els.compareBtn?.addEventListener('click', compareTargets);

// Init
healthCheck();
connectSocket();
fetchHistory();
