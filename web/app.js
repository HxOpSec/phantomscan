// PhantomScan Shadow Monarch Dashboard
const API = '';
const DEBUG = false;

class SoundEngine {
  constructor() {
    this.ctx = null;
    this.enabled = false;
    this.ambienceNode = null;
  }
  enable() {
    if (this.enabled) return;
    this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    this.enabled = true;
  }
  _play({ type = 'sine', freq = 440, duration = 0.2, vol = 0.08, sweep = null, delay = 0 }) {
    if (!this.enabled || !this.ctx) return;
    const now = this.ctx.currentTime + delay;
    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, now);
    if (sweep) osc.frequency.linearRampToValueAtTime(sweep, now + duration);
    gain.gain.setValueAtTime(vol, now);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);
    osc.connect(gain).connect(this.ctx.destination);
    osc.start(now);
    osc.stop(now + duration);
  }
  intro() {
    this._play({ type: 'sine', freq: 40, duration: 2.5, vol: 0.08 });
    this._play({ type: 'triangle', freq: 120, sweep: 40, duration: 2.5, vol: 0.06, delay: 0.3 });
  }
  introWhoosh() { this._play({ type: 'sawtooth', freq: 60, sweep: 440, duration: 0.8, vol: 0.05 }); }
  scanStart() { this._play({ type: 'sawtooth', freq: 40, sweep: 440, duration: 0.6, vol: 0.07 }); }
  portFound() { this._play({ type: 'square', freq: 880, duration: 0.05, vol: 0.05 }); }
  criticalCVE() {
    this._play({ type: 'sine', freq: 220, duration: 0.15, vol: 0.08 });
    this._play({ type: 'sine', freq: 220, duration: 0.15, vol: 0.08, delay: 0.18 });
    this._play({ type: 'sine', freq: 220, duration: 0.15, vol: 0.08, delay: 0.36 });
  }
  scanComplete() {
    this._play({ type: 'triangle', freq: 196, duration: 0.18, vol: 0.06 });
    this._play({ type: 'triangle', freq: 233, duration: 0.18, vol: 0.06, delay: 0.2 });
    this._play({ type: 'triangle', freq: 262, duration: 0.25, vol: 0.06, delay: 0.4 });
  }
  scanError() { this._play({ type: 'sawtooth', freq: 440, sweep: 110, duration: 0.5, vol: 0.06 }); }
  tabClick() { this._play({ type: 'square', freq: 1000, duration: 0.04, vol: 0.03 }); }
  buttonHover() { this._play({ type: 'square', freq: 2000, duration: 0.02, vol: 0.02 }); }
  moduleSelect() { this._play({ type: 'square', freq: 700, duration: 0.06, vol: 0.04 }); }
  toggleAmbience(enable) {
    if (!this.enabled || !this.ctx) return;
    if (enable) {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(38, this.ctx.currentTime);
      gain.gain.setValueAtTime(0.01, this.ctx.currentTime);
      osc.connect(gain).connect(this.ctx.destination);
      osc.start();
      this.ambienceNode = { osc, gain };
    } else if (this.ambienceNode) {
      this.ambienceNode.gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.5);
      this.ambienceNode.osc.stop(this.ctx.currentTime + 0.6);
      this.ambienceNode = null;
    }
  }
}

class IntroAnimation {
  constructor(sound) {
    this.el = document.getElementById('intro');
    this.sound = sound;
    if (this.el) {
      setTimeout(() => this.run(), 200);
    }
  }
  run() {
    if (!this.el) return;
    this.sound.intro();
    setTimeout(() => this.sound.introWhoosh(), 1200);
    this.el.classList.add('reveal');
    const burst = this.el.querySelector('.particle-burst');
    setTimeout(() => { if (burst) burst.classList.add('burst'); }, 3600);
    setTimeout(() => {
      this.el.classList.add('dissolve');
      setTimeout(() => {
        this.el.classList.add('hidden');
        setTimeout(() => { this.el.remove(); }, 1200);
      }, 600);
    }, 5000);
  }
}

const modules = [
  { id: '1', icon: '⚡', name: 'Full Scan', cat: 'recon', desc: 'WHOIS + ports + CVE + subs', inputs: [] },
  { id: '2', icon: '🚀', name: 'Quick Scan', cat: 'recon', desc: 'Top 1024 ports fast', inputs: [] },
  { id: '3', icon: '🌐', name: 'Subdomains', cat: 'recon', desc: 'Enumerate subdomains', inputs: [] },
  { id: '4', icon: '📡', name: 'Packet Monitor', cat: 'net', desc: 'Monitor packets (lo)', inputs: [{ key: 'interface', label: 'Interface', placeholder: 'lo' }] },
  { id: '5', icon: '🛰️', name: 'ARP Scan', cat: 'net', desc: 'Local subnet discovery', inputs: [{ key: 'subnet', label: 'Subnet', placeholder: '192.168.1.0/24' }] },
  { id: '6', icon: '🧭', name: 'Traceroute', cat: 'recon', desc: 'Trace network path', inputs: [] },
  { id: '7', icon: '🗡️', name: 'SYN Stealth', cat: 'net', desc: 'Port range stealth scan', inputs: [{ key: 'port_range', label: 'Port range', placeholder: '1-1024' }] },
  { id: '8', icon: '🔐', name: 'SSL/TLS Analysis', cat: 'vuln', desc: 'TLS posture & certs', inputs: [] },
  { id: '9', icon: '🛡️', name: 'WAF Detection', cat: 'vuln', desc: 'Detect firewalls/WAF', inputs: [] },
  { id: '10', icon: '🧨', name: 'Vuln Scanner', cat: 'vuln', desc: 'Scan vulnerable versions', inputs: [] },
  { id: '11', icon: '📜', name: 'Wordlist Generator', cat: 'osint', desc: 'Generate wordlist', inputs: [] },
  { id: '12', icon: '🔭', name: 'Shodan Lookup', cat: 'osint', desc: 'API powered lookup', inputs: [{ key: 'api_key', label: 'API Key', placeholder: 'SHODAN-KEY' }] },
  { id: '13', icon: '🧠', name: 'Exploit Suggester', cat: 'vuln', desc: 'Suggested exploits', inputs: [{ key: 'service', label: 'Service', placeholder: 'ssh/http/...' }] },
  { id: '14', icon: '🕸️', name: 'Network Topology', cat: 'recon', desc: 'Map hops', inputs: [] },
  { id: '15', icon: '💥', name: 'UDP Scan', cat: 'net', desc: 'UDP port range', inputs: [{ key: 'port_range', label: 'Port range', placeholder: '1-1024' }] },
  { id: '16', icon: '🎯', name: 'Change Target', cat: 'recon', desc: 'Update target', inputs: [{ key: 'new_target', label: 'New Target', placeholder: 'host' }] },
  { id: '17', icon: '🏅', name: 'Scorecard', cat: 'vuln', desc: 'Security grade', inputs: [] },
  { id: '18', icon: '🕵️‍♂️', name: 'HTTP Dir Scan', cat: 'osint', desc: 'Dir brute force', inputs: [{ key: 'port', label: 'Port', placeholder: '80' }] },
  { id: '19', icon: '📡', name: 'DNS Recon', cat: 'recon', desc: 'DNS enum + AXFR', inputs: [] },
  { id: '20', icon: '🗂️', name: 'Multi Scan', cat: 'net', desc: 'File of targets', inputs: [{ key: 'file_path', label: 'File path', placeholder: 'targets.txt' }] },
];

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
  selectedModule: document.getElementById('selectedModule'),
  modal: document.getElementById('moduleModal'),
  modalBody: document.getElementById('modalBody'),
  modalTitle: document.getElementById('modalTitle'),
  modalRun: document.getElementById('modalRun'),
  modalClose: document.getElementById('modalClose'),
  ambientToggle: document.getElementById('ambientToggle'),
};

let socket = null;
let reconnectTimer = null;
let pollTimer = null;
let elapsedTimer = null;
let silentTimer = null;
let currentScanId = null;
let selectedModuleId = '1';
let lastResult = null;
let logBuffer = [];
let startTs = null;
let logSeen = 0;
let lastSocketEvent = Date.now();
let ambientOn = false;

const sound = new SoundEngine();
const intro = new IntroAnimation(sound);

// Custom cursor dot
(() => {
  const dot = document.createElement('div');
  dot.id = 'cursorDot';
  document.body.appendChild(dot);
  let target = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
  window.addEventListener('mousemove', e => { target = { x: e.clientX, y: e.clientY }; });
  function animate() {
    dot.style.transform = `translate(${target.x - 6}px, ${target.y - 6}px)`;
    requestAnimationFrame(animate);
  }
  animate();
})();

// Background particle network + lightning cursor
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
      const dx = mouse.x - this.x;
      const dy = mouse.y - this.y;
      const d = Math.hypot(dx, dy) || 1;
      const accel = Math.max(0, 120 - d) / 120 * 0.08;
      this.vx += (dx / d) * accel * 0.02;
      this.vy += (dy / d) * accel * 0.02;
      this.x += this.vx; this.y += this.vy;
      this.vx *= 0.99; this.vy *= 0.99;
      if (this.x < 0 || this.x > W) this.vx *= -1;
      if (this.y < 0 || this.y > H) this.vy *= -1;
    }
  }
  for (let i = 0; i < 100; i++) nodes.push(new Node());
  function draw() {
    ctx.clearRect(0, 0, W, H);
    nodes.forEach(n => {
      n.step();
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(123,47,255,0.35)'; ctx.fill();
    });
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
        if (d < 140) {
          const alpha = 0.08 * (1 - d / 140);
          ctx.strokeStyle = `rgba(0,212,255,${alpha})`;
          ctx.beginPath(); ctx.moveTo(nodes[i].x, nodes[i].y); ctx.lineTo(nodes[j].x, nodes[j].y); ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

(() => {
  const canvas = document.getElementById('cursor-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H;
  const trails = [];
  const resize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
  resize(); window.addEventListener('resize', resize);
  window.addEventListener('mousemove', e => {
    trails.push({ x: e.clientX, y: e.clientY, life: 1 });
  });
  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (let i = 0; i < trails.length; i++) {
      const t = trails[i];
      ctx.beginPath();
      ctx.arc(t.x, t.y, 6, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(123,47,255,${t.life})`;
      ctx.shadowColor = 'rgba(123,47,255,0.8)';
      ctx.shadowBlur = 12;
      ctx.fill();
      if (i > 0) {
        const prev = trails[i - 1];
        ctx.beginPath();
        ctx.moveTo(prev.x + (Math.random() - 0.5) * 6, prev.y + (Math.random() - 0.5) * 6);
        ctx.lineTo(t.x + (Math.random() - 0.5) * 6, t.y + (Math.random() - 0.5) * 6);
        ctx.strokeStyle = `rgba(0,212,255,${t.life})`;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      t.life -= 0.02;
    }
    for (let i = trails.length - 1; i >= 0; i--) if (trails[i].life <= 0) trails.splice(i, 1);
    requestAnimationFrame(draw);
  }
  draw();
})();

// Helpers
function setStatus(ok, text) {
  if (els.statusDot) {
    els.statusDot.style.background = ok ? 'var(--accent-2)' : 'var(--danger)';
    els.statusDot.style.boxShadow = ok ? '0 0 12px var(--accent-2)' : '0 0 12px var(--danger)';
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

function progressFromLog(line) {
  const l = (line || '').toLowerCase();
  if (l.includes('готово') || l.includes('done')) return { pct: 100, action: 'Готово' };
  if (l.includes('сохраняем')) return { pct: 95, action: 'Сохраняем отчёты' };
  if (l.includes('анализ')) return { pct: 85, action: 'Анализируем' };
  if (l.includes('tls')) return { pct: 75, action: 'Проверяем TLS' };
  if (l.includes('поддомен')) return { pct: 65, action: 'Ищем поддомены' };
  if (l.includes('cve')) return { pct: 50, action: 'Проверяем CVE' };
  if (l.includes('завершено за') || l.includes('ports done')) return { pct: 35, action: 'Порты завершены' };
  if (l.includes('сканируем порты') || l.includes('ports')) return { pct: 20, action: 'Сканируем порты' };
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

function classifyLog(text) {
  if (/^\[\+\]|✓/.test(text)) return 'log-ok';
  if (/^\[-\]|✗/.test(text)) return 'log-err';
  if (/^\[\!\]|⚠/.test(text)) return 'log-warn';
  return 'log-info';
}

function typewriter(el, text) {
  let idx = 0;
  let last = 0;
  const step = ts => {
    if (!last || ts - last >= 15) {
      last = ts;
      idx++;
      el.textContent = text.slice(0, idx);
    }
    if (idx <= text.length) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
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
  lastSocketEvent = Date.now();
}

function toast(msg) {
  if (!els.toast) return;
  els.toast.textContent = msg;
  els.toast.style.display = 'block';
  clearTimeout(els.toast._timer);
  els.toast._timer = setTimeout(() => { els.toast.style.display = 'none'; }, 4000);
}

function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${tabName}`);
  });
}

function safeName(val) {
  return (val || '').replace(/[^a-zA-Z0-9._-]/g, '_');
}

// Socket handling
function connectSocket() {
  if (typeof io === 'undefined') {
    setStatus(false, 'Socket.IO unavailable');
    return;
  }
  if (socket) socket.disconnect();
  socket = io({ transports: ['polling', 'websocket'], reconnection: true, reconnectionAttempts: 10, reconnectionDelay: 1500 });

  socket.onAny((event, ...args) => {
    console.log('[socket][event]', event, args);
  });
  socket.on('connect', () => {
    console.log('[socket] connect');
    setStatus(true, 'API ONLINE');
    if (currentScanId) socket.emit('join_scan', { scan_id: currentScanId });
  });
  socket.on('connect_error', err => {
    console.log('[socket] connect_error', err?.message || err);
    setStatus(false, 'API OFFLINE');
  });
  socket.on('reconnect_attempt', attempt => console.log('[socket] reconnect_attempt', attempt));
  socket.on('disconnect', () => {
    console.log('[socket] disconnect');
    setStatus(false, 'API OFFLINE');
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connectSocket, 2000);
  });
  socket.on('log_line', payload => {
    console.log('[socket] log_line', payload);
    if (!payload || payload.scan_id !== currentScanId) return;
    lastSocketEvent = Date.now();
    handleLog(payload.line, payload.progress, payload.current_action);
  });
  socket.on('scan_status', payload => {
    console.log('[socket] scan_status', payload);
    if (!payload || payload.scan_id !== currentScanId) return;
    lastSocketEvent = Date.now();
    handleStatus(payload.progress, payload.current_action);
  });
  socket.on('scan_error', payload => {
    console.log('[socket] scan_error', payload);
    if (!payload || payload.scan_id !== currentScanId) return;
    renderLog(`[-] ${payload.error || 'Ошибка'}`, 'log-err');
    sound.scanError();
    stopTimers();
    setStatus(false, 'SCAN ERROR');
    if (els.scanBtn) els.scanBtn.disabled = false;
  });
  socket.on('scan_complete', payload => {
    console.log('[socket] scan_complete', payload);
    if (!payload || payload.scan_id !== currentScanId) return;
    lastSocketEvent = Date.now();
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
  if (/cve/i.test(line) && /critical/i.test(line)) sound.criticalCVE();
}

function handleStatus(pct, action) {
  const label = action || 'Сканирование';
  if (els.currentAction) els.currentAction.textContent = label;
  updateProgress(pct || 0, label);
}

function stopTimers() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
  if (silentTimer) { clearInterval(silentTimer); silentTimer = null; }
}

function finalizeScan(result) {
  updateProgress(100, 'Готово');
  if (els.currentAction) els.currentAction.textContent = 'Готово';
  stopTimers();
  sound.scanComplete();
  if (els.scanBtn) els.scanBtn.disabled = false;
  if (result) {
    lastResult = result;
    renderAll(result);
    fetchHistory();
    switchTab('results');
  }
}

function startSilentPoll() {
  if (silentTimer) clearInterval(silentTimer);
  silentTimer = setInterval(() => {
    if (!currentScanId) return;
    if (Date.now() - lastSocketEvent > 5000) {
      pollOnce();
    }
  }, 5000);
}

// Polling fallback
async function pollOnce() {
  if (!currentScanId) return;
  const safeId = encodeURIComponent(currentScanId);
  try {
    const res = await fetch(`${API}/api/scan/${safeId}`);
    const data = await res.json();
    if (data.error) return;
    lastSocketEvent = Date.now();
    const logs = Array.isArray(data.log) ? data.log : [];
    const unseen = logs.slice(logSeen);
    unseen.forEach(line => handleLog(line));
    logSeen = Math.max(logSeen, logs.length);
    handleStatus(data.progress || 0, data.current_action || data.status);
    if (data.status === 'done') {
      finalizeScan(data.result);
    } else if (data.status === 'error') {
      renderLog(`[-] ${data.error || 'Ошибка сканирования'}`, 'log-err');
      stopTimers();
      if (els.scanBtn) els.scanBtn.disabled = false;
      setStatus(false, 'SCAN ERROR');
    }
  } catch (e) {
    if (DEBUG) console.warn('poll error', e);
  }
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
    if (p.cves?.some(cv => cv.severity === 'CRITICAL')) tr.classList.add('critical');
    const cells = [idx + 1, p.port, p.service || '—', p.version || '—', 'OPEN'];
    cells.forEach((c, i) => {
      const td = document.createElement('td');
      td.textContent = c;
      if (i === 4) td.className = 'badge-open';
      tr.appendChild(td);
    });
    setTimeout(() => tr.classList.add('visible'), idx * 80);
    body.appendChild(tr);
    if (p.cves?.some(cv => cv.severity === 'CRITICAL')) sound.criticalCVE();
    else if (p.cves?.length) sound.portFound();
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
  els.ringGrade.classList.remove('pop');
  void els.ringGrade.offsetWidth;
  els.ringGrade.classList.add('pop');
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

  const okBad = val => val ? '✓' : '✗';
  const offOn = val => val ? '✓ Off' : '✗ On';

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
      .sort((a, b) => ({ CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 }[a.level] - ({ CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 }[b.level])))
      .forEach(r => {
        const div = document.createElement('div');
        div.className = `rec ${r.level.toLowerCase()}`;
        div.textContent = `[${r.level}] ${r.message}`;
        els.recList.appendChild(div);
      });
  }
}

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

async function loadLatestReport(target) {
  try {
    const res = await fetch(`${API}/api/reports`);
    const files = await res.json();
    const safe = safeName(target);
    const picked = (files || []).find(f => f.filename.includes(safe));
    if (picked) {
      const r = await fetch(`${API}/api/reports/${picked.filename}`);
      const data = await r.json();
      renderAll(data);
      toast(`Загружен отчёт: ${target}`);
      switchTab('results');
    } else {
      toast('Нет отчётов для цели');
    }
  } catch (e) {
    if (DEBUG) console.warn('loadLatestReport', e);
  }
}

async function deleteLatestReport(target) {
  try {
    const res = await fetch(`${API}/api/reports`);
    const files = await res.json();
    const safe = safeName(target);
    const picked = (files || []).find(f => f.filename.includes(safe));
    if (picked) {
      await fetch(`${API}/api/reports/${picked.filename}`, { method: 'DELETE' });
      toast('Отчёт удалён');
      fetchHistory();
    } else {
      toast('Файл отчёта не найден');
    }
  } catch (e) {
    if (DEBUG) console.warn('deleteLatestReport', e);
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
        <button class="mini-del" type="button">DELETE</button>
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
      card.addEventListener('click', () => {
        if (row.target) loadLatestReport(row.target);
      });
      card.querySelector('.mini-del').addEventListener('click', e => {
        e.stopPropagation();
        if (row.target) deleteLatestReport(row.target);
      });
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

// Module cards + modal
function buildModuleCards() {
  const buckets = {
    recon: document.getElementById('cat-recon'),
    vuln: document.getElementById('cat-vuln'),
    net: document.getElementById('cat-net'),
    osint: document.getElementById('cat-osint'),
  };
  modules.forEach(mod => {
    const parent = buckets[mod.cat];
    if (!parent) return;
    const card = document.createElement('div');
    card.className = 'module-card';
    card.innerHTML = `
      <div class="module-top">
        <div class="icon">${mod.icon || '★'}</div>
        <div class="title">${mod.id}. ${mod.name}</div>
      </div>
      <div class="desc">${mod.desc}</div>
      <div class="badge">${mod.inputs.length ? 'INPUT' : 'AUTO'}</div>
      <button class="run-btn" type="button">RUN</button>
    `;
    card.addEventListener('click', () => onModuleSelected(mod, card));
    card.querySelector('.run-btn').addEventListener('click', e => {
      e.stopPropagation();
      onModuleSelected(mod, card);
    });
    parent.appendChild(card);
  });
}

function onModuleSelected(mod, card) {
  selectedModuleId = mod.id;
  document.querySelectorAll('.module-card').forEach(c => c.classList.toggle('active', c === card));
  if (els.selectedModule) els.selectedModule.textContent = mod.name;
  sound.moduleSelect();
  if (mod.inputs.length) {
    openModal(mod);
  } else {
    startScan({});
  }
}

function openModal(mod) {
  if (!els.modal) return;
  els.modal.classList.add('show');
  els.modalTitle.textContent = `${mod.id}. ${mod.name}`;
  els.modalBody.innerHTML = '';
  mod.inputs.forEach(inp => {
    const wrap = document.createElement('div');
    wrap.className = 'input-stack';
    wrap.innerHTML = `
      <label>${inp.label}</label>
      <input data-key="${inp.key}" placeholder="${inp.placeholder || ''}">
    `;
    els.modalBody.appendChild(wrap);
  });
  els.modalRun.onclick = () => {
    const extra = {};
    els.modalBody.querySelectorAll('input').forEach(i => extra[i.dataset.key] = i.value);
    els.modal.classList.remove('show');
    startScan(extra);
  };
}

// Scan actions
async function startScan(extra = {}) {
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
  sound.scanStart();

  const body = { target, module: selectedModuleId, extra };
  try {
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    currentScanId = data.scan_id;
    lastSocketEvent = Date.now();
    if (socket) socket.emit('join_scan', { scan_id: currentScanId });
    pollOnce();
    startSilentPoll();
    toast('Сканирование запущено');
  } catch (err) {
    toast(err.message || 'Ошибка запуска');
    sound.scanError();
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

// Events
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => { switchTab(btn.dataset.tab); sound.tabClick(); });
});

els.scanBtn?.addEventListener('click', () => startScan({}));
els.targetInput?.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    sound.moduleSelect();
    startScan({});
  }
});
els.compareBtn?.addEventListener('click', compareTargets);
els.modalClose?.addEventListener('click', () => els.modal.classList.remove('show'));
els.modal?.addEventListener('click', e => { if (e.target === els.modal) els.modal.classList.remove('show'); });
document.body.addEventListener('click', () => sound.enable(), { once: true });

if (els.ambientToggle) {
  els.ambientToggle.addEventListener('click', () => {
    ambientOn = !ambientOn;
    sound.enable();
    sound.toggleAmbience(ambientOn);
    els.ambientToggle.textContent = ambientOn ? '🔊' : '🔇';
  });
}

// Init
document.querySelectorAll('.panel').forEach((p, i) => setTimeout(() => p.classList.add('reveal'), i * 120));
buildModuleCards();
healthCheck();
connectSocket();
fetchHistory();

// Lightning flashes
setInterval(() => {
  const flash = document.createElement('div');
  flash.style.position = 'fixed';
  flash.style.inset = '0';
  flash.style.background = 'radial-gradient(circle at 50% 50%, rgba(123,47,255,0.4), transparent 60%)';
  flash.style.pointerEvents = 'none';
  flash.style.opacity = '0';
  flash.style.transition = 'opacity 0.6s ease';
  flash.style.zIndex = '2';
  document.body.appendChild(flash);
  requestAnimationFrame(() => { flash.style.opacity = '1'; });
  setTimeout(() => { flash.style.opacity = '0'; setTimeout(() => flash.remove(), 600); }, 200);
}, 30000 + Math.random() * 30000);
