// ─────────────────────────────────────────────────────────────────────────────
//  PhantomScan Pro — app.js
//  Real API calls to Flask backend + UI logic
// ─────────────────────────────────────────────────────────────────────────────

const API = '';  // Same origin — Flask serves index.html

// Current scan state
let currentScanId  = null;
let pollInterval   = null;
let currentReport  = null;
let scanMode       = 'full';

// ─────────────────────────────────────────────────────────────────────────────
//  PARTICLES BACKGROUND
// ─────────────────────────────────────────────────────────────────────────────
const canvas = document.getElementById('canvas');
const ctx    = canvas.getContext('2d');
let W, H, nodes = [];

function resizeCanvas() {
  W = canvas.width  = window.innerWidth;
  H = canvas.height = window.innerHeight;
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

class Node {
  constructor() { this.reset(); }
  reset() {
    this.x     = Math.random() * W;
    this.y     = Math.random() * H;
    this.vx    = (Math.random() - 0.5) * 0.3;
    this.vy    = (Math.random() - 0.5) * 0.3;
    this.r     = Math.random() * 1.5 + 0.5;
    this.alpha = Math.random() * 0.5 + 0.1;
  }
  update() {
    this.x += this.vx; this.y += this.vy;
    if (this.x < 0 || this.x > W) this.vx *= -1;
    if (this.y < 0 || this.y > H) this.vy *= -1;
  }
  draw() {
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(0,212,255,${this.alpha})`;
    ctx.fill();
  }
}

for (let i = 0; i < 80; i++) nodes.push(new Node());

function drawEdges() {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
      if (d < 120) {
        ctx.beginPath();
        ctx.moveTo(nodes[i].x, nodes[i].y);
        ctx.lineTo(nodes[j].x, nodes[j].y);
        ctx.strokeStyle = `rgba(0,212,255,${0.08 * (1 - d / 120)})`;
        ctx.lineWidth   = 0.5;
        ctx.stroke();
      }
    }
  }
}

function animateParticles() {
  ctx.clearRect(0, 0, W, H);
  nodes.forEach(n => { n.update(); n.draw(); });
  drawEdges();
  requestAnimationFrame(animateParticles);
}
animateParticles();

// ─────────────────────────────────────────────────────────────────────────────
//  CLOCK
// ─────────────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toTimeString().split(' ')[0];
}
setInterval(updateClock, 1000);
updateClock();

// ─────────────────────────────────────────────────────────────────────────────
//  SOUND
// ─────────────────────────────────────────────────────────────────────────────
function beep(freq = 440, dur = 80, vol = 0.05) {
  try {
    const ac   = new AudioContext();
    const osc  = ac.createOscillator();
    const gain = ac.createGain();
    osc.connect(gain);
    gain.connect(ac.destination);
    osc.frequency.value = freq;
    osc.type            = 'square';
    gain.gain.value     = vol;
    osc.start();
    osc.stop(ac.currentTime + dur / 1000);
  } catch (e) {}
}

// ─────────────────────────────────────────────────────────────────────────────
//  SCAN OPTIONS
// ─────────────────────────────────────────────────────────────────────────────
function toggleOpt(el) {
  document.querySelectorAll('.opt-chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  scanMode = el.dataset.mode || 'full';
}

// ─────────────────────────────────────────────────────────────────────────────
//  PROGRESS LOG
// ─────────────────────────────────────────────────────────────────────────────
function addLog(msg, cls = '') {
  const el  = document.createElement('div');
  el.className  = 'log-line ' + cls;
  el.textContent = msg;
  const log = document.getElementById('progressLog');
  log.appendChild(el);
  if (log.children.length > 6) log.removeChild(log.firstChild);
  log.scrollTop = log.scrollHeight;
}

function setProgress(pct) {
  pct = Math.min(100, Math.max(0, pct));
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressPct').textContent = Math.floor(pct) + '%';
}

// ─────────────────────────────────────────────────────────────────────────────
//  START SCAN
// ─────────────────────────────────────────────────────────────────────────────
function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  if (!target) { showToast('⚠ Введите цель для сканирования'); return; }

  // UI reset
  document.getElementById('progressTarget').textContent = target;
  document.getElementById('progressSection').classList.add('visible');
  document.getElementById('resultsGrid').classList.remove('visible');
  document.getElementById('actionsBar').style.display = 'none';
  document.getElementById('progressLog').innerHTML = '';
  document.getElementById('scanBtn').classList.add('loading');
  document.getElementById('scanBtn').querySelector('span').textContent = 'СКАНИРУЮ...';
  setProgress(0);

  beep(880, 100);
  addLog('[*] Подключение к API...', '');

  // Choose endpoint based on mode
  const endpoint = (scanMode === 'scorecard') ? '/api/scorecard' : '/api/scan';

  fetch(API + endpoint, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ target })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { onScanError(data.error); return; }
    currentScanId = data.scan_id;
    addLog('[✓] Сканирование запущено', 'log-ok');
    beep(660, 80);
    startPolling();
  })
  .catch(err => {
    onScanError('Нет связи с API. Запущен ли app.py?');
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  POLL SCAN STATUS
// ─────────────────────────────────────────────────────────────────────────────
let fakeProgress = 5;

function startPolling() {
  fakeProgress = 5;
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(pollScan, 2500);
}

function pollScan() {
  if (!currentScanId) return;

  fetch(API + '/api/scan/' + currentScanId)
  .then(r => r.json())
  .then(scan => {
    // Show latest log message
    if (scan.log && scan.log.length > 0) {
      const last = scan.log[scan.log.length - 1];
      const cls  = last.includes('[+]') ? 'log-ok'
                 : last.includes('[-]') ? 'log-err'
                 : last.includes('[!]') ? 'log-warn' : '';
      addLog(last, cls);
    }

    // Fake progress increment
    if (scan.status === 'running') {
      fakeProgress = Math.min(fakeProgress + 7, 88);
      setProgress(fakeProgress);
    }

    if (scan.status === 'done') {
      clearInterval(pollInterval);
      setProgress(100);
      addLog('[✓] Сканирование завершено!', 'log-ok');
      beep(660, 200);
      setTimeout(() => beep(880, 200), 200);
      onScanDone(scan.result);
    }

    if (scan.status === 'error') {
      clearInterval(pollInterval);
      addLog('[-] Ошибка сканирования', 'log-err');
      onScanError('Сканирование завершилось с ошибкой');
    }
  })
  .catch(() => {
    addLog('[!] Потеряна связь с API', 'log-warn');
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  SCAN DONE — render results
// ─────────────────────────────────────────────────────────────────────────────
function onScanDone(data) {
  currentReport = data;
  resetScanBtn();

  if (!data) {
    showToast('✓ Готово — данные не получены');
    return;
  }

  // ── Stats row ──
  const ports = data.ports || [];
  const subs  = data.subdomains || [];
  const cves  = countCves(ports);

  document.getElementById('statPorts').textContent = ports.length;
  document.getElementById('statPortsSub').textContent =
    ports.length > 0 ? `↑ tcp:${ports.length}` : '— нет открытых';

  document.getElementById('statCve').textContent = cves.total;
  document.getElementById('statCveSub').textContent =
    cves.critical > 0 ? `⚠ ${cves.critical} CRITICAL ${cves.high} HIGH` : '✓ нет критических';

  document.getElementById('statSubs').textContent = subs.length;
  document.getElementById('statSubsSub').textContent =
    subs.length > 0 ? `✓ ${subs.length} ACTIVE` : '— не найдено';

  // ── Ports table ──
  renderPorts(ports);

  // ── Geo map ──
  renderMap(data);

  // ── Scorecard ──
  if (data.score !== undefined) renderScorecard(data);
  else renderScorecard({ score: 0, grade: '?', cves: [] });

  // ── CVE list ──
  renderCves(ports);

  // ── Subdomains ──
  renderSubdomains(subs);

  // Show grids
  document.getElementById('resultsGrid').classList.add('visible');
  document.getElementById('actionsBar').style.display = 'flex';

  showToast(`✓ Готово! Портов: ${ports.length} | CVE: ${cves.total} | Поддоменов: ${subs.length}`);
}

function onScanError(msg) {
  resetScanBtn();
  addLog('[-] ' + msg, 'log-err');
  showToast('✗ ' + msg);
  beep(220, 300);
}

function resetScanBtn() {
  const btn = document.getElementById('scanBtn');
  btn.classList.remove('loading');
  btn.querySelector('span').textContent = 'СКАНИРОВАТЬ';
}

// ─────────────────────────────────────────────────────────────────────────────
//  RENDERERS
// ─────────────────────────────────────────────────────────────────────────────

function renderPorts(ports) {
  const tbody = document.getElementById('portsBody');
  if (!ports || ports.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--dim);padding:20px">
      Открытых портов не найдено
    </td></tr>`;
    return;
  }
  tbody.innerHTML = ports.map(p => `
    <tr>
      <td class="port-num">${p.port}</td>
      <td>TCP</td>
      <td>${p.service || '—'}</td>
      <td>${p.version || '—'}</td>
      <td class="port-open">ОТКРЫТ</td>
    </tr>
  `).join('');
}

function renderMap(data) {
  const ip      = data.ip || data.target || '—';
  const country = data.country || '—';
  const city    = data.city    || '—';
  const org     = data.isp     || data.org || '—';
  document.getElementById('mapInfo').innerHTML = `
    TARGET: <span>${ip}</span><br>
    COUNTRY: <span>${country} / ${city}</span><br>
    ORG: <span>${org}</span>
  `;
}

function renderScorecard(data) {
  const score = data.score || 0;
  const grade = data.grade || '?';

  // Ring animation
  const circumference = 440;
  const offset = circumference - (score / 100) * circumference;
  const ring = document.getElementById('ringFg');
  ring.style.strokeDashoffset = offset;

  // Color by grade
  const color = grade === 'A+' || grade === 'A' ? '#00ff9d'
              : grade === 'B'                    ? '#00d4ff'
              : grade === 'C'                    ? '#ffd700'
              : '#ff2d6b';
  ring.style.stroke = color;
  ring.style.filter = `drop-shadow(0 0 8px ${color})`;

  document.getElementById('gradeLetter').textContent = grade;
  document.getElementById('gradeLetter').style.color = color;
  document.getElementById('gradeLetter').style.textShadow = `0 0 20px ${color}`;
  document.getElementById('gradeScore').textContent = `${score}/100`;

  // Count CVE severities from recommendations
  const recs  = data.recommendations || [];
  const crit  = recs.filter(r => r.level === 'CRITICAL').length;
  const high  = recs.filter(r => r.level === 'HIGH').length;
  const med   = recs.filter(r => r.level === 'MEDIUM').length;
  const low   = recs.filter(r => r.level === 'LOW').length;

  document.getElementById('legCrit').textContent = crit || '0';
  document.getElementById('legHigh').textContent = high || '0';
  document.getElementById('legMed').textContent  = med  || '0';
  document.getElementById('legLow').textContent  = low  || '0';
}

function renderCves(ports) {
  const list = document.getElementById('cveList');
  const allCves = [];

  (ports || []).forEach(p => {
    if (p.cves) p.cves.forEach(c => allCves.push(c));
  });

  if (allCves.length === 0) {
    list.innerHTML = `<div style="text-align:center;color:var(--neon3);
      padding:20px;font-family:'Share Tech Mono',monospace;font-size:12px">
      ✓ Критических уязвимостей не найдено
    </div>`;
    return;
  }

  list.innerHTML = allCves.slice(0, 8).map(c => {
    const sevClass = c.severity === 'CRITICAL' ? 'c'
                   : c.severity === 'HIGH'     ? 'h'
                   : c.severity === 'MEDIUM'   ? 'm' : 'l';
    return `<div class="cve-item">
      <div class="cve-sev ${sevClass}"></div>
      <div class="cve-info">
        <div class="cve-id">${c.id || c.cve_id || '—'}</div>
        <div class="cve-desc">${c.description || c.desc || '—'}</div>
        <div class="cve-score">CVSS: ${c.cvss || '?'} ${c.severity || ''}</div>
      </div>
    </div>`;
  }).join('');
}

function renderSubdomains(subs) {
  const list = document.getElementById('subList');
  if (!subs || subs.length === 0) {
    list.innerHTML = `<div style="text-align:center;color:var(--dim);
      padding:20px;font-family:'Share Tech Mono',monospace;font-size:12px">
      Поддомены не найдены
    </div>`;
    return;
  }
  list.innerHTML = subs.slice(0, 10).map(s => {
    const parts = s.split('→');
    const name  = (parts[0] || s).trim();
    const ip    = (parts[1] || '').trim();
    return `<div class="subdomain-item">
      <span class="sd-name">${name}</span>
      <span class="sd-ip">${ip}</span>
    </div>`;
  }).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function countCves(ports) {
  let total = 0, critical = 0, high = 0;
  (ports || []).forEach(p => {
    if (p.cves) {
      total    += p.cves.length;
      critical += p.cves.filter(c => c.severity === 'CRITICAL').length;
      high     += p.cves.filter(c => c.severity === 'HIGH').length;
    }
  });
  return { total, critical, high };
}

// ─────────────────────────────────────────────────────────────────────────────
//  TOAST
// ─────────────────────────────────────────────────────────────────────────────
let toastTimer = null;

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  beep(1000, 80);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.style.display = 'none'; }, 4000);
}

// ─────────────────────────────────────────────────────────────────────────────
//  DOWNLOAD REPORT
// ─────────────────────────────────────────────────────────────────────────────
function downloadReport() {
  if (!currentReport) { showToast('⚠ Нет данных для скачивания'); return; }
  const blob = new Blob([JSON.stringify(currentReport, null, 2)],
    { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const name = `phantomscan_${(currentReport.target || 'report').replace(/\./g,'_')}_${Date.now()}.json`;
  a.href     = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`📄 Сохранено: ${name}`);
  beep(440, 150);
}

// ─────────────────────────────────────────────────────────────────────────────
//  RESET SCAN
// ─────────────────────────────────────────────────────────────────────────────
function resetScan() {
  if (pollInterval) clearInterval(pollInterval);
  currentScanId = null;
  currentReport = null;
  document.getElementById('progressSection').classList.remove('visible');
  document.getElementById('resultsGrid').classList.remove('visible');
  document.getElementById('actionsBar').style.display = 'none';
  document.getElementById('targetInput').focus();
  beep(440, 80);
}

// ─────────────────────────────────────────────────────────────────────────────
//  HEALTH CHECK on load
// ─────────────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => {
  fetch(API + '/api/health')
  .then(r => r.json())
  .then(data => {
    if (data.binary_exists) {
      document.getElementById('statusText').textContent = 'API ONLINE';
      showToast('✓ PhantomScan API подключён');
    } else {
      document.getElementById('statusText').textContent = 'BINARY NOT FOUND';
      document.getElementById('statusDot').classList.add('error');
      showToast('⚠ phantomscan binary не найден');
    }
  })
  .catch(() => {
    document.getElementById('statusText').textContent = 'API OFFLINE';
    document.getElementById('statusDot').classList.add('error');
    showToast('⚠ API недоступен — запустите app.py');
  });
});

// Enter key to scan
document.getElementById('targetInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});