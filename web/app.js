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
    this.returning = localStorage.getItem('phantom_intro_seen') === '1';
    this.lineTop = document.getElementById('introLineTop');
    this.lineBot = document.getElementById('introLineBot');
    this.textWrap = document.getElementById('introTextWrap');
    this.phantomEl = document.getElementById('introPhantom');
    this.scanEl = document.getElementById('introScan');
    this.subtitle = document.getElementById('introSubtitle');
    this.initLines = document.getElementById('introInitLines');
    this.glitch = document.getElementById('introGlitch');
    this.scanLine = document.getElementById('introScanLine');
    this.skipBtn = document.getElementById('skipIntro');
    this.particleField = this.el?.querySelector('.particle-field');
    this._done = false;
    if (this.el) {
      this.prepareParticles();
      setTimeout(() => this.run(), 100);
    }
  }

  prepareParticles() {
    if (!this.particleField) return;
    this.particleField.innerHTML = '';
    const count = window.innerWidth <= 768 ? 30 : 60;
    for (let i = 0; i < count; i++) {
      const dot = document.createElement('span');
      dot.className = 'particle';
      dot.style.setProperty('--rx', `${(Math.random() * 2 - 1).toFixed(2)}`);
      dot.style.setProperty('--ry', `${(Math.random() * 2 - 1).toFixed(2)}`);
      dot.style.setProperty('--delay', `${Math.random() * 0.3}s`);
      this.particleField.appendChild(dot);
    }
  }

  _beep(freq, duration, vol = 0.05) {
    if (!this.sound.enabled || !this.sound.ctx) return;
    this.sound._play({ type: 'sine', freq, duration: duration / 1000, vol });
  }

  _tick() {
    this.sound._play({ type: 'square', freq: 1200, duration: 0.02, vol: 0.03 });
  }

  _noiseBurst(duration) {
    if (!this.sound.enabled || !this.sound.ctx) return;
    const ctx = this.sound.ctx;
    const buf = ctx.createBuffer(1, Math.floor(ctx.sampleRate * duration / 1000), ctx.sampleRate);
    const data = buf.getChannelData(0);
    for (let i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
    const src = ctx.createBufferSource();
    src.buffer = buf;
    const gain = ctx.createGain();
    gain.gain.setValueAtTime(0.06, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration / 1000);
    src.connect(gain).connect(ctx.destination);
    src.start();
  }

  _bootChime() {
    if (!this.sound.enabled || !this.sound.ctx) return;
    const notes = [261.63, 329.63, 392.00];
    notes.forEach((f, i) => {
      this.sound._play({ type: 'triangle', freq: f, duration: 0.12, vol: 0.05, delay: i * 0.11 });
    });
  }

  _spawnLetters(text, el, baseDelay, letterDelay) {
    el.innerHTML = '';
    [...text].forEach((ch, i) => {
      const span = document.createElement('span');
      span.className = 'intro-letter';
      span.textContent = ch;
      span.style.animationDelay = `${baseDelay + i * letterDelay}ms`;
      el.appendChild(span);
      setTimeout(() => {
        span.style.animation = `letterDrop 0.45s cubic-bezier(0.34,1.56,0.64,1) forwards`;
        this._tick();
      }, baseDelay + i * letterDelay);
    });
  }

  _triggerGlitch(intense = false) {
    if (!this.glitch) return;
    if (intense) {
      this.textWrap.style.animation = 'glitchShift 0.2s steps(3) 1';
      setTimeout(() => { if (this.textWrap) this.textWrap.style.animation = ''; }, 220);
    }
    this.glitch.classList.add('active');
    setTimeout(() => this.glitch?.classList.remove('active'), 400);
  }

  _typewriterEl(el, text, perChar = 30) {
    return new Promise(resolve => {
      let i = 0;
      el.textContent = '';
      const step = () => {
        el.textContent += text[i++];
        if (i < text.length) setTimeout(step, perChar);
        else resolve();
      };
      setTimeout(step, perChar);
    });
  }

  async _showInitLines() {
    if (!this.initLines) return;
    this.initLines.style.opacity = '1';
    const lines = [
      '[ INITIALIZING SYSTEMS... ]',
      '[ NEURAL LINK ESTABLISHED ]',
      '[ SHADOW NETWORK ONLINE ]',
    ];
    for (const text of lines) {
      const span = document.createElement('span');
      span.className = 'init-line';
      this.initLines.appendChild(span);
      await this._typewriterEl(span, text, 30);
      await new Promise(r => setTimeout(r, 80));
    }
  }

  run() {
    if (!this.el || this._done) return;
    if (this.returning) {
      this.quickFlash();
      return;
    }
    this.el.classList.add('play');
    this.sound.enable();

    // 0.3s — center line grows
    setTimeout(() => {
      this._beep(2000, 50, 0.04);
      if (this.lineTop) { this.lineTop.style.width = '60%'; }
      if (this.lineBot) { this.lineBot.style.width = '60%'; }
    }, 300);

    // 0.8s — lines split apart
    setTimeout(() => {
      if (this.lineTop) this.lineTop.style.transform = 'translateX(-50%) translateY(-40px)';
      if (this.lineBot) this.lineBot.style.transform = 'translateX(-50%) translateY(40px)';
    }, 800);

    // 1.0s — show text wrap, type PHANTOM
    setTimeout(() => {
      if (this.textWrap) this.textWrap.style.opacity = '1';
      this._spawnLetters('PHANTOM', this.phantomEl, 0, 80);
    }, 1000);

    // 1.5s — type SCAN
    setTimeout(() => {
      this._spawnLetters('SCAN', this.scanEl, 0, 80);
    }, 1500);

    // 1.8s — glitch #1
    setTimeout(() => {
      this._noiseBurst(100);
      this._triggerGlitch(false);
    }, 1800);

    // 2.1s — subtitle typewriter
    setTimeout(() => {
      if (this.subtitle) {
        this.subtitle.style.transition = 'opacity 0.3s ease';
        this.subtitle.style.opacity = '1';
        this.subtitle.classList.add('visible');
      }
    }, 2100);

    // 2.5s — glitch #2 (intense)
    setTimeout(() => {
      this._noiseBurst(200);
      this._triggerGlitch(true);
      if (this.particleField) this.particleField.classList.add('burst');
    }, 2500);

    // 2.8s — scan line sweeps
    setTimeout(() => {
      this.sound._play({ type: 'sine', freq: 400, sweep: 800, duration: 0.4, vol: 0.04 });
      if (this.scanLine) {
        this.scanLine.style.opacity = '1';
        this.scanLine.classList.add('sweep');
      }
    }, 2800);

    // 3.2s — init lines
    setTimeout(() => {
      this._showInitLines();
    }, 3200);

    // 3.8s — dissolve non-logo text, move logo to corner
    setTimeout(() => {
      this.sound._play({ type: 'sawtooth', freq: 800, sweep: 200, duration: 0.3, vol: 0.04 });
      if (this.subtitle) { this.subtitle.style.transition = 'opacity 0.4s ease'; this.subtitle.style.opacity = '0'; }
      if (this.initLines) { this.initLines.style.transition = 'opacity 0.4s ease'; this.initLines.style.opacity = '0'; }
      if (this.lineTop) { this.lineTop.style.transition = 'opacity 0.4s ease, width 0.4s ease'; this.lineTop.style.opacity = '0'; }
      if (this.lineBot) { this.lineBot.style.transition = 'opacity 0.4s ease, width 0.4s ease'; this.lineBot.style.opacity = '0'; }
      if (this.textWrap) {
        this.textWrap.style.transition = 'transform 0.6s cubic-bezier(0.4,0,0.2,1), opacity 0.6s ease';
        this.textWrap.querySelectorAll('.intro-letter').forEach(l => {
          l.style.transition = 'font-size 0.6s cubic-bezier(0.4,0,0.2,1)';
          l.style.fontSize = 'clamp(14px, 2vw, 24px)';
          l.style.textShadow = '0 0 14px #7b2fff';
        });
      }
    }, 3800);

    // 4.5s — reveal dashboard
    setTimeout(() => {
      this._bootChime();
      this.revealDashboard();
    }, 4500);

    // 5.0s — finish
    setTimeout(() => this.finish(), 5000);
  }

  quickFlash() {
    if (!this.el || this._done) return;
    this.el.classList.add('play');
    this._triggerGlitch(false);
    setTimeout(() => this.revealDashboard(), 300);
    setTimeout(() => this.finish(), 900);
  }

  revealDashboard() {
    document.body.classList.remove('intro-active');
  }

  finish() {
    if (this._done) return;
    this._done = true;
    localStorage.setItem('phantom_intro_seen', '1');
    document.body.classList.remove('intro-active');
    if (this.el) {
      this.el.classList.add('hidden');
      setTimeout(() => { this.el?.remove(); }, 900);
    }
  }

  skip() {
    this.quickFlash();
  }
}

const modules = [
  { id: '1', name: 'Full Scan', cat: 'recon', desc: 'WHOIS + ports + CVE + subs', inputs: [] },
  { id: '2', name: 'Quick Scan', cat: 'recon', desc: 'Top 1024 ports fast', inputs: [] },
  { id: '3', name: 'Subdomains', cat: 'recon', desc: 'Enumerate subdomains', inputs: [] },
  { id: '4', name: 'Packet Monitor', cat: 'net', desc: 'Monitor packets (lo)', inputs: [{ key: 'interface', label: 'Interface', placeholder: 'lo' }] },
  { id: '5', name: 'ARP Scan', cat: 'net', desc: 'Local subnet discovery', inputs: [{ key: 'subnet', label: 'Subnet', placeholder: '192.168.1.0/24' }] },
  { id: '6', name: 'Traceroute', cat: 'recon', desc: 'Trace network path', inputs: [] },
  { id: '7', name: 'SYN Stealth', cat: 'net', desc: 'Port range stealth scan', inputs: [{ key: 'port_range', label: 'Port range', placeholder: '1-1024' }] },
  { id: '8', name: 'SSL/TLS Analysis', cat: 'vuln', desc: 'TLS posture & certs', inputs: [] },
  { id: '9', name: 'WAF Detection', cat: 'vuln', desc: 'Detect firewalls/WAF', inputs: [] },
  { id: '10', name: 'Vuln Scanner', cat: 'vuln', desc: 'Scan vulnerable versions', inputs: [] },
  { id: '11', name: 'Wordlist Generator', cat: 'osint', desc: 'Generate wordlist', inputs: [] },
  { id: '12', name: 'Shodan Lookup', cat: 'osint', desc: 'API powered lookup', inputs: [{ key: 'api_key', label: 'API Key', placeholder: 'SHODAN-KEY' }] },
  { id: '13', name: 'Exploit Suggester', cat: 'vuln', desc: 'Suggested exploits', inputs: [{ key: 'service', label: 'Service', placeholder: 'ssh/http/...' }] },
  { id: '14', name: 'Network Topology', cat: 'recon', desc: 'Map hops', inputs: [] },
  { id: '15', name: 'UDP Scan', cat: 'net', desc: 'UDP port range', inputs: [{ key: 'port_range', label: 'Port range', placeholder: '1-1024' }] },
  { id: '16', name: 'Change Target', cat: 'recon', desc: 'Update target', inputs: [{ key: 'new_target', label: 'New Target', placeholder: 'host' }] },
  { id: '17', name: 'Scorecard', cat: 'vuln', desc: 'Security grade', inputs: [] },
  { id: '18', name: 'HTTP Dir Scan', cat: 'osint', desc: 'Dir brute force', inputs: [{ key: 'port', label: 'Port', placeholder: '80' }] },
  { id: '19', name: 'DNS Recon', cat: 'recon', desc: 'DNS enum + AXFR', inputs: [] },
  { id: '20', name: 'Multi Scan', cat: 'net', desc: 'File of targets', inputs: [{ key: 'file_path', label: 'File path', placeholder: 'targets.txt' }] },
];

const els = {
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  scanBtn: document.getElementById('scanBtn'),
  stopBtn: document.getElementById('stopScan'),
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
  skipIntro: document.getElementById('skipIntro'),
  rootModeBtn: document.getElementById('rootModeBtn'),
  spaceModal: document.getElementById('spaceModal'),
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
let isCancelling = false;
let lastLiveStats = { ports: 0, cve: 0, subdomains: 0, score: 0 };
let rootMode = false;
let pendingScanExtra = {};

const sound = new SoundEngine();
document.body.classList.add('intro-active');
const intro = new IntroAnimation(sound);

// Custom cursor dot
(() => {
  const dot = document.createElement('div');
  dot.id = 'cursorDot';
  document.body.appendChild(dot);
  let target = { x: window.innerWidth / 2, y: window.innerHeight / 2 };
  window.addEventListener('mousemove', e => { target = { x: e.clientX, y: e.clientY }; });
  function animate() {
    dot.style.transform = `translate3d(${target.x - 6}px, ${target.y - 6}px, 0)`;
    requestAnimationFrame(animate);
  }
  animate();
})();

// Hex grid canvas animation
(() => {
  const canvas = document.getElementById('hexCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H;
  const HEX_SIZE = 32;
  const HEX_W = HEX_SIZE * Math.sqrt(3);
  const HEX_H = HEX_SIZE * 2;
  let t = 0;

  const resize = () => {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  };
  resize();
  window.addEventListener('resize', resize);

  function hexPath(cx, cy, s) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i - Math.PI / 6;
      const x = cx + s * Math.cos(angle);
      const y = cy + s * Math.sin(angle);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.closePath();
  }

  function drawHexGrid(ts) {
    t = ts * 0.0004;
    ctx.clearRect(0, 0, W, H);
    const cols = Math.ceil(W / HEX_W) + 2;
    const rows = Math.ceil(H / (HEX_H * 0.75)) + 2;
    for (let row = -1; row < rows; row++) {
      for (let col = -1; col < cols; col++) {
        const cx = col * HEX_W + (row % 2 === 0 ? 0 : HEX_W * 0.5);
        const cy = row * HEX_H * 0.75;
        const phase = Math.sin(t + col * 0.4 + row * 0.3) * 0.5 + 0.5;
        const alpha = 0.03 + phase * 0.06;
        hexPath(cx, cy, HEX_SIZE - 1);
        ctx.strokeStyle = `rgba(123,47,255,${alpha})`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
        if (phase > 0.92) {
          ctx.fillStyle = `rgba(0,212,255,${(phase - 0.92) * 0.5})`;
          ctx.fill();
        }
      }
    }
    requestAnimationFrame(drawHexGrid);
  }
  requestAnimationFrame(drawHexGrid);
})();

// Cosmic deep space + black hole background
(() => {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, bhX, bhY;
  const isMobile = () => window.innerWidth <= 768;

  const resize = () => {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
    bhX = W * 0.75;
    bhY = H * 0.40;
  };
  resize();
  window.addEventListener('resize', resize);

  // Stars
  const starCount = () => isMobile() ? 100 : 200;
  let stars = [];
  function initStars() {
    stars = [];
    const n = starCount();
    for (let i = 0; i < n; i++) {
      stars.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: Math.random() * 1.5 + 0.5,
        vx: (Math.random() - 0.5) * 0.03,
        vy: (Math.random() - 0.5) * 0.03,
        twinkleSpeed: Math.random() * 0.02 + 0.005,
        twinklePhase: Math.random() * Math.PI * 2,
        baseBrightness: Math.random() * 0.5 + 0.5,
      });
    }
  }
  initStars();
  window.addEventListener('resize', initStars);

  // Shooting star state
  let shootingStar = null;
  let nextShoot = Date.now() + 5000 + Math.random() * 10000;

  // Hawking radiation particles
  const hwParticles = [];
  function spawnHawking() {
    const angle = Math.random() * Math.PI * 2;
    const speed = 0.5 + Math.random() * 1.5;
    hwParticles.push({
      x: bhX + Math.cos(angle) * 42,
      y: bhY + Math.sin(angle) * 42,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      life: 1,
      r: Math.random() * 1.5 + 0.5,
    });
  }

  // Accretion disk rotation
  let diskAngle = 0;

  let animId = null;

  function drawNebula() {
    // Top-left nebula
    const g1 = ctx.createRadialGradient(0, 0, 0, 0, 0, W * 0.5);
    g1.addColorStop(0, 'rgba(60,0,120,0.08)');
    g1.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g1;
    ctx.fillRect(0, 0, W, H);
    // Bottom-right nebula
    const g2 = ctx.createRadialGradient(W, H, 0, W, H, W * 0.5);
    g2.addColorStop(0, 'rgba(0,30,80,0.07)');
    g2.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g2;
    ctx.fillRect(0, 0, W, H);
  }

  function drawPulsarRings(t) {
    const cx = W * 0.3, cy = H * 0.6;
    for (let i = 0; i < 3; i++) {
      const phase = (t * 0.0003 + i * 0.33) % 1;
      const radius = phase * 120;
      const alpha = (1 - phase) * 0.08;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(123,47,255,${alpha})`;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  }

  function drawStars(t) {
    stars.forEach(s => {
      // Gravitational lensing: stars near BH curve toward it
      const dx = bhX - s.x, dy = bhY - s.y;
      const dist = Math.hypot(dx, dy) || 1;
      if (dist < 200) {
        const pull = (200 - dist) / 200 * 0.08;
        s.x += (dx / dist) * pull;
        s.y += (dy / dist) * pull;
      }
      s.x += s.vx;
      s.y += s.vy;
      if (s.x < 0) s.x = W;
      if (s.x > W) s.x = 0;
      if (s.y < 0) s.y = H;
      if (s.y > H) s.y = 0;

      s.twinklePhase += s.twinkleSpeed;
      const brightness = s.baseBrightness * (0.65 + 0.35 * Math.sin(s.twinklePhase));
      const alpha = 0.3 + 0.7 * brightness;
      // Don't draw stars inside the BH
      const bhdx = bhX - s.x, bhdy = bhY - s.y;
      if (Math.hypot(bhdx, bhdy) < 44) return;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(255,255,255,${alpha})`;
      ctx.fill();
    });
  }

  function drawShootingStar(t) {
    if (Date.now() > nextShoot && !shootingStar) {
      const sx = Math.random() * W * 0.5;
      const sy = Math.random() * H * 0.3;
      shootingStar = { x: sx, y: sy, life: 1, speed: 8 + Math.random() * 6, angle: Math.PI / 4 + (Math.random() - 0.5) * 0.4 };
      nextShoot = Date.now() + 5000 + Math.random() * 10000;
    }
    if (shootingStar) {
      const s = shootingStar;
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      const tx = s.x - Math.cos(s.angle) * 60 * s.life;
      const ty = s.y - Math.sin(s.angle) * 60 * s.life;
      ctx.lineTo(tx, ty);
      const grad = ctx.createLinearGradient(tx, ty, s.x, s.y);
      grad.addColorStop(0, 'rgba(255,255,255,0)');
      grad.addColorStop(1, `rgba(255,255,255,${s.life * 0.9})`);
      ctx.strokeStyle = grad;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      s.x += Math.cos(s.angle) * s.speed;
      s.y += Math.sin(s.angle) * s.speed;
      s.life -= 0.025;
      if (s.life <= 0 || s.x > W || s.y > H) shootingStar = null;
    }
  }

  function drawBlackHole(t) {
    // Shadow around BH
    const shadow = ctx.createRadialGradient(bhX, bhY, 40, bhX, bhY, 160);
    shadow.addColorStop(0, 'rgba(0,0,0,0.9)');
    shadow.addColorStop(0.4, 'rgba(0,0,5,0.5)');
    shadow.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = shadow;
    ctx.beginPath();
    ctx.arc(bhX, bhY, 160, 0, Math.PI * 2);
    ctx.fill();

    // Accretion disk (ellipse, rotates)
    if (!isMobile()) {
      ctx.save();
      ctx.translate(bhX, bhY);
      ctx.rotate(diskAngle);
      for (let layer = 0; layer < 3; layer++) {
        const rx = 90 - layer * 10;
        const ry = 18 - layer * 4;
        const alpha = 0.18 - layer * 0.04;
        const innerColor = layer === 0 ? `rgba(255,220,150,${alpha})` : `rgba(255,100,50,${alpha * 0.6})`;
        const outerColor = `rgba(180,40,0,0)`;
        const diskGrad = ctx.createRadialGradient(0, 0, rx * 0.3, 0, 0, rx);
        diskGrad.addColorStop(0, innerColor);
        diskGrad.addColorStop(1, outerColor);
        ctx.beginPath();
        ctx.ellipse(0, 0, rx, ry, 0, 0, Math.PI * 2);
        ctx.fillStyle = diskGrad;
        ctx.fill();
      }
      ctx.restore();
      diskAngle += (Math.PI * 2) / (8 * 60); // 360deg / 8s at 60fps
    }

    // Event horizon ring
    ctx.beginPath();
    ctx.arc(bhX, bhY, 43, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(180,100,255,0.6)';
    ctx.lineWidth = 2.5;
    ctx.shadowColor = 'rgba(150,50,255,0.9)';
    ctx.shadowBlur = 18;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Black circle (the hole)
    ctx.beginPath();
    ctx.arc(bhX, bhY, 40, 0, Math.PI * 2);
    ctx.fillStyle = '#000005';
    ctx.fill();

    // Hawking radiation
    if (Math.random() < 0.08) spawnHawking();
    for (let i = hwParticles.length - 1; i >= 0; i--) {
      const p = hwParticles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.life -= 0.018;
      if (p.life <= 0) { hwParticles.splice(i, 1); continue; }
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * p.life, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(200,150,255,${p.life * 0.7})`;
      ctx.fill();
    }
  }

  function draw(t) {
    // Deep space background
    ctx.fillStyle = '#000005';
    ctx.fillRect(0, 0, W, H);
    drawNebula();
    drawPulsarRings(t);
    drawStars(t);
    drawShootingStar(t);
    drawBlackHole(t);
    animId = requestAnimationFrame(draw);
  }

  animId = requestAnimationFrame(draw);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (animId) { cancelAnimationFrame(animId); animId = null; }
    } else {
      if (!animId) animId = requestAnimationFrame(draw);
    }
  });
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

function updateLiveStats(stats) {
  if (!stats) return;
  lastLiveStats = {
    ports: stats.ports ?? 0,
    cve: stats.cve ?? 0,
    subdomains: stats.subdomains ?? 0,
    score: stats.score ?? 0,
  };
  animateNumber(els.statPorts, lastLiveStats.ports);
  animateNumber(els.statCve, lastLiveStats.cve);
  animateNumber(els.statSubs, lastLiveStats.subdomains);
  animateNumber(els.statScore, lastLiveStats.score);
}

function toggleStop(show) {
  if (!els.stopBtn) return;
  els.stopBtn.classList.toggle('visible', !!show);
  els.stopBtn.disabled = !show;
}

function handleCancelled() {
  renderLog('[-] Сканирование остановлено', 'log-warn');
  stopTimers();
  updateProgress(0, 'Остановлено');
  if (els.currentAction) els.currentAction.textContent = 'Остановлено';
  if (els.scanBtn) els.scanBtn.disabled = false;
  toggleStop(false);
  updateLiveStats({ ports: 0, cve: 0, subdomains: 0, score: 0 });
  currentScanId = null;
}

function classifyLog(text) {
  if (/^\[\+\]|✓/.test(text)) return 'log-ok';
  if (/^\[-\]|✗/.test(text)) return 'log-err';
  if (/^\[\!\]|⚠/.test(text)) return 'log-warn';
  return 'log-info';
}

function typewriter(el, text, speed = 15) {
  let idx = 0;
  let last = 0;
  const step = ts => {
    if (!last || ts - last >= speed) {
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
  // Auto-scroll to bottom
  els.logList.scrollTop = els.logList.scrollHeight;
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
  socket.on('stats_update', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    if ((payload.ports ?? 0) > lastLiveStats.ports) sound.portFound();
    updateLiveStats(payload);
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
    toggleStop(false);
  });
  socket.on('scan_complete', payload => {
    console.log('[socket] scan_complete', payload);
    if (!payload || payload.scan_id !== currentScanId) return;
    lastSocketEvent = Date.now();
    finalizeScan(payload.result, payload.stats);
  });
  socket.on('scan_cancelled', payload => {
    if (!payload || payload.scan_id !== currentScanId) return;
    handleCancelled();
  });
}

function handleLog(line, pct, action) {
  renderLog(line);
  const derived = progressFromLog(line);
  const progress = Math.max(pct || 0, derived.pct);
  const label = action || derived.action || 'Сканирование';
  updateProgress(progress, label);
  if (els.currentAction) els.currentAction.textContent = label;
  if (/critical/i.test(line)) flashCritical();
  else if (/cve/i.test(line)) sound.criticalCVE();
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

function finalizeScan(result, liveStats) {
  updateProgress(100, 'Готово');
  if (els.currentAction) els.currentAction.textContent = 'Готово';
  stopTimers();
  sound.scanComplete();
  if (els.scanBtn) els.scanBtn.disabled = false;
  toggleStop(false);
  if (result) {
    if (liveStats) {
      result.live_stats = liveStats;
    } else if (lastLiveStats) {
      result.live_stats = lastLiveStats;
    }
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
    if (data.stats) updateLiveStats(data.stats);
    handleStatus(data.progress || 0, data.current_action || data.status);
    if (data.status === 'done') {
      finalizeScan(data.result, data.stats);
    } else if (data.status === 'cancelled') {
      handleCancelled();
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
function collectCves(data) {
  // CVEs live at the top-level data.cve (array from report.cpp) or fallback
  const cves = Array.isArray(data.cve) ? data.cve
             : Array.isArray(data.cve_findings) ? data.cve_findings
             : [];
  const total = cves.length;
  const critical = cves.filter(c => (c.severity || '').toUpperCase() === 'CRITICAL').length;
  return { total, critical };
}

function renderStats(data) {
  const live = data.live_stats || {};
  const portsVal = live.ports ?? (data.ports || []).length;
  const subsVal = live.subdomains ?? (data.subdomains || []).length;
  const cveVal = live.cve ?? collectCves(data).total;
  const scoreVal = live.score ?? (data.score || 0);
  animateNumber(els.statPorts, portsVal);
  animateNumber(els.statSubs, subsVal);
  animateNumber(els.statCve, cveVal);
  animateNumber(els.statScore, scoreVal);
}

function renderPorts(ports) {
  if (!els.portsBody) return;
  const body = els.portsBody;
  if (!ports.length) {
    body.innerHTML = '<tr><td colspan="5" style="color:var(--muted)">Нет открытых портов</td></tr>';
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
    const c = collectCves(data);
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
    if (rows.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'history-empty';
      empty.textContent = 'No scans yet';
      els.historyGrid.appendChild(empty);
      return;
    }
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
    const num = String(mod.id).padStart(2, '0');
    const needsInput = mod.inputs.length > 0;
    const card = document.createElement('div');
    card.className = 'module-card';
    card.innerHTML = `
      <div class="module-num">${num}</div>
      <div class="module-title">${mod.name.toUpperCase()}</div>
      <div class="module-desc">${mod.desc}</div>
      <div class="module-badge ${needsInput ? 'badge-input' : 'badge-auto'}">${needsInput ? 'INPUT' : 'AUTO'}</div>
    `;
    card.addEventListener('click', () => onModuleSelected(mod, card));
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
  pendingScanExtra = extra;
  const target = (els.targetInput?.value || '').trim();
  if (!target) { toast('Введите цель'); return; }
  if (els.scanBtn) els.scanBtn.disabled = true;
  isCancelling = false;
  updateLiveStats({ ports: 0, cve: 0, subdomains: 0, score: 0 });
  toggleStop(true);
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

  const body = { target, module: selectedModuleId, extra, root: rootMode };
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
    toggleStop(false);
  }
}

// Health check
async function healthCheck() {
  try {
    const res = await fetch(`${API}/api/health`);
    const data = await res.json();
    setStatus(data.binary_exists, data.binary_exists ? 'API ONLINE' : 'BINARY MISSING');
    if (data.setup_required) {
      showSetupBanner(data);
    } else {
      hideSetupBanner();
    }
    if (data.sudo_ok || data.caps_ok) {
      if (els.rootModeBtn && !els.rootModeBtn.classList.contains('root-active')) {
        els.rootModeBtn.textContent = 'ROOT READY';
      }
    } else {
      if (els.rootModeBtn && !els.rootModeBtn.classList.contains('root-active')) {
        els.rootModeBtn.textContent = 'USER MODE';
      }
    }
  } catch (e) {
    setStatus(false, 'API OFFLINE');
  }
}

function showSetupBanner(data) {
  const dismissed = localStorage.getItem('phantom_setup_dismissed') === '1';
  if (dismissed) return;
  const banner = document.getElementById('setupBanner');
  if (!banner) return;
  banner.style.display = 'flex';
  // Validate that setup_commands is a non-empty array before using it
  const cmds = Array.isArray(data?.setup_commands) ? data.setup_commands : [];
  const rawCmd = typeof cmds[0] === 'string' ? cmds[0] : '';
  // Sanitize: allow only alphanumeric, spaces, slashes, dots, underscores, hyphens, equals, commas, and +
  const safeCmd = rawCmd.replace(/[^a-zA-Z0-9 /._\-=,+]/g, '');
  const cmdEl = document.getElementById('setupBannerCmd');
  if (cmdEl) cmdEl.textContent = safeCmd || 'sudo setcap cap_net_raw,cap_net_admin+eip ./phantomscan';
}

function hideSetupBanner() {
  const banner = document.getElementById('setupBanner');
  if (banner) banner.style.display = 'none';
}

function setRootMode(enabled) {
  rootMode = enabled;
  if (!els.rootModeBtn) return;
  if (enabled) {
    els.rootModeBtn.textContent = 'ROOT MODE';
    els.rootModeBtn.classList.add('root-active');
  } else {
    els.rootModeBtn.textContent = 'USER MODE';
    els.rootModeBtn.classList.remove('root-active');
  }
}

// Ripple effect
function addRipple(btn) {
  btn.addEventListener('click', e => {
    const r = document.createElement('span');
    r.className = 'ripple';
    const rect = btn.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    r.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - rect.left - size / 2}px;top:${e.clientY - rect.top - size / 2}px;position:absolute;border-radius:50%;background:rgba(123,47,255,0.35);transform:scale(0);animation:rippleAnim 0.6s linear;pointer-events:none;`;
    btn.style.position = btn.style.position || 'relative';
    btn.style.overflow = 'hidden';
    btn.appendChild(r);
    r.addEventListener('animationend', () => r.remove());
  });
}

if (!document.getElementById('ripple-style')) {
  const s = document.createElement('style');
  s.id = 'ripple-style';
  s.textContent = '@keyframes rippleAnim{to{transform:scale(2.5);opacity:0}}';
  document.head.appendChild(s);
}

document.querySelectorAll('button').forEach(addRipple);

// Glitch timer
setInterval(() => {
  document.body.classList.add('glitch-active');
  setTimeout(() => document.body.classList.remove('glitch-active'), 200);
}, 30000 + Math.random() * 30000);

// flashCritical
function flashCritical() {
  document.body.classList.add('critical-flash');
  setTimeout(() => document.body.classList.remove('critical-flash'), 1000);
  sound.criticalCVE();
}

// ─── Deep Space Modal ────────────────────────────────────────────────────────
class SpaceScene {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.animId = null;
    this.stars = [];
    this.diskAngle = 0;
    this.galaxyAngle = 0;
    this.hwParticles = [];
    this.explodeParticles = [];
    this.soundOn = false;
    this.ambienceNode = null;

    // 10-comet pool
    this.comets = [];
    for (let i = 0; i < 10; i++) this.comets.push(this._makeComet(true));

    this.resize();
    this.initStars();

    this.canvas.addEventListener('click', e => this._explode(e.offsetX, e.offsetY));
  }

  _makeComet(offscreen = false) {
    const W = this.W || window.innerWidth;
    const H = this.H || window.innerHeight;
    return {
      active: !offscreen,
      x: offscreen ? -200 : -20,
      y: offscreen ? -200 : Math.random() * H * 0.4,
      vx: 9 + Math.random() * 7,
      vy: 2 + Math.random() * 3,
      life: offscreen ? 0 : 1,
      len: 80 + Math.random() * 60,
      nextSpawn: Date.now() + Math.random() * 8000,
    };
  }

  resize() {
    this.W = this.canvas.width = this.canvas.offsetWidth || window.innerWidth;
    this.H = this.canvas.height = this.canvas.offsetHeight || window.innerHeight;
    this.bhX = this.W * 0.5;
    this.bhY = this.H * 0.45;
    this.galX = this.W * 0.75;
    this.galY = this.H * 0.40;
  }

  initStars() {
    this.stars = [];
    const n = Math.min(350, Math.floor(this.W * this.H / 7000));
    for (let i = 0; i < n; i++) {
      this.stars.push({
        x: Math.random() * this.W,
        y: Math.random() * this.H,
        r: Math.random() * 1.5 + 0.3,
        twinkleSpeed: Math.random() * 0.025 + 0.005,
        twinklePhase: Math.random() * Math.PI * 2,
        baseBrightness: Math.random() * 0.6 + 0.4,
        vx: (Math.random() - 0.5) * 0.02,
        vy: (Math.random() - 0.5) * 0.02,
      });
    }
  }

  spawnHawking() {
    const angle = Math.random() * Math.PI * 2;
    const speed = 0.6 + Math.random() * 1.8;
    this.hwParticles.push({
      x: this.bhX + Math.cos(angle) * 75,
      y: this.bhY + Math.sin(angle) * 75,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      life: 1,
      r: Math.random() * 1.5 + 0.5,
    });
  }

  _explode(cx, cy) {
    for (let i = 0; i < 40; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 1 + Math.random() * 5;
      this.explodeParticles.push({
        x: cx, y: cy,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        life: 1,
        r: Math.random() * 3 + 1,
        color: `hsl(${Math.floor(Math.random() * 60 + 260)},100%,70%)`,
      });
    }
  }

  toggleSound(sc) {
    this.soundOn = !this.soundOn;
    if (this.soundOn) {
      sc.enable();
      if (!this.ambienceNode && sc.ctx) {
        const osc = sc.ctx.createOscillator();
        const gain = sc.ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(55, sc.ctx.currentTime);
        gain.gain.setValueAtTime(0.015, sc.ctx.currentTime);
        osc.connect(gain).connect(sc.ctx.destination);
        osc.start();
        this.ambienceNode = { osc, gain };
      }
    } else if (this.ambienceNode && sc.ctx) {
      this.ambienceNode.gain.gain.exponentialRampToValueAtTime(0.0001, sc.ctx.currentTime + 0.5);
      this.ambienceNode.osc.stop(sc.ctx.currentTime + 0.6);
      this.ambienceNode = null;
    }
  }

  _drawGalaxy(ctx) {
    const { galX, galY, galaxyAngle } = this;
    ctx.save();
    ctx.translate(galX, galY);
    ctx.rotate(galaxyAngle);

    // Core glow
    const coreGrad = ctx.createRadialGradient(0, 0, 0, 0, 0, 28);
    coreGrad.addColorStop(0, 'rgba(255,240,200,0.35)');
    coreGrad.addColorStop(0.5, 'rgba(180,100,255,0.12)');
    coreGrad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = coreGrad;
    ctx.beginPath(); ctx.arc(0, 0, 28, 0, Math.PI * 2); ctx.fill();

    // Spiral arms
    for (let arm = 0; arm < 2; arm++) {
      const armOff = arm * Math.PI;
      ctx.beginPath();
      for (let t = 0; t <= 1; t += 0.01) {
        const r = t * 90;
        const theta = armOff + t * Math.PI * 3;
        const x = r * Math.cos(theta);
        const y = r * Math.sin(theta) * 0.45;
        if (t === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = `rgba(180,100,255,0.12)`;
      ctx.lineWidth = 6;
      ctx.stroke();
      ctx.strokeStyle = `rgba(100,180,255,0.08)`;
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    ctx.restore();
    this.galaxyAngle += 0.0002;
  }

  draw() {
    const { ctx, W, H, bhX, bhY } = this;
    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, W, H);

    // Nebula
    const g1 = ctx.createRadialGradient(0, 0, 0, 0, 0, W * 0.6);
    g1.addColorStop(0, 'rgba(60,0,120,0.14)');
    g1.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g1; ctx.fillRect(0, 0, W, H);
    const g2 = ctx.createRadialGradient(W, H, 0, W, H, W * 0.5);
    g2.addColorStop(0, 'rgba(0,30,80,0.1)');
    g2.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g2; ctx.fillRect(0, 0, W, H);

    // Galaxy
    this._drawGalaxy(ctx);

    // Stars with gravitational lensing
    this.stars.forEach(s => {
      s.twinklePhase += s.twinkleSpeed;
      const brightness = s.baseBrightness * (0.6 + 0.4 * Math.sin(s.twinklePhase));
      const dx = bhX - s.x, dy = bhY - s.y;
      const dist = Math.hypot(dx, dy) || 1;
      // Gravitational lensing: pull stars near BH
      if (dist < 220) {
        const pull = (220 - dist) / 220 * 0.06;
        s.x += (dx / dist) * pull;
        s.y += (dy / dist) * pull;
      }
      s.x += s.vx; s.y += s.vy;
      if (s.x < 0) s.x = W; if (s.x > W) s.x = 0;
      if (s.y < 0) s.y = H; if (s.y > H) s.y = 0;
      if (Math.hypot(bhX - s.x, bhY - s.y) < 72) return;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(255,255,255,${0.3 + 0.7 * brightness})`;
      ctx.fill();
    });

    // Comets pool (10 slots)
    const now = Date.now();
    this.comets.forEach(c => {
      if (!c.active) {
        if (now >= c.nextSpawn) {
          c.x = -20;
          c.y = Math.random() * H * 0.4;
          c.vx = 9 + Math.random() * 7;
          c.vy = 2 + Math.random() * 3;
          c.life = 1;
          c.len = 80 + Math.random() * 60;
          c.active = true;
        }
        return;
      }
      const speed = Math.hypot(c.vx, c.vy) || 1;
      ctx.beginPath();
      ctx.moveTo(c.x, c.y);
      ctx.lineTo(c.x - (c.vx / speed) * c.len * c.life, c.y - (c.vy / speed) * c.len * c.life);
      const grad = ctx.createLinearGradient(
        c.x - (c.vx / speed) * c.len, c.y - (c.vy / speed) * c.len, c.x, c.y);
      grad.addColorStop(0, 'rgba(255,255,255,0)');
      grad.addColorStop(1, `rgba(200,180,255,${c.life * 0.9})`);
      ctx.strokeStyle = grad;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      c.x += c.vx; c.y += c.vy; c.life -= 0.012;
      if (c.life <= 0 || c.x > W + 100) {
        c.active = false;
        c.nextSpawn = Date.now() + 2000 + Math.random() * 8000;
      }
    });

    // Black hole shadow
    const shadow = ctx.createRadialGradient(bhX, bhY, 66, bhX, bhY, 200);
    shadow.addColorStop(0, 'rgba(0,0,0,0.97)');
    shadow.addColorStop(0.35, 'rgba(0,0,10,0.6)');
    shadow.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = shadow;
    ctx.beginPath(); ctx.arc(bhX, bhY, 200, 0, Math.PI * 2); ctx.fill();

    // Accretion disk (3 bright layers)
    ctx.save();
    ctx.translate(bhX, bhY);
    ctx.rotate(this.diskAngle);
    for (let layer = 0; layer < 3; layer++) {
      const rx = 110 - layer * 14;
      const ry = 22 - layer * 4;
      const alpha = 0.55 - layer * 0.12;
      const innerColor = layer === 0
        ? `rgba(255,230,160,${alpha})`
        : layer === 1 ? `rgba(255,140,60,${alpha * 0.8})` : `rgba(220,80,20,${alpha * 0.6})`;
      const diskGrad = ctx.createRadialGradient(0, 0, rx * 0.25, 0, 0, rx);
      diskGrad.addColorStop(0, innerColor);
      diskGrad.addColorStop(0.7, `rgba(200,60,0,${alpha * 0.3})`);
      diskGrad.addColorStop(1, 'rgba(180,40,0,0)');
      ctx.beginPath();
      ctx.ellipse(0, 0, rx, ry, 0, 0, Math.PI * 2);
      ctx.fillStyle = diskGrad;
      ctx.fill();
    }
    ctx.restore();
    this.diskAngle += (Math.PI * 2) / (8 * 60);

    // Event horizon ring
    ctx.beginPath();
    ctx.arc(bhX, bhY, 73, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(180,100,255,0.7)';
    ctx.lineWidth = 3;
    ctx.shadowColor = 'rgba(150,50,255,1)';
    ctx.shadowBlur = 24;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Black hole core (radius 70px)
    ctx.beginPath();
    ctx.arc(bhX, bhY, 70, 0, Math.PI * 2);
    ctx.fillStyle = '#000000';
    ctx.fill();

    // Hawking radiation
    if (Math.random() < 0.1) this.spawnHawking();
    for (let i = this.hwParticles.length - 1; i >= 0; i--) {
      const p = this.hwParticles[i];
      p.x += p.vx; p.y += p.vy; p.life -= 0.018;
      if (p.life <= 0) { this.hwParticles.splice(i, 1); continue; }
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * p.life, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(200,150,255,${p.life * 0.7})`;
      ctx.fill();
    }

    // Click explosion particles
    for (let i = this.explodeParticles.length - 1; i >= 0; i--) {
      const p = this.explodeParticles[i];
      p.x += p.vx; p.y += p.vy;
      p.vx *= 0.96; p.vy *= 0.96;
      p.life -= 0.022;
      if (p.life <= 0) { this.explodeParticles.splice(i, 1); continue; }
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * p.life, 0, Math.PI * 2);
      ctx.fillStyle = p.color.replace(')', `,${p.life})`).replace('hsl', 'hsla');
      ctx.fill();
    }

    this.animId = requestAnimationFrame(() => this.draw());
  }

  start() {
    if (!this.animId) this.draw();
  }

  stop() {
    if (this.animId) { cancelAnimationFrame(this.animId); this.animId = null; }
    if (this.ambienceNode) {
      try {
        this.ambienceNode.osc.stop();
      } catch (_) {}
      this.ambienceNode = null;
    }
  }
}

let spaceScene = null;

function openSpaceModal() {
  const modal = document.getElementById('spaceModal');
  if (!modal) return;
  modal.style.display = 'flex';
  requestAnimationFrame(() => modal.classList.add('visible'));
  const canvas = document.getElementById('spaceCanvas');
  if (canvas) {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    if (spaceScene) spaceScene.stop();
    spaceScene = new SpaceScene(canvas);
    spaceScene.start();
  }
}

function closeSpaceModal() {
  const modal = document.getElementById('spaceModal');
  if (!modal) return;
  modal.classList.remove('visible');
  setTimeout(() => { modal.style.display = 'none'; }, 300);
  if (spaceScene) { spaceScene.stop(); spaceScene = null; }
}

// ESC closes modals
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeSpaceModal();
    if (els.modal) els.modal.classList.remove('show');
  }
});

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
els.stopBtn?.addEventListener('click', async () => {
  if (!currentScanId || isCancelling) return;
  isCancelling = true;
  els.stopBtn.disabled = true;
  try {
    await fetch(`${API}/api/scan/${encodeURIComponent(currentScanId)}`, { method: 'DELETE' });
  } catch (err) {
    console.warn('cancel error', err);
  }
});

els.skipIntro?.addEventListener('click', () => {
  if (intro) intro.skip();
});

if (els.rootModeBtn) {
  els.rootModeBtn.addEventListener('click', () => {
    setRootMode(!rootMode);
    sound.enable();
    sound.buttonHover();
  });
}

if (els.ambientToggle) {
  els.ambientToggle.addEventListener('click', () => {
    ambientOn = !ambientOn;
    sound.enable();
    sound.toggleAmbience(ambientOn);
    els.ambientToggle.textContent = ambientOn ? '🔊' : '🔇';
  });
}

// Space modal events
document.getElementById('spaceBtn')?.addEventListener('click', openSpaceModal);
document.getElementById('spaceModalClose')?.addEventListener('click', closeSpaceModal);
document.getElementById('spaceSoundBtn')?.addEventListener('click', () => {
  if (spaceScene) {
    spaceScene.toggleSound(sound);
    const btn = document.getElementById('spaceSoundBtn');
    if (btn) btn.textContent = spaceScene.soundOn ? '🔊 SOUND' : '🔇 SOUND';
  }
});
els.spaceModal?.addEventListener('click', e => { if (e.target === els.spaceModal) closeSpaceModal(); });

// Setup banner
document.getElementById('setupBannerClose')?.addEventListener('click', () => {
  localStorage.setItem('phantom_setup_dismissed', '1');
  hideSetupBanner();
});
document.getElementById('setupBannerCopy')?.addEventListener('click', () => {
  const cmd = document.getElementById('setupBannerCmd')?.textContent || '';
  navigator.clipboard?.writeText(cmd).then(() => toast('Command copied!')).catch(() => toast(cmd));
});

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
