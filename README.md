# PhantomScan v1.2.0 — Shadow Monarch Edition



---

## What is PhantomScan?

PhantomScan is a modular network reconnaissance and vulnerability
analysis framework. It combines a high-performance C++17 scanning
engine with a cinematic glassmorphism web dashboard.

Run 20 specialized modules directly from the terminal or control
everything through a live web interface with WebSocket streaming,
real-time logs, interactive maps, and a Security Scorecard.

---

## Features

- **20 scanning modules** — ports, subdomains, CVE, SSL/TLS, WAF,
  ARP, traceroute, DNS recon, exploit suggestions, and more
- **Security Scorecard** — 0–100 score with A+/F grade (flagship module)
- **Live web dashboard** — glassmorphism UI with WebSocket streaming
- **Space Modal** — cinematic 3D galaxy + black hole canvas animation
- **Multi-format reports** — TXT / JSON / HTML saved per scan
- **Parallel scanning** — C++17 thread pool, std::async
- **Geolocation** — real-time IP geo via ip-api.com

---

## All 20 Modules

| # | Module | Description | Sudo |
|---|--------|-------------|:----:|
| 1 | Full Scan | WHOIS, OS detection, ports 1–1024, CVE, subdomains, report | — |
| 2 | Quick Scan | Fast top-1024 port scan | — |
| 3 | Subdomains | 132 subdomain variant enumeration | — |
| 4 | Packet Monitor | Live packet capture via libpcap | ✓ |
| 5 | ARP Scan | LAN host discovery (192.168.1.0/24) | ✓ |
| 6 | Traceroute | Route tracing to target | — |
| 7 | SYN Stealth | Stealth SYN scan via raw socket | ✓ |
| 8 | SSL/TLS Analysis | Certificates, TLS versions, cipher suites | — |
| 9 | WAF Detection | Web Application Firewall fingerprinting | — |
| 10 | Vuln Scanner | Vulnerable service version detection | — |
| 11 | Wordlist Gen | HTTP directory wordlist generation | — |
| 12 | Shodan Lookup | Shodan API integration (API key required) | — |
| 13 | Exploit Suggester | CVE exploits by service (ssh/http/ftp...) | — |
| 14 | Network Topology | Visual hop map via traceroute | — |
| 15 | UDP Scan | UDP port range scan | ✓ |
| 16 | Change Target | Switch active scan target | — |
| 17 | Scorecard | Security grade 0–100 across 6 categories | — |
| 18 | HTTP Dir Scan | Directory bruteforce (port 80/443) | — |
| 19 | DNS Recon | DNS enumeration + AXFR zone transfer | — |
| 20 | Multi Scan | Parallel scan from targets file | — |

---

## Security Scorecard (Module 17)

PhantomScan's flagship module grades any target from 0 to 100
across 6 security categories:

| Category | Max Deduction | Details |
|----------|:-------------:|---------|
| CVE Vulnerabilities | −40 pts | CVSS 9.0+ = −15 per CVE |
| Dangerous Open Ports | −20 pts | Telnet −15, FTP −10, RDP −8 |
| DNS Configuration | −20 pts | SPF, DMARC, DNSSEC, CAA, DKIM, MX |
| TLS/SSL | −15 pts | TLS 1.0/1.1, self-signed cert |
| HTTP Security Headers | −10 pts | CSP, HSTS, X-Frame-Options |
| Firewall | ±5 pts | +5 detected / −5 not detected |

**Grades:** `A+` 90–100 · `A` 80–89 · `B` 70–79 · `C` 60–69 · `D` 50–59 · `F` 0–49

---
## 📂 Структура проекта

```text
PhantomScan/
├── src/
│   ├── core/           # C++17 движок сканирования
│   └── modules/        # 20 модулей (Network, OS, Port, etc.)
├── include/            # Заголовочные файлы (.h, .hpp)
├── web/
│   ├── app.py          # Flask API + WebSocket сервер
│   ├── app.js          # Логика фронтенда (Socket.io)
│   ├── index.html      # Интерфейс (Glassmorphism UI)
│   └── style.css       # Стили Shadow Monarch
├── report/             # TXT / JSON / HTML отчёты
├── logs/               # Журналы сканирований
└── Makefile            # Сборка проекта


**Stack:**
- Core: C++17 · libpcap · pthread · resolv
- Web: Python Flask · flask-socketio · pty streaming
- UI: Glassmorphism · WebSocket · Leaflet.js · Canvas 3D

---

## Requirements

- Linux (Parrot OS / Kali / Ubuntu 22.04+)
- g++ with C++17 support
- `libpcap-dev`
- Python 3.10+
- pip: `flask` `flask-socketio`

---

## Installation
```bash
git clone https://github.com/HxOpSec/phantomscan
cd phantomscan
sudo apt install libpcap-dev build-essential
pip3 install flask flask-socketio
make rebuild
```

---

## Usage

### Terminal mode
```bash
sudo ./builds/phantomscan
```

### Web Dashboard
```bash
cd web && python3 app.py
# Open http://localhost:5000
```

### Sudo-free operation (optional)
```bash
sudo setcap cap_net_raw,cap_net_admin+eip builds/phantomscan
./builds/phantomscan
```

---

## Web Dashboard

Five tabs powered by WebSocket streaming:

| Tab | Description |
|-----|-------------|
| **SCAN** | Launch modules, live progress bar, real-time log |
| **RESULTS** | Interactive map, open ports, subdomains, OS, WHOIS, CVE |
| **SCORECARD** | Score ring, DNS / TLS / HTTP security panels |
| **HISTORY** | Last 20 scans with grades |
| **COMPARE** | Side-by-side comparison of two targets |

**Design:** Shadow Monarch Edition
- Glassmorphism panels with backdrop-filter blur
- Color scheme: `#7b2fff` purple · `#00d4ff` cyan · `#ff2d6b` red
- Space Modal: 3D galaxy + black hole with accretion disk
- Sound Engine: Web Audio API (no external files)

---

## Test Targets
scanme.nmap.org — классический тестовый хост Nmap (разрешение предоставлено) 8.8.8.8 — DNS Google (геопроверка)

---

## Legal Notice

> PhantomScan is built for **authorized security testing only.**  
> Only scan targets you own or have explicit written permission to test.  
> Unauthorized scanning may violate laws in your jurisdiction.  
> The author is not responsible for misuse of this tool.

---

## Author

**Umedjon Narkalaev** (HxOpSec) — Tajikistan  
<a href="https://github.com/HxOpSec/phantomscan">github.com/HxOpSec/phantomscan</a>

---
