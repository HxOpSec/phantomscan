<div align="center">

<pre>
██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝  ╚═╝    ╚═════╝ ╚═╝     ╚═╝
</pre>

### Модульный инструмент сетевой разведки и пентеста — C++17

[![Version](https://img.shields.io/badge/version-1.2.0-blue?style=flat-square)](https://github.com/HxOpSec/phantomscan/releases)
[![Language](https://img.shields.io/badge/C%2B%2B-17-orange?style=flat-square)](https://github.com/HxOpSec/phantomscan)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square)](https://github.com/HxOpSec/phantomscan)
[![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://github.com/HxOpSec/phantomscan)
[![Warnings](https://img.shields.io/badge/warnings-0-brightgreen?style=flat-square)](https://github.com/HxOpSec/phantomscan)
[![License](https://img.shields.io/badge/license-MIT-purple?style=flat-square)](LICENSE)

*Написан с нуля. Никаких обёрток. Только сырые сокеты и реальные протоколы.*

</div>

---

## О проекте

**PhantomScan** — это терминальный инструмент для сетевой разведки,
написанный целиком на **C++17** без внешних зависимостей (кроме libpcap).

Проект начинался как попытка разобраться — как устроены инструменты
безопасности изнутри. Не вызвать `nmap` и распарсить его вывод,
а написать то, что nmap делает сам: собрать TCP-заголовок руками,
отправить сырой пакет, обработать ответ на уровне протокола.

Сейчас это полноценный инструмент разведки с 20 модулями,
собственной CVE базой на 271 запись и поддержкой параллельного
сканирования нескольких целей. Каждый модуль тестировался на
живых целях в реальных сетях.

```
scanme.nmap.org  →  SSH CRITICAL (OpenSSH 6.6.1),  Apache HIGH (2.4.7)
cloudflare.com   →  WAF: Cloudflare [DETECTED]
google.com       →  30 поддоменов,  29 DNS записей,  SSL: Valid
8.8.8.8 + 1.1.1.1  →  параллельно,  104 CVE,  ~44 сек
```

---

## Быстрый старт

```bash
# Клонировать
git clone https://github.com/HxOpSec/phantomscan.git
cd phantomscan

# Зависимости
sudo apt install g++ make libpcap-dev

# Собрать
make rebuild

# Запустить (raw sockets требуют sudo)
sudo ./builds/phantomscan
```

---

## Модули

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  РАЗВЕДКА СЕТИ                                                  │
 ├──────┬───────────────────────────┬──────────────────────────────┤
 │  [1] │ Полное сканирование       │ TCP + CVE + ОС + Firewall    │
 │  [2] │ Быстрый скан              │ Топ-100 портов за секунды    │
 │  [5] │ ARP скан                  │ Устройства в локальной сети  │
 │  [6] │ Трассировка маршрута      │ ASCII дерево хопов           │
 │  [7] │ SYN Stealth скан          │ Невидимый режим              │
 │ [15] │ UDP скан                  │ Протокольные probe           │
 │ [20] │ Параллельный скан         │ Несколько целей из файла     │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  АНАЛИЗ УГРОЗ                                                   │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │ [10] │ Уязвимые версии           │ 45 сервисов, banner grabbing │
 │ [13] │ Exploit Suggester         │ 60+ эксплойтов + Exploit-DB  │ 
 │ [17] │ Security Scorecard        │ Итоговая оценка A+ до F      │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  ВЕБ                                                            │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  [8] │ SSL/TLS анализ            │ Сертификат, срок, CA         │
 │  [9] │ WAF детектор              │ 15 систем защиты             │
 │ [18] │ HTTP директори скан       │ 160+ путей                   │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  DNS                                                            │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  [3] │ Поиск поддоменов          │ 132 варианта                 │
 │ [11] │ Wordlist генератор        │ Вариации имени домена        │
 │ [19] │ DNS enum + AXFR           │ A/AAAA/MX/NS/TXT/SOA/CNAME   │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  ПРОЧЕЕ                                                         │
 ├──────┼───────────────────────────┼──────────────────────────────┤
 │  [4] │ Мониторинг пакетов        │ Захват с TCP флагами         │
 │ [12] │ Shodan поиск              │ Требует API ключ             │
 │ [14] │ Топология сети            │ ASCII карта маршрута         │
 └──────┴───────────────────────────┴──────────────────────────────┘
```

---

## Архитектура

```
phantomscan/
├── src/
│   ├── core/scanner.cpp          ← TCP + CVE + OS + firewall
│   └── modules/
│       ├── syn_scan.cpp          ← SYN stealth, raw sockets
│       ├── udp_scan.cpp          ← UDP с протокольными probe
│       ├── packet_capture.cpp    ← libpcap, TCP флаги
│       ├── os_detect.cpp         ← TTL + SSH banner
│       ├── ssl_scan.cpp          ← сертификат, срок, CA
│       ├── waf_detect.cpp        ← 15 WAF сигнатур
│       ├── vuln_scan.cpp         ← 45 сервисов, banner grabbing
│       ├── exploit.cpp           ← 60+ эксплойтов
│       ├── subdomain.cpp         ← DNS enumeration
│       ├── http_scan.cpp         ← 160+ путей
│       ├── dns_enum.cpp          ← AXFR + полный dump
│       ├── whois.cpp             ← IP геолокация, ASN
│       ├── threads.cpp           ← собственный ThreadPool
│       └── ...
├── include/
├── data/cve.json                 ← 271+ CVE, 39 сервисов
├── reports/                      ← TXT, JSON, HTML
└── Makefile
```

---

## CVE база

```json
{
  "total_cves"  : 271,
  "services"    : 39,
  "categories"  : [
    "SSH", "HTTP", "FTP", "MySQL", "PostgreSQL", "Redis",
    "MongoDB", "Elasticsearch", "SMB", "RDP", "VNC",
    "Docker", "WebLogic", "ActiveMQ", "PHP", "Grafana",
    "Consul", "CouchDB", "SAP", "Java RMI", "Rsync" ...
  ]
}
```

```bash
# Обновить базу
python3 scripts/update_cve.py
```

---

## Примеры

```bash
# Полный скан цели
sudo ./builds/phantomscan
# → ввести IP → [1]

# Stealth сканирование
# → [7] → диапазон портов 1-1024

# Несколько целей параллельно
echo -e "192.168.1.1\n10.0.0.1\n8.8.8.8" > targets.txt
# → [20] → targets.txt

# Найти уязвимые версии
# → [10] → проверит 45 сервисов

# Подобрать эксплойты
# → [13] → ввести сервис: smb / rdp / ssh / docker
```

---

## Тесты

| Цель | Результат |
|------|-----------|
| `scanme.nmap.org` | SSH CRITICAL (OpenSSH 6.6.1p1), Apache HIGH (2.4.7) |
| `google.com` | 30 поддоменов, 29 DNS записей, SSL: Valid |
| `cloudflare.com` | WAF: Cloudflare — определён корректно |
| `8.8.8.8` | Порты 53/443/853, OS: Windows (TTL=108) |
| `1.1.1.1` | Порты 53/443/853/80, OS: Linux (TTL=47) |

---

## Сборка

```bash
make          # сборка
make rebuild  # пересборка с нуля
make clean    # очистка
```

Флаги: `-std=c++17 -Wall -Wextra -Wshadow -O2`
Результат: **0 предупреждений, 0 ошибок.**

---

## Требования

| | |
|--|--|
| Компилятор | g++ 9+ (C++17) |
| Библиотека | libpcap |
| ОС | Linux (Ubuntu, Debian, Parrot, Kali) |
| Права | sudo — для raw sockets |

---

## Roadmap

**v2.0.0 — Веб дашборд**
- React фронтенд с live прогрессом
- C++ REST API сервер
- WebSocket стриминг результатов
- Интерактивная карта топологии
- История сканирований

**Новые модули**
- Брутфорс — SSH, FTP, HTTP Basic Auth
- Полная интеграция Shodan
- Certificate Transparency (crt.sh)
- HTTP параметр-фаззер

---

## Автор

**Умеджон — HxOpSec**
Студент второго курса, Таджикистан
[github.com/HxOpSec](https://github.com/HxOpSec)

---

## Дисклеймер

PhantomScan — инструмент для специалистов по информационной безопасности.
Он разработан в образовательных целях и для проведения **авторизованного**
тестирования на проникновение.

Использование инструмента против систем и сетей **без явного письменного
разрешения** их владельца является незаконным в большинстве стран мира
и влечёт уголовную ответственность.

Автор не несёт никакой ответственности за ущерб, причинённый в результате
неправомерного или халатного применения данного программного обеспечения.
Вся ответственность лежит исключительно на пользователе.

Перед любым сканированием убедитесь, что у вас есть разрешение.

---

<div align="center">

*PhantomScan v1.2.0 · 2026 · HxOpSec*

**Если проект полезен — поставь звезду ⭐**

</div>