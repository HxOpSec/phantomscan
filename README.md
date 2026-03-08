# ⚡ PhantomScan

> Профессиональный сетевой сканер на C++17 для Linux

![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![Language](https://img.shields.io/badge/Language-C%2B%2B17-orange)
![Version](https://img.shields.io/badge/Version-1.0-green)
![License](https://img.shields.io/badge/License-MIT-red)
```
██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
Network Scanner v1.0  |  by Umedjon
```

## 📋 Возможности

| Модуль | Описание |
|--------|----------|
| 🔍 TCP сканер | Сканирование портов 1-65535, 10 потоков |
| 👻 SYN Stealth | Невидимое сканирование через raw sockets |
| 🖥️ Определение ОС | По TTL (Linux/Windows/Cisco) |
| 🔐 SSL/TLS анализ | Проверка сертификатов |
| 🛡️ WAF детектор | CloudFlare, Akamai, Sucuri и др. |
| 📡 ARP скан | Устройства в локальной сети |
| 🌐 Traceroute | Маршрут с ASCII топологией |
| 🔎 CVE сканер | Поиск уязвимостей |
| 💥 Exploit Suggester | Ссылки на Exploit-DB |
| 🌍 WHOIS/Геолокация | Страна, город, провайдер |
| 📝 Wordlist генератор | Поиск поддоменов |
| 📊 Отчёты | TXT, JSON, HTML форматы |
| 🦈 Захват пакетов | Мониторинг трафика (libpcap) |
| 🔑 Shodan API | Интеграция с Shodan |

## ⚙️ Установка

### Зависимости
- Linux (Parrot OS / Kali Linux / Ubuntu)
- g++ (C++17)
- libpcap-dev
- nmap
- curl
- openssl

### Быстрая установка
```bash
git clone https://github.com/USERNAME/phantomscan.git
cd phantomscan
sudo ./install.sh
```

### Ручная сборка
```bash
sudo apt install g++ libpcap-dev nmap curl openssl make
make rebuild
```

## 🚀 Использование
```bash
# Интерактивное меню
sudo ./builds/phantomscan

# Полное сканирование
sudo ./builds/phantomscan -t google.com

# Диапазон портов
sudo ./builds/phantomscan -t 192.168.1.1 -p 1-1024

# HTML отчёт
sudo ./builds/phantomscan -t example.com -o html

# Все форматы отчёта
sudo ./builds/phantomscan -t example.com -o all

# Справка
./builds/phantomscan -h
```

## 📁 Структура проекта
```
phantomscan/
├── src/
│   ├── core/          # TCP сканер
│   ├── modules/       # Все модули (15 штук)
│   └── utils/         # Баннер, логгер, прогресс
├── include/           # Заголовочные файлы
├── builds/            # Скомпилированный бинарник
├── reports/           # Сгенерированные отчёты
├── data/              # CVE база, списки служб
├── Makefile
└── install.sh
```

## 📊 Статистика

- **3800+** строк кода
- **27** файлов
- **15** модулей в меню
- **494 KB** размер бинарника
- **C++17** стандарт

## ⚠️ Legal Disclaimer

> PhantomScan создан **исключительно в образовательных целях**.
> Используй только на системах для которых у тебя есть **письменное разрешение**.
> Автор не несёт ответственности за любое незаконное использование.
> Несанкционированное сканирование чужих систем **незаконно**.

## 🛠️ Технологии

- **C++17** — основной язык
- **libpcap** — захват пакетов
- **POSIX Threads** — многопоточность
- **Raw Sockets** — SYN сканирование
- **OpenSSL** — SSL/TLS анализ

## 📈 История версий

| Версия | Что добавлено |
|--------|---------------|
| v0.1 | TCP скан, ОС, службы, pcap, фаервол |
| v0.2 | Цвета, баннер, многопоточность |
| v0.3 | WHOIS, таблицы |
| v0.4 | CVE сканер |
| v0.5 | Меню, отчёты, CLI |
| v0.6 | ARP скан, Traceroute |
| v0.7 | SYN Stealth, SSL, WAF |
| v0.8 | Vuln scan, Wordlist, Shodan |
| v0.9 | Exploit Suggester, Топология |
| v1.0 | Полировка, install.sh, README |

## 👤 Автор

**Umedjon** — студент 2 курса, кибербезопасность
- 📍 Таджикистан
- 🎓 В разработке с 2025 года

---
*PhantomScan v1.0 — Network Scanner for educational purposes only*