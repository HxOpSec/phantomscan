#!/usr/bin/env python3
"""
PhantomScan CVE Updater
Качает свежие CVE с NVD API и добавляет в data/cve.json

Использование:
    python3 scripts/update_cve.py
    python3 scripts/update_cve.py --service Jenkins
    python3 scripts/update_cve.py --days 30

Требования:
    pip install requests
"""

import json
import os
import sys
import time
import argparse
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    print("[!] Установи requests: pip install requests")
    sys.exit(1)

# ─── Настройки ─────────────────────────────────────────
NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_FILE  = os.path.join(os.path.dirname(__file__), "..", "data", "cve.json")
API_DELAY = 6   # секунд между запросами (NVD лимит: 10 запросов / минуту)

# Ключевые слова для каждого сервиса
SERVICE_KEYWORDS = {
    "SSH":          "OpenSSH",
    "HTTP":         "Apache HTTP",
    "HTTPS":        "Apache Tomcat",
    "FTP":          "ProFTPd",
    "SMTP":         "Exim",
    "MySQL":        "MySQL",
    "PostgreSQL":   "PostgreSQL",
    "Redis":        "Redis",
    "MongoDB":      "MongoDB",
    "Nginx":        "Nginx",
    "IIS":          "Microsoft IIS",
    "Jenkins":      "Jenkins",
    "GitLab":       "GitLab",
    "Exchange":     "Microsoft Exchange",
    "VMware":       "VMware vCenter",
    "Fortinet":     "FortiOS",
    "Docker":       "Docker",
    "Kubernetes":   "Kubernetes",
    "WordPress":    "WordPress",
    "Drupal":       "Drupal",
    "Struts":       "Apache Struts",
    "Log4j":        "Apache Log4j",
    "Grafana":      "Grafana",
    "Samba":        "Samba",
    "Citrix":       "Citrix NetScaler",
    "PulseSecure":  "Pulse Connect Secure",
    "Oracle":       "Oracle WebLogic",
    "MSSQL":        "Microsoft SQL Server",
    "ElasticSearch":"Elasticsearch",
    "Memcached":    "Memcached",
}

def load_cve_db():
    """Загружаем текущую базу"""
    if not os.path.exists(CVE_FILE):
        print(f"[!] Файл не найден: {CVE_FILE}")
        return {}
    with open(CVE_FILE, encoding='utf-8') as f:
        return json.load(f)

def save_cve_db(db):
    """Сохраняем базу"""
    os.makedirs(os.path.dirname(CVE_FILE), exist_ok=True)
    with open(CVE_FILE, 'w', encoding='utf-8') as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

def existing_ids(db, service):
    """Уже известные CVE ID для сервиса"""
    return {e['id'] for e in db.get(service, [])}

def map_severity(cvss_score):
    """CVSS числовой → текстовый"""
    if cvss_score >= 9.0: return "CRITICAL"
    if cvss_score >= 7.0: return "HIGH"
    if cvss_score >= 4.0: return "MEDIUM"
    return "LOW"

def fetch_nvd(keyword, days_back=365):
    """Запрос к NVD API"""
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": 20,
        "startIndex":     0,
    }

    headers = {"User-Agent": "PhantomScan/1.0 CVE-Updater"}

    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        if r.status_code == 403:
            print("  [!] NVD: Превышен лимит запросов. Ждём 60 сек...")
            time.sleep(60)
            r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print("  [!] Нет подключения к интернету")
        return None
    except requests.exceptions.Timeout:
        print("  [!] NVD API не ответил (timeout)")
        return None
    except Exception as e:
        print(f"  [!] Ошибка: {e}")
        return None

def parse_nvd_response(data):
    """Парсим ответ NVD в наш формат"""
    entries = []
    if not data or 'vulnerabilities' not in data:
        return entries

    for item in data['vulnerabilities']:
        cve = item.get('cve', {})
        cve_id = cve.get('id', '')

        # Описание (берём английское)
        descriptions = cve.get('descriptions', [])
        desc = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            'No description'
        )
        # Обрезаем длинные описания
        if len(desc) > 80:
            desc = desc[:77] + "..."

        # CVSS v3 оценка
        cvss_score = 0.0
        severity   = "MEDIUM"
        metrics = cve.get('metrics', {})

        # Пробуем CVSSv3, потом CVSSv2
        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if key in metrics and metrics[key]:
                data_cvss = metrics[key][0].get('cvssData', {})
                cvss_score = data_cvss.get('baseScore', 0.0)
                severity   = map_severity(cvss_score)
                break

        if cve_id:
            entries.append({
                "id":       cve_id,
                "severity": severity,
                "cvss":     cvss_score,
                "desc":     desc
            })

    return entries

def update_service(db, service, keyword, days_back):
    """Обновляем один сервис"""
    print(f"\n[*] Обновляем {service} (ключ: '{keyword}')...")

    known = existing_ids(db, service)
    data  = fetch_nvd(keyword, days_back)

    if data is None:
        return 0

    total = data.get('totalResults', 0)
    print(f"  NVD нашёл: {total} CVE")

    new_entries = parse_nvd_response(data)
    added = 0

    if service not in db:
        db[service] = []

    for entry in new_entries:
        if entry['id'] not in known:
            db[service].append(entry)
            known.add(entry['id'])
            added += 1
            print(f"  [+] {entry['id']} ({entry['severity']}, {entry['cvss']}) — {entry['desc'][:50]}")

    if added == 0:
        print(f"  [=] Новых CVE нет")

    return added

def main():
    parser = argparse.ArgumentParser(
        description='PhantomScan CVE Updater — обновляет data/cve.json с NVD API'
    )
    parser.add_argument('--service', help='Обновить только один сервис (напр. Jenkins)')
    parser.add_argument('--days',    type=int, default=365, help='Глубина поиска в днях (default: 365)')
    parser.add_argument('--list',    action='store_true',   help='Показать все доступные сервисы')
    args = parser.parse_args()

    if args.list:
        print("Доступные сервисы:")
        for s, k in SERVICE_KEYWORDS.items():
            print(f"  {s:<15} -> '{k}'")
        return

    print("=" * 55)
    print("  PhantomScan CVE Updater")
    print(f"  Дата: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Файл: {os.path.abspath(CVE_FILE)}")
    print("=" * 55)

    db = load_cve_db()
    before = sum(len(v) for v in db.values())
    print(f"[i] Текущая база: {before} CVE в {len(db)} сервисах")

    if args.service:
        if args.service not in SERVICE_KEYWORDS:
            print(f"[!] Неизвестный сервис: {args.service}")
            print(f"    Доступные: {', '.join(SERVICE_KEYWORDS.keys())}")
            sys.exit(1)
        services = {args.service: SERVICE_KEYWORDS[args.service]}
    else:
        services = SERVICE_KEYWORDS

    total_added = 0
    for service, keyword in services.items():
        added = update_service(db, service, keyword, args.days)
        total_added += added
        if len(services) > 1:
            time.sleep(API_DELAY)  # уважаем лимит NVD

    save_cve_db(db)

    after = sum(len(v) for v in db.values())
    print("\n" + "=" * 55)
    print(f"[+] Добавлено новых CVE : {total_added}")
    print(f"[+] Итого в базе       : {after} CVE в {len(db)} сервисах")
    print(f"[+] Сохранено в        : {os.path.abspath(CVE_FILE)}")
    print("=" * 55)

if __name__ == "__main__":
    main()