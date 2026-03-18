#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#  PhantomScan Web API — app.py
#  Run: python3 app.py
#  Open: http://localhost:5000
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import glob
import subprocess
import threading
import re
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

# Paths
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PHANTOMSCAN  = os.path.join(BASE_DIR, '..', 'builds', 'phantomscan')
REPORTS_DIR  = os.path.join(BASE_DIR, '..', 'reports')

# Active scans { scan_id: { status, log, result } }
active_scans = {}


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def strip_ansi(text):
    """Remove ANSI escape codes from string"""
    return re.sub(r'\033\[[0-9;]*m', '', text)

def find_latest_report(target):
    """Find the most recently modified JSON report for a target"""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    safe = re.sub(r'[^a-zA-Z0-9_-]', '_', target)
    patterns = [
        os.path.join(REPORTS_DIR, f"{safe}_*.json"),
        os.path.join(REPORTS_DIR, f"{target}_*.json"),
        os.path.join(REPORTS_DIR, "*.json"),
    ]
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat))
    if not files:
        return None
    return max(set(files), key=os.path.getmtime)


# ─────────────────────────────────────────────────────────────────────────────
#  Background scan runner
# ─────────────────────────────────────────────────────────────────────────────

def run_scan_bg(scan_id, target, menu_choice='1'):
    """Run phantomscan in background thread"""
    scan = active_scans[scan_id]
    scan['status'] = 'running'
    scan['log'].append(f'[*] Запускаем сканирование: {target}')

    binary = os.path.abspath(PHANTOMSCAN)
    if not os.path.exists(binary):
        scan['status'] = 'error'
        scan['log'].append(f'[-] Binary не найден: {binary}')
        return

    try:
        # Input sequence: target → menu choice → exit
        input_seq = f"{target}\n{menu_choice}\n0\n"

        proc = subprocess.Popen(
            ['sudo', binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        scan['log'].append('[*] PhantomScan запущен...')
        stdout, stderr = proc.communicate(input=input_seq, timeout=300)

        scan['log'].append('[+] Процесс завершён, читаем отчёт...')

        # Try to load JSON report
        report_file = find_latest_report(target)
        if report_file:
            with open(report_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
            scan['result'] = result
            scan['log'].append(f'[+] Отчёт загружен: {os.path.basename(report_file)}')
        else:
            # Parse stdout as fallback
            scan['result'] = parse_stdout_fallback(stdout, target)
            scan['log'].append('[*] JSON не найден, парсим вывод терминала')

        scan['status'] = 'done'

    except subprocess.TimeoutExpired:
        scan['status'] = 'error'
        scan['log'].append('[-] Таймаут (5 минут)')
    except Exception as e:
        scan['status'] = 'error'
        scan['log'].append(f'[-] Ошибка: {str(e)}')


def run_scorecard_bg(scan_id, target):
    """Run scorecard module (17)"""
    scan = active_scans[scan_id]
    scan['status'] = 'running'
    scan['log'].append(f'[*] Запускаем Scorecard: {target}')

    binary = os.path.abspath(PHANTOMSCAN)
    if not os.path.exists(binary):
        scan['status'] = 'error'
        scan['log'].append(f'[-] Binary не найден: {binary}')
        return

    try:
        input_seq = f"{target}\n17\n0\n"
        proc = subprocess.Popen(
            ['sudo', binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, _ = proc.communicate(input=input_seq, timeout=120)

        result = parse_scorecard_output(stdout, target)
        scan['result'] = result
        scan['status'] = 'done'
        scan['log'].append('[+] Scorecard завершён')

    except subprocess.TimeoutExpired:
        scan['status'] = 'error'
        scan['log'].append('[-] Таймаут (2 минуты)')
    except Exception as e:
        scan['status'] = 'error'
        scan['log'].append(f'[-] Ошибка: {str(e)}')


# ─────────────────────────────────────────────────────────────────────────────
#  Output parsers
# ─────────────────────────────────────────────────────────────────────────────

def parse_stdout_fallback(stdout, target):
    """Parse terminal output when no JSON report available"""
    result = {
        'target': target,
        'ip': target,
        'os': 'Unknown',
        'country': '',
        'city': '',
        'isp': '',
        'firewall_detected': False,
        'ports': [],
        'subdomains': [],
        'scan_time': 0,
        'timestamp': datetime.now().isoformat()
    }
    clean = strip_ansi(stdout)
    for line in clean.split('\n'):
        if 'Страна' in line and ':' in line:
            result['country'] = line.split(':', 1)[1].strip()
        if 'ОС:' in line:
            result['os'] = line.split(':', 1)[1].strip()
        if 'Фаервол ОБНАРУЖЕН' in line:
            result['firewall_detected'] = True
        if 'Найден:' in line and '→' in line:
            parts = line.split('→')
            if len(parts) == 2:
                name = parts[0].split()[-1].strip()
                ip   = parts[1].strip()
                result['subdomains'].append(f"{name} → {ip}")
    return result


def parse_scorecard_output(stdout, target):
    """Parse scorecard terminal output into structured JSON"""
    clean = strip_ansi(stdout)
    result = {
        'target': target,
        'score': 0,
        'grade': 'F',
        'verdict': 'Критически опасно',
        'recommendations': [],
        'timestamp': datetime.now().isoformat()
    }
    for line in clean.split('\n'):
        # Score
        if 'SCORE:' in line and '/' in line:
            try:
                score_str = line.split('SCORE:')[1].split('/')[0].strip()
                result['score'] = int(''.join(filter(str.isdigit, score_str)))
            except Exception:
                pass
        # Grade
        if 'Grade:' in line:
            try:
                g = line.split('Grade:')[1].strip().split()[0]
                result['grade'] = g.strip()
            except Exception:
                pass
        # Recommendations
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if f'[{level}]' in line:
                msg = line.split(f'[{level}]', 1)[-1].strip()
                if msg:
                    result['recommendations'].append({
                        'level': level,
                        'message': msg
                    })
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  API Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)


@app.route('/api/health', methods=['GET'])
def health():
    binary = os.path.abspath(PHANTOMSCAN)
    return jsonify({
        'status': 'ok',
        'binary': binary,
        'binary_exists': os.path.exists(binary),
        'reports_dir': os.path.abspath(REPORTS_DIR),
        'version': '1.2.0'
    })


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    if not data or not data.get('target', '').strip():
        return jsonify({'error': 'Target required'}), 400

    target  = data['target'].strip()
    scan_id = f"scan_{re.sub(r'[^a-z0-9]', '_', target.lower())}_{datetime.now().strftime('%H%M%S')}"

    active_scans[scan_id] = {
        'id': scan_id, 'target': target,
        'status': 'queued', 'log': [], 'result': None,
        'started': datetime.now().isoformat()
    }

    t = threading.Thread(target=run_scan_bg, args=(scan_id, target, '1'))
    t.daemon = True
    t.start()

    return jsonify({'scan_id': scan_id, 'status': 'queued'})


@app.route('/api/scorecard', methods=['POST'])
def start_scorecard():
    data = request.get_json()
    if not data or not data.get('target', '').strip():
        return jsonify({'error': 'Target required'}), 400

    target  = data['target'].strip()
    scan_id = f"sc_{re.sub(r'[^a-z0-9]', '_', target.lower())}_{datetime.now().strftime('%H%M%S')}"

    active_scans[scan_id] = {
        'id': scan_id, 'target': target,
        'status': 'queued', 'log': [], 'result': None,
        'started': datetime.now().isoformat()
    }

    t = threading.Thread(target=run_scorecard_bg, args=(scan_id, target))
    t.daemon = True
    t.start()

    return jsonify({'scan_id': scan_id, 'status': 'queued'})


@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(active_scans[scan_id])


@app.route('/api/reports', methods=['GET'])
def list_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, '*.json')),
                   key=os.path.getmtime, reverse=True)[:20]
    return jsonify([{
        'filename': os.path.basename(f),
        'size':     os.path.getsize(f),
        'modified': datetime.fromtimestamp(os.path.getmtime(f)).isoformat()
    } for f in files])


@app.route('/api/reports/<filename>', methods=['GET'])
def get_report(filename):
    if '..' in filename or '/' in filename or not filename.endswith('.json'):
        return jsonify({'error': 'Invalid filename'}), 400
    fp = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(fp):
        return jsonify({'error': 'Not found'}), 404
    with open(fp, 'r', encoding='utf-8') as f:
        return jsonify(json.load(f))


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    binary = os.path.abspath(PHANTOMSCAN)
    print("╔══════════════════════════════════════════╗")
    print("║   PhantomScan Web API  v1.2.0            ║")
    print("║   http://localhost:5000                  ║")
    print("╚══════════════════════════════════════════╝")
    print(f"[*] Binary : {binary}")
    print(f"[*] Exists : {os.path.exists(binary)}")
    print(f"[*] Reports: {os.path.abspath(REPORTS_DIR)}")
    app.run(host='0.0.0.0', port=5000, debug=False)