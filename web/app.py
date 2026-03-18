#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#  PhantomScan Web Dashboard API + WebSocket streamer
#  Run: python3 app.py
#  Open: http://localhost:5000
# ─────────────────────────────────────────────────────────────────────────────

import glob
import json
import logging
import os
import re
import subprocess
import threading
import ipaddress
from collections import deque
from datetime import datetime
from typing import Dict, Optional, Tuple

import eventlet

eventlet.monkey_patch()

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

# ─────────────────────────────────────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PHANTOMSCAN = os.path.join(BASE_DIR, "..", "builds", "phantomscan")
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")
FULL_SCAN_TIMEOUT = 420
SCORECARD_TIMEOUT = 180
LOG_LIMIT = 500

app = Flask(__name__, static_folder=".")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# In‑memory scan registry
active_scans: Dict[str, Dict] = {}
scan_history: deque = deque(maxlen=50)

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes."""
    return re.sub(r"\033\[[0-9;]*m", "", text or "")


def safe_target(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)


def is_valid_target(target: str) -> bool:
    """Only allow hostname or IPv4/IPv6; block shell metacharacters."""
    if not target or re.search(r"[;&|`$(){}\\]", target):
        return False
    stripped = target.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        pass
    hostname = re.fullmatch(
        r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
        target,
    )
    return bool(hostname)


def find_latest_report(target: str) -> Optional[str]:
    """Return newest JSON report for a target."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    candidates = glob.glob(os.path.join(REPORTS_DIR, f"{safe_target(target)}_*.json"))
    if not candidates:
        candidates = glob.glob(os.path.join(REPORTS_DIR, "*.json"))
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def load_report_file(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logging.error("Failed to read report %s: %s", path, exc)
        return None


def add_history_entry(result: dict) -> None:
    entry = {
        "target": result.get("target") or result.get("ip") or "unknown",
        "score": result.get("score"),
        "grade": result.get("grade"),
        "ports": len(result.get("ports", [])) if isinstance(result.get("ports"), list) else 0,
        "timestamp": result.get("timestamp") or datetime.utcnow().isoformat(),
    }
    scan_history.appendleft(entry)


def backend_progress_from_line(line: str, current: int) -> int:
    text = line.lower()
    milestones = [
        (30, ["сканируем порты", "ports"]),
        (60, ["проверяем cve", "cve", "vuln"]),
        (80, ["поддомен", "subdomain"]),
        (100, ["завершено", "готово", "report", "done"]),
    ]
    for pct, keys in milestones:
        if any(k in text for k in keys):
            return max(current, pct)
    return current


def parse_scorecard_output(stdout: str, target: str) -> dict:
    clean = strip_ansi(stdout)
    result = {
        "target": target,
        "score": 0,
        "grade": "F",
        "verdict": "",
        "dns": {},
        "tls": {},
        "http": {},
        "whois": {},
        "recommendations": [],
        "timestamp": datetime.utcnow().isoformat(),
    }

    for line in clean.splitlines():
        if "SCORE:" in line and "/" in line:
            try:
                result["score"] = int(re.findall(r"SCORE:\s*([0-9]+)", line)[0])
            except (IndexError, ValueError):
                result["score"] = 0
            grade_match = re.search(r"Grade:\s*([A-F][+]?)", line)
            if grade_match:
                result["grade"] = grade_match.group(1).strip()
        if "Grade:" in line and not result.get("verdict"):
            parts = line.split("Grade:")
            if len(parts) > 1:
                result["verdict"] = parts[-1].strip()
        rec_match = re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.+)", line)
        if rec_match:
            result["recommendations"].append(
                {"level": rec_match.group(1), "message": rec_match.group(2).strip()}
            )

        # DNS
        if line.startswith("SPF"):
            result["dns"]["spf"] = "✓" in line or "OK" in line
        if line.startswith("DMARC"):
            result["dns"]["dmarc"] = "✓" in line or "OK" in line
        if "DNSSEC" in line:
            result["dns"]["dnssec"] = "✓" in line or "OK" in line
        if "CAA" in line:
            result["dns"]["caa"] = "✓" in line or "OK" in line
        if "DKIM" in line:
            result["dns"]["dkim"] = "✓" in line or "OK" in line
        if re.match(r"\s*MX", line):
            result["dns"]["mx"] = "✓" in line or "OK" in line

        # TLS
        if "TLS 1.0" in line:
            result["tls"]["tls10"] = "✓" in line and "Отключён" in line
        if "TLS 1.1" in line:
            result["tls"]["tls11"] = "✓" in line and "Отключён" in line
        if "TLS 1.2" in line:
            result["tls"]["tls12"] = "✓" in line or "Поддерживается" in line
        if "TLS 1.3" in line:
            result["tls"]["tls13"] = "✓" in line or "Поддерживается" in line
        if "Сертификат истекает" in line:
            match = re.search(r"через:\s*([0-9]+)", line)
            if match:
                result["tls"]["days_left"] = int(match.group(1))
        if "Самоподписанный" in line:
            result["tls"]["self_signed"] = True
        if "Слабые шифры" in line:
            result["tls"]["weak_ciphers"] = True
        if "HSTS" in line:
            result["tls"]["hsts"] = "✓" in line or "Включён" in line

        # HTTP
        if "X-Frame-Options" in line:
            result["http"]["x_frame_options"] = "✓" in line or "Настроен" in line
        if "X-Content-Type-Options" in line:
            result["http"]["x_content_type_options"] = "✓" in line or "Настроен" in line
        if "Content-Security-Policy" in line:
            result["http"]["csp"] = "✓" in line or "Настроен" in line
        if "Referrer-Policy" in line:
            result["http"]["referrer_policy"] = "✓" in line or "Настроен" in line

        # WHOIS
        if "Возраст домена" in line:
            age_match = re.search(r"([0-9]+)\s*дн", line)
            if age_match:
                result["whois"]["domain_age_days"] = int(age_match.group(1))
        if "Истекает через" in line:
            exp_match = re.search(r"через:\s*([0-9]+)", line)
            if exp_match:
                result["whois"]["days_until_expiry"] = int(exp_match.group(1))
        if "Регистратор:" in line:
            result["whois"]["registrar"] = line.split(":", 1)[-1].strip()
        if "Страна:" in line:
            result["whois"]["country"] = line.split(":", 1)[-1].strip()

    return result


def parse_stdout_fallback(stdout: str, target: str) -> dict:
    """Minimal parser when JSON report is missing."""
    clean = strip_ansi(stdout)
    data = {
        "target": target,
        "ip": target,
        "ports": [],
        "subdomains": [],
        "os": "",
        "country": "",
        "city": "",
        "isp": "",
        "firewall": False,
        "timestamp": datetime.utcnow().isoformat(),
    }
    for line in clean.splitlines():
        if "ОС:" in line:
            data["os"] = line.split(":", 1)[-1].strip()
        if "Страна" in line and ":" in line:
            data["country"] = line.split(":", 1)[-1].strip()
        if "Фаервол" in line:
            data["firewall"] = "ОБНАРУЖЕН" in line
        if "Найден:" in line and "→" in line:
            parts = line.split("→")
            data["subdomains"].append("→".join(p.strip() for p in parts))
    return data


def launch_process(binary: str, input_data: str) -> Tuple[Optional[subprocess.Popen], Optional[list]]:
    """Try sudo -n first, then plain execution."""
    commands = [["sudo", "-n", binary], [binary]]
    for cmd in commands:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            proc.stdin.write(input_data)
            proc.stdin.flush()
            proc.stdin.close()
            return proc, cmd
        except FileNotFoundError:
            continue
        except Exception as exc:  # noqa: BLE001
            logging.error("Failed to start process %s: %s", cmd, exc)
            continue
    return None, None


def stream_scan(scan_id: str, target: str, menu_choice: str) -> None:
    """Background scanner with live websocket streaming."""
    scan = active_scans[scan_id]
    scan["status"] = "running"
    scan["progress"] = 0
    socketio.emit("scan_status", {"scan_id": scan_id, "status": "running", "progress": 0})

    binary = os.path.abspath(PHANTOMSCAN)
    if not os.path.exists(binary):
        msg = f"Binary not found: {binary}"
        scan["status"] = "error"
        socketio.emit("scan_error", {"scan_id": scan_id, "error": msg}, room=scan_id)
        return

    input_seq = f"{target}\n{menu_choice}\n0\n"
    proc, cmd_used = launch_process(binary, input_seq)
    if not proc:
        scan["status"] = "error"
        socketio.emit("scan_error", {"scan_id": scan_id, "error": "Не удалось запустить phantomscan"}, room=scan_id)
        return

    logging.info("Started scan %s with cmd %s", scan_id, cmd_used)

    try:
        for raw_line in iter(proc.stdout.readline, ""):
            if raw_line == "" and proc.poll() is not None:
                break
            clean = strip_ansi(raw_line.rstrip())
            if not clean:
                continue
            scan["log"].append(clean)
            if len(scan["log"]) > LOG_LIMIT:
                scan["log"] = scan["log"][-LOG_LIMIT:]
            scan["progress"] = backend_progress_from_line(clean, scan.get("progress", 0))
            socketio.emit(
                "log_line",
                {"scan_id": scan_id, "line": clean, "progress": scan["progress"]},
                room=scan_id,
            )

        proc.wait(timeout=FULL_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        scan["status"] = "error"
        socketio.emit("scan_error", {"scan_id": scan_id, "error": "Таймаут сканирования"}, room=scan_id)
        return
    except (OSError, ValueError) as exc:
        scan["status"] = "error"
        socketio.emit("scan_error", {"scan_id": scan_id, "error": str(exc)}, room=scan_id)
        return

    report_file = find_latest_report(target)
    result = None
    if report_file:
        result = load_report_file(report_file)
    if not result:
        try:
            stdout = proc.stdout.read() if proc.stdout else ""
        except Exception:
            stdout = ""
        result = parse_stdout_fallback(stdout, target)

    scan["status"] = "done"
    scan["result"] = result
    scan["progress"] = 100
    add_history_entry(result)
    socketio.emit(
        "scan_complete",
        {"scan_id": scan_id, "result": result, "progress": 100},
        room=scan_id,
    )


def run_scorecard(target: str) -> dict:
    binary = os.path.abspath(PHANTOMSCAN)
    if not os.path.exists(binary):
        raise FileNotFoundError("phantomscan binary not found")
    input_seq = f"{target}\n17\n0\n"
    proc, _ = launch_process(binary, input_seq)
    if not proc:
        raise RuntimeError("scorecard start failed")
    try:
        stdout, _ = proc.communicate(timeout=SCORECARD_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    return parse_scorecard_output(stdout, target)


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(".", filename)


@app.route("/api/health", methods=["GET"])
def health():
    try:
        binary = os.path.abspath(PHANTOMSCAN)
        return jsonify(
            {
                "status": "ok",
                "binary": binary,
                "binary_exists": os.path.exists(binary),
                "reports_dir": os.path.abspath(REPORTS_DIR),
                "version": "2.0.0",
            }
        )
    except Exception as exc:  # noqa: BLE001
        logging.error("Health error: %s", exc)
        return jsonify({"error": "health check failed"}), 500


@app.route("/api/scan", methods=["POST"])
def start_scan():
    try:
        data = request.get_json(force=True, silent=True) or {}
        target = (data.get("target") or "").strip()
        mode = data.get("mode", "full")
        if not target or not is_valid_target(target):
            return jsonify({"error": "Invalid target"}), 400

        mode_map = {
            "full": "1",
            "quick": "2",
            "subs": "3",
            "scorecard": "17",
            "ssl": "8",
        }
        menu_choice = mode_map.get(mode, "1")
        scan_id = f"scan_{safe_target(target)}_{datetime.utcnow().strftime('%H%M%S%f')}"
        active_scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "queued",
            "log": [],
            "result": None,
            "progress": 0,
            "started": datetime.utcnow().isoformat(),
        }
        socketio.start_background_task(stream_scan, scan_id, target, menu_choice)
        return jsonify({"scan_id": scan_id, "status": "queued"})
    except (ValueError, OSError, RuntimeError) as exc:
        logging.error("start_scan error: %s", exc)
        return jsonify({"error": "Failed to start scan"}), 500


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    try:
        if scan_id not in active_scans:
            return jsonify({"error": "Not found"}), 404
        return jsonify(active_scans[scan_id])
    except Exception as exc:  # noqa: BLE001
        logging.error("get_scan error: %s", exc)
        return jsonify({"error": "Failed to get scan"}), 500


@app.route("/api/history", methods=["GET"])
def history():
    try:
        files = sorted(
            glob.glob(os.path.join(REPORTS_DIR, "*.json")),
            key=os.path.getmtime,
            reverse=True,
        )[:20]
        from_files = []
        for path in files:
            content = load_report_file(path)
            if not content:
                continue
            from_files.append(
                {
                    "target": content.get("target"),
                    "ports": len(content.get("ports", [])),
                    "score": content.get("score"),
                    "grade": content.get("grade"),
                    "timestamp": datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
                }
            )
        combined = list(scan_history) + from_files
        return jsonify(combined[:20])
    except Exception as exc:  # noqa: BLE001
        logging.error("history error: %s", exc)
        return jsonify({"error": "history fetch failed"}), 500


@app.route("/api/compare", methods=["POST"])
def compare():
    try:
        data = request.get_json(force=True, silent=True) or {}
        t1 = (data.get("target_a") or "").strip()
        t2 = (data.get("target_b") or "").strip()
        if not (is_valid_target(t1) and is_valid_target(t2)):
            return jsonify({"error": "Invalid targets"}), 400
        r1 = run_scorecard(t1)
        r2 = run_scorecard(t2)
        return jsonify({"a": r1, "b": r2})
    except Exception as exc:  # noqa: BLE001
        logging.error("compare error: %s", exc)
        return jsonify({"error": "compare failed"}), 500


@app.route("/api/reports", methods=["GET"])
def list_reports():
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        files = sorted(
            glob.glob(os.path.join(REPORTS_DIR, "*.json")),
            key=os.path.getmtime,
            reverse=True,
        )[:20]
        return jsonify(
            [
                {
                    "filename": os.path.basename(f),
                    "size": os.path.getsize(f),
                    "modified": datetime.fromtimestamp(os.path.getmtime(f)).isoformat(),
                }
                for f in files
            ]
        )
    except Exception as exc:  # noqa: BLE001
        logging.error("list_reports error: %s", exc)
        return jsonify({"error": "Failed to list reports"}), 500


@app.route("/api/reports/<filename>", methods=["GET"])
def get_report(filename: str):
    try:
        if ".." in filename or "/" in filename or not filename.endswith(".json"):
            return jsonify({"error": "Invalid filename"}), 400
        fp = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(fp):
            return jsonify({"error": "Not found"}), 404
        content = load_report_file(fp)
        if content is None:
            return jsonify({"error": "Failed to read report"}), 500
        return jsonify(content)
    except Exception as exc:  # noqa: BLE001
        logging.error("get_report error: %s", exc)
        return jsonify({"error": "Failed to fetch report"}), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Socket.IO
# ─────────────────────────────────────────────────────────────────────────────


@socketio.on("join_scan")
def handle_join(data):
    scan_id = data.get("scan_id") if isinstance(data, dict) else None
    if not scan_id:
        emit("error", {"error": "scan_id required"})
        return
    join_room(scan_id)
    emit("joined", {"scan_id": scan_id})


@socketio.on("leave_scan")
def handle_leave(data):
    scan_id = data.get("scan_id") if isinstance(data, dict) else None
    if scan_id:
        leave_room(scan_id)


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.info("PhantomScan Web API starting…")
    logging.info("Binary: %s (exists=%s)", PHANTOMSCAN, os.path.exists(PHANTOMSCAN))
    os.makedirs(REPORTS_DIR, exist_ok=True)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
