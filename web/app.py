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
import pty
import re
import select
import subprocess
import threading
import time
import ipaddress
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

# ─────────────────────────────────────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────────────────────────────────────
os.environ.setdefault("PYTHONUNBUFFERED", "1")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PHANTOMSCAN = os.path.join(BASE_DIR, "..", "builds", "phantomscan")
REPORTS_DIR = os.path.join(BASE_DIR, "..", "reports")
FULL_SCAN_TIMEOUT_SECONDS = 420
SCORECARD_TIMEOUT_SECONDS = 300
LOG_LIMIT = 500
HOSTNAME_REGEX = r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"

def check_sudo_available() -> bool:
    binary = os.path.abspath(PHANTOMSCAN)
    try:
        result = subprocess.run(
            ["sudo", "-n", binary, "--help"],
            capture_output=True, timeout=3,
        )
        return result.returncode in (0, 1)  # any response = sudo works
    except Exception:
        return False


SUDO_AVAILABLE = check_sudo_available()

app = Flask(__name__, static_folder=".")
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

active_scans: Dict[str, Dict] = {}
scan_history: deque = deque(maxlen=50)

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def ws_emit(event: str, payload: dict, room: Optional[str] = None) -> None:
    """Emit with required namespace and pacing."""
    socketio.emit(event, payload, room=room, namespace="/")
    time.sleep(0.05)


def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text or "")


def safe_target(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)


def sanitize_input(val: str) -> str:
    return re.sub(r"[\r\n\t]", " ", (val or "").strip())


def is_valid_target(target: str) -> bool:
    if not target or re.search(r"[\n\r\x00;&|`$(){}\\]", target):
        return False
    stripped = target.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        pass
    hostname = re.fullmatch(HOSTNAME_REGEX, target)
    return bool(hostname)


def find_latest_report(target: str, started_at: float) -> Optional[str]:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    candidates: list[str] = []
    t = safe_target(target)
    patterns = [
        os.path.join(REPORTS_DIR, f"{t}_*.json"),
        os.path.join(REPORTS_DIR, f"safe_{t}_*.json"),
        os.path.join(REPORTS_DIR, "*.json"),
    ]
    for pat in patterns:
        candidates.extend(glob.glob(pat))
    if not candidates:
        return None
    filtered = [p for p in candidates if os.path.getmtime(p) >= started_at]
    pool = filtered or candidates
    return max(pool, key=os.path.getmtime)


def load_report_file(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logging.error("Failed to read report %s: %s", path, exc)
        return None


def is_menu_line(line: str) -> bool:
    """Filter out PhantomScan menu/banner/decoration lines."""
    if not line:
        return True
    # Box drawing characters
    if any(c in line for c in ['║', '╔', '╚', '╠', '╗', '╝', '─', '│', '┌', '└', '┐', '┘', '├', '┤']):
        return True
    # Menu items pattern
    if re.search(r'\[\s*\d+\s*\]', line):
        return True
    # Common menu/banner strings
    menu_patterns = [
        'Выбор:', 'PhantomScan', 'Network Scanner',
        'by UMEDJON', 'HxOpSec', '██', 'Введите IP',
        'Цель:', 'Новая цель', 'До свидания', 'Неверный выбор',
    ]
    if any(p in line for p in menu_patterns):
        return True
    return False


def add_history_entry(result: dict) -> None:
    entry = {
        "target": result.get("target") or result.get("ip") or "unknown",
        "score": result.get("score"),
        "grade": result.get("grade"),
        "ports": len(result.get("ports", [])) if isinstance(result.get("ports"), list) else 0,
        "timestamp": result.get("timestamp") or datetime.now(timezone.utc).isoformat(),
    }
    scan_history.appendleft(entry)


def backend_progress_from_line(line: str, current: int) -> Tuple[int, Optional[str]]:
    text = line.lower()
    milestones = [
        (12, ["запуск", "start"], "Запуск"),
        (20, ["сканируем порты", "scanning ports", "ports"], "Сканируем порты"),
        (35, ["завершено за", "ports done", "port scan"], "Порты завершены"),
        (50, ["cve", "уязвим"], "Проверяем CVE"),
        (65, ["поддомен", "subdomain"], "Ищем поддомены"),
        (75, ["tls", "ssl"], "Проверяем TLS"),
        (85, ["анализ", "analyz", "firewall"], "Анализируем"),
        (95, ["сохраняем", "report", "отчёт", "отчет"], "Сохраняем отчёты"),
        (100, ["завершено", "готово", "done", "complete"], "Готово"),
    ]
    for pct, keys, label in milestones:
        if any(k in text for k in keys):
            return max(current, pct), label
    return current, None


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
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    score_re = re.compile(r"SCORE:\s*(\d+)\s*/\s*100", re.IGNORECASE)
    grade_re = re.compile(r"Grade:\s*([A-F][+]?)", re.IGNORECASE)

    def has_ok(line: str) -> bool:
        return ("✓" in line) or ("OK" in line.upper())

    def has_fail(line: str) -> bool:
        return ("✗" in line) or ("FAIL" in line.upper())

    for line in clean.splitlines():
        if "scorecard" in line.lower() and not result["verdict"]:
            parts = line.split("—")
            if len(parts) > 1:
                result["verdict"] = parts[-1].strip()
        if "SCORE:" in line.upper():
            sm = score_re.search(line)
            gm = grade_re.search(line)
            if sm:
                try:
                    result["score"] = int(sm.group(1))
                except ValueError:
                    result["score"] = 0
            if gm:
                result["grade"] = gm.group(1).strip().upper()
        rec_match = re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.+)", line)
        if rec_match:
            result["recommendations"].append(
                {"level": rec_match.group(1), "message": rec_match.group(2).strip()}
            )

        section_line = strip_ansi(line.replace("║", " ").replace("|", " "))

        # DNS
        if re.search(r"\bSPF\b", section_line):
            result["dns"]["spf"] = has_ok(line) and not has_fail(line)
        if re.search(r"\bDMARC\b", section_line):
            result["dns"]["dmarc"] = has_ok(line) and not has_fail(line)
        if re.search(r"\bDNSSEC\b", section_line):
            result["dns"]["dnssec"] = has_ok(line) and not has_fail(line)
        if re.search(r"\bCAA\b", section_line):
            result["dns"]["caa"] = has_ok(line) and not has_fail(line)
        if re.search(r"\bDKIM\b", section_line):
            result["dns"]["dkim"] = has_ok(line) and not has_fail(line)
        if re.search(r"\bMX\b", section_line):
            result["dns"]["mx"] = has_ok(line) and not has_fail(line)

        # TLS
        if "TLS 1.0" in line:
            result["tls"]["tls10"] = has_ok(line) and not has_fail(line)
        if "TLS 1.1" in line:
            result["tls"]["tls11"] = has_ok(line) and not has_fail(line)
        if "TLS 1.2" in line:
            result["tls"]["tls12"] = has_ok(line) and not has_fail(line)
        if "TLS 1.3" in line:
            result["tls"]["tls13"] = has_ok(line) and not has_fail(line)
        if re.search(r"(Сертификат истекает через|notAfter|Days left)", line, re.IGNORECASE):
            match = re.search(r"([0-9]+)", line)
            if match:
                result["tls"]["days_left"] = int(match.group(1))
        if "Самоподписанный" in line:
            result["tls"]["self_signed"] = True
        if "Слабые шифры" in line:
            result["tls"]["weak_ciphers"] = True
        if re.search(r"\bHSTS\b", section_line):
            result["tls"]["hsts"] = has_ok(line) and not has_fail(line)

        # HTTP
        if "X-Frame-Options" in line:
            result["http"]["x_frame_options"] = has_ok(line) and not has_fail(line)
        if "X-Content-Type" in line:
            result["http"]["x_content_type_options"] = has_ok(line) and not has_fail(line)
        if "Content-Security-Policy" in line:
            result["http"]["csp"] = has_ok(line) and not has_fail(line)
        if "Referrer-Policy" in line:
            result["http"]["referrer_policy"] = has_ok(line) and not has_fail(line)

        # WHOIS
        if "Возраст домена" in line:
            age_match = re.search(r"([0-9]+)\s*д", line)
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
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


def build_input_sequence(target: str, module: str, extra: dict) -> list[str]:
    module = str(module or "1")
    seq = [target, module]
    extra = extra or {}
    defaults = {
        "4": ("interface", "lo"),
        "5": ("subnet", "192.168.1.0/24"),
        "7": ("port_range", "1-1024"),
        "12": ("api_key", ""),
        "13": ("service", "http"),
        "15": ("port_range", "1-1024"),
        "16": ("new_target", target),
        "18": ("port", "80"),
        "20": ("file_path", "targets.txt"),
    }
    if module in defaults:
        key, default_val = defaults[module]
        seq.append(sanitize_input(extra.get(key, default_val)))
    seq.append("0")
    return seq


def launch_process(binary: str, input_seq: list[str], root_mode: bool = False) -> Tuple[Optional[subprocess.Popen], Optional[list]]:
    binary = os.path.abspath(binary)
    if binary != os.path.abspath(PHANTOMSCAN):
        logging.error("Unexpected binary path: %s", binary)
        return None, None
    if root_mode:
        commands = [
            ["stdbuf", "-oL", "-eL", "sudo", "-n", binary],
            ["sudo", "-n", binary],
            ["stdbuf", "-oL", "-eL", binary],
            [binary],
        ]
    else:
        commands = [
            ["stdbuf", "-oL", "-eL", binary],
            [binary],
            ["stdbuf", "-oL", "-eL", "sudo", "-n", binary],
            ["sudo", "-n", binary],
        ]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    for cmd in commands:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
            for idx, line in enumerate(input_seq):
                proc.stdin.write(f"{line}\n")
                proc.stdin.flush()
                time.sleep(0.5)
            return proc, cmd
        except FileNotFoundError:
            continue
        except (OSError, PermissionError) as exc:
            logging.error("Failed to start process %s: %s", cmd, exc)
            continue
    return None, None


def stream_scan(scan_id: str, target: str, module: str, extra_inputs: dict, root_mode: bool = False) -> None:
    scan = active_scans[scan_id]
    scan["status"] = "running"
    scan["progress"] = 0
    scan["current_action"] = "Запуск"
    scan["stats"] = {"ports": 0, "cve": 0, "subdomains": 0, "score": 0}
    scan["proc"] = None
    ws_emit(
        "scan_status",
        {"scan_id": scan_id, "status": "running", "progress": 0, "current_action": scan["current_action"]},
        room=scan_id,
    )

    binary = os.path.abspath(PHANTOMSCAN)
    if not os.path.exists(binary):
        msg = f"Binary not found: {binary}"
        scan["status"] = "error"
        ws_emit("scan_error", {"scan_id": scan_id, "error": msg}, room=scan_id)
        return

    input_seq = build_input_sequence(target, module, extra_inputs)

    # Create pseudo-terminal — tricks PhantomScan into thinking it has a real
    # terminal, disabling all internal stdout buffering in the C++ binary.
    master_fd, slave_fd = pty.openpty()

    if root_mode or SUDO_AVAILABLE:
        cmd_options = [["sudo", "-n", binary], [binary]]
    else:
        cmd_options = [[binary], ["sudo", "-n", binary]]

    env = os.environ.copy()
    env.update({"PYTHONUNBUFFERED": "1", "TERM": "xterm", "COLUMNS": "120", "LINES": "40"})

    proc = None
    cmd_used = None
    for cmd in cmd_options:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                env=env,
            )
            cmd_used = cmd
            break
        except (FileNotFoundError, OSError, PermissionError) as exc:
            logging.warning("Failed to start %s: %s", cmd, exc)

    # slave_fd is now owned by the child; close our copy in the parent
    os.close(slave_fd)

    if not proc:
        os.close(master_fd)
        scan["status"] = "error"
        ws_emit("scan_error", {"scan_id": scan_id, "error": "Не удалось запустить phantomscan"}, room=scan_id)
        return

    scan["proc"] = proc
    logging.info("Started scan %s with cmd %s (pty)", scan_id, cmd_used)

    captured_output: list[str] = []
    started_at = time.time()
    scan["started_ts"] = started_at

    port_count = 0
    cve_count = 0
    sub_count = 0
    score_value = 0
    last_stats: dict = {"ports": -1, "cve": -1, "subdomains": -1, "score": -1}

    def emit_stats() -> None:
        nonlocal last_stats
        current = {"ports": port_count, "cve": cve_count, "subdomains": sub_count, "score": score_value}
        if current == last_stats:
            return
        last_stats = current
        ws_emit("stats_update", {"scan_id": scan_id, **current}, room=scan_id)

    emit_stats()

    # Send inputs with delays in a background thread so we don't block reading.
    # Delays give the binary time to display each prompt before we answer it:
    # first item (target) needs 0.5 s, module choice 0.3 s, extras 0.2 s each.
    def write_inputs() -> None:
        delays = [0.5, 0.3] + [0.2] * max(0, len(input_seq) - 2)
        for text, delay in zip(input_seq, delays):
            try:
                proc.stdin.write(f"{text}\n".encode())
                proc.stdin.flush()
                time.sleep(delay)
            except (BrokenPipeError, OSError):
                break

    input_thread = threading.Thread(target=write_inputs, daemon=True)
    input_thread.start()

    def _process_line(raw_line: str) -> None:
        nonlocal port_count, cve_count, sub_count, score_value
        clean = strip_ansi(raw_line.strip())
        if not clean or is_menu_line(clean):
            return
        captured_output.append(clean)
        scan["log"].append(clean)
        if len(scan["log"]) > LOG_LIMIT:
            scan["log"] = scan["log"][-LOG_LIMIT:]
        if re.search(r"\[\s*\+\s*\]\s*Найден:", clean):
            sub_count += 1
        if re.search(r"Открыт", clean, re.IGNORECASE):
            port_count += 1
        cve_hits = re.findall(r"CVE-\d{4}-\d+", clean, re.IGNORECASE)
        if cve_hits:
            cve_count += len(cve_hits)
        score_match = re.search(r"SCORE:\s*(\d+)", clean, re.IGNORECASE)
        if score_match:
            try:
                score_value = int(score_match.group(1))
            except ValueError:
                pass
        scan["stats"] = {"ports": port_count, "cve": cve_count, "subdomains": sub_count, "score": score_value}
        emit_stats()
        scan["progress"], action = backend_progress_from_line(clean, scan.get("progress", 0))
        if action:
            scan["current_action"] = action
        ws_emit(
            "log_line",
            {"scan_id": scan_id, "line": clean, "progress": scan["progress"], "current_action": scan.get("current_action")},
            room=scan_id,
        )

    # Read from pty master using select; no readline() to avoid blocking
    no_output_count = 0
    line_buf = ""
    try:
        while True:
            if time.time() - started_at > FULL_SCAN_TIMEOUT_SECONDS:
                proc.kill()
                scan["status"] = "error"
                ws_emit("scan_error", {"scan_id": scan_id, "error": "Таймаут сканирования"}, room=scan_id)
                return
            if scan.get("status") == "cancelled":
                try:
                    proc.kill()
                except Exception:
                    pass
                return

            proc_done = proc.poll() is not None

            try:
                # 1.0 s timeout: short enough for responsive cancellation / timeout
                # checks, long enough not to busy-spin between output bursts.
                ready, _, _ = select.select([master_fd], [], [], 1.0)
            except (ValueError, OSError):
                break

            if ready:
                try:
                    raw = os.read(master_fd, 4096)
                    if not raw:
                        break
                    no_output_count = 0
                    text = line_buf + raw.decode("utf-8", errors="replace")
                    line_buf = ""
                    # Normalize line endings
                    text = text.replace("\r\n", "\n").replace("\r", "\n")
                    lines = text.split("\n")
                    # Keep partial last line in buffer
                    if not text.endswith("\n"):
                        line_buf = lines[-1]
                        lines = lines[:-1]
                    for line in lines:
                        _process_line(line)
                except OSError:
                    break
            else:
                if proc_done:
                    no_output_count += 1
                    if no_output_count >= 3:
                        break
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except Exception:
            pass

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    report_file = find_latest_report(target, started_at=started_at)
    result = None
    if report_file:
        result = load_report_file(report_file)
    if not result:
        result = parse_stdout_fallback("\n".join(captured_output), target)

    scan["stats"] = {"ports": port_count, "cve": cve_count, "subdomains": sub_count, "score": score_value}
    scan["status"] = "done"
    scan["result"] = result
    scan["progress"] = 100
    scan["current_action"] = "Готово"
    scan["proc"] = None
    add_history_entry(result)
    ws_emit(
        "scan_complete",
        {
            "scan_id": scan_id,
            "result": result,
            "stats": scan.get("stats"),
            "progress": 100,
            "current_action": scan.get("current_action"),
        },
        room=scan_id,
    )


def run_scorecard(target: str) -> dict:
    binary = os.path.abspath(PHANTOMSCAN)
    if not os.path.exists(binary):
        raise FileNotFoundError("phantomscan binary not found")
    seq = build_input_sequence(target, "17", {})
    proc, _ = launch_process(binary, seq)
    if not proc:
        raise RuntimeError("scorecard start failed")
    try:
        stdout_parts: list[str] = []
        started = time.time()
        while True:
            if time.time() - started > SCORECARD_TIMEOUT_SECONDS:
                proc.kill()
                raise subprocess.TimeoutExpired(cmd="phantomscan", timeout=SCORECARD_TIMEOUT_SECONDS)
            ready, _, _ = select.select([proc.stdout], [], [], 0.25)
            if ready:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                stdout_parts.append(line)
            else:
                if proc.poll() is not None:
                    remainder = proc.stdout.read()
                    if remainder:
                        stdout_parts.append(remainder)
                    break
        proc.wait(timeout=5)
        stdout = "".join(stdout_parts)
    finally:
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except Exception:
            pass
    return parse_scorecard_output(stdout, target)


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    try:
        return send_from_directory(".", "index.html")
    except OSError as exc:
        logging.error("Index serve error: %s", exc)
        return jsonify({"error": "index unavailable"}), 500


@app.route("/<path:filename>")
def static_files(filename):
    try:
        return send_from_directory(".", filename)
    except OSError as exc:
        logging.error("Static serve error: %s", exc)
        return jsonify({"error": "static unavailable"}), 500


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
                "sudo_available": SUDO_AVAILABLE,
            }
        )
    except OSError as exc:
        logging.error("Health error: %s", exc)
        return jsonify({"error": "health check failed"}), 500


@app.route("/api/scan", methods=["POST"])
def start_scan():
    try:
        data = request.get_json(force=True, silent=True) or {}
        target = sanitize_input(data.get("target") or "")
        module = str(data.get("module") or data.get("mode") or "1")
        extra_inputs = data.get("extra") or {}
        root_mode = bool(data.get("root", SUDO_AVAILABLE))
        legacy_map = {
            "full": "1",
            "quick": "2",
            "subs": "3",
            "scorecard": "17",
            "ssl": "8",
        }
        module = legacy_map.get(module, module)

        if not target or not is_valid_target(target):
            return jsonify({"error": "Invalid target"}), 400
        if not module.isdigit() or not (1 <= int(module) <= 20):
            return jsonify({"error": "Invalid module"}), 400

        scan_id = f"scan_{safe_target(target)}_{datetime.now(timezone.utc).strftime('%H%M%S%f')}"
        active_scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "module": module,
            "status": "queued",
            "log": [],
            "result": None,
            "progress": 0,
            "started": datetime.now(timezone.utc).isoformat(),
            "current_action": "Очередь",
            "stats": {"ports": 0, "cve": 0, "subdomains": 0, "score": 0},
            "proc": None,
        }
        threading.Thread(target=stream_scan, args=(scan_id, target, module, extra_inputs, root_mode), daemon=True).start()
        return jsonify({"scan_id": scan_id, "status": "queued"})
    except (ValueError, OSError, RuntimeError) as exc:
        logging.error("start_scan error: %s", exc)
        return jsonify({"error": "Failed to start scan"}), 500


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    try:
        if scan_id not in active_scans:
            return jsonify({"error": "Not found"}), 404
        data = dict(active_scans[scan_id])
        data.pop("proc", None)
        return jsonify(data)
    except (ValueError, KeyError) as exc:
        logging.error("get_scan error: %s", exc)
        return jsonify({"error": "Failed to get scan"}), 500


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def cancel_scan(scan_id: str):
    try:
        if scan_id not in active_scans:
            return jsonify({"error": "Not found"}), 404
        scan = active_scans[scan_id]
        proc = scan.get("proc")
        if scan.get("status") == "done":
            return jsonify({"status": "done"})
        scan["status"] = "cancelled"
        scan["current_action"] = "Отменено"
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        scan["proc"] = None
        ws_emit("scan_cancelled", {"scan_id": scan_id}, room=scan_id)
        return jsonify({"status": "cancelled"})
    except (ValueError, KeyError, OSError) as exc:
        logging.error("cancel_scan error: %s", exc)
        return jsonify({"error": "Failed to cancel scan"}), 500


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
                    "timestamp": datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc).isoformat(),
                }
            )
        combined = list(scan_history) + from_files
        return jsonify(combined[:20])
    except (OSError, ValueError) as exc:
        logging.error("history error: %s", exc)
        return jsonify({"error": "history fetch failed"}), 500


@app.route("/api/compare", methods=["POST"])
def compare():
    try:
        data = request.get_json(force=True, silent=True) or {}
        t1 = sanitize_input(data.get("target_a") or "")
        t2 = sanitize_input(data.get("target_b") or "")
        if not (is_valid_target(t1) and is_valid_target(t2)):
            return jsonify({"error": "Invalid targets"}), 400
        r1 = run_scorecard(t1)
        r2 = run_scorecard(t2)
        return jsonify({"a": r1, "b": r2})
    except (OSError, ValueError, RuntimeError) as exc:
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
    except OSError as exc:
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
    except (OSError, ValueError) as exc:
        logging.error("get_report error: %s", exc)
        return jsonify({"error": "Failed to fetch report"}), 500


@app.route("/api/reports/<filename>", methods=["DELETE"])
def delete_report(filename: str):
    try:
        if ".." in filename or "/" in filename or not filename.endswith(".json"):
            return jsonify({"error": "Invalid filename"}), 400
        fp = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(fp):
            return jsonify({"error": "Not found"}), 404
        os.remove(fp)
        return jsonify({"status": "deleted"})
    except OSError as exc:
        logging.error("delete_report error: %s", exc)
        return jsonify({"error": "Failed to delete report"}), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Socket.IO
# ─────────────────────────────────────────────────────────────────────────────


@socketio.on("join_scan", namespace="/")
def handle_join(data):
    try:
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        if not scan_id:
            emit("error", {"error": "scan_id required"}, namespace="/")
            time.sleep(0.05)
            return
        join_room(scan_id)
        emit("joined", {"scan_id": scan_id}, namespace="/")
        time.sleep(0.05)

        # Replay buffered log lines so late-joining clients catch up
        if scan_id in active_scans:
            scan = active_scans[scan_id]
            for line in scan.get("log", []):
                emit(
                    "log_line",
                    {
                        "scan_id": scan_id,
                        "line": line,
                        "progress": scan.get("progress", 0),
                        "current_action": scan.get("current_action"),
                    },
                    namespace="/",
                )
                time.sleep(0.01)  # brief yield so the client can process each line
            if scan.get("stats"):
                emit("stats_update", {"scan_id": scan_id, **scan["stats"]}, namespace="/")
                time.sleep(0.05)
            emit(
                "scan_status",
                {
                    "scan_id": scan_id,
                    "status": scan["status"],
                    "progress": scan.get("progress", 0),
                    "current_action": scan.get("current_action"),
                },
                namespace="/",
            )
            time.sleep(0.05)
            if scan["status"] == "done" and scan.get("result"):
                emit(
                    "scan_complete",
                    {
                        "scan_id": scan_id,
                        "result": scan["result"],
                        "stats": scan.get("stats"),
                        "progress": 100,
                        "current_action": scan.get("current_action"),
                    },
                    namespace="/",
                )
                time.sleep(0.05)
    except (KeyError, TypeError) as exc:  # pragma: no cover - defensive
        logging.error("join_scan error: %s", exc)


@socketio.on("leave_scan", namespace="/")
def handle_leave(data):
    try:
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        if scan_id:
            leave_room(scan_id)
            time.sleep(0.05)
    except (KeyError, TypeError) as exc:  # pragma: no cover - defensive
        logging.error("leave_scan error: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.info("PhantomScan Web API starting…")
    logging.info("Binary: %s (exists=%s)", PHANTOMSCAN, os.path.exists(PHANTOMSCAN))
    os.makedirs(REPORTS_DIR, exist_ok=True)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
