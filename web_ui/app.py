import hmac
import io
import json
import os
import queue
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, send_file, session, url_for)

app = Flask(__name__)

MAIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_DIR   = os.path.dirname(os.path.abspath(__file__))

PROFILES_FILE  = os.path.join(UI_DIR, "profiles.json")
HISTORY_FILE   = os.path.join(UI_DIR, "history.json")
SCHEDULES_FILE = os.path.join(UI_DIR, "schedules.json")
NOTES_FILE     = os.path.join(UI_DIR, "notes.json")
SETTINGS_FILE  = os.path.join(UI_DIR, "settings.json")
TOKEN_FILE     = os.path.join(UI_DIR, ".auth_token")
CONFIG_FILE    = os.path.join(MAIN_DIR, "config.yaml")


def _load_config() -> dict:
    """Load config.yaml; returns empty dict if missing or unparseable."""
    try:
        import yaml
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

# scan_id -> { queue, running, output_dir, process }
active_scans: dict = {}

ANSI_ESCAPE = re.compile(r"\033\[[0-9;]*[mK]")

# Track app start time for uptime
APP_START_TIME = time.time()

# Prime psutil CPU measurement so interval=None works from the first request
try:
    import psutil as _psutil
    _psutil.cpu_percent(interval=None)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _secure_token_file(path: str) -> None:
    """Attempt chmod 600 on the token file. Silently skips on filesystems that
    don't support Unix permissions (e.g. Windows NTFS mounts in WSL)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        # Verify it actually took effect
        actual = stat.S_IMODE(os.stat(path).st_mode)
        if actual != 0o600:
            print(
                f"  [!] Warning: could not set 600 on {path} "
                f"(filesystem may not support Unix permissions). "
                f"Current mode: {oct(actual)}",
                file=sys.stderr,
            )
    except OSError:
        pass


def _load_or_create_token() -> str:
    """Load token from env > file > generate new one."""
    env_token = os.environ.get("UI_TOKEN", "").strip()
    if env_token:
        with open(TOKEN_FILE, "w") as f:
            f.write(env_token)
        _secure_token_file(TOKEN_FILE)
        return env_token
    if os.path.exists(TOKEN_FILE):
        _secure_token_file(TOKEN_FILE)
        with open(TOKEN_FILE, "r") as f:
            token = f.read().strip()
        if token:
            return token
    token = secrets.token_urlsafe(24)
    with open(TOKEN_FILE, "w") as f:
        f.write(token)
    _secure_token_file(TOKEN_FILE)
    return token


# Flask secret key for signing session cookies
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# Auth token — set once at startup
AUTH_TOKEN: str = _load_or_create_token()

# Allow disabling auth entirely (for localhost-only trusted setups)
AUTH_DISABLED: bool = os.environ.get("UI_NO_AUTH", "").lower() in ("1", "true", "yes")

# Sessions expire after 12 hours of inactivity
app.permanent_session_lifetime = timedelta(hours=12)

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

# Sensitive filesystem dirs that the UI must never serve.
# Listed without trailing slash — matching is done with exact-or-prefix logic.
_BLOCKED_DIRS = (
    "/etc", "/root", "/proc", "/sys", "/dev",
    "/boot", "/run", "/snap", "/usr", "/bin",
    "/sbin", "/lib", "/lib64", "/lost+found",
)
_HOME_DIR = os.path.expanduser("~")


def safe_path(requested: str, fallback_base: str) -> "str | None":
    """
    Resolve a user-supplied path and return the real absolute path,
    or None if it points to a sensitive system location.

    - Relative paths are anchored to fallback_base.
    - Symlinks are fully resolved before checking.
    - Sensitive OS directories are blocked regardless of who is logged in.
    """
    if not requested:
        return None
    if os.path.isabs(requested):
        real = os.path.realpath(requested)
    else:
        real = os.path.realpath(os.path.join(fallback_base, requested))

    # Block if real path IS a sensitive dir or is INSIDE one
    # Example: real="/etc" → matches "/etc"; real="/etc/passwd" → matches "/etc/"
    for blocked in _BLOCKED_DIRS:
        if real == blocked or real.startswith(blocked + "/"):
            return None

    # Block hidden dirs inside home (e.g. ~/.ssh, ~/.gnupg, ~/.bashrc)
    if real.startswith(os.path.join(_HOME_DIR, ".")):
        return None

    return real


def is_safe_redirect(url: str) -> bool:
    """Return True only for relative URLs (no scheme or netloc)."""
    if not url:
        return False
    parsed = urlparse(url)
    return (not parsed.scheme) and (not parsed.netloc) and url.startswith("/")


# Simple in-memory login rate limiter: max 10 attempts per IP per 60 s
_login_attempts: dict = defaultdict(list)
_RATE_LIMIT_MAX   = 10
_RATE_LIMIT_WINDOW = 60  # seconds


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    window_start = now - _RATE_LIMIT_WINDOW
    attempts = [t for t in _login_attempts[ip] if t > window_start]
    _login_attempts[ip] = attempts
    if len(attempts) >= _RATE_LIMIT_MAX:
        return True
    _login_attempts[ip].append(now)
    return False


# ---------------------------------------------------------------------------
# Security headers — applied to every response
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["Referrer-Policy"]        = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    return response


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if AUTH_DISABLED:
            return f(*args, **kwargs)
        if not session.get("authenticated"):
            accept = request.headers.get("Accept", "")
            xhr    = request.headers.get("X-Requested-With", "") == "XMLHttpRequest"
            is_api = (request.is_json or xhr
                      or "application/json" in accept
                      or accept.startswith("text/event-stream"))
            if is_api:
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def load_json(path, default=None):
    if default is None:
        default = []
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception:
        pass
    return default


def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _is_rate_limited(ip):
            error = "Too many attempts. Wait 60 seconds and try again."
        else:
            token = request.form.get("token", "").strip()
            # Constant-time comparison prevents timing oracle attacks
            if hmac.compare_digest(token.encode(), AUTH_TOKEN.encode()):
                session["authenticated"] = True
                session.permanent = True
                next_url = request.args.get("next", "")
                # Only follow relative redirects — block open redirect
                return redirect(next_url if is_safe_redirect(next_url) else url_for("index"))
            error = "Invalid token."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Routes — existing
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/check_tools")
@login_required
def check_tools():
    """Run main.py --check-tools and return output."""
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(MAIN_DIR, "main.py"), "--check-tools"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=MAIN_DIR,
        )
        output = strip_ansi(result.stdout + result.stderr)
        return jsonify({"output": output})
    except Exception as e:
        return jsonify({"output": f"Error: {e}"}), 500


@app.route("/start_scan", methods=["POST"])
@login_required
def start_scan():
    data = request.get_json() or {}

    domains_text        = data.get("domains", "").strip()
    output_dir          = data.get("output", "scan_results").strip() or "scan_results"
    config_path         = data.get("config", "config.yaml").strip() or "config.yaml"
    email               = data.get("email", "").strip()
    run_nuclei          = bool(data.get("nuclei"))
    run_ffuf            = bool(data.get("ffuf"))
    wordlist            = data.get("wordlist", "").strip()
    run_cors            = bool(data.get("cors"))
    run_crlf            = bool(data.get("crlf"))
    run_dirsearch       = bool(data.get("dirsearch"))
    dirsearch_wordlist  = data.get("dirsearch_wordlist", "").strip()
    bypass_403          = bool(data.get("bypass_403"))
    run_api             = bool(data.get("api"))
    api_wordlist        = data.get("api_wordlist", "").strip()
    run_xss             = bool(data.get("xss"))
    run_redirect        = bool(data.get("redirect"))
    run_secrets         = bool(data.get("secrets"))

    if not domains_text:
        return jsonify({"error": "No domains provided"}), 400

    # Write domains to a temp file
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    tmp.write(domains_text)
    tmp.close()
    domains_file = tmp.name

    scan_id = str(uuid.uuid4())

    cmd = [
        sys.executable,
        os.path.join(MAIN_DIR, "main.py"),
        "-d", domains_file,
        "-o", output_dir,
        "-c", config_path,
    ]
    if email:
        cmd += ["-e", email]
    if run_nuclei:
        cmd.append("--nuclei")
    if run_ffuf:
        cmd.append("--ffuf")
        if wordlist:
            cmd += ["--wordlist", wordlist]
    if run_cors:
        cmd.append("--cors")
    if run_crlf:
        cmd.append("--crlf")
    if run_dirsearch:
        cmd.append("--dirsearch")
        if dirsearch_wordlist:
            cmd += ["--dirsearch-wordlist", dirsearch_wordlist]
    if bypass_403:
        cmd.append("--403")
    if run_api:
        cmd.append("--api")
        if api_wordlist:
            cmd += ["--api-wordlist", api_wordlist]
    if run_xss:
        cmd.append("--xss")
    if run_redirect:
        cmd.append("--redirect")
    if run_secrets:
        cmd.append("--secrets")

    out_q: queue.Queue = queue.Queue()

    scan_meta = {
        "queue":        out_q,
        "running":      True,
        "output_dir":   output_dir,
        "domains_file": domains_file,
        "process":      None,
        "domains_text": domains_text,
        "started_at":   datetime.now().isoformat(timespec="seconds"),
    }
    active_scans[scan_id] = scan_meta

    def _run():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=MAIN_DIR,
                encoding="utf-8",
                errors="replace",
            )
            scan_meta["process"] = proc
            for line in proc.stdout:
                out_q.put(strip_ansi(line))
            proc.wait()
            final_status = "done" if proc.returncode == 0 else "error"
        except Exception as exc:
            out_q.put(f"[ERROR] {exc}\n")
            final_status = "error"
        finally:
            scan_meta["running"] = False
            out_q.put(None)  # sentinel
            try:
                os.unlink(domains_file)
            except OSError:
                pass
            # Save to history
            history = load_json(HISTORY_FILE, [])
            history.insert(0, {
                "id":         scan_id,
                "target":     scan_meta["domains_text"][:120],
                "output_dir": scan_meta["output_dir"],
                "status":     final_status,
                "started_at": scan_meta["started_at"],
                "ended_at":   datetime.now().isoformat(timespec="seconds"),
            })
            # Cap history at 200 entries
            history = history[:200]
            save_json(HISTORY_FILE, history)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({"scan_id": scan_id, "output_dir": output_dir})


@app.route("/stream/<scan_id>")
@login_required
def stream(scan_id):
    def _generate():
        if scan_id not in active_scans:
            yield "data: {}\n\n".format(json.dumps({"line": "Scan not found.", "done": True}))
            return

        meta = active_scans[scan_id]
        q = meta["queue"]

        while True:
            try:
                line = q.get(timeout=25)
            except queue.Empty:
                yield "data: {}\n\n".format(json.dumps({"heartbeat": True}))
                continue

            if line is None:
                yield "data: {}\n\n".format(json.dumps({"line": "", "done": True}))
                break

            yield "data: {}\n\n".format(json.dumps({"line": line}))

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":      "keep-alive",
        },
    )


@app.route("/stop_scan/<scan_id>", methods=["POST"])
@login_required
def stop_scan(scan_id):
    meta = active_scans.get(scan_id)
    if not meta:
        return jsonify({"error": "Scan not found"}), 404
    proc = meta.get("process")
    if proc and meta["running"]:
        proc.terminate()
        return jsonify({"status": "terminated"})
    return jsonify({"status": "not running"})


@app.route("/results")
@login_required
def list_results():
    """List non-empty result files inside a given output directory."""
    output_dir = request.args.get("dir", "")
    if not output_dir:
        return jsonify({"files": []})

    abs_dir = safe_path(output_dir, MAIN_DIR)
    if abs_dir is None:
        return jsonify({"files": [], "error": "Access denied: path outside allowed directories"}), 403

    if not os.path.isdir(abs_dir):
        return jsonify({"files": [], "error": "Directory not found"})

    files = []
    for root, _dirs, fnames in os.walk(abs_dir):
        for fname in fnames:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                if size == 0:
                    continue
                rel = os.path.relpath(fpath, abs_dir).replace("\\", "/")
                # abs path is stored server-side only for /file requests; not exposed to client
                files.append({"path": rel, "size": size, "abs": fpath})
            except OSError:
                pass

    files.sort(key=lambda x: x["path"])
    # Return abs_dir for display only (already validated safe)
    return jsonify({"files": files, "abs_dir": abs_dir})


@app.route("/file")
@login_required
def read_file():
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "No path specified"}), 400
    abs_path = safe_path(path, MAIN_DIR)
    if abs_path is None:
        return jsonify({"error": "Access denied: path outside allowed directories"}), 403
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        if len(content) > 512_000:
            content = content[:512_000] + "\n\n[... truncated ...]"
        return jsonify({"content": content})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


active_execs: dict = {}


@app.route("/exec", methods=["POST"])
@login_required
def execute_command():
    data = request.get_json() or {}
    cmd_str = data.get("command", "").strip()
    if not cmd_str:
        return jsonify({"error": "No command provided"}), 400

    exec_id = str(uuid.uuid4())
    out_q: queue.Queue = queue.Queue()
    exec_meta = {"queue": out_q, "running": True, "process": None}
    active_execs[exec_id] = exec_meta

    def _run():
        try:
            proc = subprocess.Popen(
                cmd_str, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=MAIN_DIR,
                encoding="utf-8", errors="replace",
            )
            exec_meta["process"] = proc
            for line in proc.stdout:
                out_q.put(strip_ansi(line))
            proc.wait()
        except Exception as exc:
            out_q.put(f"[ERROR] {exc}\n")
        finally:
            exec_meta["running"] = False
            out_q.put(None)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"exec_id": exec_id})


@app.route("/exec_stream/<exec_id>")
@login_required
def exec_stream_route(exec_id):
    def _generate():
        if exec_id not in active_execs:
            yield "data: {}\n\n".format(json.dumps({"line": "Exec not found.", "done": True}))
            return
        meta = active_execs[exec_id]
        q = meta["queue"]
        while True:
            try:
                line = q.get(timeout=25)
            except queue.Empty:
                yield "data: {}\n\n".format(json.dumps({"heartbeat": True}))
                continue
            if line is None:
                yield "data: {}\n\n".format(json.dumps({"line": "", "done": True}))
                break
            yield "data: {}\n\n".format(json.dumps({"line": line}))

    return Response(
        _generate(), mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.route("/kill_exec/<exec_id>", methods=["POST"])
@login_required
def kill_exec(exec_id):
    meta = active_execs.get(exec_id)
    if not meta:
        return jsonify({"error": "Not found"}), 404
    proc = meta.get("process")
    if proc and meta["running"]:
        proc.terminate()
    return jsonify({"status": "terminated"})


# ---------------------------------------------------------------------------
# Routes — Profiles
# ---------------------------------------------------------------------------

@app.route("/profiles", methods=["GET"])
@login_required
def get_profiles():
    return jsonify(load_json(PROFILES_FILE, []))


@app.route("/profiles", methods=["POST"])
@login_required
def create_profile():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Profile name required"}), 400
    profiles = load_json(PROFILES_FILE, [])
    profile = {
        "id":         str(uuid.uuid4()),
        "name":       name,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "config":     data.get("config", {}),
    }
    profiles.append(profile)
    save_json(PROFILES_FILE, profiles)
    return jsonify(profile), 201


@app.route("/profiles/<profile_id>", methods=["DELETE"])
@login_required
def delete_profile(profile_id):
    profiles = load_json(PROFILES_FILE, [])
    profiles = [p for p in profiles if p.get("id") != profile_id]
    save_json(PROFILES_FILE, profiles)
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Routes — History
# ---------------------------------------------------------------------------

@app.route("/history", methods=["GET"])
@login_required
def get_history():
    return jsonify(load_json(HISTORY_FILE, []))


@app.route("/history", methods=["DELETE"])
@login_required
def clear_history():
    save_json(HISTORY_FILE, [])
    return jsonify({"status": "cleared"})


@app.route("/history/<entry_id>", methods=["DELETE"])
@login_required
def delete_history_entry(entry_id):
    history = load_json(HISTORY_FILE, [])
    history = [h for h in history if h.get("id") != entry_id]
    save_json(HISTORY_FILE, history)
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Routes — Export ZIP
# ---------------------------------------------------------------------------

@app.route("/export_zip")
@login_required
def export_zip():
    output_dir = request.args.get("dir", "")
    if not output_dir:
        return jsonify({"error": "No dir specified"}), 400

    abs_dir = safe_path(output_dir, MAIN_DIR)
    if abs_dir is None:
        return jsonify({"error": "Access denied: path outside allowed directories"}), 403
    if not os.path.isdir(abs_dir):
        return jsonify({"error": "Directory not found"}), 404

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, fnames in os.walk(abs_dir):
            for fname in fnames:
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, abs_dir).replace("\\", "/")
                zf.write(fpath, arcname)
    buf.seek(0)
    zip_name = os.path.basename(abs_dir.rstrip("/\\")) + ".zip"
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=zip_name)


# ---------------------------------------------------------------------------
# Routes — Search across files
# ---------------------------------------------------------------------------

@app.route("/search_files")
@login_required
def search_files():
    output_dir = request.args.get("dir", "")
    query      = request.args.get("q", "").strip()
    if not output_dir or not query:
        return jsonify({"matches": []})

    abs_dir = safe_path(output_dir, MAIN_DIR)
    if abs_dir is None:
        return jsonify({"matches": [], "error": "Access denied"}), 403
    if not os.path.isdir(abs_dir):
        return jsonify({"matches": [], "error": "Directory not found"})

    matches = []
    try:
        pattern = re.compile(query, re.IGNORECASE)
    except re.error:
        pattern = re.compile(re.escape(query), re.IGNORECASE)

    for root, _dirs, fnames in os.walk(abs_dir):
        for fname in fnames:
            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, abs_dir).replace("\\", "/")
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if pattern.search(line):
                            matches.append({
                                "file":    rel,
                                "abs":     fpath,
                                "line":    lineno,
                                "content": line.rstrip("\n")[:300],
                            })
                            if len(matches) >= 500:
                                return jsonify({"matches": matches, "truncated": True})
            except (OSError, UnicodeDecodeError):
                pass

    return jsonify({"matches": matches})


# ---------------------------------------------------------------------------
# Routes — Findings summary
# ---------------------------------------------------------------------------

@app.route("/findings_summary")
@login_required
def findings_summary():
    output_dir = request.args.get("dir", "")
    if not output_dir:
        return jsonify({"error": "No dir specified"}), 400

    abs_dir = safe_path(output_dir, MAIN_DIR)
    if abs_dir is None:
        return jsonify({"error": "Access denied: path outside allowed directories"}), 403
    if not os.path.isdir(abs_dir):
        return jsonify({"error": "Directory not found"}), 404

    file_count  = 0
    line_count  = 0
    url_count   = 0
    ip_count    = 0
    sub_count   = 0
    sev_critical = 0
    sev_high     = 0
    sev_medium   = 0
    sev_low      = 0

    url_re  = re.compile(r'https?://', re.IGNORECASE)
    ip_re   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    sub_re  = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,}\b', re.IGNORECASE)
    crit_re = re.compile(r'\[critical\]|severity:\s*critical', re.IGNORECASE)
    high_re = re.compile(r'\[high\]|severity:\s*high',         re.IGNORECASE)
    med_re  = re.compile(r'\[medium\]|severity:\s*medium',     re.IGNORECASE)
    low_re  = re.compile(r'\[low\]|severity:\s*low',           re.IGNORECASE)

    for root, _dirs, fnames in os.walk(abs_dir):
        for fname in fnames:
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) == 0:
                    continue
                file_count += 1
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line_count   += 1
                        url_count    += len(url_re.findall(line))
                        ip_count     += len(ip_re.findall(line))
                        sub_count    += len(sub_re.findall(line))
                        sev_critical += len(crit_re.findall(line))
                        sev_high     += len(high_re.findall(line))
                        sev_medium   += len(med_re.findall(line))
                        sev_low      += len(low_re.findall(line))
            except OSError:
                pass

    return jsonify({
        "files":      file_count,
        "lines":      line_count,
        "urls":       url_count,
        "ips":        ip_count,
        "subdomains": sub_count,
        "vulns":      sev_critical + sev_high + sev_medium + sev_low,
        "critical":   sev_critical,
        "high":       sev_high,
        "medium":     sev_medium,
        "low":        sev_low,
    })


# ---------------------------------------------------------------------------
# Routes — System Stats (NEW)
# ---------------------------------------------------------------------------

def _read_proc_cpu():
    """Read CPU usage from /proc/stat (Linux fallback)."""
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        parts = line.split()
        # cpu user nice system idle iowait irq softirq steal guest guest_nice
        fields = [int(x) for x in parts[1:]]
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
        total = sum(fields)
        return idle, total
    except Exception:
        return None, None


_last_cpu_idle  = None
_last_cpu_total = None


def _get_cpu_percent():
    global _last_cpu_idle, _last_cpu_total
    idle, total = _read_proc_cpu()
    if idle is None:
        return 0.0
    if _last_cpu_idle is None:
        _last_cpu_idle  = idle
        _last_cpu_total = total
        return 0.0
    d_idle  = idle  - _last_cpu_idle
    d_total = total - _last_cpu_total
    _last_cpu_idle  = idle
    _last_cpu_total = total
    if d_total == 0:
        return 0.0
    return round(100.0 * (1.0 - d_idle / d_total), 1)


def _get_ram_info():
    """Read RAM info from /proc/meminfo (Linux fallback)."""
    try:
        info = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
        total_kb     = info.get("MemTotal", 0)
        available_kb = info.get("MemAvailable", info.get("MemFree", 0))
        used_kb  = total_kb - available_kb
        total_mb = total_kb // 1024
        used_mb  = used_kb  // 1024
        pct = round(100.0 * used_kb / total_kb, 1) if total_kb > 0 else 0.0
        return pct, used_mb, total_mb
    except Exception:
        return 0.0, 0, 0


@app.route("/system_stats")
@login_required
def system_stats():
    """Return CPU% and RAM% using psutil if available, else /proc fallback."""
    try:
        import psutil
        cpu_pct      = psutil.cpu_percent(interval=None)
        vm           = psutil.virtual_memory()
        ram_pct      = vm.percent
        ram_used_mb  = vm.used  // (1024 * 1024)
        ram_total_mb = vm.total // (1024 * 1024)
    except ImportError:
        cpu_pct = _get_cpu_percent()
        ram_pct, ram_used_mb, ram_total_mb = _get_ram_info()
    except Exception:
        cpu_pct = 0.0
        ram_pct, ram_used_mb, ram_total_mb = _get_ram_info()

    uptime_seconds = int(time.time() - APP_START_TIME)

    return jsonify({
        "cpu":          cpu_pct,
        "ram":          ram_pct,
        "ram_used_mb":  ram_used_mb,
        "ram_total_mb": ram_total_mb,
        "uptime_s":     uptime_seconds,
    })


# ---------------------------------------------------------------------------
# Routes — Notes (NEW)
# ---------------------------------------------------------------------------

@app.route("/notes", methods=["GET"])
@login_required
def get_notes():
    """Return all notes as {scan_id: text}."""
    return jsonify(load_json(NOTES_FILE, {}))


@app.route("/notes", methods=["POST"])
@login_required
def save_note():
    """Save a note for a scan. Body: {scan_id, text}."""
    data    = request.get_json() or {}
    scan_id = data.get("scan_id", "").strip()
    text    = data.get("text", "")
    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    notes = load_json(NOTES_FILE, {})
    if isinstance(notes, list):
        notes = {}
    notes[scan_id] = text
    save_json(NOTES_FILE, notes)
    return jsonify({"status": "saved", "scan_id": scan_id})


# ---------------------------------------------------------------------------
# Routes — Settings (NEW)
# ---------------------------------------------------------------------------

@app.route("/settings", methods=["GET"])
@login_required
def get_settings():
    """Return stored user settings as a flat object."""
    return jsonify(load_json(SETTINGS_FILE, {}))


@app.route("/settings", methods=["POST"])
@login_required
def save_settings():
    """Save user settings. Body is a flat object."""
    data = request.get_json() or {}
    save_json(SETTINGS_FILE, data)
    return jsonify({"status": "saved"})


# ---------------------------------------------------------------------------
# Routes — Schedules
# ---------------------------------------------------------------------------

def _scheduler_loop():
    """Background thread: fire scheduled scans when next_run arrives."""
    while True:
        try:
            schedules = load_json(SCHEDULES_FILE, [])
            changed   = False
            now       = datetime.now()

            for sched in schedules:
                if not sched.get("enabled", False):
                    continue
                next_run_str = sched.get("next_run", "")
                if not next_run_str:
                    continue
                try:
                    next_run = datetime.fromisoformat(next_run_str)
                except ValueError:
                    continue

                if now >= next_run:
                    # Fire scan
                    domains_text = sched.get("domains", "")
                    output_dir   = sched.get("output_dir", "scheduled_results")
                    if domains_text:
                        try:
                            tmp = tempfile.NamedTemporaryFile(
                                mode="w", suffix=".txt", delete=False, encoding="utf-8"
                            )
                            tmp.write(domains_text)
                            tmp.close()
                            domains_file = tmp.name
                            scan_id = str(uuid.uuid4())
                            cmd = [
                                sys.executable,
                                os.path.join(MAIN_DIR, "main.py"),
                                "-d", domains_file,
                                "-o", output_dir,
                            ]
                            out_q: queue.Queue = queue.Queue()
                            scan_meta = {
                                "queue":        out_q,
                                "running":      True,
                                "output_dir":   output_dir,
                                "domains_file": domains_file,
                                "process":      None,
                                "domains_text": domains_text,
                                "started_at":   now.isoformat(timespec="seconds"),
                            }
                            active_scans[scan_id] = scan_meta

                            def _run_scheduled(meta=scan_meta, sid=scan_id, df=domains_file):
                                try:
                                    proc = subprocess.Popen(
                                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1, cwd=MAIN_DIR,
                                        encoding="utf-8", errors="replace",
                                    )
                                    meta["process"] = proc
                                    for line in proc.stdout:
                                        meta["queue"].put(strip_ansi(line))
                                    proc.wait()
                                    final_status = "done" if proc.returncode == 0 else "error"
                                except Exception as exc:
                                    meta["queue"].put(f"[ERROR] {exc}\n")
                                    final_status = "error"
                                finally:
                                    meta["running"] = False
                                    meta["queue"].put(None)
                                    try:
                                        os.unlink(df)
                                    except OSError:
                                        pass
                                    hist = load_json(HISTORY_FILE, [])
                                    hist.insert(0, {
                                        "id":         sid,
                                        "target":     meta["domains_text"][:120],
                                        "output_dir": meta["output_dir"],
                                        "status":     final_status,
                                        "started_at": meta["started_at"],
                                        "ended_at":   datetime.now().isoformat(timespec="seconds"),
                                    })
                                    save_json(HISTORY_FILE, hist[:200])

                            threading.Thread(target=_run_scheduled, daemon=True).start()
                        except Exception:
                            pass

                    # Update next_run and last_run
                    interval = int(sched.get("interval_minutes", 60))
                    sched["last_run"]  = now.isoformat(timespec="seconds")
                    sched["next_run"]  = (now + timedelta(minutes=interval)).isoformat(timespec="seconds")
                    changed = True

            if changed:
                save_json(SCHEDULES_FILE, schedules)

        except Exception:
            pass

        time.sleep(30)


_scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
_scheduler_thread.start()


@app.route("/schedules", methods=["GET"])
@login_required
def get_schedules():
    return jsonify(load_json(SCHEDULES_FILE, []))


@app.route("/schedules", methods=["POST"])
@login_required
def create_schedule():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Schedule name required"}), 400

    interval = int(data.get("interval_minutes", 60))
    start_dt = data.get("start_datetime", "")
    try:
        next_run = datetime.fromisoformat(start_dt).isoformat(timespec="seconds") if start_dt else datetime.now().isoformat(timespec="seconds")
    except ValueError:
        next_run = datetime.now().isoformat(timespec="seconds")

    schedules = load_json(SCHEDULES_FILE, [])
    sched = {
        "id":               str(uuid.uuid4()),
        "name":             name,
        "domains":          data.get("domains", ""),
        "output_dir":       data.get("output_dir", "scheduled_results"),
        "interval_minutes": interval,
        "enabled":          True,
        "created_at":       datetime.now().isoformat(timespec="seconds"),
        "next_run":         next_run,
        "last_run":         None,
    }
    schedules.append(sched)
    save_json(SCHEDULES_FILE, schedules)
    return jsonify(sched), 201


@app.route("/schedules/<sched_id>", methods=["DELETE"])
@login_required
def delete_schedule(sched_id):
    schedules = load_json(SCHEDULES_FILE, [])
    schedules = [s for s in schedules if s.get("id") != sched_id]
    save_json(SCHEDULES_FILE, schedules)
    return jsonify({"status": "deleted"})


@app.route("/schedules/<sched_id>/toggle", methods=["POST"])
@login_required
def toggle_schedule(sched_id):
    schedules = load_json(SCHEDULES_FILE, [])
    for sched in schedules:
        if sched.get("id") == sched_id:
            sched["enabled"] = not sched.get("enabled", False)
            save_json(SCHEDULES_FILE, schedules)
            return jsonify({"enabled": sched["enabled"]})
    return jsonify({"error": "Not found"}), 404




@app.route("/export_report")
@login_required
def export_report():
    """Generate a Markdown report from a scan output directory."""
    output_dir = request.args.get("dir", "")
    if not output_dir:
        return jsonify({"error": "No dir specified"}), 400
    abs_dir = safe_path(output_dir, MAIN_DIR)
    if abs_dir is None or not os.path.isdir(abs_dir):
        return jsonify({"error": "Directory not found or access denied"}), 404

    lines = [
        f"# FalconHunter Scan Report",
        f"",
        f"**Target directory:** `{output_dir}`  ",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
    ]

    SECTION_MAP = [
        ("hosts/subs.txt",            "## Subdomains"),
        ("hosts/alive-hosts.txt",     "## Alive Hosts"),
        ("hosts/cnames.txt",          "## CNAME Records"),
        ("hosts/zone-transfer.txt",   "## Zone Transfer Results"),
        ("vuln/missing-dmarc.json",   "## Email Security (DMARC/SPF/DKIM)"),
        ("vuln/takeovers.json",       "## Subdomain Takeovers"),
        ("vuln/waf.txt",              "## WAF Detection"),
        ("vuln/nuclei-output.txt",    "## Nuclei Findings"),
        ("vuln/nuclei-dast-output.txt", "## Nuclei DAST Findings"),
        ("vuln/dalfox-xss.txt",       "## XSS Findings"),
        ("vuln/cors.txt",             "## CORS Findings"),
        ("vuln/crlf.txt",             "## CRLF Findings"),
        ("vuln/open-redirects.txt",   "## Open Redirects"),
        ("vuln/secrets.txt",          "## Secrets Found"),
        ("vuln/params-arjun.txt",     "## Hidden Parameters"),
        ("vuln/403-bypass.txt",       "## 403 Bypass Results"),
        ("urls/all-urls.txt",         "## Collected URLs"),
        ("urls/js-files.txt",         "## JavaScript Files"),
        ("urls/leaked-docs.txt",      "## Leaked Documents"),
    ]

    for rel_path, heading in SECTION_MAP:
        fpath = os.path.join(abs_dir, rel_path)
        if not os.path.isfile(fpath) or os.path.getsize(fpath) == 0:
            continue
        lines.append(heading)
        lines.append("")
        try:
            if rel_path.endswith(".json"):
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                lines.append("```json")
                lines.append(json.dumps(data, indent=2))
                lines.append("```")
            else:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    content_lines = [l.rstrip() for l in fh][:500]  # cap at 500 lines
                lines.append("```")
                lines.extend(content_lines)
                lines.append("```")
        except Exception:
            lines.append("*(error reading file)*")
        lines.append("")

    report_md = "\n".join(lines)
    scan_name = os.path.basename(output_dir.rstrip("/")) or "scan"
    filename  = f"falconhunter-report-{scan_name}.md"
    return Response(
        report_md,
        mimetype="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


_crypto_cache: dict = {"data": None, "ts": 0}
_CRYPTO_CACHE_TTL = 25  # seconds — slightly under the 30 s frontend refresh

import urllib.request as _ur
import urllib.parse as _up


def _binance_fetch(symbols: list[str]) -> list[dict]:
    """Fetch price + 24 h change + 7-day sparkline from Binance for a list of
    base symbols (e.g. ['BTC', 'ETH']).  Returns a list of dicts shaped the
    same way the frontend expects."""

    pairs = [s.upper() + "USDT" for s in symbols]

    # ── 24 h ticker ──────────────────────────────────────────────────
    encoded = _up.quote(json.dumps(pairs, separators=(',', ':')))
    ticker_url = f"https://api.binance.com/api/v3/ticker/24hr?symbols={encoded}"
    req = _ur.Request(ticker_url, headers={"User-Agent": "FalconHunter/1.0"})
    with _ur.urlopen(req, timeout=10) as r:
        tickers = {t["symbol"]: t for t in json.loads(r.read())}

    # ── klines for sparkline (42 × 4 h ≈ 7 days) ────────────────────
    sparklines: dict[str, list[float]] = {}
    for pair in pairs:
        try:
            kline_url = (
                f"https://api.binance.com/api/v3/klines"
                f"?symbol={pair}&interval=4h&limit=42"
            )
            kreq = _ur.Request(kline_url, headers={"User-Agent": "FalconHunter/1.0"})
            with _ur.urlopen(kreq, timeout=10) as kr:
                sparklines[pair] = [float(k[4]) for k in json.loads(kr.read())]
        except Exception:
            sparklines[pair] = []

    result = []
    for sym, pair in zip(symbols, pairs):
        t = tickers.get(pair, {})
        result.append({
            "id":                    sym.lower(),
            "symbol":                sym.upper(),
            "name":                  sym.upper(),
            "current_price":         float(t.get("lastPrice", 0)),
            "price_change_percentage_24h": float(t.get("priceChangePercent", 0)),
            "sparkline_in_7d":       {"price": sparklines.get(pair, [])},
        })
    return result


@app.route("/crypto_prices")
@login_required
def crypto_prices():
    symbols = request.args.get("symbols", "")
    if not symbols:
        return jsonify({"error": "symbols required"}), 400

    now = time.time()
    if _crypto_cache["data"] and (now - _crypto_cache["ts"]) < _CRYPTO_CACHE_TTL:
        return jsonify(_crypto_cache["data"])

    try:
        sym_list = [s.strip() for s in symbols.split(",") if s.strip()]
        data = _binance_fetch(sym_list)
        _crypto_cache["data"] = data
        _crypto_cache["ts"] = now
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
