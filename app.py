#!/usr/bin/env python3
"""
Unbound DNS Web GUI — FastAPI edition
Run with: uvicorn app:app --host 0.0.0.0 --port 8443 --ssl-keyfile ssl_key.pem --ssl-certfile ssl_cert.pem
       or: python3 app.py
"""

import os, re, glob, json, shutil, secrets, socket, platform
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Optional, List, Dict, Any
import subprocess

from fastapi import FastAPI, Request, Form, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, field_validator, model_validator
import uvicorn

from auth import init_creds, check_creds, change_password, get_active_sessions, set_active_session, clear_active_session

# ─────────────────────────────────────────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.resolve()

# Stable secret key persisted across restarts
_sk_file = BASE_DIR / ".secret_key"
if not _sk_file.exists():
    _sk_file.write_text(secrets.token_hex(32))
    _sk_file.chmod(0o600)
SECRET_KEY = os.environ.get("SECRET_KEY", _sk_file.read_text().strip())

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # disable API docs in prod
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    max_age=86400,
    same_site="lax",
    https_only=False,   # set True when behind TLS (handled at startup)
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Add url_for to Jinja2 globals (Flask-compatible shim for templates)
templates.env.globals["url_for"] = lambda endpoint, **kw: (
    f"/static/{kw.get('filename','')}" if endpoint == "static" else f"/{endpoint}"
)

# ── Load .env (simple built-in parser — no extra dependencies) ───────────────
def _load_dotenv(env_path: Path) -> None:
    """Read KEY=VALUE pairs from .env, set into os.environ if not already set."""
    if not env_path.exists():
        return
    with open(env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _k, _, _v = _line.partition("=")
            _k = _k.strip(); _v = _v.strip().strip('"').strip("'")
            if _k and _k not in os.environ:
                os.environ[_k] = _v

_load_dotenv(BASE_DIR / ".env")

def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)

# ── Resolved paths (override any of these in .env) ───────────────────────────
DEFAULT_CONFIG_FILE = _env("DEFAULT_CONFIG_FILE", "/etc/unbound/unbound.conf")
DEFAULT_CONFIG_DIR  = _env("DEFAULT_CONFIG_DIR",  "/etc/unbound/unbound.conf.d/")
ALLOWED_CONFIG_DIRS = [DEFAULT_CONFIG_DIR, "/etc/unbound/"]
BACKUP_DIR          = str(Path(_env("BACKUP_DIR", str(BASE_DIR / "backups"))).resolve())
UNBOUND_SERVER_KEY  = _env("UNBOUND_SERVER_KEY",  "/etc/unbound/unbound_server.key")
UNBOUND_SERVER_PEM  = _env("UNBOUND_SERVER_PEM",  "/etc/unbound/unbound_server.pem")
UNBOUND_CONTROL_KEY = _env("UNBOUND_CONTROL_KEY", "/etc/unbound/unbound_control.key")
UNBOUND_CONTROL_PEM = _env("UNBOUND_CONTROL_PEM", "/etc/unbound/unbound_control.pem")
HTTPS_ENABLED       = _env("HTTPS_ENABLED", "true").lower() not in {"false","0","no"}
HTTP_PORT           = int(_env("HTTP_PORT",  "8080"))
HTTPS_PORT          = int(_env("HTTPS_PORT", "8443"))

os.makedirs(BACKUP_DIR, exist_ok=True)

init_creds()

# ─────────────────────────────────────────────────────────────────────────────
#  SECURITY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_hex(32)
    return request.session["csrf_token"]

def _verify_csrf(request: Request):
    """Dependency: verify CSRF token on state-changing requests."""
    token = request.headers.get("X-CSRF-Token", "")
    expected = request.session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="CSRF validation failed")

def _login_required(request: Request):
    """Dependency: redirect to login if not authenticated."""
    if not request.session.get("logged_in"):
        raise HTTPException(status_code=307, headers={"Location": f"/login?next={request.url.path}"})
    # Single-session enforcement: verify session token matches server-side record
    username = request.session.get("username", "")
    sess_token = request.session.get("session_token", "")
    server_token = get_active_sessions().get(username, "")
    if not server_token or not secrets.compare_digest(sess_token, server_token):
        request.session.clear()
        raise HTTPException(status_code=307, headers={"Location": "/login?next=/"})
    return username

def _template(request: Request, name: str, ctx: dict):
    ctx["csrf_token"] = _csrf_token(request)
    ctx.setdefault("session", request.session)
    return templates.TemplateResponse(request=request, name=name, context=ctx)

# ─────────────────────────────────────────────────────────────────────────────
#  INPUT VALIDATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_HOSTNAME_RE  = re.compile(r'^[a-zA-Z0-9._\-]{1,253}$')
_IP_RE        = re.compile(r'^[0-9a-fA-F.:]{2,45}$')
_RECORD_TYPES = {"A","AAAA","MX","TXT","NS","CNAME","SOA","SRV","PTR","ANY"}
_SAFE_FNAME   = re.compile(r'^[a-zA-Z0-9_\-]+\.conf$')

def _safe_target(value: str) -> str:
    """Validate a DNS target (hostname or IP) to prevent injection."""
    v = value.strip()[:253]
    if _HOSTNAME_RE.match(v) or _IP_RE.match(v):
        return v
    raise ValueError(f"Invalid target: {v!r}")

def _safe_config_path(path: str) -> str:
    """Ensure config path stays within allowed directories."""
    real = os.path.realpath(path)
    for d in ALLOWED_CONFIG_DIRS:
        if real.startswith(d) and real.endswith(".conf"):
            return real
    if real == os.path.realpath(DEFAULT_CONFIG_FILE):
        return real
    raise ValueError(f"Config path not allowed: {path!r}")

def _safe_filename(name: str) -> str:
    name = name.strip()
    if not name.endswith(".conf"):
        name += ".conf"
    if not _SAFE_FNAME.match(name):
        raise ValueError(f"Invalid filename: {name!r}")
    return name

def _safe_backup_filename(name: str) -> str:
    name = os.path.basename(name.strip())
    if not re.match(r'^[a-zA-Z0-9_\-\.]+\.conf$', name):
        raise ValueError(f"Invalid backup filename: {name!r}")
    return name

# ─────────────────────────────────────────────────────────────────────────────
#  SUBPROCESS HELPERS  (no shell=True anywhere)
# ─────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd: list, timeout: int = 15) -> tuple[str, str, int]:
    """Run a command safely using a list (no shell expansion)."""
    try:
        r = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), 1

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM INFO  (Python-native, no shell pipelines)
# ─────────────────────────────────────────────────────────────────────────────

def _read_file(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text()
    except Exception:
        return default

def get_system_info() -> dict:
    info: Dict[str, Any] = {}

    info["hostname"] = socket.gethostname()
    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        info["fqdn"] = info["hostname"]

    # OS name from /etc/os-release
    os_rel = _read_file("/etc/os-release")
    for line in os_rel.splitlines():
        if line.startswith("PRETTY_NAME="):
            info["os"] = line.split("=", 1)[1].strip().strip('"')
            break
    else:
        info["os"] = platform.system()

    info["kernel"] = platform.release()
    info["arch"]   = platform.machine()

    # Uptime from /proc/uptime
    try:
        uptime_secs = float(_read_file("/proc/uptime").split()[0])
        d, rem = divmod(int(uptime_secs), 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        info["uptime_raw"] = f"up {d}d {h}h {m}m" if d else f"up {h}h {m}m"
        boot_ts = datetime.fromtimestamp(datetime.now().timestamp() - uptime_secs)
        info["uptime_since"] = boot_ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        info["uptime_raw"] = "—"
        info["uptime_since"] = "—"

    # Load average
    try:
        la = os.getloadavg()
        info["load"] = f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}"
    except Exception:
        info["load"] = "—"

    info["cpu_count"] = str(os.cpu_count() or 1)

    # CPU model
    cpu_model = ""
    for line in _read_file("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    info["cpu_model"] = cpu_model

    # Memory from /proc/meminfo
    meminfo = {}
    for line in _read_file("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB → bytes
    if "MemTotal" in meminfo:
        total = meminfo["MemTotal"]
        avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used  = total - avail
        info["mem_total"] = total
        info["mem_used"]  = used
        info["mem_free"]  = meminfo.get("MemFree", 0)
        info["mem_avail"] = avail
        info["mem_pct"]   = round(used / total * 100, 1) if total else 0

    # Disk
    try:
        disk = shutil.disk_usage("/")
        info["disk_total"] = disk.total
        info["disk_used"]  = disk.used
        info["disk_free"]  = disk.free
        info["disk_pct"]   = str(round(disk.used / disk.total * 100, 1)) if disk.total else "0"
    except Exception:
        pass

    # Network interfaces via 'ip -o addr show' (list, no shell)
    ifaces = []
    out, _, rc = run_cmd(["ip", "-o", "addr", "show"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] != "lo":
                ifaces.append({"name": parts[1], "addr": parts[3]})
    info["interfaces"] = ifaces
    info["datetime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return info


def get_unbound_info() -> dict:
    info: Dict[str, Any] = {}

    # Status
    status_out, _, _ = run_cmd(["systemctl", "is-active", "unbound"])
    info["active"]  = status_out == "active"
    info["status"]  = status_out or "unknown"

    enabled_out, _, _ = run_cmd(["systemctl", "is-enabled", "unbound"])
    info["enabled"] = enabled_out.lower().strip() == "enabled"

    # Version
    ver_out, ver_err, _ = run_cmd(["unbound", "-V"])
    info["version"] = (ver_out or ver_err).splitlines()[0] if (ver_out or ver_err) else "—"

    # PID
    pid_out, _, _ = run_cmd(["systemctl", "show", "unbound", "--property=MainPID", "--value"])
    info["pid"] = pid_out.strip()

    info["config_file"] = DEFAULT_CONFIG_FILE

    # Stats from unbound-control
    stats: Dict[str, str] = {}
    stat_out, stat_err, stat_rc = run_cmd(["unbound-control", "stats_noreset"])
    if stat_rc == 0:
        for line in stat_out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                stats[k.strip()] = v.strip()
    elif stat_rc == 127:
        # unbound-control not found
        info["stats_error"] = "unbound-control not found"
    else:
        info["stats_error"] = stat_err or "unbound-control failed"

    info["stats"] = stats

    def _int(key: str) -> int:
        try: return int(float(stats.get(key, 0)))
        except: return 0

    def _float(key: str) -> float:
        try: return float(stats.get(key, 0))
        except: return 0.0

    info["total_queries"]     = _int("total.num.queries")
    info["cache_hits"]        = _int("total.num.cachehits")
    info["cache_misses"]      = _int("total.num.cachemiss")
    info["prefetch"]          = _int("total.num.prefetch")
    info["recursion_avg"]     = round(_float("total.recursion.time.avg") * 1000, 2)
    info["cache_hit_pct"]     = round(
        info["cache_hits"] / info["total_queries"] * 100, 1
    ) if info["total_queries"] > 0 else 0
    info["rrset_cache_count"] = _int("rrset.cache.count")
    info["msg_cache_count"]   = _int("msg.cache.count")
    info["infra_cache"]       = _int("infra.cache.count")
    info["key_cache"]         = _int("key.cache.count")
    info["unwanted_replies"]  = _int("unwanted.replies")
    info["unwanted_queries"]  = _int("unwanted.queries")

    ts_out, _, _ = run_cmd(["systemctl", "show", "unbound", "--property=ActiveEnterTimestamp", "--value"])
    info["started"] = ts_out.strip() or "—"

    # Memory usage of unbound process
    mem_kb = 0
    if info["pid"] and info["pid"] != "0":
        try:
            mem_out, _, _ = run_cmd(["cat", f"/proc/{info['pid']}/status"])
            for line in mem_out.splitlines():
                if line.startswith("VmRSS:"):
                    mem_kb = int(line.split()[1])
                    break
        except Exception:
            pass
    info["mem_kb"] = mem_kb

    return info


def get_log_lines(n: int = 100) -> str:
    out, _, rc = run_cmd(["journalctl", "-u", "unbound", "--no-pager",
                          "-n", str(min(n, 1000)), "--output=short-iso"])
    return out


def get_config_file(request: Request) -> str:
    return request.session.get("config_file", DEFAULT_CONFIG_FILE)


# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG PARSING / BUILDING  (unchanged logic, kept server-side)
# ─────────────────────────────────────────────────────────────────────────────

def parse_unbound_conf(filepath: str) -> dict:
    config = {"server": {}, "forward_zones": [], "local_zones": [],
              "local_data": [], "access_control": [], "raw": ""}
    if not os.path.exists(filepath):
        return config
    try:
        with open(filepath, "r") as f:
            content = f.read()
        config["raw"] = content
        current_section = None
        current_block: dict = {}

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped == "server:":
                current_section = "server"; continue
            elif stripped == "forward-zone:":
                if current_section == "forward-zone" and current_block:
                    config["forward_zones"].append(current_block)
                current_section = "forward-zone"
                current_block = {"name": "", "addrs": [], "tls": False, "first": False}
                continue

            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip(); val = val.strip().strip('"').strip("'")
                if current_section == "server":
                    if key == "access-control":   config["access_control"].append(val)
                    elif key == "local-zone":     config["local_zones"].append(val)
                    elif key == "local-data":     config["local_data"].append(val)
                    else:                         config["server"][key] = val
                elif current_section == "forward-zone":
                    if key == "name":             current_block["name"] = val
                    elif key == "forward-addr":   current_block["addrs"].append(val)
                    elif key == "forward-tls-upstream": current_block["tls"] = val.lower() == "yes"
                    elif key == "forward-first":  current_block["first"] = val.lower() == "yes"

        if current_section == "forward-zone" and current_block:
            config["forward_zones"].append(current_block)
    except Exception as e:
        config["error"] = str(e)
    return config


def build_unbound_conf(data: dict) -> str:
    lines = ["# Unbound DNS Configuration", "# Generated by Unbound Web GUI",
             "# " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "", "server:"]

    bool_opts = {
        "do-ip4","do-ip6","do-udp","do-tcp","do-daemonize","hide-identity","hide-version",
        "hide-trustanchor","harden-glue","harden-dnssec-stripped","harden-below-nxdomain",
        "harden-referral-path","harden-algo-downgrade","use-caps-for-id","prefetch",
        "prefetch-key","qname-minimisation","aggressive-nsec","minimal-responses",
        "rrset-roundrobin","log-queries","log-replies","use-syslog","extended-statistics",
        "statistics-cumulative","val-permissive-mode","ignore-cd-flag","so-reuseport",
        "serve-expired","serve-original-ttl",
    }

    def boolval(v: str) -> str:
        return "yes" if str(v).lower() in {"yes","on","true","1"} else "no"

    def emit(key: str, val: str):
        if not val: return
        if key in bool_opts:
            lines.append(f"    {key}: {boolval(val)}")
        else:
            # Sanitize: strip newlines and quotes to prevent config injection
            val = re.sub(r'[\r\n"\'\\]', "", val)[:500]
            lines.append(f"    {key}: {val}")

    for key in ["verbosity","num-threads","port","interface","outgoing-interface",
                "do-ip4","do-ip6","do-udp","do-tcp"]:
        emit(key, data.get(key, ""))

    lines += ["", "    # Security & Hardening"]
    for key in ["hide-identity","hide-version","hide-trustanchor","harden-glue",
                "harden-dnssec-stripped","harden-below-nxdomain","harden-referral-path",
                "harden-algo-downgrade","use-caps-for-id","qname-minimisation",
                "aggressive-nsec","val-permissive-mode","ignore-cd-flag"]:
        emit(key, data.get(key, ""))

    lines += ["", "    # Performance"]
    for key in ["prefetch","prefetch-key","rrset-roundrobin","minimal-responses",
                "so-reuseport","serve-expired","cache-min-ttl","cache-max-ttl",
                "msg-cache-size","rrset-cache-size","num-queries-per-thread",
                "outgoing-range","edns-buffer-size","max-udp-size",
                "infra-cache-numhosts","infra-host-ttl"]:
        emit(key, data.get(key, ""))

    lines += ["", "    # Logging"]
    for key in ["log-queries","log-replies","use-syslog","extended-statistics",
                "statistics-cumulative","statistics-interval","logfile"]:
        emit(key, data.get(key, ""))

    lines += ["", "    # Access Control"]
    for ac in data.get("access_control", []):
        if ac.strip():
            ac_clean = re.sub(r'[\r\n"\'\\]', "", ac.strip())[:200]
            lines.append(f"    access-control: {ac_clean}")

    for key in ["module-config","root-hints","auto-trust-anchor-file","pidfile",
                "username","directory","chroot","identity","version"]:
        val = data.get(key, "")
        if val:
            val_clean = re.sub(r'[\r\n"\'\\]', "", val.strip())[:500]
            lines.append(f'    {key}: "{val_clean}"')

    lines += ["", "    # Local Zones"]
    for lz in data.get("local_zones", []):
        lz_clean = re.sub(r'[\r\n"\'\\]', "", lz.strip())[:500]
        if lz_clean: lines.append(f"    local-zone: {lz_clean}")

    lines += ["", "    # Local Data"]
    for ld in data.get("local_data", []):
        ld_clean = re.sub(r'[\r\n"\'\\]', "", ld.strip())[:500]
        if ld_clean: lines.append(f'    local-data: "{ld_clean}"')

    for zone in data.get("forward_zones", []):
        if zone.get("name"):
            name_clean = re.sub(r'[\r\n"\'\\]', "", zone["name"].strip())[:253]
            lines += ["", "forward-zone:", f'    name: "{name_clean}"']
            for addr in zone.get("addrs", []):
                addr_clean = re.sub(r'[^\w.:@#\-]', "", addr.strip())[:50]
                if addr_clean: lines.append(f"    forward-addr: {addr_clean}")
            if zone.get("tls"):  lines.append("    forward-tls-upstream: yes")
            if zone.get("first"): lines.append("    forward-first: yes")

    # Always preserve remote-control so unbound-control / stats always work
    lines += ["", "remote-control:", "    control-enable: yes", ""]

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
#  TAB → KEY MAPPING  (which server: keys belong to each config tab)
# ─────────────────────────────────────────────────────────────────────────────

ALL_TABS: set = {"basic","security","performance","logging","access","forwarding","local","dnssec","advanced"}

TAB_SERVER_KEYS: Dict[str, List[str]] = {
    "basic":       ["interface","port","outgoing-interface","do-ip4","do-ip6","do-udp","do-tcp",
                    "num-threads","verbosity","do-daemonize","username","directory","chroot",
                    "pidfile","root-hints"],
    "security":    ["hide-identity","hide-version","hide-trustanchor","identity","version",
                    "harden-glue","harden-dnssec-stripped","harden-below-nxdomain",
                    "harden-referral-path","harden-algo-downgrade","harden-short-bufsize",
                    "harden-large-queries","use-caps-for-id","qname-minimisation",
                    "qname-minimisation-strict","aggressive-nsec","minimal-responses",
                    "do-not-query-localhost","ratelimit","ip-ratelimit",
                    "unwanted-reply-threshold","private-address","ignore-cd-flag"],
    "performance": ["prefetch","prefetch-key","cache-min-ttl","cache-max-ttl",
                    "cache-max-negative-ttl","serve-expired","serve-expired-ttl",
                    "rrset-roundrobin","msg-cache-size","rrset-cache-size","neg-cache-size",
                    "msg-buffer-size","outgoing-range","num-queries-per-thread",
                    "so-rcvbuf","so-sndbuf","edns-buffer-size","so-reuseport",
                    "infra-cache-numhosts","infra-host-ttl","jostle-timeout"],
    "logging":     ["use-syslog","logfile","log-queries","log-replies","log-tag-queryreply",
                    "log-local-actions","log-servfail","extended-statistics",
                    "statistics-interval","statistics-cumulative","log-identity"],
    "access":      [],   # uses access_control list
    "forwarding":  [],   # uses forward_zones list
    "local":       [],   # uses local_zones + local_data lists
    "dnssec":      ["module-config","auto-trust-anchor-file","trust-anchor-file",
                    "val-permissive-mode","val-clean-additional","add-holddown",
                    "del-holddown","keep-missing","disable-dnssec-lame-check"],
    "advanced":    ["dns64","dns64-prefix","dns64-synthall","tls-upstream","tls-cert-bundle",
                    "target-fetch-policy","unblock-lan-zones","insecure-lan-zones",
                    "ip-transparent","delay-close","private-domain"],
}

_BOOL_OPTS_SET: set = {
    "do-ip4","do-ip6","do-udp","do-tcp","do-daemonize","hide-identity","hide-version",
    "hide-trustanchor","harden-glue","harden-dnssec-stripped","harden-below-nxdomain",
    "harden-referral-path","harden-algo-downgrade","harden-short-bufsize","harden-large-queries",
    "use-caps-for-id","qname-minimisation","qname-minimisation-strict","aggressive-nsec",
    "minimal-responses","do-not-query-localhost","ignore-cd-flag","prefetch","prefetch-key",
    "serve-expired","rrset-roundrobin","log-queries","log-replies","log-tag-queryreply",
    "log-local-actions","log-servfail","use-syslog","extended-statistics",
    "statistics-cumulative","val-permissive-mode","val-clean-additional",
    "disable-dnssec-lame-check","dns64","dns64-synthall","tls-upstream",
    "unblock-lan-zones","insecure-lan-zones","ip-transparent","so-reuseport",
}

# ── include-section markers ───────────────────────────────────────────────────
_INCL_START = "# gui-includes-start"
_INCL_END   = "# gui-includes-end"
_INCL_HDR   = "# --- GUI managed includes - do not edit this section manually ---"


def _clean_error(context: str, raw: str = "") -> str:
    """Strip unbound timestamps/PIDs from error, return short human message."""
    if not raw:
        return context
    clean = re.sub(r"\[\d{7,}\]", "", raw)
    clean = re.sub(r"\w[\w\-]*\[\d+:\d+\]\s*", "", clean)
    clean = re.sub(r"[ \t]+", " ", clean).strip()
    clean = re.sub(r"\n+", " | ", clean)
    if len(clean) > 300:
        clean = clean[:297] + "..."
    return f"{context} — {clean}" if clean else context


def parse_file_meta(filepath: str) -> dict:
    """Read # gui-allowed: and # gui-description: header lines."""
    meta: Dict[str, Any] = {
        "is_main":      filepath == DEFAULT_CONFIG_FILE,
        "allowed_tabs": [],
        "description":  "",
        "filename":     os.path.basename(filepath),
        "filepath":     filepath,
    }
    if meta["is_main"]:
        return meta
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("#"):
                    break
                if line.startswith("# gui-allowed:"):
                    tabs_raw = line.split(":", 1)[1].strip()
                    meta["allowed_tabs"] = [
                        t.strip() for t in tabs_raw.split(",")
                        if t.strip() in ALL_TABS
                    ]
                elif line.startswith("# gui-description:"):
                    meta["description"] = line.split(":", 1)[1].strip()[:200]
    except Exception:
        pass
    return meta


def parse_includes(content: str) -> List[Dict]:
    """Extract {path, enabled} entries from the gui-includes section."""
    entries: List[Dict] = []
    in_sec = False
    for line in content.splitlines():
        s = line.strip()
        if s == _INCL_START:   in_sec = True;  continue
        if s == _INCL_END:     break
        if not in_sec:         continue
        enabled = not s.startswith("#")
        m = re.search(r'include:\s*"([^"]+)"', s)
        if m:
            entries.append({"path": m.group(1), "enabled": enabled})
    return entries


def build_includes_section(files: List[Dict]) -> str:
    rows = ["", _INCL_HDR, _INCL_START]
    for f in files:
        if f.get("enabled", True):
            rows.append(f'include: "{f["path"]}"')
        else:
            rows.append(f'# include: "{f["path"]}"  # disabled')
    rows.append(_INCL_END)
    return "\n".join(rows)


def _splice_includes(content: str, includes: List[Dict]) -> str:
    """Replace or append the gui-includes section in a config string."""
    new_section = build_includes_section(includes)
    if _INCL_START in content:
        return re.sub(
            r"\n" + re.escape(_INCL_HDR) + r".*?" + re.escape(_INCL_END),
            new_section, content, flags=re.DOTALL,
        )
    return content.rstrip("\n") + "\n" + new_section + "\n"


def add_to_includes(conf_path: str, new_file_path: str) -> bool:
    """Append new_file_path to gui-includes in conf_path if not already there."""
    try:
        content  = Path(conf_path).read_text() if os.path.exists(conf_path) else ""
        includes = parse_includes(content)
        if any(f["path"] == new_file_path for f in includes):
            return True
        includes.append({"path": new_file_path, "enabled": True})
        new_content = _splice_includes(content, includes)
        proc = subprocess.run(["sudo", "tee", conf_path],
                              input=new_content, capture_output=True, text=True)
        return proc.returncode == 0
    except Exception:
        return False


def _san(v: str) -> str:
    return re.sub(r'[\r\n"\'\\]', "", str(v).strip())[:500]


def _bv(v: str) -> str:
    return "yes" if str(v).lower() in {"yes","on","true","1"} else "no"


def build_subfile_conf(data: dict, allowed_tabs: List[str], description: str = "") -> str:
    """Build a partial conf that only covers the tabs listed in allowed_tabs."""
    header = [f"# gui-allowed: {','.join(allowed_tabs)}"]
    if description:
        header.append(f"# gui-description: {_san(description)}")
    header += [f"# Generated by Unbound Web GUI — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]

    server_lines: List[str] = []
    for tab in allowed_tabs:
        for key in TAB_SERVER_KEYS.get(tab, []):
            val = data.get(key, "")
            if not val:
                continue
            if key in _BOOL_OPTS_SET:
                server_lines.append(f"    {key}: {_bv(val)}")
            else:
                server_lines.append(f"    {key}: {_san(val)}")
        if tab == "access":
            for ac in data.get("access_control", []):
                c = _san(ac)
                if c:
                    server_lines.append(f"    access-control: {c}")
        if tab == "local":
            for lz in data.get("local_zones", []):
                c = _san(lz)
                if c:
                    server_lines.append(f"    local-zone: {c}")
            for ld in data.get("local_data", []):
                c = _san(ld)
                if c:
                    server_lines.append(f'    local-data: "{c}"')

    lines = header[:]
    if server_lines:
        lines += ["server:"] + server_lines

    if "forwarding" in allowed_tabs:
        for zone in data.get("forward_zones", []):
            if zone.get("name"):
                n = _san(zone["name"])
                lines += ["", "forward-zone:", f'    name: "{n}"']
                for addr in zone.get("addrs", []):
                    a = re.sub(r'[^\w.:@#\-]', "", addr.strip())[:50]
                    if a:
                        lines.append(f"    forward-addr: {a}")
                if zone.get("tls"):   lines.append("    forward-tls-upstream: yes")
                if zone.get("first"): lines.append("    forward-first: yes")

    return "\n".join(lines) + "\n"


def _write_config(cfg_file: str, conf_text: str) -> None:
    """Backup, write via sudo tee, then validate with unbound-checkconf."""
    if os.path.exists(cfg_file):
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        try:
            shutil.copy2(cfg_file, cfg_file + f".bak.{ts}")
        except Exception:
            pass
    proc = subprocess.run(["sudo", "tee", cfg_file],
                          input=conf_text, capture_output=True, text=True)
    if proc.returncode != 0:
        raise HTTPException(500, detail=_clean_error("Write failed", proc.stderr))
    _, val_err, val_rc = run_cmd(["unbound-checkconf"])
    if val_rc != 0:
        raise HTTPException(422, detail=_clean_error("Config validation failed", val_err))


# ─────────────────────────────────────────────────────────────────────────────
#  PYDANTIC REQUEST MODELS
# ─────────────────────────────────────────────────────────────────────────────

class ServiceAction(str):
    ALLOWED = {"start","stop","restart","reload","enable","disable"}

class DebugPayload(BaseModel):
    tool: str
    target: str = ""
    record: str = "A"

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        allowed = {"ping","trace","whois","nslookup","dig","dig_short","dig_trace",
                   "dnssec","reverse","check_control","check_conf","stats",
                   "local_zones","local_data","dump_cache","lookup"}
        if v not in allowed:
            raise ValueError(f"Unknown tool: {v!r}")
        return v

    @field_validator("record")
    @classmethod
    def validate_record(cls, v: str) -> str:
        if v.upper() not in _RECORD_TYPES:
            raise ValueError(f"Invalid record type: {v!r}")
        return v.upper()

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not v: return v
        v = v.strip()[:253]
        if _HOSTNAME_RE.match(v) or _IP_RE.match(v):
            return v
        raise ValueError(f"Invalid target: {v!r}")


class ConfigFilePayload(BaseModel):
    file: str

    @field_validator("file")
    @classmethod
    def validate_file(cls, v: str) -> str:
        return _safe_config_path(v)


class CreateFilePayload(BaseModel):
    filename: str
    allowed_tabs: List[str] = []
    description: str = ""
    move_existing: bool = False

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        return _safe_filename(v)

    @field_validator("allowed_tabs")
    @classmethod
    def validate_tabs(cls, v: List[str]) -> List[str]:
        return [t.strip() for t in v if t.strip() in ALL_TABS]

    @field_validator("description")
    @classmethod
    def sanitize_desc(cls, v: str) -> str:
        return re.sub(r'[\r\n]', ' ', v.strip())[:200]


class IncludeFile(BaseModel):
    path: str
    enabled: bool = True

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        real = os.path.realpath(v)
        if not real.startswith(os.path.realpath(DEFAULT_CONFIG_DIR)):
            raise ValueError(f"Path not in allowed directory: {v!r}")
        if not real.endswith(".conf"):
            raise ValueError("Must be a .conf file")
        return real


class IncludesSavePayload(BaseModel):
    files: List[IncludeFile]


class BackupPayload(BaseModel):
    label: str = "manual"

    @field_validator("label")
    @classmethod
    def sanitize_label(cls, v: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-]", "_", v.strip())[:64] or "manual"


class RestorePayload(BaseModel):
    filename: str

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        return _safe_backup_filename(v)


class DeleteBackupPayload(BaseModel):
    filename: str

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        return _safe_backup_filename(v)


class DeleteFilePayload(BaseModel):
    file: str

    @field_validator("file")
    @classmethod
    def validate_file(cls, v: str) -> str:
        real = os.path.realpath(v)
        if not real.startswith(DEFAULT_CONFIG_DIR) or not real.endswith(".conf"):
            raise ValueError(f"Cannot delete: {v!r}")
        if real == os.path.realpath(DEFAULT_CONFIG_FILE):
            raise ValueError("Cannot delete the main config file")
        return real


class PasswordPayload(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password too long")
        return v


class RawConfigPayload(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        if len(v) > 1_000_000:  # 1 MB sanity limit
            raise ValueError("Config content too large")
        return v


# ─────────────────────────────────────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, next: str = "/"):
    if request.session.get("logged_in"):
        return RedirectResponse("/", status_code=302)
    return _template(request, "login.html", {"error": None, "next": next, "last_username": ""})


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(default="/"),
):
    # Basic sanitization
    username = username.strip()[:64]
    next_url = next if (next.startswith("/") and len(next) <= 200) else "/"

    if check_creds(username, password):
        # Generate new session token — invalidates any existing session
        token = secrets.token_hex(32)
        set_active_session(username, token)

        request.session.clear()
        request.session["logged_in"] = True
        request.session["username"]  = username
        request.session["session_token"] = token
        _csrf_token(request)  # generate fresh CSRF token

        return RedirectResponse(next_url, status_code=302)

    return _template(request, "login.html", {
        "error": "Invalid username or password.",
        "next": next_url,
        "last_username": username,
    })


@app.get("/logout")
async def logout(request: Request):
    username = request.session.get("username", "")
    if username:
        clear_active_session(username)
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.post("/api/change_password")
async def api_change_password(
    request: Request,
    payload: PasswordPayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    change_password(request.session.get("username", "admin"), payload.password)
    return {"success": True}


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, _user: str = Depends(_login_required)):
    return _template(request, "home.html", {
        "sys": get_system_info(),
        "unb": get_unbound_info(),
        "active_tab": "home",
    })


@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request, _user: str = Depends(_login_required)):
    cfg_file  = get_config_file(request)
    is_main   = (cfg_file == DEFAULT_CONFIG_FILE)
    parsed    = parse_unbound_conf(cfg_file)
    file_meta = parse_file_meta(cfg_file)
    conf_d    = sorted(glob.glob(DEFAULT_CONFIG_DIR + "*.conf"))

    if not is_main:
        # Merge main config values so disabled tabs still show readable content
        main_p = parse_unbound_conf(DEFAULT_CONFIG_FILE)
        merged_server = {**main_p.get("server", {}), **parsed.get("server", {})}
        parsed["server"] = merged_server
        allowed = set(file_meta.get("allowed_tabs", []))
        if "access"     not in allowed: parsed["access_control"] = main_p.get("access_control", [])
        if "forwarding" not in allowed: parsed["forward_zones"]  = main_p.get("forward_zones", [])
        if "local"      not in allowed:
            parsed["local_zones"] = main_p.get("local_zones", [])
            parsed["local_data"]  = main_p.get("local_data", [])

    # For UI-prefs tab: current includes list
    main_content  = Path(DEFAULT_CONFIG_FILE).read_text() if os.path.exists(DEFAULT_CONFIG_FILE) else ""
    includes_list = parse_includes(main_content)
    for inc in includes_list:
        # FIX: always populate 'exists' — missing this key caused Jinja2 to treat
        # it as Undefined (falsy), so `not inc.exists` was always True → "file missing"
        inc["exists"] = os.path.exists(inc["path"])
        inc["meta"]   = parse_file_meta(inc["path"])

    import json as _json
    return _template(request, "config.html", {
        "cfg":            parsed,
        "cfg_file":       cfg_file,
        "cfg_filename":   os.path.basename(cfg_file),
        "conf_d_files":   conf_d,
        "active_tab":     "config",
        "file_meta":      file_meta,
        "is_main_config": is_main,
        "includes_list":  includes_list,
        "file_meta_json": _json.dumps(file_meta),
        "all_tabs_json":  _json.dumps(sorted(ALL_TABS)),
        "tab_labels_json": _json.dumps({
            "basic":"Basic","security":"Security","performance":"Performance",
            "logging":"Logging","access":"Access Control","forwarding":"Forwarding",
            "local":"Local Zones","dnssec":"DNSSEC","advanced":"Advanced",
        }),
    })


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, _user: str = Depends(_login_required)):
    cfg_file = get_config_file(request)
    conf_d   = sorted(glob.glob(DEFAULT_CONFIG_DIR + "*.conf"))
    return _template(request, "settings.html", {
        "cfg_file": cfg_file, "conf_d_files": conf_d,
        "all_conf": conf_d, "active_tab": "settings",
    })


@app.get("/debug", response_class=HTMLResponse)
async def debug_page(request: Request, _user: str = Depends(_login_required)):
    return _template(request, "debug.html", {"active_tab": "debug"})


# ─────────────────────────────────────────────────────────────────────────────
#  API — STATUS / STATS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def api_stats(_user: str = Depends(_login_required)):
    info = get_unbound_info()
    return {
        "total_queries":     info["total_queries"],
        "cache_hits":        info["cache_hits"],
        "cache_misses":      info["cache_misses"],
        "cache_hit_pct":     info["cache_hit_pct"],
        "recursion_avg":     info["recursion_avg"],
        "prefetch":          info["prefetch"],
        "rrset_cache_count": info["rrset_cache_count"],
        "msg_cache_count":   info["msg_cache_count"],
        "infra_cache":       info["infra_cache"],
        "key_cache":         info["key_cache"],
        "unwanted_replies":  info["unwanted_replies"],
        "unwanted_queries":  info["unwanted_queries"],
        "status":            info["status"],
        "active":            info["active"],
        "enabled":           info["enabled"],
        "pid":               info.get("pid", "—"),
        "started":           info.get("started", "—"),
        "mem_kb":            info.get("mem_kb", 0),
        "full_stats":        info["stats"],    # raw k=v pairs for the detailed table
        "stats_error":       info.get("stats_error", ""),
    }


@app.get("/api/sysinfo")
async def api_sysinfo(_user: str = Depends(_login_required)):
    return get_system_info()


@app.get("/api/status")
async def api_status(_user: str = Depends(_login_required)):
    return get_unbound_info()


@app.get("/api/logs")
async def api_logs(n: int = 100, _user: str = Depends(_login_required)):
    n = max(10, min(n, 1000))  # clamp
    return {"logs": get_log_lines(n)}


# ─────────────────────────────────────────────────────────────────────────────
#  API — SERVICE CONTROL
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/service/status")
async def api_service_status(_user: str = Depends(_login_required)):
    out, err, _ = run_cmd(["systemctl", "status", "unbound", "--no-pager"])
    return {"output": out or err}


@app.post("/api/service/{action}")
async def api_service(
    action: str,
    request: Request,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    if action not in {"start","stop","restart","reload","enable","disable"}:
        raise HTTPException(400, detail="Invalid action")
    out, err, rc = run_cmd(["systemctl", action, "unbound"])
    return {"success": rc == 0, "output": out,
            "error": err if err else "", "rc": rc}


# ─────────────────────────────────────────────────────────────────────────────
#  API — CONFIG
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/config/files")
async def api_config_files(request: Request, _user: str = Depends(_login_required)):
    files = sorted(glob.glob(DEFAULT_CONFIG_DIR + "*.conf"))
    if DEFAULT_CONFIG_FILE not in files and os.path.exists(DEFAULT_CONFIG_FILE):
        files.insert(0, DEFAULT_CONFIG_FILE)
    return {"files": files, "current": get_config_file(request)}


@app.post("/api/config/set_file")
async def api_config_set_file(
    request: Request,
    payload: ConfigFilePayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    request.session["config_file"] = payload.file
    return {"success": True, "file": payload.file}


@app.post("/api/config/load_file")
async def api_config_load_file(
    request: Request,
    payload: ConfigFilePayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    if not os.path.exists(payload.file):
        raise HTTPException(404, detail=f"File not found: {payload.file}")
    request.session["config_file"] = payload.file
    parsed = parse_unbound_conf(payload.file)
    return {"success": True, "config": parsed, "file": payload.file}


@app.post("/api/config/create_file")
async def api_config_create_file(
    request: Request,
    payload: CreateFilePayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    filepath  = os.path.join(DEFAULT_CONFIG_DIR, payload.filename)
    real_path = os.path.realpath(filepath)
    if not real_path.startswith(os.path.realpath(DEFAULT_CONFIG_DIR)):
        raise HTTPException(400, detail="Invalid file path — must be inside conf.d/")
    if not payload.allowed_tabs:
        raise HTTPException(400, detail="Select at least one allowed tab for this file.")

    # Optionally seed with existing main-config values for allowed tabs
    seed_data: Dict[str, Any] = {
        "forward_zones": [], "access_control": [], "local_zones": [], "local_data": []
    }
    if payload.move_existing:
        mp = parse_unbound_conf(DEFAULT_CONFIG_FILE)
        seed_data = {**mp.get("server", {}), "forward_zones": mp.get("forward_zones", []),
                     "access_control": mp.get("access_control", []),
                     "local_zones": mp.get("local_zones", []),
                     "local_data": mp.get("local_data", [])}

    stub = build_subfile_conf(seed_data, payload.allowed_tabs, payload.description)
    try:
        proc = subprocess.run(["sudo", "tee", real_path],
                              input=stub, capture_output=True, text=True)
        if proc.returncode != 0:
            raise HTTPException(500, detail=_clean_error("Write failed", proc.stderr))
        add_to_includes(DEFAULT_CONFIG_FILE, real_path)
        request.session["config_file"] = real_path
        return {"success": True, "file": real_path}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/api/config/delete_file")
async def api_config_delete_file(
    request: Request,
    payload: DeleteFilePayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    if not os.path.exists(payload.file):
        raise HTTPException(404, detail="File not found")
    try:
        os.remove(payload.file)
        # Remove from gui-includes section in main config
        if os.path.exists(DEFAULT_CONFIG_FILE):
            content  = Path(DEFAULT_CONFIG_FILE).read_text()
            includes = [f for f in parse_includes(content) if f["path"] != payload.file]
            if _INCL_START in content:
                new_content = _splice_includes(content, includes)
                subprocess.run(["sudo", "tee", DEFAULT_CONFIG_FILE],
                               input=new_content, capture_output=True, text=True)
        if request.session.get("config_file") == payload.file:
            request.session["config_file"] = DEFAULT_CONFIG_FILE
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.get("/api/config/includes")
async def api_config_get_includes(_user: str = Depends(_login_required)):
    content  = Path(DEFAULT_CONFIG_FILE).read_text() if os.path.exists(DEFAULT_CONFIG_FILE) else ""
    includes = parse_includes(content)
    enriched = []
    for inc in includes:
        meta = parse_file_meta(inc["path"])
        enriched.append({**inc, "filename": os.path.basename(inc["path"]),
                         "exists": os.path.exists(inc["path"]),
                         "allowed_tabs": meta.get("allowed_tabs", []),
                         "description": meta.get("description", "")})
    return {"success": True, "includes": enriched}


@app.post("/api/config/includes/save")
async def api_config_save_includes(
    payload: IncludesSavePayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    if not os.path.exists(DEFAULT_CONFIG_FILE):
        raise HTTPException(404, detail="Main config file not found")
    content     = Path(DEFAULT_CONFIG_FILE).read_text()
    new_content = _splice_includes(content, [{"path": f.path, "enabled": f.enabled} for f in payload.files])
    proc = subprocess.run(["sudo", "tee", DEFAULT_CONFIG_FILE],
                          input=new_content, capture_output=True, text=True)
    if proc.returncode != 0:
        raise HTTPException(500, detail=_clean_error("Write failed", proc.stderr))
    _, val_err, val_rc = run_cmd(["unbound-checkconf"])
    if val_rc != 0:
        raise HTTPException(422, detail=_clean_error("Config validation failed", val_err))
    return {"success": True}


@app.get("/api/config/raw")
async def api_config_raw(request: Request, _user: str = Depends(_login_required)):
    cfg_file = get_config_file(request)
    try:
        content = Path(cfg_file).read_text()
        return {"success": True, "content": content, "file": cfg_file}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/api/config/raw/save")
async def api_config_raw_save(
    request: Request,
    payload: RawConfigPayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    cfg_file = get_config_file(request)
    _safe_config_path(cfg_file)
    proc = subprocess.run(["sudo", "tee", cfg_file],
                          input=payload.content, capture_output=True, text=True)
    if proc.returncode != 0:
        raise HTTPException(500, detail=_clean_error("Write failed", proc.stderr))
    _, err, rc = run_cmd(["unbound-checkconf"])
    if rc != 0:
        raise HTTPException(422, detail=_clean_error("Config validation failed", err))
    return {"success": True}


def _build_conf_text(cfg_file: str, data: dict) -> str:
    """Build conf text appropriately for main config vs sub-file."""
    if cfg_file == DEFAULT_CONFIG_FILE:
        conf_text = build_unbound_conf(data)
        # Preserve the gui-includes section
        if os.path.exists(cfg_file):
            existing = parse_includes(Path(cfg_file).read_text())
            if existing:
                conf_text = _splice_includes(conf_text, existing)
        return conf_text
    else:
        meta    = parse_file_meta(cfg_file)
        allowed = meta.get("allowed_tabs", [])
        if not allowed:
            raise HTTPException(400, detail=(
                "No gui-allowed tabs defined in this file. "
                "Use Raw Editor to add '# gui-allowed: tab1,tab2' at the top of the file."
            ))
        return build_subfile_conf(data, allowed, meta.get("description", ""))


@app.post("/api/config/save")
async def api_config_save(
    request: Request,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    data     = await request.json()
    cfg_file = get_config_file(request)
    _safe_config_path(cfg_file)
    _write_config(cfg_file, _build_conf_text(cfg_file, data))
    return {"success": True, "message": "Configuration saved"}


@app.post("/api/config/apply")
async def api_config_apply(
    request: Request,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    data     = await request.json()
    cfg_file = get_config_file(request)
    _safe_config_path(cfg_file)
    _write_config(cfg_file, _build_conf_text(cfg_file, data))
    out, err, rc = run_cmd(["systemctl", "reload-or-restart", "unbound"])
    return {
        "success": rc == 0,
        "message": "Config saved and Unbound restarted" if rc == 0 else "Save OK, restart failed",
        "error":   _clean_error("Restart failed", err) if rc != 0 else "",
    }


@app.post("/api/config/validate")
async def api_config_validate(_user: str = Depends(_login_required)):
    out, err, rc = run_cmd(["unbound-checkconf"])
    return {"valid": rc == 0, "output": out or err}




# ─────────────────────────────────────────────────────────────────────────────
#  API — SYSTEM ACTIONS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/system/{action}")
async def api_system(
    action: str,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    if action == "reboot":
        run_cmd(["sudo", "shutdown", "-r", "now"])
        return {"success": True, "message": "System reboot initiated"}
    elif action == "restart_networking":
        out, err, rc = run_cmd(["systemctl", "restart", "networking"])
        return {"success": rc == 0, "output": out, "error": err, "rc": rc}
    elif action == "flush_dns":
        out, err, rc = run_cmd(["unbound-control", "reload"])
        return {"success": rc == 0, "output": out or "DNS cache flushed", "error": err, "rc": rc}
    elif action == "flush_cache":
        out, err, rc = run_cmd(["unbound-control", "flush_zone", "."])
        return {"success": rc == 0, "output": out or "Cache flushed", "error": err, "rc": rc}
    elif action == "dump_cache":
        out, err, rc = run_cmd(["unbound-control", "dump_cache"])
        return {"success": rc == 0, "output": out, "error": err, "rc": rc}
    raise HTTPException(400, detail=f"Unknown action: {action!r}")


# ─────────────────────────────────────────────────────────────────────────────
#  API — DEBUG
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/debug/run")
async def api_debug_run(
    payload: DebugPayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    tool   = payload.tool
    target = payload.target
    record = payload.record

    needs_target = {"ping","trace","whois","nslookup","dig","dig_short",
                    "dig_trace","dnssec","reverse","lookup"}

    if tool in needs_target and not target:
        return {"success": False, "output": "Error: enter a hostname or IP first.", "rc": 1}

    # All DNS tools route through 127.0.0.1 to test the local Unbound instance
    cmd_map: Dict[str, list] = {
        "ping":          ["ping", "-c", "4", "-W", "2", target],
        "trace":         ["traceroute", "-m", "15", target],
        "whois":         ["whois", target],
        "nslookup":      ["nslookup", f"-type={record}", target, "127.0.0.1"],
        "dig":           ["dig", "@127.0.0.1", target, record],
        "dig_short":     ["dig", "@127.0.0.1", "+short", target],
        "dig_trace":     ["dig", "@127.0.0.1", "+trace", target],
        "dnssec":        ["dig", "@127.0.0.1", "+dnssec", target],
        "reverse":       ["dig", "@127.0.0.1", "-x", target],
        "check_control": ["unbound-control", "status"],
        "check_conf":    ["unbound-checkconf"],
        "stats":         ["unbound-control", "stats_noreset"],
        "local_zones":   ["unbound-control", "list_local_zones"],
        "local_data":    ["unbound-control", "list_local_data"],
        "dump_cache":    ["unbound-control", "dump_cache"],
        "lookup":        ["unbound-control", "lookup", target],
    }

    if tool not in cmd_map:
        raise HTTPException(400, detail=f"Unknown tool: {tool!r}")

    cmd = cmd_map[tool]
    out, err, rc = run_cmd(cmd, timeout=20)

    # Provide detailed error info to the UI
    output = out if out else (err or "(no output)")
    if rc != 0 and err:
        output = f"{output}\n\n--- stderr ---\n{err}" if out else err

    return {
        "success": rc == 0,
        "output":  output,
        "rc":      rc,
        "cmd":     " ".join(cmd),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  API — SSL
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/ssl/info")
async def api_ssl_info(_user: str = Depends(_login_required)):
    try:
        from ssl_utils import get_cert_info
        return get_cert_info()
    except Exception as e:
        return {"exists": False, "error": str(e)}


@app.post("/api/ssl/regenerate")
async def api_ssl_regenerate(
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    try:
        from ssl_utils import CERT_FILE, KEY_FILE, ensure_ssl_cert
        for f in (CERT_FILE, KEY_FILE):
            if os.path.exists(f): os.remove(f)
        ensure_ssl_cert()
        return {"success": True, "message": "Certificate regenerated. Restart the server to apply."}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
#  API — UNBOUND CONTROL CERTIFICATES
#  Paths are loaded from .env (UNBOUND_SERVER_KEY etc.), never hardcoded here.
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/unbound/certs/info")
async def api_unbound_certs_info(_user: str = Depends(_login_required)):
    files = {
        "server_key": UNBOUND_SERVER_KEY,
        "server_pem": UNBOUND_SERVER_PEM,
        "control_key": UNBOUND_CONTROL_KEY,
        "control_pem": UNBOUND_CONTROL_PEM,
    }
    return {
        k: {"path": v, "exists": os.path.exists(v)}
        for k, v in files.items()
    }


@app.post("/api/unbound/certs/delete")
async def api_unbound_certs_delete(
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    deleted, errors = [], []
    for path in (UNBOUND_SERVER_KEY, UNBOUND_SERVER_PEM,
                 UNBOUND_CONTROL_KEY, UNBOUND_CONTROL_PEM):
        if not path.startswith("/etc/unbound/"):
            errors.append(f"Path outside /etc/unbound/ blocked: {path}")
            continue
        if os.path.exists(path):
            out, err, rc = run_cmd(["sudo", "rm", "-f", path])
            if rc == 0: deleted.append(path)
            else:       errors.append(f"{path}: {err}")
    if errors:
        raise HTTPException(500, detail=_clean_error("Delete failed", "; ".join(errors)))
    return {"success": True, "deleted": deleted}


@app.post("/api/unbound/certs/regenerate")
async def api_unbound_certs_regenerate(
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    out, err, rc = run_cmd(["sudo", "unbound-control-setup"], timeout=30)
    if rc != 0:
        raise HTTPException(500, detail=_clean_error("unbound-control-setup failed", err or out))
    return {"success": True, "output": out or "Certificates regenerated successfully."}


# ─────────────────────────────────────────────────────────────────────────────
#  API — SUB-FILE TAB MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

class SubfileTabsPayload(BaseModel):
    file: str
    allowed_tabs: List[str]
    description: str = ""
    move_existing: bool = False

    @field_validator("file")
    @classmethod
    def validate_file(cls, v: str) -> str:
        return _safe_config_path(v)

    @field_validator("allowed_tabs")
    @classmethod
    def validate_tabs(cls, v: List[str]) -> List[str]:
        return [t.strip() for t in v if t.strip() in ALL_TABS]

    @field_validator("description")
    @classmethod
    def sanitize_desc(cls, v: str) -> str:
        return re.sub(r'[\r\n]', ' ', v.strip())[:200]


@app.post("/api/config/subfile/update_tabs")
async def api_subfile_update_tabs(
    request: Request,
    payload: SubfileTabsPayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    """Update # gui-allowed: and optionally move settings from main config into this sub-file."""
    if payload.file == DEFAULT_CONFIG_FILE:
        raise HTTPException(400, detail="Cannot set allowed tabs on the main config file.")
    if not payload.allowed_tabs:
        raise HTTPException(400, detail="Select at least one tab.")
    if not os.path.exists(payload.file):
        raise HTTPException(404, detail="Config file not found.")

    # Read existing file, preserve non-header content
    existing_content = Path(payload.file).read_text()
    non_header_lines = []
    for line in existing_content.splitlines():
        if line.startswith("# gui-allowed:") or line.startswith("# gui-description:") \
                or line.startswith("# Generated by"):
            continue
        non_header_lines.append(line)
    # Strip leading blank lines from body
    body = "\n".join(non_header_lines).lstrip("\n")

    seed_data: Dict[str, Any] = {"forward_zones": [], "access_control": [],
                                  "local_zones": [], "local_data": []}
    if payload.move_existing:
        mp = parse_unbound_conf(DEFAULT_CONFIG_FILE)
        seed_data = {**mp.get("server", {}), "forward_zones": mp.get("forward_zones", []),
                     "access_control": mp.get("access_control", []),
                     "local_zones": mp.get("local_zones", []),
                     "local_data": mp.get("local_data", [])}
        # Build fresh file from seed
        new_content = build_subfile_conf(seed_data, payload.allowed_tabs, payload.description)
    else:
        # Rewrite just the header, keep existing body
        header_lines = [f"# gui-allowed: {','.join(payload.allowed_tabs)}"]
        if payload.description:
            header_lines.append(f"# gui-description: {_san(payload.description)}")
        header_lines.append(f"# Generated by Unbound Web GUI — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        new_content = "\n".join(header_lines) + "\n\n" + body

    proc = subprocess.run(["sudo", "tee", payload.file],
                          input=new_content, capture_output=True, text=True)
    if proc.returncode != 0:
        raise HTTPException(500, detail=_clean_error("Write failed", proc.stderr))
    _, val_err, val_rc = run_cmd(["unbound-checkconf"])
    if val_rc != 0:
        raise HTTPException(422, detail=_clean_error("Config validation failed", val_err))
    return {"success": True}




# ─────────────────────────────────────────────────────────────────────────────
#  API — BACKUPS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/backup/create")
async def api_backup_create(
    request: Request,
    payload: BackupPayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    src  = get_config_file(request)
    dest = os.path.join(BACKUP_DIR, f"unbound_{payload.label}_{ts}.conf")
    try:
        shutil.copy2(src, dest)
        return {"success": True, "filename": os.path.basename(dest)}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.get("/api/backup/list")
async def api_backup_list(_user: str = Depends(_login_required)):
    files = sorted(glob.glob(os.path.join(BACKUP_DIR, "*.conf")),
                   key=os.path.getmtime, reverse=True)
    result = []
    for f in files:
        stat = os.stat(f)
        result.append({
            "filename": os.path.basename(f),
            "size":     stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return {"success": True, "backups": result}


@app.post("/api/backup/restore")
async def api_backup_restore(
    request: Request,
    payload: RestorePayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    src  = os.path.join(BACKUP_DIR, payload.filename)
    dest = get_config_file(request)
    if not os.path.exists(src):
        raise HTTPException(404, detail="Backup file not found")
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy2(dest, os.path.join(BACKUP_DIR, f"pre_restore_{ts}.conf"))
        shutil.copy2(src, dest)
        run_cmd(["systemctl", "reload-or-restart", "unbound"])
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/api/backup/delete")
async def api_backup_delete(
    payload: DeleteBackupPayload,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    path = os.path.join(BACKUP_DIR, payload.filename)
    if not os.path.exists(path):
        raise HTTPException(404, detail="File not found")
    try:
        os.remove(path)
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.get("/api/backup/download/{filename}")
async def api_backup_download(
    filename: str,
    _user: str = Depends(_login_required),
):
    safe = _safe_backup_filename(filename)
    path = os.path.join(BACKUP_DIR, safe)
    if not os.path.exists(path):
        raise HTTPException(404, detail="File not found")
    return FileResponse(path, filename=safe, media_type="text/plain")


@app.post("/api/backup/upload")
async def api_backup_upload(
    request: Request,
    _user: str = Depends(_login_required),
    _csrf: None = Depends(_verify_csrf),
):
    from fastapi import UploadFile, File as _File
    form  = await request.form()
    ufile = form.get("file")
    if not ufile or not hasattr(ufile, "filename"):
        raise HTTPException(400, detail="No file uploaded")
    fname = os.path.basename(ufile.filename or "backup.conf")
    fname = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", fname)
    if not fname.endswith(".conf"):
        fname += ".conf"
    dest  = os.path.join(BACKUP_DIR, fname)
    content = await ufile.read()
    if len(content) > 2_000_000:
        raise HTTPException(413, detail="File too large (max 2 MB)")
    # Validate it looks like an unbound config
    text = content.decode("utf-8", errors="replace")
    if "server:" not in text and "forward-zone:" not in text:
        raise HTTPException(422, detail="File does not appear to be an Unbound config")
    Path(dest).write_bytes(content)
    return {"success": True, "filename": fname}


# ─────────────────────────────────────────────────────────────────────────────

def run_http_redirect(http_port: int, https_port: int):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            host = self.headers.get("Host", "").split(":")[0] or "localhost"
            self.send_response(301)
            self.send_header("Location", f"https://{host}:{https_port}{self.path}")
            self.send_header("Content-Length", "0")
            self.end_headers()
        do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET
        def log_message(self, *args): pass

    def _serve():
        try:
            HTTPServer(("0.0.0.0", http_port), RedirectHandler).serve_forever()
        except Exception as e:
            print(f"[http-redirect] Could not bind {http_port}: {e}")

    threading.Thread(target=_serve, daemon=True).start()
    print(f"[http-redirect] {http_port} → https://...:{https_port}")


if __name__ == "__main__":
    # HTTPS_ENABLED / HTTP_PORT / HTTPS_PORT are loaded from .env at module level.
    # Set HTTPS_ENABLED=false in .env when running behind nginx/caddy (TLS termination
    # at the proxy — app serves plain HTTP internally).

    if not HTTPS_ENABLED:
        print(f"[app] HTTPS_ENABLED=false — running plain HTTP on port {HTTP_PORT}")
        print("[app] TLS must be handled by your reverse proxy (nginx, caddy, etc.)")
        uvicorn.run("app:app", host="0.0.0.0", port=HTTP_PORT,
                    log_level="warning", access_log=False)
    else:
        try:
            from ssl_utils import ensure_ssl_cert
            cert_file, key_file = ensure_ssl_cert()

            run_http_redirect(HTTP_PORT, HTTPS_PORT)
            print(f"[app] HTTPS on https://0.0.0.0:{HTTPS_PORT}")
            print(f"[app] HTTP redirect on http://0.0.0.0:{HTTP_PORT}")

            uvicorn.run(
                "app:app",
                host="0.0.0.0",
                port=HTTPS_PORT,
                ssl_keyfile=key_file,
                ssl_certfile=cert_file,
                log_level="warning",
                access_log=False,
            )
        except RuntimeError as e:
            print(f"\n[ssl] WARNING: {e}")
            print("[ssl] Falling back to plain HTTP on port 8080.\n")
            uvicorn.run("app:app", host="0.0.0.0", port=HTTP_PORT,
                        log_level="warning", access_log=False)
