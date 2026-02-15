#!/usr/bin/env python3
import sys
import curses
import subprocess
import re
import textwrap
import os
import time
import argparse
import json
from datetime import datetime, timedelta
try:
    import psutil
except ImportError:
    psutil = None
from shutil import which, get_terminal_size
from collections import Counter
import ipaddress
import functools
import threading
import hashlib
import urllib.request

# Debug logging
DEBUG_LOG_PATH = os.path.expanduser("~/.config/heimdall/debug.log")

def debug_log(msg):
    """Write a timestamped message to the debug log."""
    try:
        os.makedirs(os.path.dirname(DEBUG_LOG_PATH), exist_ok=True)
        with open(DEBUG_LOG_PATH, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except:
        pass

SERVICES_DB = {}
CONFIG = {
    "auto_update_services": True,
    "update_interval_minutes": 30,
    "auto_scan_interval": 3.0
}
CONFIG_LOCK = threading.Lock()
UPDATING_SERVICES_EVENT = threading.Event()
UPDATE_STATUS_MSG = ""
ACTION_STATUS_MSG = ""
ACTION_STATUS_EXP = 0.0
SCANNING_STATUS_EXP = 0.0
CONFIG_DIR = os.path.expanduser("~/.config/heimdall")
SERVICES_URL = "https://raw.githubusercontent.com/sunels/heimdall/main/services.json"
SHA_URL = "https://raw.githubusercontent.com/sunels/heimdall/main/services.sha256"

def init_config():
    global CONFIG
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, exist_ok=True)
    config_path = os.path.join(CONFIG_DIR, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                saved = json.load(f)
                CONFIG.update(saved)
        except Exception as e:
            debug_log(f"CONFIG: Error loading: {e}")
    else:
        save_config()

def save_config():
    config_path = os.path.join(CONFIG_DIR, "config.json")
    try:
        with open(config_path, 'w') as f:
            json.dump(CONFIG, f, indent=2)
    except Exception as e:
        debug_log(f"CONFIG: Error saving: {e}")

def get_hash(data):
    return hashlib.sha256(data).hexdigest()

def update_services_bg():
    global SERVICES_DB, UPDATE_STATUS_MSG
    # Initial wait to avoid startup lag
    time.sleep(10)
    
    while True:
        with CONFIG_LOCK:
            auto_enabled = CONFIG.get("auto_update_services")
            interval_mins = CONFIG.get("update_interval_minutes", 30)
            
        if not auto_enabled:
            UPDATE_STATUS_MSG = "Updates disabled"
            time.sleep(60)
            continue
            
        UPDATING_SERVICES_EVENT.set()
        UPDATE_STATUS_MSG = "Loading latest services.json..."
        debug_log("UPDATER: Starting check...")
        start_time = time.time()
        
        try:
            debug_log(f"UPDATER: Checking {SHA_URL} for updates...")
            # Fetch remote SHA first
            with urllib.request.urlopen(SHA_URL, timeout=10) as response:
                remote_sha = response.read().decode('utf-8').strip().split()[0]
            
            local_json_path = os.path.join(CONFIG_DIR, "services.json")
            local_sha_path = os.path.join(CONFIG_DIR, "services.sha256")
            
            do_update = True
            if os.path.exists(local_sha_path):
                with open(local_sha_path, 'r') as f:
                    local_sha = f.read().strip()
                
                debug_log(f"UPDATER: Remote SHA: {remote_sha}")
                debug_log(f"UPDATER: Local SHA:  {local_sha} (at {local_sha_path})")
                
                if local_sha == remote_sha:
                    do_update = False
                    debug_log("UPDATER: Match found. No update needed.")
            else:
                debug_log(f"UPDATER: No local SHA found at {local_sha_path}. First-time update forced.")
            
            if do_update:
                UPDATE_STATUS_MSG = "Downloading new services.json..."
                debug_log("UPDATER: New version detected. Downloading from GitHub...")
                with urllib.request.urlopen(SERVICES_URL, timeout=10) as response:
                    raw_data = response.read()
                    computed_sha = get_hash(raw_data)
                    
                    if computed_sha == remote_sha:
                        data = json.loads(raw_data.decode('utf-8'))
                        if isinstance(data, dict) and "sshd" in data: # simple schema check
                            with open(local_json_path, 'wb') as f:
                                f.write(raw_data)
                            with open(local_sha_path, 'w') as f:
                                f.write(remote_sha)
                            SERVICES_DB = data
                            debug_log(f"UPDATER: Download complete. Applied {len(data)} service definitions.")
                            UPDATE_STATUS_MSG = "Update successful! ✅"
                        else:
                            debug_log("UPDATER: ERROR - Remote JSON schema invalid.")
                    else:
                        debug_log("UPDATER: ERROR - SHA256 mismatch from remote.")
        except Exception as e:
            debug_log(f"UPDATER: Error during update: {e}")
            
        # Ensure the message is visible for at least 4 seconds
        elapsed = time.time() - start_time
        if elapsed < 4.0:
            time.sleep(4.0 - elapsed)
            
        UPDATING_SERVICES_EVENT.clear()
        UPDATE_STATUS_MSG = ""
        
        sleep_interval = max(1, interval_mins) # Keep min 1m for flexibility
        time.sleep(sleep_interval * 60)

def start_services_updater():
    t = threading.Thread(target=update_services_bg, daemon=True)
    t.start()
    return t

def load_services_db():
    global SERVICES_DB
    # Priority: ~/.config/heimdall/services.json > local services.json
    paths = [
        os.path.join(CONFIG_DIR, "services.json"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "services.json")
    ]
    for json_path in paths:
        try:
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    SERVICES_DB = json.load(f)
                debug_log(f"SERVICES: Loaded from {json_path}")
                return
        except Exception as e:
            debug_log(f"SERVICES: Error loading {json_path}: {e}")

init_config()
load_services_db()
# Updater starts in main()

KEY_SEP_UP = ord('+')
KEY_SEP_DOWN = ord('-')
KEY_TAB = 9
KEY_FIREWALL = ord('f')

# initialize global refresh trigger used by request_full_refresh()
TRIGGER_REFRESH = False

# --------------------------------------------------
# 🎨 Themes & Colors
# --------------------------------------------------
# Config path for persistence
CONFIG_PATH = os.path.expanduser("~/.config/heimdall/theme")

def load_theme_preference():
    """Load the theme index from the config file. Defaults to 1 (Gruvbox Dark)."""
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                return int(f.read().strip())
    except:
        pass
    return 1  # Default to Gruvbox Dark (index 1)

def save_theme_preference(index):
    """Save the theme index to the config file."""
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            f.write(str(index))
    except:
        pass

CURRENT_THEME_INDEX = load_theme_preference()

# Curses color pair IDs (1-based because 0 is reserved)
CP_HEADER = 1   # Headers, Branding, important labels
CP_ACCENT = 2   # Secondary highlights, key shortcuts
CP_TEXT = 3     # Normal body text
CP_WARN = 4     # Warnings, errors, critical items
CP_BORDER = 5   # Borders, separators

THEMES = [
    {
        "name": "🔵 VSCode Dark (Default)",
        # Standard fallback
        "colors": {
            CP_HEADER: (curses.COLOR_BLUE, -1),
            CP_ACCENT: (curses.COLOR_CYAN, -1),
            CP_TEXT: (curses.COLOR_WHITE, -1),
            CP_WARN: (curses.COLOR_YELLOW, -1),
            CP_BORDER: (curses.COLOR_BLUE, -1)
        },
        # Precise 256-color map (FG, BG)
        "colors_256": {
            CP_HEADER: (33, 234),    # DodgerBlue1 on DarkGrey
            CP_ACCENT: (45, 234),    # Turquoise2
            CP_TEXT: (255, 234),     # White
            CP_WARN: (226, 234),     # Yellow
            CP_BORDER: (33, 234)     # Blue border
        },
        "attrs": { CP_HEADER: curses.A_BOLD, CP_ACCENT: curses.A_BOLD, CP_BORDER: curses.A_DIM }
    },
    {
        "name": "🔸 Gruvbox Dark (Retro)",
        "colors": {
            CP_HEADER: (curses.COLOR_YELLOW, -1),
            CP_ACCENT: (curses.COLOR_RED, -1),
            CP_TEXT: (curses.COLOR_WHITE, -1),
            CP_WARN: (curses.COLOR_RED, -1),
            CP_BORDER: (curses.COLOR_YELLOW, -1)
        },
        "colors_256": {
            CP_HEADER: (214, 235),   # Orange1 on Black/Grey (Gruvbox BG)
            CP_ACCENT: (167, 235),   # IndianRed
            CP_TEXT: (223, 235),     # Bisque/Cream
            CP_WARN: (208, 235),     # OrangeRed
            CP_BORDER: (246, 235)    # Grey border
        },
        "attrs": { CP_HEADER: curses.A_BOLD, CP_ACCENT: curses.A_BOLD, CP_BORDER: curses.A_DIM }
    },
    {
        "name": "🌆 Tokyo Night (Neon)",
        "colors": {
            CP_HEADER: (curses.COLOR_MAGENTA, -1),
            CP_ACCENT: (curses.COLOR_CYAN, -1),
            CP_TEXT: (curses.COLOR_WHITE, -1),
            CP_WARN: (curses.COLOR_YELLOW, -1),
            CP_BORDER: (curses.COLOR_BLUE, -1)
        },
        "colors_256": {
            CP_HEADER: (135, 234),   # MediumPurple on DarkBG
            CP_ACCENT: (45, 234),    # Cyan
            CP_TEXT: (189, 234),     # Light Grey-Blue
            CP_WARN: (220, 234),     # Gold
            CP_BORDER: (63, 234)     # SlateBlue
        },
        "attrs": { CP_HEADER: curses.A_BOLD, CP_ACCENT: curses.A_BOLD, CP_BORDER: curses.A_DIM }
    },
    {
        "name": "☕ Catppuccin Mocha (Soft)",
        "colors": {
            CP_HEADER: (curses.COLOR_BLUE, -1),
            CP_ACCENT: (curses.COLOR_RED, -1),
            CP_TEXT: (curses.COLOR_WHITE, -1),
            CP_WARN: (curses.COLOR_YELLOW, -1),
            CP_BORDER: (curses.COLOR_CYAN, -1)
        },
        "colors_256": {
            CP_HEADER: (117, 235),   # SkyBlue on DeepDark
            CP_ACCENT: (210, 235),   # Salmon/Flamingo
            CP_TEXT: (254, 235),     # White-ish
            CP_WARN: (228, 235),     # Yellow
            CP_BORDER: (103, 235)    # SlateGray
        },
        "attrs": { CP_HEADER: curses.A_BOLD, CP_ACCENT: curses.A_BOLD, CP_BORDER: curses.A_DIM }
    },
    {
        "name": "🌌 One Dark Pro (Atom)",
        "colors": {
            CP_HEADER: (curses.COLOR_BLUE, -1),
            CP_ACCENT: (curses.COLOR_MAGENTA, -1),
            CP_TEXT: (curses.COLOR_WHITE, -1),
            CP_WARN: (curses.COLOR_RED, -1),
            CP_BORDER: (curses.COLOR_WHITE, -1)
        },
        "colors_256": {
            CP_HEADER: (39, 236),    # DeepSkyBlue on DarkGreyBlue
            CP_ACCENT: (170, 236),   # Orchid
            CP_TEXT: (253, 236),     # Very Light Grey
            CP_WARN: (203, 236),     # IndianRed
            CP_BORDER: (59, 236)     # Grey59
        },
        "attrs": { CP_HEADER: curses.A_BOLD, CP_ACCENT: curses.A_BOLD, CP_BORDER: curses.A_DIM }
    }
]

def apply_current_theme(stdscr=None):
    """Initializes color pairs based on CURRENT_THEME_INDEX using 256 colors if available."""
    if not curses.has_colors():
        return
    idx = CURRENT_THEME_INDEX % len(THEMES)
    theme = THEMES[idx]
    
    # Check if we support 256 colors
    use_256 = (curses.COLORS >= 256) and ("colors_256" in theme)

    try:
        if not use_256:
           curses.use_default_colors()
    except:
        pass
        
    color_map = theme["colors_256"] if use_256 else theme["colors"]

    for pair_id, (fg, bg) in color_map.items():
        try:
             # In 256 mode, bg is a specific color index. In fallback, it might be -1.
             curses.init_pair(pair_id, fg, bg)
        except:
             pass
    
    # Apply background to the window if stdscr is provided
    # We use CP_TEXT's background which is usually the theme background
    if stdscr:
        try:
            stdscr.bkgd(' ', curses.color_pair(CP_TEXT))
            stdscr.erase() # ⚡ Force repaint everything with new background
            stdscr.refresh()
        except:
            pass

def get_theme_attr(pair_id):
    """Get extra attribute (BOLD, DIM) for a specific UI element type in current theme."""
    idx = CURRENT_THEME_INDEX % len(THEMES)
    theme = THEMES[idx]
    base_attr = curses.color_pair(pair_id)
    extra_attr = theme.get("attrs", {}).get(pair_id, curses.A_NORMAL)
    return base_attr | extra_attr


# --------------------------------------------------
# Checks
# --------------------------------------------------
def check_python_version():
    if sys.version_info < (3, 6):
        print("Python 3.6 or newer is required.")
        sys.exit(1)

def check_witr_exists():
    if which("witr") is None:
        print("Error: 'witr' command not found. Please install 'witr' and ensure it is in your PATH.")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='heimdall 0.6.0')
    parser.add_argument('--no-update', action='store_true', help='Disable background service updates')
    return parser.parse_args()


# --------------------------------------------------
# 🌍 Network Scope / Exposure
# --------------------------------------------------
def analyze_network_scope(port):
    listening_ips = set()
    interfaces = set()
    scope = "Unknown"
    external = False

    # Listening IP’leri bul
    try:
        result = subprocess.run(
            ["ss", "-lntu"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                if addr.endswith(f":{port}"):
                    ip = addr.rsplit(":", 1)[0].strip("[]")
                    listening_ips.add(ip)
    except:
        pass

    # Match Interface
    try:
        ip_out = subprocess.run(
            ["ip", "-o", "addr"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in ip_out.stdout.splitlines():
            parts = line.split()
            iface = parts[1]
            ip = parts[3].split("/")[0]
            if ip in listening_ips:
                interfaces.add(iface)
    except:
        pass

    # Scope belirle
    for ip in listening_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback:
                scope = "Localhost"
            elif addr.is_private:
                if scope != "Localhost":
                    scope = "Internal"
            else:
                scope = "Public"
                external = True
        except:
            continue

    return {
        "scope": scope,
        "interfaces": ", ".join(sorted(interfaces)) if interfaces else "-",
        "external": "YES" if external else "NO"
    }

# --------------------------------------------------
# Utils
# --------------------------------------------------
def strip_ansi(line):
    return re.sub(r'\x1b\[[0-9;]*m', '', line)

def parse_ss():
    result = subprocess.run(
        ["ss", "-lntuHp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    seen = {}  # (port, proto) -> row
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        icon = "🔗" if proto == "tcp" else "📡"
        local = parts[4]
        port = local.split(":")[-1]
        pid = "-"
        prog = "-"
        m = re.search(r'pid=(\d+)', line)
        if m:
            pid = m.group(1)
        m = re.search(r'\("([^"]+)"', line)
        if m:
            prog = m.group(1)
        key = (port, proto)
        if key in seen:
            continue
        seen[key] = (port, f"{icon} {proto.upper()}", f"{pid}/{prog}", prog, pid)
    rows = list(seen.values())
    rows.sort(key=lambda r: (0 if "tcp" in r[1].lower() else 1, int(r[0]) if r[0].isdigit() else 0))
    return rows

def get_witr_output(port):
    try:
        result = subprocess.run(
            ["sudo", "witr", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        lines = [strip_ansi(l) for l in result.stdout.splitlines() if l.strip()]
        return lines if lines else ["No data"]
    except Exception as e:
        return [str(e)]

def get_witr_output_cached(port, ttl=None):
    """
    Return cached witr output lines for a port. Calls get_witr_output() only
    if no cached entry exists or TTL expired.

    Use ttl=None so we can read the global WITR_TTL at runtime (avoids NameError
    when function is defined before the constant).
    """
    if ttl is None:
        ttl = globals().get("WITR_TTL", 1.5)
    if not port:
        return ["No data"]
    now = time.time()
    entry = _witr_cache.get(str(port))
    if entry:
        val, ts = entry
        if now - ts < ttl:
            return val
    val = get_witr_output(port)
    _witr_cache[str(port)] = (val, now)
    return val

def extract_user_from_witr(lines):
    for l in lines:
        m = re.search(r'User\s*:\s*(\S+)', l, re.I)
        if m:
            return m.group(1)
    return "-"

def get_process_user(pid):
    """Get process owner via psutil first, then /proc fallback. Never returns '-'."""
    if not pid or not str(pid).isdigit():
        return "-"
    # Strategy 1: psutil (most reliable)
    if psutil:
        try:
            return psutil.Process(int(pid)).username()
        except Exception:
            pass
    # Strategy 2: /proc/pid/status
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    import pwd
                    return pwd.getpwuid(uid).pw_name
    except Exception:
        pass
    # Strategy 3: ps command
    try:
        res = subprocess.run(["ps", "-o", "user=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=1)
        user = res.stdout.strip()
        if user:
            return user
    except Exception:
        pass
    return "-"

def extract_process_from_witr(lines):
    for l in lines:
        m = re.search(r'Process\s*:\s*(.+)', l, re.I)
        if m:
            return m.group(1)
    return "-"

def get_open_files(pid):
    files = []
    if not pid or not pid.isdigit():
        return files
    fd_dir = f"/proc/{pid}/fd"
    try:
        if not os.path.isdir(fd_dir):
            return files
        for fd in sorted(os.listdir(fd_dir), key=lambda x: int(x)):
            try:
                path = os.readlink(os.path.join(fd_dir, fd))
                files.append((fd, path))
            except PermissionError:
                files.append((fd, "Permission denied"))
            except OSError:
                continue
    except PermissionError:
        files.append(("-", "Permission denied (run as root to view)"))
    return files

def format_mem_kb(kb):
    try:
        kb = float(kb)
    except:
        return "-"
    mb = kb / 1024
    if mb > 1024:
        return f"{mb/1024:.1f}G"
    return f"{mb:.0f}M"

def get_process_usage(pid):
    """Return CPU%/MEM formatted as MB or GB (legacy uncached)."""
    if not pid or not pid.isdigit():
        return "-"
    try:
        result = subprocess.run(
            ["ps", "-p", pid, "-o", "pcpu=,rss="],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        cpu, mem_kb = result.stdout.strip().split()
        mem = format_mem_kb(mem_kb)
        return f"{mem}/{cpu}%"
    except Exception:
        return "-"

# Cache TTLs (seconds)
USAGE_TTL = 1.0
FILES_TTL = 1.0
PARSE_TTL = 0.7
WITR_TTL = 1.5
CONN_TTL = 1.0
SELECT_STABLE_TTL = 0.40
TABLE_ROW_TTL = 1.0  # New for preformatted rows

# Simple caches: pid/port -> (value, timestamp)
_proc_usage_cache = {}
_open_files_cache = {}
_parse_cache = {"rows": None, "ts": 0.0}
_witr_cache = {}
_conn_cache = {}
_table_row_cache = {}  # New: port -> (preformatted_str, ts)

# NEW: snapshot flag and additional caches for fully eager preload
SNAPSHOT_MODE = False             # when True, parse_ss_cached returns the snapshot and no heavy calls during scroll
_proc_chain_cache = {}           # pid -> chain list
_fd_cache = {}                   # pid -> fd_info dict
_runtime_cache = {}              # pid -> runtime dict

# New cached wrapper for get_process_usage to reduce subprocess calls on fast scrolling.
def get_process_usage_cached(pid, ttl=USAGE_TTL):
    """
    Return cached process usage string. Calls underlying get_process_usage()
    only if cache expired or pid changed.
    """
    if not pid or not pid.isdigit():
        return "-"
    now = time.time()
    entry = _proc_usage_cache.get(pid)
    if entry:
        val, ts = entry
        if now - ts < ttl:
            return val
    # refresh
    val = get_process_usage(pid)
    _proc_usage_cache[pid] = (val, now)
    return val

def get_open_files_cached(pid, ttl=FILES_TTL):
    """
    Return cached open-files list; refresh only if TTL expired or not cached.
    """
    if not pid or not pid.isdigit():
        return []
    now = time.time()
    entry = _open_files_cache.get(pid)
    if entry:
        val, ts = entry
        if now - ts < ttl:
            return val
    val = get_open_files(pid)
    _open_files_cache[pid] = (val, now)
    return val

def parse_ss_cached(ttl=PARSE_TTL):
    """Cached wrapper for parse_ss. When SNAPSHOT_MODE is True and rows exist, return snapshot only."""
    now = time.time()
    # If snapshot exists and snapshot mode is active -> always return cached snapshot
    if _parse_cache.get("rows") is not None and SNAPSHOT_MODE:
        return _parse_cache["rows"]
    # otherwise honor TTL
    entry_ts = _parse_cache.get("ts", 0.0)
    if _parse_cache.get("rows") is not None and (now - entry_ts) < ttl:
        return _parse_cache["rows"]
    rows = parse_ss()
    _parse_cache["rows"] = rows
    _parse_cache["ts"] = now
    return rows

# Cached wrappers for process chain / fd / runtime so draw_detail never runs heavy ops directly
def get_process_parent_chain_cached(pid):
    if not pid or not pid.isdigit():
        return []
    entry = _proc_chain_cache.get(pid)
    if entry is not None:
        return entry
    val = get_process_parent_chain(pid)
    _proc_chain_cache[pid] = val
    return val

def get_fd_pressure_cached(pid):
    if not pid or not pid.isdigit():
        return {"open": "-", "limit": "-", "usage": "-", "risk": "-"}
    entry = _fd_cache.get(pid)
    if entry is not None:
        return entry
    val = get_fd_pressure(pid)
    _fd_cache[pid] = val
    return val

def detect_runtime_type_cached(pid):
    if not pid or not pid.isdigit():
        return {"type": "-", "mode": "-", "gc": "-"}
    entry = _runtime_cache.get(pid)
    if entry is not None:
        return entry
    val = detect_runtime_type(pid)
    _runtime_cache[pid] = val
    return val

def get_connections_info(port):
    """Return dict with active connections and top IPs"""
    try:
        # Get ESTABLISHED connections
        result = subprocess.run(
            ["ss", "-ntu", "state", "established", f"( dport = :{port} or sport = :{port} )"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        lines = result.stdout.strip().splitlines()[1:]  # skip header

        unique_connections = set()  # Unique connection based on IP:PORT
        ips = []

        for l in lines:
            parts = l.split()
            if len(parts) >= 5:
                raddr = parts[4]
                # Unique connection
                if raddr not in unique_connections:
                    unique_connections.add(raddr)
                    ip = raddr.rsplit(":", 1)[0]
                    ips.append(ip)

        counter = Counter(ips)
        top_ip = counter.most_common(1)[0] if counter else ("-", 0)
        return {
            "active_connections": len(unique_connections),
            "top_ip": top_ip[0],
            "top_ip_count": top_ip[1],
            "all_ips": counter
        }

    except Exception:
        return {
            "active_connections": 0,
            "top_ip": "-",
            "top_ip_count": 0,
            "all_ips": {}
        }

def get_connection_list(port):
    """
    Return list of active connections for a port with detailed info.
    Each connection is a dict with: proto, local_addr, remote_addr, state
    
    Note: Deduplicates bidirectional connections to avoid showing the same
    connection twice (once from each direction).
    """
    connections = []
    seen_pairs = set()  # Track unique connection pairs
    
    try:
        result = subprocess.run(
            ["ss", "-ntu", "state", "established", f"( dport = :{port} or sport = :{port} )"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        lines = result.stdout.strip().splitlines()[1:]  # skip header
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].lower()
                local = parts[3]
                remote = parts[4]
                state = parts[1] if len(parts) > 1 else "ESTAB"
                
                # Create a normalized pair to detect duplicates
                # Sort addresses to ensure (A,B) and (B,A) are treated as same
                pair = tuple(sorted([local, remote]))
                
                # Skip if we've already seen this connection pair
                if pair in seen_pairs:
                    continue
                    
                seen_pairs.add(pair)
                
                # Prefer showing the connection where our port is on the local side
                # This makes it clearer which is the server and which is the client
                local_port = local.rsplit(":", 1)[1]
                remote_port = remote.rsplit(":", 1)[1]
                
                if local_port == str(port):
                    # Our port is local - show as-is (server perspective)
                    display_local = local
                    display_remote = remote
                else:
                    # Our port is remote - swap to show server perspective
                    display_local = remote
                    display_remote = local
                
                connections.append({
                    "proto": proto,
                    "local_addr": display_local,
                    "remote_addr": display_remote,
                    "state": state,
                    "display": f"{proto.upper()} {display_local} ↔ {display_remote}"
                })
    except Exception:
        pass
    
    return connections

def get_connections_info_cached(port, ttl=CONN_TTL):
    """Cached wrapper for get_connections_info; short TTL to avoid frequent ss calls while scrolling."""
    if not port:
        return {
            "active_connections": 0,
            "top_ip": "-",
            "top_ip_count": 0,
            "all_ips": Counter()
        }
    now = time.time()
    entry = _conn_cache.get(str(port))
    if entry:
        val, ts = entry
        if now - ts < ttl:
            return val
    val = get_connections_info(port)
    _conn_cache[str(port)] = (val, now)
    return val

# initialize global refresh triggers
TRIGGER_REFRESH = False
TRIGGER_LIST_ONLY = False

def request_full_refresh():
    """Signal main loop to perform full refresh (clears ALL caches including heavy witr info)."""
    global TRIGGER_REFRESH
    TRIGGER_REFRESH = True

def request_list_refresh():
    """Signal main loop to refresh only the port list (preserves heavy witr/conn caches)."""
    global TRIGGER_LIST_ONLY
    TRIGGER_LIST_ONLY = True

def invalidate_port_cache(port):
    """Specifically invalidate cached UI row for a single port."""
    key = str(port)
    if key in _table_row_cache:
        del _table_row_cache[key]

# --------------------------------------------------
# Splash Screen with Preloading
# --------------------------------------------------
def splash_screen(stdscr, rows, cache):
    if curses.has_colors():
        try:
            curses.start_color()
        except:
            pass
        apply_current_theme(stdscr)


    h, w = stdscr.getmaxyx()

    bh = min(18, h - 6)          # Higher window
    bw = min(99, w - 6)          # Wider (enough to prevent overflow)
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    # 🎨 Set window background to theme
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass

    heimdall_art = [
        "  ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     ",
        "  ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     ",
        "  ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     ",
        "  ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     ",
        "  ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗",
        "  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝",
    ]

    art_height = len(heimdall_art)
    slogan = "The All-Seeing Port & Process Guardian"
    slogan_y = art_height + 1

    total = len(rows)
    progress_y = slogan_y + 3

    # Make bar width a bit more secure and controlled
    bar_w = max(40, bw - 20)   # min 40 characters guaranteed, no overflow

    for i, row in enumerate(rows, 1):
        port = row[0]

        win.erase()
        win.box()

        # HEIMDALL text (purple)
        for idx, line in enumerate(heimdall_art):
            line_x = max(0, (bw - len(line)) // 2)
            win.addstr(2 + idx, line_x, line[:bw-4],
                       curses.color_pair(1) | curses.A_BOLD)

        # Slogan (cyan)
        slogan_x = max(0, (bw - len(slogan)) // 2)
        win.addstr(slogan_y + 2, slogan_x, slogan,
                   curses.color_pair(2) | curses.A_ITALIC)

        # Bottom part: Collecting data + port
        win.addstr(progress_y, 4, "Collecting system intelligence...", curses.color_pair(3))
        win.addstr(progress_y + 1, 4, f"Scanning port: {port}", curses.color_pair(4))

        # Progress bar + step count INSIDE BAR (overflow impossible)
        filled = int(bar_w * i / total)
        bar = "█" * filled + "░" * (bar_w - filled)

        progress_str = f" {i}/{total} "
        mid = bar_w // 2
        start_pos = mid - len(progress_str) // 2

        # If bar is too short, align to start (security)
        if start_pos < 0:
            start_pos = 0
        if start_pos + len(progress_str) > bar_w:
            start_pos = bar_w - len(progress_str)

        bar_with_progress = (
            bar[:start_pos] + progress_str + bar[start_pos + len(progress_str):]
        )

        bar_x = (bw - bar_w) // 2
        win.addstr(progress_y + 3, bar_x, f"[{bar_with_progress}]", curses.color_pair(CP_ACCENT) | curses.A_BOLD)

        win.refresh()

        # --- Preload data per port ---
        prog_name = row[3] if len(row) > 3 else "-"
        try:
            lines = get_witr_output(port)
            _witr_cache[str(port)] = (lines, time.time())
            user = extract_user_from_witr(lines)
            # Fallback: if witr didn't provide user, resolve from PID
            if user == "-":
                pid_val = row[4] if len(row) > 4 else "-"
                user = get_process_user(pid_val)
            process = extract_process_from_witr(lines)
            detail_width = w - 4
            wrapped_icon_lines = prepare_witr_content(lines, detail_width, prog=prog_name, port=port)
            cache[port] = {
                "user": user,
                "process": process,
                "lines": lines,
                "wrapped_icon_lines": wrapped_icon_lines,
                "prewrapped_width": detail_width
            }
        except Exception:
            detail_width = w - 4
            fallback_lines = prepare_witr_content(["No data"], detail_width, prog=prog_name, port=port)
            cache[port] = {"user": "-", "process": "-", "lines": ["No data"], "wrapped_icon_lines": fallback_lines}

        try:
            conn = get_connections_info(port)
            _conn_cache[str(port)] = (conn, time.time())
        except Exception:
            _conn_cache[str(port)] = ({"active_connections": 0, "top_ip": "-", "top_ip_count": 0, "all_ips": Counter()}, time.time())

        try:
            pid = row[4] if len(row) > 4 else "-"
            if pid and pid.isdigit():
                _proc_usage_cache[pid] = (get_process_usage(pid), time.time())
                _open_files_cache[pid] = (get_open_files(pid), time.time())
                _proc_chain_cache[pid] = get_process_parent_chain(pid)
                _fd_cache[pid] = get_fd_pressure(pid)
                _runtime_cache[pid] = detect_runtime_type(pid)
        except Exception:
            pass

        cache[port]["preloaded"] = True

    # Final screen
    win.erase()
    win.box()

    done_lines = [
        "Initialization Complete",
        "Heimdall is now watching..."
    ]
    for idx, text in enumerate(done_lines):
        text_x = max(0, (bw - len(text)) // 2)
        win.addstr(bh // 2 - 1 + idx, text_x, text,
                   curses.color_pair(1) | curses.A_BOLD)

    win.refresh()
    time.sleep(1.2)

    stdscr.clear()
    stdscr.refresh()

    global SNAPSHOT_MODE
    SNAPSHOT_MODE = True

def prepare_witr_content(lines, width, prog=None, port=None):
    # If witr returned nothing useful, generate fallback from services.json
    if (not lines or lines == ["No data"]) and (prog or port):
        return _generate_service_fallback(prog, port, width)

    lines = annotate_warnings(lines)
    wrapped = []
    icons = {
        "Target": "🎯",
        "Container": "🐳",
        "Command": "🧠",
        "Started": "⏱ ",
        "Why it Exists!": "🔍",
        "Source": "📦",
        "Working Dir": "🗂 ",
        "Listening": "👂",
        "Socket": "🔌",
        "Warnings": "⚠️ ",
        "PID": "🆔",
        "User": "👤",
        "Process": "🧠"
    }
    for line in lines:
        # Icon replacement is only performed once
        for key, icon in icons.items():
            if key in line and not line.strip().startswith(icon):
                line = line.replace(key, f"{icon} {key}", 1)
        wrapped.extend(textwrap.wrap(line, width=width) or [""])
    return wrapped

def _generate_service_fallback(prog, port, width):
    """Generate rich detail content when witr has no data.
    Layer 1: services.json → Layer 2: local package manager intelligence."""
    wrapped = []
    svc = get_service_info(prog, port)
    is_unknown = svc.get("name") == "Unknown"

    # Layer 2: If services.json doesn't know it, ask the OS package manager
    pkg_info = None
    if is_unknown and prog:
        pkg_info = get_local_package_info(prog)

    if pkg_info:
        # We got real data from the local system!
        wrapped.append(f"📦 {pkg_info.get('name', prog)}")
        wrapped.append(f"   Process: {prog}")
        wrapped.append(f"   Port: {port or '-'}")
        if pkg_info.get("version"):
            wrapped.append(f"   Version: {pkg_info['version']}")
        if pkg_info.get("package"):
            wrapped.append(f"   Package: {pkg_info['package']}")
        wrapped.append("")

        wrapped.append("🔍 What is this service?")
        desc = pkg_info.get("description", "No description available.")
        for line in textwrap.wrap(f"   {desc}", width=width):
            wrapped.append(line)
        wrapped.append("")

        if pkg_info.get("homepage"):
            wrapped.append(f"🌐 Homepage: {pkg_info['homepage']}")
            wrapped.append("")

        if pkg_info.get("maintainer"):
            wrapped.append(f"👤 Maintainer: {pkg_info['maintainer']}")
        if pkg_info.get("installed_size"):
            wrapped.append(f"💾 Installed Size: {pkg_info['installed_size']}")
        wrapped.append("")

        wrapped.append("ℹ️  Source: Local package manager (dpkg/rpm)")
        wrapped.append("   This information was auto-discovered from your")
        wrapped.append("   system's installed packages.")
    else:
        # Use services.json data (Layer 1) or show unknown
        name = svc.get("name", prog or "Unknown")
        desc = svc.get("description", "No description available.")
        risk = svc.get("risk", "Unknown")
        rec = svc.get("recommendation", "No specific recommendation.")
        typical_user = svc.get("typical_user", "-")
        known_ports = svc.get("ports", [])
        dynamic = svc.get("dynamic_ports", False)

        wrapped.append(f"📦 Service: {name}")
        wrapped.append(f"   Process: {prog or '-'}")
        wrapped.append(f"   Port: {port or '-'}")
        wrapped.append("")

        wrapped.append("🔍 What is this service?")
        for line in textwrap.wrap(f"   {desc}", width=width):
            wrapped.append(line)
        wrapped.append("")

        wrapped.append(f"👤 Typical User: {typical_user}")
        port_str = ", ".join(str(p) for p in known_ports) if known_ports else "Dynamic"
        if dynamic:
            port_str += " + dynamic high ports"
        wrapped.append(f"🔌 Known Ports: {port_str}")
        wrapped.append("")

        wrapped.append("⚠️  Risk Assessment:")
        for line in textwrap.wrap(f"   {risk}", width=width):
            wrapped.append(line)
        wrapped.append("")

        wrapped.append("🛡️ Recommendation:")
        for line in textwrap.wrap(f"   {rec}", width=width):
            wrapped.append(line)
        wrapped.append("")

        if is_unknown:
            wrapped.append("ℹ️  This process is not in the Heimdall knowledge")
            wrapped.append("   base and no local package info was found.")
            wrapped.append("   Consider investigating manually.")
        else:
            wrapped.append("ℹ️  Source: Heimdall service knowledge base")

    return wrapped

# ── Layer 2: Local System Intelligence ──────────────────────────────
_pkg_info_cache = {}

def get_local_package_info(prog):
    """
    Query the local package manager (dpkg/rpm) to discover information
    about a running process. Zero internet, zero API keys required.
    Results are cached for the session.
    """
    if prog in _pkg_info_cache:
        return _pkg_info_cache[prog]

    info = None
    # Strategy 1: Direct dpkg query by process name
    info = _try_dpkg(prog)

    # Strategy 2: Find binary path and reverse-lookup package
    if not info:
        binary_path = _find_binary_path(prog)
        if binary_path:
            pkg_name = _dpkg_search_file(binary_path)
            if pkg_name:
                info = _try_dpkg(pkg_name)

    # Strategy 3: Try rpm (RHEL/Fedora/SUSE)
    if not info:
        info = _try_rpm(prog)

    # Strategy 4: Try snap
    if not info:
        info = _try_snap(prog)

    # Strategy 5: whatis (man page one-liner) as last resort
    if not info:
        info = _try_whatis(prog)

    # Strategy 6: .desktop file search
    if not info:
        info = _try_desktop_file(prog)

    _pkg_info_cache[prog] = info
    return info

def _find_binary_path(prog):
    """Find the actual binary path of a process via 'which' or /proc."""
    try:
        res = subprocess.run(["which", prog], capture_output=True, text=True, timeout=1)
        path = res.stdout.strip()
        if path and os.path.exists(path):
            # Resolve symlinks to find the real package
            return os.path.realpath(path)
    except Exception:
        pass
    return None

def _dpkg_search_file(filepath):
    """Reverse-lookup: which package owns this file?"""
    try:
        res = subprocess.run(["dpkg", "-S", filepath], capture_output=True, text=True, timeout=1)
        if res.returncode == 0 and res.stdout.strip():
            # Output format: "package-name: /path/to/file"
            return res.stdout.strip().split(":")[0].strip()
    except Exception:
        pass
    return None

def _try_dpkg(pkg_name):
    """Query dpkg for package metadata (Debian/Ubuntu)."""
    try:
        res = subprocess.run(["dpkg", "-s", pkg_name], capture_output=True, text=True, timeout=1.5)
        if res.returncode != 0:
            return None
        info = {"package": pkg_name}
        lines = res.stdout.splitlines()
        desc_lines = []
        in_desc = False
        for line in lines:
            if line.startswith("Package:"):
                info["package"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                info["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Homepage:"):
                info["homepage"] = line.split(":", 1)[1].strip()
            elif line.startswith("Maintainer:"):
                info["maintainer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Installed-Size:"):
                size_kb = line.split(":", 1)[1].strip()
                try:
                    size_mb = int(size_kb) / 1024
                    info["installed_size"] = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{size_kb} KB"
                except:
                    info["installed_size"] = f"{size_kb} KB"
            elif line.startswith("Description:"):
                desc_lines.append(line.split(":", 1)[1].strip())
                in_desc = True
            elif in_desc:
                if line.startswith(" "):
                    text = line.strip()
                    if text == ".":
                        desc_lines.append("")
                    else:
                        desc_lines.append(text)
                else:
                    in_desc = False

        if desc_lines:
            # Use package name as display name (capitalize nicely)
            info["name"] = info.get("package", "").replace("-", " ").title()
            info["description"] = " ".join(desc_lines).strip()
            return info
    except Exception:
        pass
    return None

def _try_rpm(pkg_name):
    """Query rpm for package metadata (RHEL/Fedora/SUSE)."""
    try:
        res = subprocess.run(["rpm", "-qi", pkg_name], capture_output=True, text=True, timeout=1.5)
        if res.returncode != 0:
            return None
        info = {"package": pkg_name}
        for line in res.stdout.splitlines():
            if line.startswith("Name"):
                info["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version"):
                info["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Summary"):
                info["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("URL"):
                info["homepage"] = line.split(":", 1)[1].strip()
            elif line.startswith("Size"):
                info["installed_size"] = line.split(":", 1)[1].strip()
        if info.get("description"):
            return info
    except Exception:
        pass
    return None

def _try_snap(prog):
    """Query snap for package info."""
    try:
        res = subprocess.run(["snap", "info", prog], capture_output=True, text=True, timeout=2)
        if res.returncode != 0:
            return None
        info = {"package": prog}
        for line in res.stdout.splitlines():
            if line.startswith("name:"):
                info["name"] = line.split(":", 1)[1].strip().title()
            elif line.startswith("summary:"):
                info["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("publisher:"):
                info["maintainer"] = line.split(":", 1)[1].strip()
            elif line.startswith("store-url:"):
                info["homepage"] = line.split(":", 1)[1].strip()
        if info.get("description"):
            return info
    except Exception:
        pass
    return None

def _try_whatis(prog):
    """Use whatis to get a one-line description from man pages."""
    try:
        res = subprocess.run(["whatis", prog], capture_output=True, text=True, timeout=1)
        if res.returncode == 0 and res.stdout.strip():
            # Format: "prog (section) - description"
            line = res.stdout.strip().splitlines()[0]
            if " - " in line:
                desc = line.split(" - ", 1)[1].strip()
                return {
                    "name": prog.title(),
                    "description": desc,
                    "package": prog
                }
    except Exception:
        pass
    return None

def _try_desktop_file(prog):
    """Search .desktop files for application metadata."""
    try:
        desktop_dirs = ["/usr/share/applications", "/var/lib/snapd/desktop/applications",
                        os.path.expanduser("~/.local/share/applications")]
        for d in desktop_dirs:
            if not os.path.isdir(d):
                continue
            for fname in os.listdir(d):
                if prog.lower() in fname.lower() and fname.endswith(".desktop"):
                    filepath = os.path.join(d, fname)
                    info = {"package": prog}
                    with open(filepath, 'r', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("Name=") and "name" not in info:
                                info["name"] = line.split("=", 1)[1]
                            elif line.startswith("Comment=") and "description" not in info:
                                info["description"] = line.split("=", 1)[1]
                            elif line.startswith("Icon="):
                                pass  # TUI can't show icons
                    if info.get("name") or info.get("description"):
                        return info
    except Exception:
        pass
    return None


def stop_process_or_service(pid, prog, stdscr):
    if not pid or not pid.isdigit():
        show_message(stdscr, "Invalid PID.")
        return

    # First check if it's a systemd service
    try:
        result = subprocess.run(
            ["systemctl", "status", prog],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            subprocess.run(["sudo", "systemctl", "stop", prog])
            show_message(stdscr, f"Service '{prog}' stopped.")
            return
    except Exception:
        pass

    # Otherwise kill normal process
    try:
        subprocess.run(["sudo", "kill", "-TERM", pid])
        show_message(stdscr, f"Process {pid} stopped.")
    except Exception as e:
        show_message(stdscr, f"Failed to stop {pid}: {e}")

def reload_process(pid, prog, stdscr):
    if not pid or not pid.isdigit():
        show_message(stdscr, "Invalid PID.")
        return

    # First check if it's a systemd service (does it support reload?)
    try:
        result = subprocess.run(
            ["systemctl", "status", prog],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            # systemctl reload usually sends SIGHUP but must be defined in service file
            subprocess.run(["sudo", "systemctl", "reload", prog])
            show_message(stdscr, f"Service '{prog}' reloaded.")
            return
    except Exception:
        pass

    # Otherwise send SIGHUP to normal process
    try:
        subprocess.run(["sudo", "kill", "-HUP", pid])
        show_message(stdscr, f"Sent SIGHUP to process {pid} ({prog}).")
    except Exception as e:
        show_message(stdscr, f"Failed to reload {pid}: {e}")

def force_kill_process(pid, prog, stdscr):
    if not pid or not pid.isdigit():
        show_message(stdscr, "Invalid PID.")
        return

    # Force kill can be dangerous, but requested from Action Center
    try:
        # Check if this process has a script ancestor to warn in logs
        cmd = get_full_cmdline(pid)
        debug_log(f"F-KILL: Targeted PID {pid} ({prog}). Cmd: {cmd}")
        
        res = subprocess.run(["sudo", "kill", "-9", pid], capture_output=True, text=True)
        debug_log(f"F-KILL: Result - Code {res.returncode}, Out: {res.stdout.strip()}, Err: {res.stderr.strip()}")
        
        # If it's a known loop runner (nc, bash), suggest tree kill in logs
        if "nc" in prog or "bash" in prog or "sh" in prog:
            debug_log("F-KILL ADVICE: This looks like a script/loop child. If it respawns, use [t] Force Kill Tree instead of [9].")
            
        show_message(stdscr, f"Process {pid} ({prog}) force killed (SIGKILL).")
    except Exception as e:
        debug_log(f"F-KILL: Exception - {str(e)}")
        show_message(stdscr, f"Failed to force kill {pid}: {e}")

def kill_process_group(pid, prog, port, stdscr):
    if not pid or not pid.isdigit():
        show_message(stdscr, "Invalid PID.")
        return
    
    show_message(stdscr, f"🚀 Precision Tree Strike on port {port}...", duration=1.0)
    
    try:
        debug_log(f"TREE-KILL: Starting precision scan for port {port} (PID {pid})")
        pids_to_strike = set([pid])
        scripts_found = set()
        
        # 1. ANCESTOR SCAN: Identify the script without killing the login shell
        curr_p = pid
        for level in range(12):
            if not curr_p or curr_p in ("0", "1"): break
            try:
                with open(f"/proc/{curr_p}/stat", "r") as f:
                    content = f.read()
                match = re.search(r"(\d+) \((.*)\) [A-Z] (\d+)", content)
                if not match: break
                
                name = match.group(2)
                ppid = match.group(3)
                cmdline = get_full_cmdline(curr_p)
                
                # Check if this is an interactive/login shell we should PROTECT
                # We skip shells that are likely the user's terminal session
                is_shell = name in ("bash", "sh", "dash", "zsh", "fish")
                
                # If it's a shell, only target it if it's running a specific script file
                # Otherwise, it might be the user's active terminal. 
                has_script = any(ext in cmdline for ext in (".sh", ".py", ".pl", ".php", ".js"))
                
                if is_shell and not has_script:
                    debug_log(f"TREE-KILL: Protecting interactive shell parent: {name}({curr_p})")
                    break # STOP HERE: Do not follow tree into the user's terminal
                
                if has_script:
                    for part in cmdline.split():
                        if any(part.endswith(ext) for ext in (".sh", ".py", ".pl", ".php", ".js")):
                            s_name = os.path.basename(part)
                            scripts_found.add(s_name)
                            debug_log(f"TREE-KILL: Targeting script process: {s_name}({curr_p})")
                
                pids_to_strike.add(curr_p)
                if name in ("sshd", "login", "tmux", "screen", "systemd", "init"): break
                curr_p = ppid
            except: break

        # 2. BROADCAST CLUSTER: Find all children of identified scripts
        for script in scripts_found:
            try:
                res = subprocess.run(["pgrep", "-f", script], capture_output=True, text=True)
                for p in res.stdout.split():
                    pids_to_strike.add(p)
            except: pass

        # 3. ATOMIC STRIKE: Kill only the target cluster
        if pids_to_strike:
            debug_log(f"TREE-KILL: Striking PIDs {pids_to_strike}")
            # Individual PIDs
            subprocess.run(["sudo", "kill", "-9"] + list(pids_to_strike), capture_output=True)
            
            # 4. PGID cleanup (only for the cluster PIDs, not general)
            for p in pids_to_strike:
                try:
                    res = subprocess.run(["ps", "-o", "pgid=", "-p", p], capture_output=True, text=True)
                    pg = res.stdout.strip()
                    if pg and pg != "0":
                         # Only kill the group if the leader is one of our targets
                         subprocess.run(["sudo", "kill", "-9", f"-{pg}"], capture_output=True)
                except: pass
            
            # Final fuser backup constrained to port only
            subprocess.run(["sudo", "fuser", "-k", "-9", "-n", "tcp", str(port)], capture_output=True)
            
            time.sleep(0.5) 
            show_message(stdscr, f"✅ Clean Kill: Tree terminated (Terminal protected).")
        else:
            show_message(stdscr, "No process found.")
            
    except Exception as e:
        debug_log(f"TREE-KILL: Precision Exception - {str(e)}")
        show_message(stdscr, f"Strike failed: {e}")

def pause_process(pid, prog, stdscr):
    try:
        pids = {pid}
        # Deep scan to find script parents that might be printing to terminal
        curr_p = pid
        for _ in range(10):
            if not curr_p or curr_p in ("0", "1"): break
            try:
                with open(f"/proc/{curr_p}/stat", "r") as f:
                    content = f.read()
                match = re.search(r"(\d+) \((.*)\) [A-Z] (\d+)", content)
                if not match: break
                name, ppid = match.group(2), match.group(3)
                cmdline = get_full_cmdline(curr_p)
                
                # Protect interactive shells
                if name in ("bash", "sh", "zsh", "fish") and not any(ext in cmdline for ext in (".sh", ".py", ".pl", ".js")):
                    break
                
                pids.add(curr_p)
                if name in ("sshd", "login", "tmux", "screen", "systemd"): break
                curr_p = ppid
            except: break

        for p in pids:
            subprocess.run(["sudo", "kill", "-STOP", p], capture_output=True)
        
        show_message(stdscr, f"Tree Paused: {prog} and script parents ({len(pids)} PIDs).")
        debug_log(f"PAUSE: Sent STOP to {pids}")
    except Exception as e:
        show_message(stdscr, f"Failed to pause: {e}")

def continue_process(pid, prog, stdscr):
    try:
        pids = {pid}
        curr_p = pid
        for _ in range(10):
            if not curr_p or curr_p in ("0", "1"): break
            try:
                with open(f"/proc/{curr_p}/stat", "r") as f:
                    content = f.read()
                match = re.search(r"(\d+) \((.*)\) [A-Z] (\d+)", content)
                if not match: break
                name, ppid = match.group(2), match.group(3)
                cmdline = get_full_cmdline(curr_p)
                if name in ("bash", "sh", "zsh", "fish") and not any(ext in cmdline for ext in (".sh", ".py", ".pl", ".js")):
                    break
                pids.add(curr_p)
                curr_p = ppid
            except: break

        for p in pids:
            subprocess.run(["sudo", "kill", "-CONT", p], capture_output=True)
            
        show_message(stdscr, f"Tree Continued: {prog} and parents resumed.")
        debug_log(f"CONTINUE: Sent CONT to {pids}")
    except Exception as e:
        show_message(stdscr, f"Failed to continue: {e}")

def restart_service(prog, stdscr):
    try:
        debug_log(f"RESTART: Attempting restart for '{prog}'")
        
        # 1. Check if it's actually a systemd service
        check = subprocess.run(["systemctl", "list-unit-files", f"{prog}.service"], capture_output=True, text=True)
        is_service = prog in check.stdout or (subprocess.run(["systemctl", "status", prog], capture_output=True).returncode < 4)

        if not is_service:
            msg = f"Error: '{prog}' is not a systemd service. Restarting scripts via 'r' is not supported (use 't' then run manually)."
            debug_log(f"RESTART: FAILED - {msg}")
            show_message(stdscr, msg, duration=3.0)
            return

        # 2. Execute restart
        res = subprocess.run(["sudo", "systemctl", "restart", prog], capture_output=True, text=True)
        
        if res.returncode == 0:
            msg = f"Service '{prog}' restarted successfully."
            debug_log(f"RESTART: SUCCESS - {prog}")
            show_message(stdscr, msg)
        else:
            msg = f"Failed to restart {prog}: {res.stderr.strip()}"
            debug_log(f"RESTART: ERROR - {msg}")
            show_message(stdscr, msg, duration=3.0)
            
    except Exception as e:
        debug_log(f"RESTART: Exception - {str(e)}")
        show_message(stdscr, f"Restart error: {e}")

def renice_process(pid, prog, nice_val, stdscr):
    try:
        debug_log(f"RENICE: Changing PID {pid} ({prog}) priority to {nice_val}")
        res = subprocess.run(["sudo", "renice", str(nice_val), "-p", pid], capture_output=True, text=True)
        if res.returncode == 0:
            show_message(stdscr, f"Priority of {prog} set to {nice_val}.")
            debug_log(f"RENICE: Success")
        else:
            show_message(stdscr, f"Renice failed: {res.stderr.strip()}")
            debug_log(f"RENICE: Error - {res.stderr.strip()}")
    except Exception as e:
        debug_log(f"RENICE: Exception - {str(e)}")
        show_message(stdscr, f"Renice error: {e}")

def draw_renice_modal(stdscr, pid, prog):
    h, w = stdscr.getmaxyx()
    bh, bw = 10, 50
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    
    title = f" ⚖️ Renice: {prog} ({pid}) "
    win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    
    options = [
        ("[1] High Priority (-10)", -10),
        ("[2] Normal (0)", 0),
        ("[3] Low Priority (10)", 10),
        ("[4] Very Low / BG (19)", 19),
        ("[ESC] Cancel", None)
    ]
    
    for i, (txt, val) in enumerate(options):
        win.addstr(2 + i, 4, txt)
    
    win.refresh()
    while True:
        k = win.getch()
        if k == 27: break # ESC
        if ord('1') <= k <= ord('4'):
            val = options[k - ord('1')][1]
            renice_process(pid, prog, val, stdscr)
            break
    
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def adjust_oom_score(pid, prog, score, stdscr):
    try:
        debug_log(f"OOM: Changing PID {pid} ({prog}) OOM Score Adj to {score}")
        # Use shell with sudo to write to /proc
        cmd = f"echo {score} | sudo tee /proc/{pid}/oom_score_adj"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode == 0:
            show_message(stdscr, f"OOM Score of {prog} set to {score}.")
            debug_log("OOM: Success")
        else:
            show_message(stdscr, f"OOM adjust failed: {res.stderr.strip()}")
            debug_log(f"OOM: Error - {res.stderr.strip()}")
    except Exception as e:
        debug_log(f"OOM: Exception - {str(e)}")
        show_message(stdscr, f"OOM adjust error: {e}")

def draw_oom_modal(stdscr, pid, prog):
    h, w = stdscr.getmaxyx()
    bh, bw = 12, 54
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    
    title = f" ☠️ OOM Score: {prog} ({pid}) "
    win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    
    options = [
        ("[1] Protected (-1000) - Never Kill", -1000),
        ("[2] Important (-500)", -500),
        ("[3] Normal (0)", 0),
        ("[4] Sacrificial (500)", 500),
        ("[5] Kill Me First (1000)", 1000),
        ("[ESC] Cancel", None)
    ]
    
    for i, (txt, val) in enumerate(options):
        win.addstr(2 + i, 4, txt)
    
    win.refresh()
    while True:
        k = win.getch()
        if k == 27: break
        if ord('1') <= k <= ord('5'):
            val = options[k - ord('1')][1]
            adjust_oom_score(pid, prog, val, stdscr)
            break
            
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def get_service_info(process_name, port=None):
    key = process_name.lower()
    if key in SERVICES_DB:
        return SERVICES_DB[key]
    # fallback to port
    if port:
        try:
            p_int = int(port)
            for svc, info in SERVICES_DB.items():
                if p_int in info.get('ports', []):
                    return info
        except: pass
    return {
        "name": "Unknown",
        "description": "This process does not match any known service in the local database.",
        "risk": "Unknown",
        "recommendation": "Investigate the process and port usage manually."
    }

def get_runtime_classification(pid, prog):
    if not pid or not pid.isdigit(): return "Unknown"
    try:
        if os.path.exists(f"/etc/systemd/system/{prog}.service") or \
           os.path.exists(f"/lib/systemd/system/{prog}.service") or \
           subprocess.run(["systemctl", "status", prog], capture_output=True).returncode == 0:
            return "systemd Service"
        
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmd = f.read().replace('\0', ' ')
            if any(ext in cmd for ext in [".sh", ".py", ".pl", ".php", ".js"]):
                return "Interpreter / Script"
        return "Binary Executable"
    except:
        return "Generic Process"

def build_inspect_content(pid, port, prog, username):
    lines = []
    lines.append(("                🔍 SYSTEM INSPECTION REPORT", CP_HEADER))
    lines.append(("" * 60, CP_BORDER))

    # 1. Service Knowledge (MOVED TO TOP)
    lines.append(("📚 SERVICE KNOWLEDGE", CP_ACCENT))
    svc_info = get_service_info(prog, port)
    lines.append((f"  Identity    : {svc_info.get('name')}", CP_TEXT))
    lines.append(("  Scope       :", CP_TEXT))
    desc_wrapped = textwrap.wrap(svc_info.get('description', ''), 70)
    for d_line in desc_wrapped:
        lines.append((f"    {d_line}", CP_TEXT))
    
    risk_lvl = svc_info.get('risk', 'Unknown')
    lines.append((f"  🚩 Risk Level: {risk_lvl}", CP_WARN if any(x in risk_lvl for x in ["High", "Danger", "Medium"]) else CP_TEXT))
    lines.append((f"  💡 Recommendation:", CP_ACCENT))
    rec_wrapped = textwrap.wrap(svc_info.get('recommendation', ''), 70)
    for r_line in rec_wrapped:
        lines.append((f"    {r_line}", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 2. Security Audit (MOVED TO TOP)
    lines.append(("⚠️ SECURITY AUDIT", CP_ACCENT))
    risks = []
    if username == "root":
        risks.append(("[!] PRIVILEGE: Running as ROOT", CP_WARN))
    if psutil and pid.isdigit():
        try:
            p = psutil.Process(int(pid))
            if "(deleted)" in p.exe():
                risks.append(("[!!!] DANGER: Executable deleted/malware suspect", CP_WARN))
            cwd = p.cwd()
            if any(pat in cwd for pat in ["/tmp", "/dev/shm"]):
                risks.append(("[!] SUSPICIOUS: Working in world-writable DIR", CP_WARN))
            conns = p.connections(kind='inet')
            for c in conns:
                if c.status == 'LISTEN' and c.laddr.ip in ['0.0.0.0', '::']:
                    risks.append(("[!] EXPOSURE: Listening on PUBLIC interface", CP_WARN))
                    break
        except: pass
        
    if not risks:
        lines.append(("  ✅ No critical security indicators detected.", CP_TEXT))
    else:
        for r_txt, r_cp in risks:
            lines.append((f"  {r_txt}", r_cp))

    lines.append(("", CP_TEXT))

    # 3. Runtime Classification
    lines.append(("🏷️ CLASSIFICATION", CP_ACCENT))
    classification = get_runtime_classification(pid, prog)
    lines.append((f"  Type        : {classification}", CP_TEXT))
    lines.append(("", CP_TEXT))
    
    # 4. Basic Process Info
    lines.append(("🧠 PROCESS DETAILS", CP_ACCENT))
    lines.append((f"  Name        : {prog}", CP_TEXT))
    lines.append((f"  PID         : {pid}", CP_TEXT))
    lines.append((f"  User        : {username}", CP_TEXT))
    
    if psutil and pid.isdigit():
        try:
            p = psutil.Process(int(pid))
            lines.append((f"  Status      : {p.status().upper()}", CP_TEXT))
            lines.append((f"  Started     : {datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S')}", CP_TEXT))
            lines.append((f"  CWD         : {p.cwd()}", CP_TEXT))
            lines.append((f"  Exec Path   : {p.exe()}", CP_TEXT))
            
            cmdline = " ".join(p.cmdline())
            lines.append(("  Command Line:", CP_TEXT))
            wrapped_cmd = textwrap.wrap(cmdline, 70)
            for w_line in wrapped_cmd:
                lines.append((f"    {w_line}", CP_TEXT))
        except Exception as e:
            lines.append((f"  [!] psutil meta error: {e}", CP_WARN))

    lines.append(("", CP_TEXT))

    # 5. Resource Pressure
    lines.append(("📊 RESOURCE PRESSURE", CP_ACCENT))
    usage = get_process_usage_cached(pid)
    lines.append((f"  System Load : {usage} (Mem/CPU)", CP_TEXT))
    if pid.isdigit():
        try:
            p = psutil.Process(int(pid))
            mem = p.memory_info().rss / (1024 * 1024)
            lines.append((f"  Resident Set: {mem:.2f} MB", CP_TEXT))
            lines.append((f"  Threads     : {p.num_threads()}", CP_TEXT))
        except: pass

    lines.append(("", CP_TEXT))

    # 6. Process Tree
    lines.append(("🌳 PROCESS TREE (Ancestry)", CP_ACCENT))
    tree = get_process_parent_chain(pid)
    for i, t_node in enumerate(tree):
        prefix = "  └─ " if i > 0 else "  "
        lines.append((f"{prefix}{t_node}", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 7. Process Reality Check
    lines.append(("🔥 PROCESS REALITY CHECK", CP_ACCENT))
    nice_val = get_process_nice(pid)
    oom_val = get_oom_score_adj(pid)
    lines.append((f"  Priority (Nice) : {nice_val}", CP_TEXT))
    lines.append((f"  OOM Score Adj   : {oom_val}", CP_TEXT))
    lines.append(("", CP_TEXT))

    # 8. Connection Visibility
    lines.append(("🌐 CONNECTION VISIBILITY", CP_ACCENT))
    c_info = get_connections_info_cached(port)
    lines.append((f"  Active Conn     : {c_info.get('active_connections', 0)}", CP_TEXT))
    lines.append((f"  Top Talker IP   : {c_info.get('top_ip', '-')}", CP_TEXT))
    lines.append(("  Recent IPs      :", CP_TEXT))
    for ip, cnt in c_info.get('all_ips', Counter()).most_common(5):
        lines.append((f"    {ip:<20} | {cnt} sessions", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 9. Service Activity History (NEW)
    lines.append(("🎬 SERVICE ACTIVITY HISTORY (Recent Events)", CP_ACCENT))
    history = get_service_activity_history(prog, pid, port)
    if not history:
        lines.append(("  ℹ️ No recent historical activity found in system logs.", CP_TEXT))
    else:
        for entry in history:
             # Entry format: (Timestamp, Message, Color)
             ts, msg, color = entry
             lines.append((f"  [{ts}] {msg}", color))

    lines.append(("", CP_TEXT))

    # 10. Why It Exists
    lines.append(("❓ WHY IT EXISTS (witr output)", CP_ACCENT))
    w_lines = get_witr_output_cached(port)
    if not w_lines or w_lines == ["No data"]:
        lines.append(("  No detailed witr analysis available.", CP_TEXT))
    else:
        for w_line in w_lines:
            for wrapped_w in textwrap.wrap(w_line, 70):
                lines.append((f"  {wrapped_w}", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 11. Open Files
    lines.append(("📂 OPEN FILES", CP_ACCENT))
    f_list = get_open_files_cached(pid)
    if not f_list:
        lines.append(("  Access denied or no files open.", CP_TEXT))
    else:
        lines.append((f"  Count: {len(f_list)} items", CP_TEXT))
        for f_item in f_list[:20]:
            lines.append((f"    {f_item}", CP_TEXT))
        if len(f_list) > 20:
            lines.append((f"    ... and {len(f_list)-20} more (see main view)", CP_TEXT))

    lines.append(("", CP_TEXT))
    return lines

def get_service_activity_history(prog, pid, port, max_entries=15):
    """
    Multi-strategy service activity history extraction.
    Adds process lifecycle info and deduplicates repeated messages.
    """
    events = []

    # ── SECTION 1: Process Lifecycle ────────────────────────────
    lifecycle = _get_process_lifecycle(prog, pid)
    if lifecycle:
        for entry in lifecycle:
            events.append(entry)
        events.append(("", "─" * 50, CP_TEXT))

    # ── SECTION 2: Log History ──────────────────────────────────
    raw_lines = []

    # Strategy 1: _COMM (most reliable — catches all instances)
    if prog:
        raw_lines = _journal_query(["journalctl", "-n", "100", "--output=short-iso",
                                     "--no-pager", f"_COMM={prog}"])

    # Strategy 2: systemd unit
    if not raw_lines and prog:
        raw_lines = _journal_query(["journalctl", "-n", "100", "--output=short-iso",
                                     "--no-pager", "-u", f"{prog}.service"])

    # Strategy 3: Current PID
    if not raw_lines and pid and pid.isdigit():
        raw_lines = _journal_query(["journalctl", "-n", "100", "--output=short-iso",
                                     "--no-pager", f"_PID={pid}"])

    # Strategy 4: grep /var/log/syslog
    if not raw_lines and prog:
        raw_lines = _syslog_grep(prog)

    # Strategy 5: Application-specific log files
    app_log_lines = []
    if prog:
        app_log_lines = _find_app_logs(prog, pid)

    # Parse and deduplicate log events
    log_events = _parse_log_events(raw_lines, max_entries * 2)  # Parse more, dedupe reduces
    log_events = _deduplicate_events(log_events, max_entries - len(events))

    events.extend(log_events)

    # Append app-specific log entries
    remaining = max_entries - len(events)
    if remaining > 0 and app_log_lines:
        deduped_app = _deduplicate_events(app_log_lines, remaining)
        events.extend(deduped_app)

    return events

def _get_process_lifecycle(prog, pid):
    """Extract process lifecycle: start time, uptime, who started it, restarts."""
    info = []
    try:
        if pid and pid.isdigit():
            # Start time from /proc
            try:
                with open(f"/proc/{pid}/stat") as f:
                    stat = f.read().split()
                    # Field 22 is starttime in clock ticks
                with open("/proc/uptime") as f:
                    uptime_secs = float(f.read().split()[0])
                clock_ticks = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
                start_ticks = int(stat[21])
                start_secs_ago = uptime_secs - (start_ticks / clock_ticks)
                start_time = datetime.now() - timedelta(seconds=start_secs_ago)
                uptime_str = _format_duration(start_secs_ago)

                info.append(("⏰", f"🚀 Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}", CP_ACCENT))
                info.append(("⏰", f"⏱️  Uptime: {uptime_str}", CP_ACCENT))
            except Exception:
                pass

            # Who started it (loginuid / parent)
            try:
                with open(f"/proc/{pid}/loginuid") as f:
                    loginuid = f.read().strip()
                if loginuid and loginuid != "4294967295":  # -1 means no login user
                    import pwd
                    username = pwd.getpwuid(int(loginuid)).pw_name
                    info.append(("👤", f"👤 Started by: {username}", CP_ACCENT))
            except Exception:
                pass

            # Current user running it
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("Uid:"):
                            uid = int(line.split()[1])
                            import pwd
                            owner = pwd.getpwuid(uid).pw_name
                            info.append(("👤", f"🏃 Running as: {owner}", CP_TEXT))
                            break
            except Exception:
                pass

        # Systemd service status (start/stop/restarts)
        if prog:
            try:
                res = subprocess.run(["systemctl", "show", f"{prog}.service",
                                       "--property=ActiveEnterTimestamp,InactiveEnterTimestamp,NRestarts,MainPID"],
                                      capture_output=True, text=True, timeout=1.5)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if line.startswith("ActiveEnterTimestamp=") and line.split("=", 1)[1].strip():
                            val = line.split("=", 1)[1].strip()
                            info.append(("📋", f"📋 Service activated: {val}", CP_TEXT))
                        elif line.startswith("InactiveEnterTimestamp=") and line.split("=", 1)[1].strip():
                            val = line.split("=", 1)[1].strip()
                            info.append(("📋", f"📋 Last stopped: {val}", CP_TEXT))
                        elif line.startswith("NRestarts="):
                            val = line.split("=", 1)[1].strip()
                            if val and val != "0":
                                info.append(("🔄", f"🔄 Restarts: {val}", CP_WARN))
            except Exception:
                pass

    except Exception:
        pass
    return info

def _format_duration(seconds):
    """Format seconds into human-readable duration."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    elif seconds < 86400:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h {m}m"
    else:
        d = seconds // 86400
        h = (seconds % 86400) // 3600
        return f"{d}d {h}h"

def _deduplicate_events(events, max_entries):
    """Collapse consecutive identical messages into '×N' counts."""
    if not events:
        return []
    deduped = []
    prev_msg = None
    repeat_count = 0

    for ts, msg, color in events:
        # Normalize message for comparison (strip timestamp-specific parts)
        msg_key = msg.strip()
        if msg_key == prev_msg:
            repeat_count += 1
        else:
            if repeat_count > 0 and deduped:
                # Update the last entry with repeat count
                last_ts, last_msg, last_color = deduped[-1]
                deduped[-1] = (last_ts, f"{last_msg} (×{repeat_count + 1})", last_color)
            prev_msg = msg_key
            repeat_count = 0
            deduped.append((ts, msg, color))
        if len(deduped) >= max_entries:
            break

    # Handle trailing repeats
    if repeat_count > 0 and deduped:
        last_ts, last_msg, last_color = deduped[-1]
        deduped[-1] = (last_ts, f"{last_msg} (×{repeat_count + 1})", last_color)

    return deduped[:max_entries]


def _journal_query(cmd):
    """Run a journalctl command and return non-empty lines."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if res.stdout and res.stdout.strip():
            lines = res.stdout.strip().splitlines()
            # Filter out journalctl meta-lines
            return [l for l in lines if not l.startswith("-- ")]
    except Exception:
        pass
    return []

def _syslog_grep(prog):
    """Search /var/log/syslog for process mentions."""
    syslog_paths = ["/var/log/syslog", "/var/log/messages"]
    for path in syslog_paths:
        try:
            if not os.path.exists(path):
                continue
            res = subprocess.run(["grep", "-i", prog, path],
                                 capture_output=True, text=True, timeout=2)
            if res.stdout and res.stdout.strip():
                lines = res.stdout.strip().splitlines()
                return lines[-100:]  # Last 100 lines
        except Exception:
            pass
    return []

def _find_app_logs(prog, pid=None):
    """Search for application-specific log files and extract recent entries."""
    events = []
    search_dirs = [
        os.path.expanduser(f"~/.config/{prog}"),
        os.path.expanduser(f"~/.local/share/{prog}"),
        f"/var/log/{prog}",
        f"/opt/{prog}",
        f"/tmp/{prog}",
    ]

    log_files = []
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for root, dirs, files in os.walk(d):
                for f in files:
                    if any(f.endswith(ext) for ext in [".log", ".log.1", ".txt"]) or "log" in f.lower():
                        fpath = os.path.join(root, f)
                        try:
                            mtime = os.path.getmtime(fpath)
                            log_files.append((mtime, fpath))
                        except:
                            pass
                # Don't recurse too deep
                if root.count(os.sep) - d.count(os.sep) >= 2:
                    dirs.clear()
        except Exception:
            pass

    # Sort by modification time (newest first) and read recent entries
    log_files.sort(reverse=True)
    for mtime, fpath in log_files[:3]:  # Check top 3 most recent log files
        try:
            # Read last 20 lines of each log file
            res = subprocess.run(["tail", "-n", "20", fpath],
                                 capture_output=True, text=True, timeout=1)
            if res.stdout:
                fname = os.path.basename(fpath)
                for line in res.stdout.strip().splitlines()[-5:]:
                    line = line.strip()
                    if line:
                        events.append(("LOG", f"📄 [{fname}] {line[:60]}", CP_TEXT))
        except Exception:
            pass

    return events

def _parse_log_events(raw_lines, max_entries):
    """Parse raw log lines into structured (timestamp, message, color) events."""
    events = []

    # Regex patterns for intelligence extraction
    ssh_login = re.compile(r"Accepted \w+ for (.*) from ([\d\.\:a-f]+) port (\d+)")
    ip_detect = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    session_open = re.compile(r"session opened|Connection from|Connected|Accepted", re.IGNORECASE)
    session_end = re.compile(r"session closed|Disconnected|Connection closed|closed by", re.IGNORECASE)
    error_detect = re.compile(r"failed|error|denied|Refused|Invalid|Cannot load|cannot", re.IGNORECASE)
    warning_detect = re.compile(r"warning|timeout|retry|deprecated", re.IGNORECASE)
    start_detect = re.compile(r"start|launch|listen|bind|init", re.IGNORECASE)

    for line in reversed(raw_lines):  # Most recent first
        if len(events) >= max_entries:
            break

        # Parse timestamp
        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            continue

        ts_raw = parts[0]
        try:
            dt = datetime.fromisoformat(ts_raw)
            ts = dt.strftime("%m-%d %H:%M")
        except:
            # Try traditional syslog format (Month Day HH:MM:SS)
            ts = ts_raw[:16] if len(ts_raw) > 16 else ts_raw

        content = parts[2] if len(parts) > 2 else line
        color = CP_TEXT
        display_msg = content

        # Intelligent Parsing (priority order)
        m_login = ssh_login.search(content)
        if m_login:
            user, ip, p = m_login.groups()
            display_msg = f"🔑 LOGIN: {user}@{ip} (p:{p})"
            color = CP_ACCENT
        elif session_end.search(content):
            display_msg = f"🚪 CLOSE: {content.split(':')[-1].strip()}"
            color = CP_TEXT
        elif session_open.search(content):
            display_msg = f"🟢 OPEN: {content.split(':')[-1].strip()}"
            color = CP_ACCENT
        elif error_detect.search(content):
            display_msg = f"⚠️ ALERT: {content.split(':')[-1].strip()}"
            color = CP_WARN
        elif warning_detect.search(content):
            display_msg = f"⚡ WARN: {content.split(':')[-1].strip()}"
            color = CP_WARN
        elif start_detect.search(content):
            display_msg = f"🚀 START: {content.split(':')[-1].strip()}"
            color = CP_ACCENT
        elif ip_detect.search(content):
            display_msg = f"🌐 {content.split(':')[-1].strip()}"
            color = CP_TEXT
        else:
            # Filter common noise
            if any(x in content for x in ["pam_unix", "Reached target", "Stopping",
                                           "Started", "systemd[1]"]):
                continue
            display_msg = content.split(":")[-1].strip()

        if display_msg:
            events.append((ts, display_msg[:70], color))

    return events


def show_inspect_modal(stdscr, port, prog, pid, username):
    lines = build_inspect_content(pid, port, prog, username)
    h, w = stdscr.getmaxyx()
    bh, bw = h - 6, min(80, w - 8)
    y, x = (h - bh) // 2, (w - bw) // 2
    
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.scrollok(True)
    
    scroll_pos = 0
    total_lines = len(lines)
    max_visible = bh - 4
    
    while True:
        win.erase()
        try: win.bkgd(' ', curses.color_pair(CP_TEXT))
        except: pass
        win.box()
        
        title = f" 🔍 Inspect: Port {port} - {prog} "
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        # Draw visible lines
        for i in range(max_visible):
            idx = scroll_pos + i
            if idx < total_lines:
                txt, color = lines[idx]
                try:
                    win.addstr(2 + i, 2, txt[:bw-4], curses.color_pair(color))
                except: pass
        
        footer = " ↑↓ Scroll | [e] Export | [q/ESC] Close "
        win.addstr(bh-1, (bw - len(footer)) // 2, footer, curses.color_pair(CP_ACCENT))
        
        win.refresh()
        k = win.getch()
        
        if k in (ord('q'), 27):
            break
        elif k == curses.KEY_UP and scroll_pos > 0:
            scroll_pos -= 1
        elif k == curses.KEY_DOWN and scroll_pos < total_lines - max_visible:
            scroll_pos += 1
        elif k == ord('e'):
            # Export to file
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = os.path.expanduser(f"~/heimdall-inspect-{port}-{timestamp}.txt")
            try:
                with open(filename, 'w') as f:
                    f.write(f"Heimdall Inspection Report - {datetime.now()}\n")
                    f.write("="*60 + "\n")
                    for txt, _ in lines:
                        f.write(txt + "\n")
                show_message(stdscr, f"Exported to {filename}")
            except Exception as e:
                show_message(stdscr, f"Export failed: {e}")
            break
            
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_status_indicator(stdscr):
    """
    Heimdall 'System Tray': Displays background update status and action feedback
    at the top-right corner.
    """
    global ACTION_STATUS_MSG, ACTION_STATUS_EXP
    h, w = stdscr.getmaxyx()
    now = time.time()
    
    msg = ""
    color = curses.color_pair(CP_WARN) | curses.A_BOLD
    
    # Priority 1: Action Feedback (Killed, Blocked, etc.)
    if ACTION_STATUS_MSG and now < ACTION_STATUS_EXP:
        is_error = any(kw in ACTION_STATUS_MSG.lower() for kw in ["failed", "error", "invalid", "danger", "strike failed"])
        msg = f" ⚡ {ACTION_STATUS_MSG} "
        if is_error:
            color = curses.color_pair(CP_WARN) | curses.A_REVERSE | curses.A_BOLD
        else:
            color = curses.color_pair(CP_ACCENT) | curses.A_REVERSE | curses.A_BOLD
    # Priority 2: Background Service Updates
    elif UPDATE_STATUS_MSG:
        icon = "🔄" if "Loading" in UPDATE_STATUS_MSG else "📡"
        msg = f" {icon} {UPDATE_STATUS_MSG} "
        color = curses.color_pair(CP_WARN) | curses.A_BOLD
    # Priority 3: Auto-Scan Heartbeat
    elif now < SCANNING_STATUS_EXP:
        msg = " 📡 Scanning... "
        color = curses.color_pair(CP_ACCENT) | curses.A_BOLD
        
    if msg:
        try:
            stdscr.addstr(0, max(0, w - len(msg) - 2), msg, color)
        except: pass

def draw_period_modal(stdscr):
    h, w = stdscr.getmaxyx()
    # Expanded intervals: (minutes, label)
    options = [
        (1, "1 Minute"),
        (5, "5 Minutes"),
        (15, "15 Minutes"),
        (30, "30 Minutes"),
        (60, "1 Hour"),
        (120, "2 Hours"),
        (1440, "1 Day")
    ]
    bh, bw = len(options) + 4, 40
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    
    title = " ⏱️ Update Interval "
    
    idx = 0
    curr = CONFIG.get("update_interval_minutes", 30)
    for i, opt in enumerate(options):
        if opt[0] == curr:
            idx = i
            break

    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        for i, (mins, label) in enumerate(options):
            display = f" {label} "
            if i == idx:
                win.addstr(2 + i, (bw - len(display)) // 2, display, curses.A_REVERSE | curses.A_BOLD)
            else:
                win.addstr(2 + i, (bw - len(display)) // 2, display, curses.color_pair(CP_TEXT))
        
        win.refresh()
        k = win.getch()
        if k == 27 or k == ord('q'): break
        elif k == curses.KEY_UP: idx = (idx - 1) % len(options)
        elif k == curses.KEY_DOWN: idx = (idx + 1) % len(options)
        elif k in (curses.KEY_ENTER, 10, 13):
            with CONFIG_LOCK:
                CONFIG["update_interval_minutes"] = options[idx][0]
            save_config()
            show_message(stdscr, f"Interval set to {options[idx][1]}")
            break
            
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_auto_update_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 10, 50
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    while True:
        win.erase(); win.box()
        title = " 🔄 Auto Update Settings "
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        auto_on = CONFIG.get("auto_update_services", True)
        interval = CONFIG.get("update_interval_minutes", 30)
        
        status_str = "[ENABLED]" if auto_on else "[DISABLED]"
        win.addstr(2, 4, f"Status: ", curses.color_pair(CP_TEXT))
        win.addstr(2, 12, status_str, curses.color_pair(CP_ACCENT) | curses.A_BOLD)
        
        win.addstr(4, 4, f"Interval: {interval} minutes", curses.color_pair(CP_TEXT))
        
        win.addstr(6, 4, "[t] Toggle On/Off", curses.color_pair(CP_TEXT))
        win.addstr(7, 4, "[p] Change Period", curses.color_pair(CP_TEXT))
        
        footer = " [q/ESC] Back "
        win.addstr(bh-2, (bw - len(footer)) // 2, footer, curses.color_pair(CP_TEXT))
        
        win.refresh()
        k = win.getch()
        if k == ord('q') or k == 27: break
        elif k == ord('t'):
            with CONFIG_LOCK:
                CONFIG["auto_update_services"] = not CONFIG["auto_update_services"]
            save_config()
        elif k == ord('p'):
            draw_period_modal(stdscr)

    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 8, 45
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    title = " ⚙️ Global Settings "
    
    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        win.addstr(2, 4, "[s] Auto Update Settings (Services)", curses.color_pair(CP_TEXT))
        win.addstr(3, 4, "[r] Background Scan Interval (UI)", curses.color_pair(CP_TEXT))
        
        footer = " [q/ESC] Close "
        win.addstr(bh-2, (bw - len(footer)) // 2, footer, curses.color_pair(CP_TEXT))
        
        win.refresh()
        k = win.getch()
        if k == ord('q') or k == 27: break
        elif k == ord('s'):
            draw_auto_update_settings_modal(stdscr)
        elif k == ord('r'):
            draw_auto_scan_settings_modal(stdscr)
            
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_auto_scan_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 12, 55
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    options = [
        (0.0, "Off (Manual Only)"),
        (1.0, "1 Second (Very Fast)"),
        (2.0, "2 Seconds (Fast)"),
        (3.0, "3 Seconds (Standard)"),
        (5.0, "5 Seconds (Balanced)"),
        (10.0, "10 Seconds (Relaxed)"),
        (30.0, "30 Seconds (Slower)")
    ]
    
    idx = 0
    curr = CONFIG.get("auto_scan_interval", 3.0)
    for i, opt in enumerate(options):
        if opt[0] == curr:
            idx = i
            break
            
    title = " 📡 UI Auto-Scan Settings "
    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        win.addstr(2, 4, "How often should the port list refresh by itself?", curses.A_DIM)
        
        for i, (val, label) in enumerate(options):
            display = f" {label} "
            if i == idx:
                win.addstr(4 + i, (bw - len(display)) // 2, display, curses.A_REVERSE | curses.A_BOLD)
            else:
                win.addstr(4 + i, (bw - len(display)) // 2, display, curses.color_pair(CP_TEXT))
                
        win.refresh()
        k = win.getch()
        if k == 27 or k == ord('q'): break
        elif k == curses.KEY_UP: idx = (idx - 1) % len(options)
        elif k == curses.KEY_DOWN: idx = (idx + 1) % len(options)
        elif k in (curses.KEY_ENTER, 10, 13):
            with CONFIG_LOCK:
                CONFIG["auto_scan_interval"] = options[idx][0]
            save_config()
            show_message(stdscr, f"Auto-Scan set to {options[idx][1]}")
            break
            
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def confirm_dialog(stdscr, question):
    h, w = stdscr.getmaxyx()
    win_h, win_w = 5, min(60, w - 4)
    win = curses.newwin(
        win_h,
        win_w,
        (h - win_h) // 2,
        (w - win_w) // 2
    )
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    win.addstr(1, 2, question, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    win.addstr(3, 2, "[y] Yes    [n] No")

    win.refresh()
    while True:
        k = win.getch()
        if k in (ord('y'), ord('Y')):
            return True
        if k in (ord('n'), ord('N'), 27):
            return False

# --------------------------------------------------
# Warnings / Annotation
# --------------------------------------------------
def annotate_warnings(lines):
    annotated = []
    for line in lines:
        annotated.append(line)
        if "Process is running from a suspicious working directory" in line:
            annotated.append("  ✔ Technical: Correct")
            annotated.append("  ⚠ Practical: normal for systemd services")
            annotated.append("  👉 Likely false positive")
    return annotated

# --------------------------------------------------
# Firewall toggle
# --------------------------------------------------
def toggle_firewall(port, stdscr, firewall_status):
    pid = None
    try:
        result = subprocess.run(
            ["ss", "-lntuHp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in result.stdout.splitlines():
            if f":{port}" in line:
                m = re.search(r'pid=(\d+)', line)
                if m:
                    pid = m.group(1)
                    break
    except Exception:
        pass
    if not pid:
        show_message(stdscr, f"No process found on port {port}.")
        return
    status = firewall_status.get(port, True)
    if status:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
        firewall_status[port] = False
        msg = f"Port {port} traffic DROPPED."
    else:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
        firewall_status[port] = True
        msg = f"Port {port} traffic ALLOWED."
    show_message(stdscr, msg)

def show_message(stdscr, msg, duration=3.0):
    """
    Post a non-blocking notification to the 'System Tray' (top-right).
    Does not halt execution; the message persists for `duration` seconds.
    """
    global ACTION_STATUS_MSG, ACTION_STATUS_EXP
    ACTION_STATUS_MSG = msg.strip()
    ACTION_STATUS_EXP = time.time() + duration
    debug_log(f"NOTIFY: {msg}")

def show_modal_message(stdscr, msg, duration=1.5):
    """
    Traditional blocking modal message for critical errors that require immediate attention.
    """
    h, w = stdscr.getmaxyx()
    win_h, win_w = 3, min(80, w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h)//2, (w - win_w)//2)
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
        win.box()
        msg_display = msg if len(msg) <= win_w - 4 else msg[:win_w - 7] + "..."
        win.addstr(1, 2, msg_display, curses.color_pair(CP_TEXT))
        win.refresh()
        time.sleep(duration)
    except Exception: pass
    finally:
        try:
            win.erase(); win.refresh(); del win
        except: pass
        stdscr.touchwin(); curses.doupdate()

# --------------------------------------------------
# UI Draw
# --------------------------------------------------
def get_process_state(pid):
    """Check if process is stopped (T) or running."""
    if not pid or not pid.isdigit(): return "RUNNING"
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            content = f.read()
            match = re.search(r"\) ([A-Zrt]) ", content)
            if match:
                state = match.group(1)
                # T: Stopped by job control signal, t: Stopped by debugger during tracing
                if state in ("T", "t"):
                    return "PAUSED"
    except:
        pass
    return "RUNNING"

def get_process_nice(pid):
    """Get the nice value from /proc/pid/stat (19th field)."""
    if not pid or not pid.isdigit(): return "0"
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            # 19th field (index 18) is the nice value
            return fields[18]
    except:
        return "0"

def get_oom_score_adj(pid):
    """Get OOM score adjustment from /proc/pid/oom_score_adj."""
    if not pid or not pid.isdigit(): return "0"
    try:
        with open(f"/proc/{pid}/oom_score_adj", "r") as f:
            return f.read().strip()
    except:
        return "0"

def get_preformatted_table_row(row, cache, firewall_status, w):
    port, proto, pidprog, prog, pid = row
    user = cache.get(port, {}).get("user", "-")
    now = time.time()
    key = str(port)
    entry = _table_row_cache.get(key)
    if entry:
        val, ts = entry
        if now - ts < TABLE_ROW_TTL:
            return val

    usage = get_process_usage_cached(pid)
    fw_icon = "⚡" if firewall_status.get(port, True) else "⛔"
    proc_icon = "👑" if user == "root" else "🧑"
    
    # Process status check for visual feedback
    is_paused = (get_process_state(pid) == "PAUSED")
    status_tag = "⏸ [PAUSED] " if is_paused else ""
    
    # Preformat with widths (adjust to table widths)
    widths = [10, 8, 18, 28, w - 68]  # same as headers
    data = [f"{fw_icon} {port}", proto.upper(), usage, f"{status_tag}{proc_icon} {prog}", f"👤 {user}"]
    row_str = ""
    for val, wd in zip(data, widths):
        row_str += val.ljust(wd)
    _table_row_cache[key] = (row_str, now)
    return row_str

def draw_table(win, rows, selected, offset, cache, firewall_status):
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    h, w = win.getmaxyx()
    
    # Border with theme color
    try:
        win.attron(curses.color_pair(CP_BORDER))
        win.box()
        win.attroff(curses.color_pair(CP_BORDER))
    except:
        pass

    # Header
    headers = ["🌐 PORT", "PROTO", "📊 USAGE [Mem/CPU]", "  🧠 PROCESS", "   👤 USER"]
    # Calculate widths dynamically to ensure right side is drawn
    # Fixed widths for first columns, dynamic for USER
    widths = [10, 8, 18, 28, max(10, w - 66)]
    x = 1
    
    hdr_attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
    
    for htxt, wd in zip(headers, widths):
        if x >= w - 1: 
            break
        try:
            # Ensure we don't write past the window width
            avail_w = w - x - 1
            if avail_w <= 0: break
            
            print_w = min(wd, avail_w)
            win.addstr(1, x, htxt[:print_w].ljust(print_w), hdr_attr)
        except:
            pass
        x += wd
        
    try:
        win.hline(2, 1, curses.ACS_HLINE, w - 2, curses.color_pair(CP_BORDER))
    except:
        pass
 
    # Rows
    for i in range(h - 4):
        idx = offset + i
        if idx >= len(rows):
            break
            
        is_selected = (idx == selected)
        # Apply theme colors to content
        if is_selected:
            attr = curses.color_pair(CP_ACCENT) | curses.A_REVERSE
        else:
            attr = curses.color_pair(CP_TEXT)
        
        pre_row_str = get_preformatted_table_row(rows[idx], cache, firewall_status, w)
        
        try:
            # Write row content, ensuring it fits within borders
            # Reduce max_len to w-4 to account for wide characters (emojis) taking up extra visual space
            max_len = max(1, w - 4)
            win.addstr(i+3, 1, pre_row_str[:max_len].ljust(max_len), attr)
            
            # 🔧 REPAIR BORDERS: Force redraw vertical lines to fix any overflow damage
            win.addch(i+3, 0, curses.ACS_VLINE, curses.color_pair(CP_BORDER))
            win.addch(i+3, w-1, curses.ACS_VLINE, curses.color_pair(CP_BORDER))
        except:
            pass
            
    win.noutrefresh()


def draw_detail(win, wrapped_icon_lines, scroll=0, conn_info=None):
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass

    h, w = win.getmaxyx()
    
    # Border
    try:
        win.attron(curses.color_pair(CP_BORDER))
        win.box()
        win.attroff(curses.color_pair(CP_BORDER))
    except:
        win.box()
        
    header = f"❓ Why It Exists"
    if h > 1:
        win.addstr(1, 2, header[:w-4], curses.color_pair(CP_HEADER) | curses.A_BOLD)
        try:
            win.hline(2, 1, curses.ACS_HLINE, w - 2, curses.color_pair(CP_BORDER))
        except:
            pass

    max_rows = h - 4

    # 🔹 Right-side panel
    conn_panel_w = max(34, w // 2)
    conn_panel_x = w - conn_panel_w - 1

    if conn_info:
        row_y = 3
        def safe_add(y, x, txt, attr=None):
            if attr is None:
                attr = curses.color_pair(CP_TEXT)
            elif not (attr & curses.A_COLOR):
                # If no color pair is specified in attr, default to CP_TEXT background/foreground
                attr |= curses.color_pair(CP_TEXT)

            if y < h - 1:
                try:
                    win.addstr(y, x, txt[:w - x - 1], attr)
                except curses.error:
                    pass

        # 🔴 Connection Visibility
        safe_add(row_y, conn_panel_x, "🔴 Connection Visibility", curses.A_BOLD | curses.A_UNDERLINE)
        row_y += 2
        safe_add(row_y, conn_panel_x, f"Active Connections : {conn_info['active_connections']}")
        row_y += 1
        safe_add(row_y, conn_panel_x, f"Top IP : {conn_info['top_ip']} ({conn_info['top_ip_count']})")
        row_y += 1
        safe_add(row_y, conn_panel_x, "IPs:")
        row_y += 1
        for ip, cnt in conn_info["all_ips"].most_common(5):
            if row_y >= h - 1:
                break
            safe_add(row_y, conn_panel_x, f"{ip} : {cnt}")
            row_y += 1

        row_y += 1
        # 🔥 PROCESS REALITY CHECK
        if row_y < h - 1:
            safe_add(row_y, conn_panel_x, "🔥 Process Reality Check (DEBUG)", curses.A_BOLD | curses.A_UNDERLINE)
            row_y += 1
        
        pid = conn_info.get("pid")
        if pid and pid.isdigit():
            # Show process priority (nice value)
            nice_val = get_process_nice(pid)
            nice_text = f"{nice_val} (Normal)" if nice_val == "0" else (f"{nice_val} (High)" if int(nice_val) < 0 else f"{nice_val} (Low)")
            safe_add(row_y, conn_panel_x, f"Priority (Nice)    : {nice_text}")
            row_y += 1

            # Show OOM Score
            oom_val = get_oom_score_adj(pid)
            oom_text = f"{oom_val} (Neutral)" if oom_val == "0" else (f"{oom_val} (Protected)" if int(oom_val) < 0 else f"{oom_val} (Vulnerable)")
            safe_add(row_y, conn_panel_x, f"OOM Score Adj      : {oom_text}")
            row_y += 1
            
            # Show full command line
            cmdline = get_full_cmdline(pid)
            safe_add(row_y, conn_panel_x, "📜 Command Line:")
            row_y += 1
            # Wrap cmdline if it's too long
            wrapped_cmd = textwrap.wrap(cmdline, conn_panel_w - 4)
            for l in wrapped_cmd[:3]: # Limit to 3 lines
                if row_y >= h - 1: break
                safe_add(row_y, conn_panel_x, f"  {l}")
                row_y += 1
            row_y += 1

            # use cached wrappers to avoid running heavy /proc ops during scroll
            chain = get_process_parent_chain_cached(pid)
            tree = format_process_tree(chain)
            for line in tree:
                if row_y >= h - 1:
                    break
                safe_add(row_y, conn_panel_x, line)
                row_y += 1

            # FILE DESCRIPTOR PRESSURE (use cached)
            row_y += 1
            if row_y < h - 1:
                safe_add(row_y, conn_panel_x, "🔥 RESOURCE PRESSURE (OPS)", curses.A_BOLD | curses.A_UNDERLINE)
                row_y += 1
            if row_y < h - 1:
                safe_add(row_y, conn_panel_x, "🔥 4. File Descriptor Pressure")
                row_y += 1
            if row_y < h - 1:
                safe_add(row_y, conn_panel_x, "📂 File Descriptors :")
                row_y += 1

            fd_info = get_fd_pressure_cached(pid)
            for key in ["open", "limit", "usage"]:
                if row_y >= h - 1:
                    break
                safe_add(row_y, conn_panel_x, f"  {key.capitalize()} : {fd_info[key]}")
                row_y += 1
            if row_y < h - 1:
                safe_add(row_y, conn_panel_x, f"  Risk  : {fd_info.get('risk','-')}")
                row_y += 1
            row_y += 1

            # RUNTIME CLASSIFICATION (use cached)
            if pid and pid.isdigit() and row_y < h - 1:
                runtime = detect_runtime_type_cached(pid)
                safe_add(row_y, conn_panel_x, "6️⃣ RUNTIME CLASSIFICATION (SMART)", curses.A_BOLD | curses.A_UNDERLINE)
                row_y += 1
                safe_add(row_y, conn_panel_x, f"🧩 Runtime :")
                row_y += 1
                safe_add(row_y, conn_panel_x, f"  Type : {runtime['type']}")
                row_y += 1
                safe_add(row_y, conn_panel_x, f"  Mode : {runtime['mode']}")
                row_y += 1
                safe_add(row_y, conn_panel_x, f"  GC   : {runtime['gc']}")
                row_y += 1
        else:
            safe_add(row_y, conn_panel_x, "<no pid>")

    # 🔹 Detail lines (LEFT PANE) - prewrapped and iconified
    for i in range(max_rows):
        idx = scroll + i
        if idx >= len(wrapped_icon_lines):
            continue
        line = wrapped_icon_lines[idx]
        try:
            safe_len = max(1, conn_panel_x - 5)
            win.addstr(i + 3, 2, line[:safe_len], curses.color_pair(CP_TEXT))
        except curses.error:
            pass
            
    win.noutrefresh()

def draw_open_files(win, pid, prog, files, scroll=0):
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    h, w = win.getmaxyx()
    
    # Border
    try:
        win.attron(curses.color_pair(CP_BORDER))
        win.box()
        win.attroff(curses.color_pair(CP_BORDER))
    except:
        win.box()

    header = f"📂 Open Files — PID {pid}/{prog} ({len(files)})"
    try:
        win.addstr(1, 2, header[:w-4], curses.color_pair(CP_HEADER) | curses.A_BOLD)
        try:
            win.hline(2, 1, curses.ACS_HLINE, w - 2, curses.color_pair(CP_BORDER))
        except: pass
    except:
        pass
        
    max_rows = h - 4
    for i in range(max_rows):
        idx = scroll + i
        if idx >= len(files):
            continue
        fd, path = files[idx]
        try:
            # Use normal text color
            line = f"{idx+1:3d}. [{fd}] {path}"
            max_len = max(1, w - 4)
            win.addstr(i+3, 2, line[:max_len], curses.color_pair(CP_TEXT))
        except:
            pass
            
    win.noutrefresh()


def draw_help_bar(stdscr, show_detail):
    h, w = stdscr.getmaxyx()
    # Descriptive labels restored with optimal spacing
    snap = " [🔄 r Refresh]" if SNAPSHOT_MODE else ""
    
    if not show_detail:
        help_text = (
            f" [🔍 i Inspect]{snap} [🎨 c Color] [⚙️ p Settings]"
            " [🧭 ↑↓ Select] [↕️ +/- Resize] [⇱⇲ Tab Pane]"
            " [📂 ←→ Files] [⛔ s Stop] [🔥 f Firewall] [🛠 a Actions] [❌ q Quit]"
        )
    else:
        help_text = " 🧭 ↑↓ Scroll  [Tab] Restore  ❌ Quit "

    try:
        bar_win = curses.newwin(3, w, h-3, 0)
        bar_win.erase()
        try:
            bar_win.bkgd(' ', curses.color_pair(CP_TEXT))
        except: pass
        
        # Border
        try:
            bar_win.attron(curses.color_pair(CP_BORDER))
            bar_win.box()
            bar_win.attroff(curses.color_pair(CP_BORDER))
        except:
            bar_win.box()
            
        # If terminal is too narrow, use the compact version as fallback
        if len(help_text) > w - 2:
            if not show_detail:
                help_text = (
                    f" [🔍i]{snap}[🎨c][⚙️p] [↑↓][+/-][Tab]"
                    " [📂←→][⛔s][🔥f][🛠a][❌q]"
                )
            else:
                help_text = " 🧭 ↑↓ [Tab]⇲ ❌q "

        x = max(1, (w - len(help_text)) // 2)
        try:
            bar_win.addstr(1, x, help_text, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except:
            try:
                bar_win.addstr(1, x, help_text, curses.color_pair(CP_TEXT) | curses.A_BOLD)
            except: pass
            
        bar_win.noutrefresh()
    except:
        pass

# -------------------------
# Action Center / Modals
# -------------------------
def draw_action_center_modal(stdscr, highlight_key=None):
    """
    Draw Action Center in a responsive modal with two columns.
    Ensures minimum/maximum sizes so it behaves on small terminals and is cleanly redrawable.
    """
    h, w = stdscr.getmaxyx()
    pad = 3
    # compute modal size respecting terminal
    bh = 14
    bh = min(bh, max(8, h - 6))
    bw = min(64, max(40, w - 10))
    y = max(0, (h - bh) // 2)
    x = max(0, (w - bw) // 2)
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()

    title = " 🔧 Action Center "
    try:
        win.addstr(0, max(1, (bw - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except curses.error:
        pass

    # columns
    col_gap = 3
    inner_w = bw - pad*2
    col_w = max(12, (inner_w - col_gap) // 2)
    left_x = pad
    right_x = pad + col_w + col_gap

    left_lines = [
        ("🌐 PORT OPERATIONS", None),
        ("  🚫  [b] Block IP", 'b'),
        ("  💥  [k] Kill Connections", 'k'),
        ("  🚦  [l] Connection Limit", 'l'),
    ]
    right_lines = [
        ("🧠 PROCESS OPERATIONS", None),
        ("  ⚡  [h] Reload (SIGHUP)", 'h'),
        ("  💀  [9] Force Kill (SIGKILL)", '9'),
        ("  🌳  [t] Force Kill Tree", 't'),
        ("  ⏸   [p] Pause Process", 'p'),
        ("  ▶   [c] Continue Process", 'c'),
        ("  🔄  [r] Restart Service", "r"),
        ("  ⚖️   [n] Renice", "n"),
        ("  ☠   [o] Adjust OOM Score", 'o'),
        ("  🐞  [d] Debug Dump", 'd'),
    ]

    start_row = 2
    for i, (txt, key) in enumerate(left_lines):
        attr = curses.A_NORMAL
        if key and highlight_key and key == highlight_key:
            attr = curses.A_REVERSE | curses.A_BOLD
        try:
            win.addstr(start_row + i, left_x, txt[:col_w].ljust(col_w), attr)
        except curses.error:
            pass

    for i, (txt, key) in enumerate(right_lines):
        attr = curses.A_NORMAL
        if key and highlight_key and key == highlight_key:
            attr = curses.A_REVERSE | curses.A_BOLD
        try:
            win.addstr(start_row + i, right_x, txt[:col_w].ljust(col_w), attr)
        except curses.error:
            pass

    footer = "[ESC] Cancel"
    try:
        win.addstr(bh - 2, pad, footer)
    except curses.error:
        pass

    win.noutrefresh()
    curses.doupdate()
    return win


def handle_action_center_input(stdscr, rows, selected, cache, firewall_status):
    """
    Draw the action center and handle single-key operations.
    Ensure modal fully clears on ESC and leaves main screen consistent.
    """
    if selected < 0 or selected >= len(rows):
        show_message(stdscr, "No port selected.")
        return

    port = rows[selected][0]
    conn_info = get_connections_info(port)
    conn_info["port"] = port

    win = draw_action_center_modal(stdscr)
    while True:
        k = win.getch()
        if k == 27:  # ESC
            # cleanly remove modal and refresh main screen
            try:
                win.erase()
                win.refresh()
                del win
            except Exception:
                pass
            stdscr.touchwin()
            curses.doupdate()
            return
        try:
            ch = chr(k)
        except Exception:
            ch = None

        if not ch:
            continue

        # Flash highlight feedback
        draw_action_center_modal(stdscr, highlight_key=ch)
        curses.doupdate()
        time.sleep(0.16)  # 160ms flash
        win = draw_action_center_modal(stdscr)  # redraw without highlight

        if ch == 'b':
            # Open Block IP modal
            draw_block_ip_modal(stdscr, port, conn_info, cache, firewall_status)
            # after modal returns, ensure main UI will be redrawn by caller
            try:
                win.erase()
                win.refresh()
                del win
            except Exception:
                pass
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'k':
            # Open Kill Connections modal
            draw_kill_connections_modal(stdscr, port, cache)
            # after modal returns, ensure main UI will be redrawn by caller
            try:
                win.erase()
                win.refresh()
                del win
            except Exception:
                pass
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'l':
            # Open Connection Limit modal
            draw_connection_limit_modal(stdscr, port)
            try:
                win.erase()
                win.refresh()
                del win
            except Exception:
                pass
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'h':
            # Reload (SIGHUP)
            port, proto, pidprog, prog, pid = rows[selected]
            reload_process(pid, prog, stdscr)
            request_list_refresh() 
            try:
                win.erase()
                win.refresh()
                del win
            except Exception:
                pass
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == '9':
            # Force Kill (SIGKILL)
            port, proto, pidprog, prog, pid = rows[selected]
            force_kill_process(pid, prog, stdscr)
            request_list_refresh()
            try:
                win.erase()
                win.refresh()
                del win
            except Exception:
                pass
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 't':
            # Kill Process Group
            port, proto, pidprog, prog, pid = rows[selected]
            kill_process_group(pid, prog, port, stdscr)
            request_list_refresh()
            # Since we cleared everything, we should probably exit modal back to main screen
            try:
                win.erase()
                win.refresh()
                del win
            except: pass
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'p':
            # Pause
            port, proto, pidprog, prog, pid = rows[selected]
            pause_process(pid, prog, stdscr)
            invalidate_port_cache(port) # ensure [PAUSED] tag shows up immediately
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'c':
            # Continue
            port, proto, pidprog, prog, pid = rows[selected]
            continue_process(pid, prog, stdscr)
            invalidate_port_cache(port)
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'r':
            # Restart Service
            port, proto, pidprog, prog, pid = rows[selected]
            restart_service(prog, stdscr)
            request_list_refresh()
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'n':
            # Renice
            port, proto, pidprog, prog, pid = rows[selected]
            draw_renice_modal(stdscr, pid, prog)
            invalidate_port_cache(port)
            stdscr.touchwin()
            curses.doupdate()
            return
        elif ch == 'o':
            # Adjust OOM Score
            port, proto, pidprog, prog, pid = rows[selected]
            draw_oom_modal(stdscr, pid, prog)
            invalidate_port_cache(port)
            stdscr.touchwin()
            curses.doupdate()
            return
        else:
            # For other keys, simple not-implemented message
            if ch in ('d',):
                show_message(stdscr, f"Action '{ch}' not implemented yet.")
                win = draw_action_center_modal(stdscr)
            else:
                # ignore other keys
                pass




def execute_block_ip(ip, port, cache, stdscr):
    """
    Validate IP strictly, run iptables to DROP traffic to the given port from ip,
    update cache[port]['blocked_ips'] and show a short message.
    """
    # basic safety checks
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        show_message(stdscr, "Invalid IP address.")
        return

    # length sanity: protect against overly long / malicious input
    if isinstance(addr, ipaddress.IPv4Address) and len(ip) > 15:
        show_message(stdscr, "IPv4 length too long.")
        return
    if isinstance(addr, ipaddress.IPv6Address) and len(ip) > 45:
        show_message(stdscr, "IPv6 length too long.")
        return

    # Attempt to apply iptables rule
    try:
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
        # update cache for immediate UI reflection
        cache.setdefault(port, {})
        blocked = cache[port].setdefault("blocked_ips", set())
        blocked.add(ip)
        show_message(stdscr, f"Blocked {ip} → port {port}")
        request_list_refresh()
    except subprocess.CalledProcessError:
        show_message(stdscr, "iptables failed (check sudo/iptables).")
    except Exception as e:
        show_message(stdscr, f"Error: {e}")


def kill_connection(local_addr, remote_addr, stdscr):
    """
    Kill a specific TCP connection using ss command.
    Uses sudo ss -K to kill the connection.
    """
    try:
        # ss -K requires src and dst specification
        # Format: ss -K dst REMOTE_ADDR src LOCAL_ADDR
        result = subprocess.run(
            ["sudo", "ss", "-K", "dst", remote_addr, "src", local_addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            show_message(stdscr, f"✅ Connection killed: {local_addr} ↔ {remote_addr}")
            request_full_refresh()
        else:
            # Try alternative method using conntrack if ss -K fails
            try:
                # Extract IPs and ports
                local_ip, local_port = local_addr.rsplit(":", 1)
                remote_ip, remote_port = remote_addr.rsplit(":", 1)
                
                subprocess.run(
                    ["sudo", "conntrack", "-D", "-p", "tcp",
                     "-s", local_ip, "--sport", local_port,
                     "-d", remote_ip, "--dport", remote_port],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                show_message(stdscr, f"✅ Connection killed (via conntrack): {local_addr} ↔ {remote_addr}")
                request_full_refresh()
            except Exception:
                show_message(stdscr, "⚠️ Failed to kill connection. Try sudo or check permissions.")
    except subprocess.TimeoutExpired:
        show_message(stdscr, "⚠️ Connection kill timed out.")
    except Exception as e:
        show_message(stdscr, f"❌ Error killing connection: {e}")


def get_connection_limits(port):
    """
    Get existing connection limit rules for a port from iptables.
    Returns list of dicts with: limit, action, rule_num
    """
    limits = []
    try:
        # iptables -L INPUT --line-numbers -n
        # We need to parse output to find rules related to our port and connlimit
        result = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5
        )
        
        # Parse iptables output
        # Example line:
        # 1    REJECT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 #conn src/32 > 10 reject-with tcp-reset
        for line in result.stdout.splitlines():
            # Basic filtering: ensure it's about our port and has connlimit marker
            if f"dpt:{port}" in line and ("connlimit" in line or "#conn" in line):
                parts = line.split()
                if len(parts) >= 2:
                    rule_num = parts[0]
                    target = parts[1]  # REJECT or DROP
                    
                    # Extract limit value
                    # Implementation detail: different iptables versions format this differently
                    # We look for something like "#conn ... > X"
                    limit_val = "?"
                    try:
                        # naive parser: look for number after '>'
                        if ">" in line:
                            # split by '>' and take the first token of the next part
                            limit_val = line.split(">")[1].strip().split()[0]
                    except:
                        pass
                    
                    limits.append({
                        "rule_num": rule_num,
                        "limit": limit_val,
                        "action": target
                    })
    except Exception:
        pass
    
    return limits


def set_connection_limit(port, limit, stdscr):
    """
    Set a per-IP connection limit for a port using iptables connlimit module.
    iptables -I INPUT -p tcp --dport PORT -m connlimit --connlimit-above LIMIT --connlimit-mask 32 -j REJECT --reject-with tcp-reset
    """
    try:
        cmd = [
            "sudo", "iptables", "-I", "INPUT", 
            "-p", "tcp", "--dport", str(port),
            "-m", "connlimit", "--connlimit-above", str(limit), 
            "--connlimit-mask", "32", 
            "-j", "REJECT", "--reject-with", "tcp-reset"
        ]
        
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=5
        )
        show_message(stdscr, f"✅ Limit set: {limit} conn/IP (port {port})")
        request_full_refresh()
        return True
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else "Unknown error"
        if "No chain/target/match" in error_msg or "connlimit" in error_msg:
             show_message(stdscr, "⚠️ 'connlimit' module missing in iptables?")
        else:
             show_message(stdscr, f"⚠️ Failed: {error_msg[:40]}...")
        return False
    except subprocess.TimeoutExpired:
        show_message(stdscr, "⚠️ iptables command timed out")
        return False
    except Exception as e:
        show_message(stdscr, f"❌ Error: {e}")
        return False


def remove_connection_limit(rule_num, stdscr):
    """
    Remove a connection limit rule by its line number.
    """
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", str(rule_num)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=5
        )
        show_message(stdscr, f"✅ Rule #{rule_num} removed")
        request_full_refresh()
        return True
    except subprocess.CalledProcessError:
        show_message(stdscr, "⚠️ Failed (rule changed position?)")
        return False
    except Exception as e:
        show_message(stdscr, f"❌ Error: {e}")
        return False



def draw_block_ip_modal(stdscr, port, conn_info, cache, firewall_status):
    """
    Block IP modal (iconography-enhanced):
    - Improved hints with emojis/icons
    - Shows Top connections and current ⛔ Blocked IPs for the port
    - Retains manual entry / numeric selection behavior
    """
    h, w = stdscr.getmaxyx()
    pad = 2
    # slightly wider modal to reduce wrapping
    prev_limit = min(100, max(60, w - 8))
    bw = min(w - 4, max(72, int(prev_limit * 1.10)))
    bh = min(18, max(10, h - 6))
    y = max(0, (h - bh) // 2)
    x = max(0, (w - bw) // 2)

    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.timeout(-1)
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    title = f" 🚫 Block IP — port {port} "
    try:
        win.addstr(0, max(1, (bw - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except curses.error:
        pass

    # Top IPs
    top_ips = []
    all_ips = conn_info.get("all_ips", {})
    for i, (ip, cnt) in enumerate(all_ips.most_common(8), start=1):
        top_ips.append((str(i), ip, cnt))

    # Current blocked IPs from cache
    blocked_set = set()
    try:
        blocked_set = set(cache.get(port, {}).get("blocked_ips", set()) or set())
    except Exception:
        blocked_set = set()

    row = 2
    # Header / instructions with icons
    try:
        hint = "🔎 Select a Top IP [1-8]  •  ✍️  Press 'm' to enter manually  •  ▶ Press 'x' to execute manual"
        win.addstr(row, pad, hint[:bw - pad*2], curses.color_pair(CP_TEXT) | curses.A_NORMAL)
    except curses.error:
        pass
    row += 2

    top_start_row = None
    if top_ips:
        try:
            win.addstr(row, pad, "🔥 Top connections (most active):", curses.color_pair(CP_ACCENT) | curses.A_BOLD)
        except curses.error:
            pass
        row += 1
        top_start_row = row
        for key, ip, cnt in top_ips:
            line = f"  [{key}] {ip}  •  {cnt} conn"
            try:
                win.addstr(row, pad, line[:bw - pad*2])
            except curses.error:
                pass
            row += 1
    else:
        try:
            win.addstr(row, pad, "ℹ️ No active connections found.", curses.color_pair(CP_TEXT) | curses.A_DIM)
        except curses.error:
            pass
        row += 1

    # Show current blocked IPs if any
    row += 0
    try:
        win.addstr(row, pad, "⛔ Blocked IPs:", curses.A_BOLD)
    except curses.error:
        pass
    row += 1
    if blocked_set:
        for ip in sorted(blocked_set)[: (bh - row - 5)]:
            try:
                win.addstr(row, pad, f"  • {ip}")
            except curses.error:
                pass
            row += 1
    else:
        try:
            win.addstr(row, pad, "  (none)", curses.A_DIM)
        except curses.error:
            pass
        row += 1

    # Manual hint
    try:
        manual_hint = "⌨️ Manual entry: press 'm' then type digits/dots (':' allowed for IPv6). ⌫ Backspace supported."
        win.addstr(row + 1, pad, manual_hint[:bw - pad*2], curses.A_NORMAL)
    except curses.error:
        pass

    input_buf = ""
    manual_mode = False

    def redraw_input():
        try:
            win.addstr(bh - 3, pad, " " * (bw - pad*2))
            prompt = ("🖊️  Manual IP: " + input_buf) if manual_mode else "✅ Ready"
            attr = curses.A_REVERSE | curses.A_BOLD if manual_mode else curses.A_DIM
            win.addstr(bh - 3, pad, prompt[:bw - pad*2], attr)
            win.noutrefresh()
            curses.doupdate()
        except curses.error:
            pass

    redraw_input()

    while True:
        k = win.getch()
        # ESC: cancel and cleanup
        if k == 27:
            try:
                win.erase(); win.refresh(); del win
            except Exception:
                pass
            stdscr.touchwin(); curses.doupdate()
            return

        # Manual input first (so digits are consumed into input_buf)
        if manual_mode:
            # Backspace variants
            if k in (8, 127, curses.KEY_BACKSPACE, 263):
                input_buf = input_buf[:-1]
                redraw_input()
                continue
            # Execute manual entry
            if k == ord('x'):
                if not input_buf:
                    show_message(stdscr, "⚠️ No IP entered.")
                    manual_mode = False
                    redraw_input()
                    continue
                # Validate IP
                try:
                    parsed = ipaddress.ip_address(input_buf)
                    if (isinstance(parsed, ipaddress.IPv4Address) and len(input_buf) > 15) or \
                       (isinstance(parsed, ipaddress.IPv6Address) and len(input_buf) > 45):
                        raise ValueError("IP textual length invalid.")
                except Exception:
                    show_message(stdscr, "❌ Invalid IP format.")
                    manual_mode = False
                    redraw_input()
                    continue

                # flash and execute
                try:
                    win.addstr(bh - 3, pad, f"⏳ Blocking {input_buf}...".ljust(bw - pad*2), curses.A_REVERSE | curses.A_BOLD)
                    win.noutrefresh(); curses.doupdate(); time.sleep(0.16)
                except curses.error:
                    pass

                execute_block_ip(input_buf, port, cache, stdscr)

                try:
                    win.erase(); win.refresh(); del win
                except Exception:
                    pass
                stdscr.touchwin(); curses.doupdate()
                return

            # Accept digits, dot, colon (for IPv6), hex letters for IPv6 a-f/A-F
            if (48 <= k <= 57) or k in (ord('.'), ord(':'), ord('a'), ord('b'), ord('c'), ord('d'), ord('e'), ord('f'),
                                        ord('A'), ord('B'), ord('C'), ord('D'), ord('E'), ord('F')):
                if len(input_buf) < 64:
                    input_buf += chr(k)
                    redraw_input()
                continue

            # ignore other keys while in manual
            continue

        # Toggle manual input
        if k in (ord('m'), ord('M')):
            manual_mode = True
            input_buf = ""
            redraw_input()
            continue

        # Numeric selection for top IPs (single-key)
        if 48 <= k <= 57 and top_ips:
            key = chr(k)
            for idx, (tkey, ip, cnt) in enumerate(top_ips):
                if tkey == key:
                    # highlight, flash
                    if top_start_row is not None:
                        line_y = top_start_row + idx
                    else:
                        line_y = 5 + idx
                    try:
                        win.addstr(line_y, pad, f"  [{tkey}] {ip}  •  {cnt} conn".ljust(bw - pad*2), curses.A_REVERSE | curses.A_BOLD)
                        win.noutrefresh(); curses.doupdate(); time.sleep(0.16)
                    except curses.error:
                        pass
                    # execute block
                    execute_block_ip(ip, port, cache, stdscr)
                    try:
                        win.erase(); win.refresh(); del win
                    except Exception:
                        pass
                    stdscr.touchwin(); curses.doupdate()
                    return
            continue

        # any other key is ignored in non-manual mode


def draw_kill_connections_modal(stdscr, port, cache):
    """
    Kill Connections modal:
    - Lists all active ESTABLISHED connections for the port
    - Allows user to select a connection by number (1-9) to kill it
    - Shows connection details: protocol, local addr, remote addr
    """
    h, w = stdscr.getmaxyx()
    pad = 2
    bw = min(w - 4, max(70, int(w * 0.85)))
    bh = min(20, max(12, h - 6))
    y = max(0, (h - bh) // 2)
    x = max(0, (w - bw) // 2)

    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.timeout(-1)
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    
    title = f" 💥 Kill Connections — port {port} "
    try:
        win.addstr(0, max(1, (bw - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except curses.error:
        pass

    # Get active connections
    connections = get_connection_list(port)
    
    row = 2
    try:
        hint = "🔎 Select connection [1-9] to kill  •  [ESC] Cancel"
        win.addstr(row, pad, hint[:bw - pad*2], curses.A_NORMAL)
    except curses.error:
        pass
    row += 2

    if not connections:
        try:
            win.addstr(row, pad, "ℹ️  No active connections found.", curses.A_DIM)
        except curses.error:
            pass
        row += 2
        try:
            win.addstr(row, pad, "Press any key to close...", curses.A_DIM)
        except curses.error:
            pass
        win.noutrefresh()
        curses.doupdate()
        win.getch()
        try:
            win.erase(); win.refresh(); del win
        except Exception:
            pass
        stdscr.touchwin(); curses.doupdate()
        return

    # Display connections (max 9)
    try:
        win.addstr(row, pad, "🔗 Active Connections:", curses.A_BOLD)
    except curses.error:
        pass
    row += 1
    
    conn_start_row = row
    display_connections = connections[:9]  # Limit to 9 for single-key selection
    
    for i, conn in enumerate(display_connections, 1):
        line = f"  [{i}] {conn['display']}"
        try:
            win.addstr(row, pad, line[:bw - pad*2])
        except curses.error:
            pass
        row += 1

    if len(connections) > 9:
        try:
            win.addstr(row, pad, f"  ... and {len(connections) - 9} more (showing first 9)", curses.A_DIM)
        except curses.error:
            pass
        row += 1

    row += 1
    try:
        footer = "⚠️  Warning: This will forcefully terminate the selected connection"
        win.addstr(row, pad, footer[:bw - pad*2], curses.A_DIM)
    except curses.error:
        pass

    win.noutrefresh()
    curses.doupdate()

    # Wait for user input
    while True:
        k = win.getch()
        
        # ESC: cancel
        if k == 27:
            try:
                win.erase(); win.refresh(); del win
            except Exception:
                pass
            stdscr.touchwin(); curses.doupdate()
            return

        # Numeric selection (1-9)
        if 49 <= k <= 57:  # ASCII codes for '1' to '9'
            idx = k - 49  # Convert to 0-based index
            if idx < len(display_connections):
                conn = display_connections[idx]
                
                # Highlight selected connection
                try:
                    line_y = conn_start_row + idx
                    line = f"  [{idx+1}] {conn['display']}"
                    win.addstr(line_y, pad, line[:bw - pad*2].ljust(bw - pad*2), 
                              curses.A_REVERSE | curses.A_BOLD)
                    win.noutrefresh()
                    curses.doupdate()
                    time.sleep(0.16)
                except curses.error:
                    pass

                # Kill the connection
                kill_connection(conn['local_addr'], conn['remote_addr'], stdscr)
                
                try:
                    win.erase(); win.refresh(); del win
                except Exception:
                    pass
                stdscr.touchwin(); curses.doupdate()
                return


def draw_connection_limit_modal(stdscr, port):
    """
    Connection Limit Modal:
    - Lists active iptables connlimit rules for the port
    - Allows adding new Per-IP limits (5, 10, 25, 50, 100)
    - Allows removing existing rules
    """
    h, w = stdscr.getmaxyx()
    pad = 2
    bw = min(w - 4, max(66, int(w * 0.80)))
    bh = min(20, max(14, h - 5))
    y = max(0, (h - bh) // 2)
    x = max(0, (w - bw) // 2)

    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.timeout(-1)
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    
    title = f" 🚦 Connection Limit — port {port} "
    try:
        win.addstr(0, max(1, (bw - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except curses.error:
        pass

    # 1. Get existing limits
    limits = get_connection_limits(port)
    
    current_row = 2
    
    # --- Existing Limits Section ---
    try:
        if limits:
            win.addstr(current_row, pad, "📜 Existing Limit Rules:", curses.A_BOLD)
            current_row += 1
            for rule in limits:
                line = f"  [#{rule['rule_num']}] Max {rule['limit']} conn/IP ({rule['action']})"
                if current_row < bh - 6:
                    try:
                        win.addstr(current_row, pad, line[:bw - pad*2])
                    except: pass
                    current_row += 1
        else:
            win.addstr(current_row, pad, "ℹ️  No limits active.", curses.A_DIM)
            current_row += 1
    except: pass
    
    # Separator
    current_row = max(current_row, 5) # Ensure some min height
    try:
        win.hline(current_row, 1, curses.ACS_HLINE, bw - 2)
    except: pass
    current_row += 1
    
    # --- Add Limit Section ---
    options = [5, 10, 25, 50, 100]
    option_map = {} # key char -> limit
    
    try:
        win.addstr(current_row, pad, "✨ Set New Per-IP Limit (REJECT):", curses.A_BOLD)
        current_row += 1
        
        chars = 'abcde'
        for i, opt in enumerate(options):
            key = chars[i]
            option_map[key] = opt
            line = f"  [{key}] Max {opt} connections"
            if current_row < bh - 3:
                try:
                     win.addstr(current_row, pad, line)
                except: pass
                current_row += 1
    except: pass

    # --- Footer / Instructions ---
    try:
         footer = "Press [a-e] to set • [x] Remove ALL limits • [ESC] Cancel"
         win.addstr(bh-2, pad, footer[:bw-pad*2], curses.A_DIM)
    except: pass
    
    win.noutrefresh()
    curses.doupdate()
    
    while True:
        k = win.getch()
        
        if k == 27: # ESC
            break
            
        try:
            ch = chr(k).lower()
        except:
            ch = None
            
        # Add Limit [a-e]
        if ch in option_map:
            limit = option_map[ch]
            try:
                msg = f"⏳ Setting limit {limit}..."
                win.addstr(bh-2, pad, msg.ljust(bw-pad*2), curses.A_REVERSE | curses.A_BOLD)
                win.noutrefresh(); curses.doupdate()
            except: pass
            
            set_connection_limit(port, limit, stdscr)
            break
            
        # Remove all limits [x]
        if ch == 'x':
            if not limits:
                # Flash "No limits"
                try:
                    win.addstr(bh-2, pad, "⚠️ No limits to remove!".ljust(bw-pad*2), curses.A_REVERSE | curses.A_BOLD)
                    win.noutrefresh(); curses.doupdate(); time.sleep(0.5)
                    # Restore footer
                    win.addstr(bh-2, pad, footer[:bw-pad*2], curses.A_DIM)
                    win.noutrefresh(); curses.doupdate()
                except: pass
                continue
                
            try:
                win.addstr(bh-2, pad, "⏳ Removing all limits...".ljust(bw-pad*2), curses.A_REVERSE | curses.A_BOLD)
                win.noutrefresh(); curses.doupdate()
            except: pass
            
            # Remove from bottom to top (highest rule num first) to avoid shifting issues
            # We must re-fetch limits because they might have changed (unlikely here but safe)
            current_limits = get_connection_limits(port)
            current_limits.sort(key=lambda x: int(x['rule_num']), reverse=True)
            
            count = 0
            for rule in current_limits:
               if remove_connection_limit(rule['rule_num'], stdscr):
                   count += 1
                   # short pause to let iptables serialize
                   time.sleep(0.1)
            
            show_message(stdscr, f"✅ Removed {count} rules.")
            break
            
    # Cleanup
    try:
        win.erase(); win.refresh(); del win
    except: pass
    stdscr.touchwin(); curses.doupdate()


def get_process_parent_chain(pid, max_depth=10):
    """
    Return real parent/supervisor chain like:
    systemd(1) -> bash datePrinter.sh(742) -> nc(3112)
    """
    chain = []
    seen = set()

    while pid and pid.isdigit() and pid not in seen and len(chain) < max_depth:
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                stat_content = f.read()
            
            # Use regex to find everything after the last ')' to safely get ppid (stat[3] equivalent)
            # stat format: pid (comm) state ppid ...
            match = re.search(r"(\d+) \((.*)\) [A-Z] (\d+)", stat_content)
            if not match: break
            
            comm_name = match.group(2)
            ppid = match.group(3)

            display_name = comm_name
            # Try to enrich with script name if it's a known interpreter
            try:
                with open(f"/proc/{pid}/cmdline", "r") as f:
                    cmd = f.read().replace("\0", " ").strip()
                    parts = cmd.split()
                    if parts:
                        exe = os.path.basename(parts[0])
                        if exe in ("bash", "sh", "python", "python3", "php", "node"):
                            # If second part looks like a script/file, include it
                            if len(parts) > 1 and not parts[1].startswith("-"):
                                script_name = os.path.basename(parts[1])
                                display_name = f"{exe} {script_name}"
            except:
                pass

            chain.append(f"{display_name}({pid})")

            if ppid == "0" or ppid == pid:
                break

            pid = ppid
        except Exception:
            break

    return list(reversed(chain))


def format_process_tree(chain):
    """
    Pretty tree output for UI
    """
    if not chain:
        return ["<no process chain>"]

    lines = ["🌳 Process Tree:"]
    for i, node in enumerate(chain):
        prefix = "   " * i + ("└─ " if i else "")
        lines.append(f"{prefix}{node}")
    return lines

def get_full_cmdline(pid):
    """Return full cmdline from /proc, with nulls replaced by spaces."""
    if not pid or not pid.isdigit():
        return "-"
    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmdline = f.read().replace("\0", " ").strip()
            return cmdline if cmdline else "-"
    except:
        return "-"

def get_fd_pressure(pid):
    """
    Return dict with open, limit, usage% and risk comment
    """
    fd_info = {
        "open": "-",
        "limit": "-",
        "usage": "-",
        "risk": "-"
    }
    if not pid or not pid.isdigit():
        return fd_info
    try:
        open_count = len(os.listdir(f"/proc/{pid}/fd"))
    except PermissionError:
        open_count = "-"
    except FileNotFoundError:
        open_count = "-"

    try:
        with open(f"/proc/{pid}/limits", "r") as f:
            for line in f:
                if "Max open files" in line:
                    parts = line.split()
                    limit = int(parts[3])
                    break
            else:
                limit = "-"
    except Exception:
        limit = "-"

    if isinstance(open_count, int) and isinstance(limit, int) and limit > 0:
        usage = int(open_count / limit * 100)
        risk = "⚠️ FD exhaustion often crashes in prod." if usage > 80 else "✔ Normal"
    else:
        usage = "-"
        risk = "-"

    fd_info.update({
        "open": open_count,
        "limit": limit,
        "usage": f"{usage}%" if usage != "-" else "-",
        "risk": risk
    })
    return fd_info

def detect_runtime_type(pid):
    """
    Detect runtime environment from PID.
    Returns dict:
    {
        "type": "-",
        "mode": "-",
        "gc": "-"
    }
    """
    runtime = {"type": "-", "mode": "-", "gc": "-"}
    if not pid or not pid.isdigit():
        return runtime
    try:
        # cmdline
        with open(f"/proc/{pid}/cmdline", "r") as f:
            cmdline = f.read().replace("\0", " ").lower()

        # environ
        env = {}
        try:
            with open(f"/proc/{pid}/environ", "r") as f:
                for e in f.read().split("\0"):
                    if "=" in e:
                        k,v = e.split("=",1)
                        env[k] = v
        except Exception:
            pass

        # Java detection
        if "java" in cmdline:
            runtime["type"] = "Java"
            if "spring-boot" in cmdline or "springboot" in cmdline:
                runtime["mode"] = "Spring Boot Server"
            else:
                runtime["mode"] = "Server" if "-jar" in cmdline else "App"
            # detect GC type from JAVA_OPTS or cmdline
            gc_match = re.search(r"-XX:\+Use([A-Za-z0-9]+)GC", cmdline)
            if not gc_match:
                gc_match = re.search(r"GC=([A-Za-z0-9]+)", " ".join(env.get("JAVA_OPTS","").split()))
            runtime["gc"] = gc_match.group(1) if gc_match else "Unknown"
        elif "node" in cmdline or "nodejs" in cmdline:
            runtime["type"] = "Node"
            runtime["mode"] = "Server"
        elif "python" in cmdline:
            runtime["type"] = "Python"
            runtime["mode"] = "Script"
        elif "nginx" in cmdline:
            runtime["type"] = "Nginx"
            runtime["mode"] = "Server"
        elif "postgres" in cmdline or "postmaster" in cmdline:
            runtime["type"] = "Postgres"
            runtime["mode"] = "DB Server"
        elif "go" in cmdline:
            runtime["type"] = "Go"
            runtime["mode"] = "Server"
    except Exception:
        pass
    return runtime
# --------------------------------------------------
# Main Loop
# --------------------------------------------------
def main(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)
    # make input non-blocking with short timeout so we can debounce selection and let caches serve during fast scroll
    stdscr.timeout(120)  # ms

    # Initialize theme
    apply_current_theme(stdscr)

    # Start the background services updater
    start_services_updater()

    # use cached parse initially to reduce startup churn

    rows = parse_ss_cached()
    cache = {}
    firewall_status = {}
    splash_screen(stdscr, rows, cache)

    selected = 0 if rows else -1
    offset = 0
    table_h = max(6, (curses.LINES-3)//2)
    show_detail = False
    detail_scroll = 0
    open_files_scroll = 0
    cached_port = None
    cached_wrapped_icon_lines = []
    cached_total_lines = 0
    cached_conn_info = None

    # track selection changes to avoid fetching heavy details while user scrolls quickly
    last_selected = selected
    last_selected_change_time = time.time()

    global TRIGGER_REFRESH  # we will mutate this inside the loop
    last_auto_scan_time = time.time()
    
    while True:
        # Periodic background refresh (Auto-scan)
        if not show_detail:
            auto_interval = CONFIG.get("auto_scan_interval", 3.0)
            if auto_interval > 0 and time.time() - last_auto_scan_time > auto_interval:
                global SCANNING_STATUS_EXP
                SCANNING_STATUS_EXP = time.time() + 1.0
                request_list_refresh()

        h, w = stdscr.getmaxyx()
        visible_rows = table_h-4

        # refresh rows from cached parser (fast)
        rows = parse_ss_cached()

        if not show_detail and rows:
            table_win = curses.newwin(table_h, w//2, 0, 0)
            try: table_win.bkgd(' ', curses.color_pair(CP_TEXT))
            except: pass
            draw_table(table_win, rows, selected, offset, cache, firewall_status)

            open_files_win = curses.newwin(table_h, w-w//2, 0, w//2)
            try: open_files_win.bkgd(' ', curses.color_pair(CP_TEXT))
            except: pass
            pid = rows[selected][4] if selected>=0 and selected < len(rows) else "-"
            prog = rows[selected][3] if selected>=0 and selected < len(rows) else "-"
            # use cached open-files to avoid expensive /proc reads on every keypress
            files = get_open_files_cached(pid)
            draw_open_files(open_files_win, pid, prog, files, scroll=open_files_scroll)

            detail_win = curses.newwin(h-table_h-3, w, table_h, 0)
            try: detail_win.bkgd(' ', curses.color_pair(CP_TEXT))
            except: pass

            # debounce heavy detail fetch: only update cached_wrapped_lines / conn_info when selection stable
            now = time.time()
            selection_changed = (selected != last_selected)
            if selection_changed:
                last_selected_change_time = now
                last_selected = selected

            selection_stable = (now - last_selected_change_time) >= SELECT_STABLE_TTL

            if selected>=0 and rows:
                port = rows[selected][0]
                # only refresh heavy witr+conn+proc details if selection stable or cached_port different
                if cached_port != port:
                    # Prefer already-preloaded cached data even if selection debounce not yet expired.
                    port_cache = cache.get(port, {})
                    witr_entry = _witr_cache.get(str(port))
                    conn_entry = _conn_cache.get(str(port))
                    if selection_stable or (witr_entry is not None and conn_entry is not None):
                        cached_port = port
                        # Use prewrapped icon lines from cache
                        cached_wrapped_icon_lines = port_cache.get("wrapped_icon_lines", [])
                        cached_total_lines = len(cached_wrapped_icon_lines)
                        cached_conn_info = get_connections_info_cached(port)
                        cached_conn_info["port"] = port
                        cached_conn_info["pid"] = rows[selected][4]
                    else:
                        # show quick placeholder until stable or until preloaded
                        placeholder = ["Waiting for selection to stabilize..."]
                        cached_wrapped_icon_lines = placeholder
                        cached_total_lines = len(placeholder)
                        cached_conn_info = {"active_connections": 0, "top_ip": "-", "top_ip_count": 0, "all_ips": Counter(), "port": port, "pid": rows[selected][4]}
                # Check if window resized significantly, rewrap if needed
                prewrapped_width = port_cache.get("prewrapped_width", 0)
                if abs(w - prewrapped_width) > 10:  # Threshold for rewrap
                    lines = port_cache.get("lines", [])
                    sel_prog = rows[selected][3] if selected >= 0 and selected < len(rows) else None
                    cached_wrapped_icon_lines = prepare_witr_content(lines, w - 4, prog=sel_prog, port=port)
                    if port in cache:
                        cache[port]["wrapped_icon_lines"] = cached_wrapped_icon_lines
                        cache[port]["prewrapped_width"] = w
                    cached_total_lines = len(cached_wrapped_icon_lines)
                draw_detail(detail_win, cached_wrapped_icon_lines, scroll=detail_scroll, conn_info=cached_conn_info)
            else:
                draw_detail(detail_win, [], scroll=0, conn_info=None)

            draw_help_bar(stdscr, show_detail)

        elif show_detail:
            detail_win = curses.newwin(h-3, w, 0, 0)
            draw_detail(detail_win, cached_wrapped_icon_lines, scroll=detail_scroll, conn_info=cached_conn_info)
            draw_help_bar(stdscr, show_detail)

        draw_status_indicator(stdscr)
        curses.doupdate()

        # If any modal/action requested a full refresh, do the same sequence used for 'r'
        global TRIGGER_LIST_ONLY
        if TRIGGER_REFRESH or TRIGGER_LIST_ONLY:
            is_full = TRIGGER_REFRESH
            TRIGGER_REFRESH = False
            TRIGGER_LIST_ONLY = False
            
            # IMPORTANT: Disable snapshot mode temporarily to allow fresh scan
            global SNAPSHOT_MODE
            old_mode = SNAPSHOT_MODE
            SNAPSHOT_MODE = False
            
            # For list-only, we skip clearing service metadata caches (witr, conn)
            if is_full:
                _witr_cache.clear()
                _conn_cache.clear()
                cache.clear()
            
            _parse_cache.clear()
            _table_row_cache.clear()
            
            # Force a real, non-cached parse
            rows = parse_ss() 
            if is_full:
                splash_screen(stdscr, rows, cache)
            
            SNAPSHOT_MODE = old_mode
            
            if selected >= len(rows):
                selected = len(rows) - 1
            if selected < 0 and rows:
                selected = 0
            offset = min(max(selected - visible_rows // 2, 0), max(0, len(rows) - visible_rows))
            # update last interaction to avoid immediate fetch churn
            last_selected_change_time = time.time()
            last_auto_scan_time = time.time()
            continue

        k = stdscr.getch()

        # if no key pressed (timeout), continue loop so cached parse and selection debounce can update UI
        if k == -1:
            continue

        if k == ord('q'):
            break
        if show_detail:
            if k == curses.KEY_UP and detail_scroll>0:
                detail_scroll -= 1
            elif k == curses.KEY_DOWN and detail_scroll < max(0,cached_total_lines-(h-3)):
                detail_scroll += 1
            elif k == KEY_TAB:
                show_detail = False
                detail_scroll = 0
        else:
            if k == curses.KEY_UP and selected>0:
                selected -=1
            elif k == curses.KEY_DOWN and selected<len(rows)-1:
                selected +=1
            elif k == KEY_SEP_UP and table_h<max(6, h-3-2):
                table_h +=1
            elif k == KEY_SEP_DOWN and table_h>6:
                table_h -=1
            elif k == ord('r'):
                # force real refresh and clear caches
                rows = parse_ss()
                _parse_cache.clear(); _witr_cache.clear(); _conn_cache.clear()
                _table_row_cache.clear()
                cache.clear()
                splash_screen(stdscr, rows, cache)
                if selected>=len(rows):
                    selected = len(rows)-1
                offset=0
            elif k == KEY_TAB:
                show_detail = True
                detail_scroll =0
            elif k == curses.KEY_RIGHT:
                open_files_scroll +=1
            elif k == curses.KEY_LEFT and open_files_scroll>0:
                open_files_scroll -=1
            elif k == ord('s') and selected>=0 and rows:
                port, proto, pidprog, prog, pid = rows[selected]
                confirm = confirm_dialog(stdscr, f"{pidprog} ({port}) stop?")
                if confirm:
                    stop_process_or_service(pid, prog, stdscr)
                    request_list_refresh()
            elif k == ord('a'):
                # open Action Center modal
                handle_action_center_input(stdscr, rows, selected, cache, firewall_status)
            elif k == ord('i') and selected >= 0 and rows:
                # Open Inspection/Information modal
                port, proto, pidprog, prog, pid = rows[selected]
                # get username from cache if available
                user = cache.get(port, {}).get("user", "unknown")
                show_inspect_modal(stdscr, port, prog, pid, user)
            elif k == ord('p'):
                # Settings modal (changed from 'S' to 'p')
                draw_settings_modal(stdscr)
            elif k == KEY_FIREWALL and selected >= 0 and rows:
                port = rows[selected][0]
                toggle_firewall(port, stdscr, firewall_status)
            elif k == ord('c'):
                # Switch theme (Colorize)
                global CURRENT_THEME_INDEX
                CURRENT_THEME_INDEX = (CURRENT_THEME_INDEX + 1) % len(THEMES)
                save_theme_preference(CURRENT_THEME_INDEX)
                apply_current_theme(stdscr)
                # Show feedback
                t_name = THEMES[CURRENT_THEME_INDEX]['name']
                try:
                    h, w = stdscr.getmaxyx()
                    msg = f" Theme: {t_name} "
                    stdscr.addstr(h//2, (w-len(msg))//2, msg, curses.A_REVERSE | curses.A_BOLD)
                    stdscr.refresh()
                    time.sleep(0.5)
                except: pass
                # Force redraw
                rows = parse_ss_cached()
                splash_screen(stdscr, rows, cache)
                continue
            elif k == 27:  # Potential ALT key (ESC) sequence
                stdscr.nodelay(True)
                next_k = stdscr.getch()
                stdscr.nodelay(False)  # restore loop timeout later
                stdscr.timeout(120)    # restore explicit timeout

                if next_k == ord('c'):
                    pass # Handled by direct 'c' key now

            if selected >= len(rows):
                selected = len(rows) - 1
            if selected < 0 and rows:
                selected = 0

            offset = min(max(selected - visible_rows // 2, 0), max(0, len(rows) - visible_rows))


def check_and_show_terminal_size_then_exit():
    try:
        # os.get_terminal_size() is most reliable and doesn't require curses initialized
        size = os.get_terminal_size()
        cols = size.columns
        rows = size.lines

        # Minimum required dimensions
        MIN_COLS = 100
        MIN_ROWS = 24
        
        if cols < MIN_COLS or rows < MIN_ROWS:
            print("┌────────────────────────────────────────────────────────────┐")
            print("│                  TERMINAL SIZE TOO SMALL                   │")
            print("├────────────────────────────────────────────────────────────┤")
            print(f"│  Current size:    {cols:4d} cols × {rows:3d} lines                    │")
            print("│                                                            │")
            print("│  Minimum required:                                         │")
            print(f"│     → At least {MIN_COLS} cols × {MIN_ROWS} lines                         │")
            print("│     → 140+ cols recommended for best experience            │")
            print("└────────────────────────────────────────────────────────────┘")
            print("\nPlease resize your terminal and try again.\n")
            sys.exit(1)
        
    except OSError:
        # If not a TTY, we might still want to try running or just exit.
        # For now, let's just let it pass or show a warning.
        pass


def cli_entry():
    """terminal command 'heimdall' entry point"""
    check_and_show_terminal_size_then_exit()
    check_python_version()
    check_witr_exists()
    args = parse_args()
    if args.no_update:
        CONFIG["auto_update_services"] = False
    curses.wrapper(main)


if __name__ == "__main__":
    # developer entry python heimdall.py
    cli_entry()