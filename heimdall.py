#!/usr/bin/env python3
import sys
import curses
import subprocess
import re
import textwrap
import os
import time
import argparse
from shutil import which
from collections import Counter
import ipaddress
import functools
import threading

KEY_SEP_UP = ord('+')
KEY_SEP_DOWN = ord('-')
KEY_TAB = 9
KEY_FIREWALL = ord('f')

# initialize global refresh trigger used by request_full_refresh()
TRIGGER_REFRESH = False

# --------------------------------------------------
# 🎨 Themes & Colors
# --------------------------------------------------
CURRENT_THEME_INDEX = 0

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
    parser.add_argument('--version', action='version', version='heimdall 0.3.0')
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

    # Interface eşleştir
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
        # ESTABLISHED bağlantıları al
        result = subprocess.run(
            ["ss", "-ntu", "state", "established", f"( dport = :{port} or sport = :{port} )"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        lines = result.stdout.strip().splitlines()[1:]  # skip header

        unique_connections = set()  # IP:PORT bazlı tekil bağlantı
        ips = []

        for l in lines:
            parts = l.split()
            if len(parts) >= 5:
                raddr = parts[4]
                # Tekil bağlantı
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

def request_full_refresh():
    """Signal main loop to perform full refresh (same as pressing 'r')."""
    global TRIGGER_REFRESH
    TRIGGER_REFRESH = True

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

    bh = min(18, h - 6)          # Daha yüksek pencere
    bw = min(99, w - 6)          # Daha geniş (taşma önlemek için yeterli)
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

    # Bar genişliğini biraz daha güvenli ve kontrollü yapalım
    bar_w = max(40, bw - 20)   # min 40 karakter garanti, taşma olmaz

    for i, row in enumerate(rows, 1):
        port = row[0]

        win.erase()
        win.box()

        # HEIMDALL yazısı (mor)
        for idx, line in enumerate(heimdall_art):
            line_x = max(0, (bw - len(line)) // 2)
            win.addstr(2 + idx, line_x, line[:bw-4],
                       curses.color_pair(1) | curses.A_BOLD)

        # Slogan (cyan)
        slogan_x = max(0, (bw - len(slogan)) // 2)
        win.addstr(slogan_y + 2, slogan_x, slogan,
                   curses.color_pair(2) | curses.A_ITALIC)

        # Alt kısım: Collecting data + port
        win.addstr(progress_y, 4, "Collecting system intelligence...", curses.color_pair(3))
        win.addstr(progress_y + 1, 4, f"Scanning port: {port}", curses.color_pair(4))

        # Progress bar + adım sayısı BAR'IN İÇİNDE (taşma imkansız)
        filled = int(bar_w * i / total)
        bar = "█" * filled + "░" * (bar_w - filled)

        progress_str = f" {i}/{total} "
        mid = bar_w // 2
        start_pos = mid - len(progress_str) // 2

        # Eğer bar çok kısa ise başa yasla (güvenlik)
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

        # --- Mevcut preload kodları (hiç değişmiyor) ---
        try:
            lines = get_witr_output(port)
            _witr_cache[str(port)] = (lines, time.time())
            user = extract_user_from_witr(lines)
            process = extract_process_from_witr(lines)
            detail_width = w - 4
            wrapped_icon_lines = prepare_witr_content(lines, detail_width)
            cache[port] = {
                "user": user,
                "process": process,
                "lines": lines,
                "wrapped_icon_lines": wrapped_icon_lines,
                "prewrapped_width": detail_width
            }
        except Exception:
            cache[port] = {"user": "-", "process": "-", "lines": ["No data"], "wrapped_icon_lines": []}

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

    # Bitiş ekranı
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

def prepare_witr_content(lines, width):
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
        # icon replacement sadece bir kere yapılacak
        for key, icon in icons.items():
            if key in line and not line.strip().startswith(icon):
                line = line.replace(key, f"{icon} {key}", 1)
        wrapped.extend(textwrap.wrap(line, width=width) or [""])
    return wrapped

def stop_process_or_service(pid, prog, stdscr):
    if not pid or not pid.isdigit():
        show_message(stdscr, "Invalid PID.")
        return

    # Önce systemd service mi diye bak
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

    # Değilse normal process öldür
    try:
        subprocess.run(["sudo", "kill", "-TERM", pid])
        show_message(stdscr, f"Process {pid} stopped.")
    except Exception as e:
        show_message(stdscr, f"Failed to stop {pid}: {e}")

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

def show_message(stdscr, msg, duration=1.5):
    """
    Display a small centered message for `duration` seconds without altering stdscr timeout.
    Uses sleep + refresh so it does not interfere with main input loop.
    """
    h, w = stdscr.getmaxyx()
    win_h, win_w = 3, min(80, w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h)//2, (w - win_w)//2)
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
        win.box()
        # center message or left-pad a bit if too long
        msg_display = msg if len(msg) <= win_w - 4 else msg[:win_w - 7] + "..."
        win.addstr(1, 2, msg_display, curses.color_pair(CP_TEXT))
        win.refresh()
        # sleep without touching stdscr timeout; ensures UI remains visible for duration
        time.sleep(duration)
    except Exception:
        pass
    finally:
        try:
            win.erase()
            win.refresh()
            del win
        except Exception:
            pass
        stdscr.touchwin()
        curses.doupdate()

# --------------------------------------------------
# UI Draw
# --------------------------------------------------
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
    # Preformat with widths (adjust to table widths)
    widths = [10, 8, 18, 28, w - 68]  # same as headers
    data = [f"{fw_icon} {port}", proto.upper(), usage, f"{proc_icon} {prog}", f"👤 {user}"]
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
        
    header = f"❓ Why It Exists — {len(wrapped_icon_lines)} lines"
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
    # include Actions (a) hint for main view; indicate snapshot mode
    base_help = (
        " [🎨 Colorize c] "
        " [🧭 ↑/↓ Select] [↕️ +/- Resize] [⇱⇲ Tab Witr Pane] "
        " [📂 ←/→ Files Scroll] [⛔ s Stop Proc] [🔥 f Firewall] "
        " [🛠 a Actions] [❌ q Quit]"
    ) if not show_detail else " [🎨 Colorize c]   🧭 ↑/↓ Scroll   [Tab] Restore   ❌ Quit "

    # snapshot indicator
    snap_label = " [🔄 'r' Refresh] " if SNAPSHOT_MODE else ""
    help_text = (snap_label + base_help) if not show_detail else base_help

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
            
        x = max(1, (w - len(help_text)) // 2)
        try:
            bar_win.addstr(1, x, help_text, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except:
            try:
                # Last resort fallback with theme text color
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
        ("  ⏸   [p] Pause Process", 'p'),
        ("  ▶   [c] Continue Process", 'c'),
        ("  🐢  [n] Renice", 'n'),
        ("  🔄  [r] Restart Service", 'r'),
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
        else:
            # For other keys, simple not-implemented message
            if ch in ('h','9','p','c','n','r','o','d'):
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
        # request main loop to refresh the whole UI (same behavior as pressing 'r')
        request_full_refresh()
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
    systemd(1) -> sshd(742) -> sshd(3112)
    """
    chain = []
    seen = set()

    while pid and pid.isdigit() and pid not in seen and len(chain) < max_depth:
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                stat = f.read().split()
                ppid = stat[3]

            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()

            chain.append(f"{name}({pid})")

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
        risk = "⚠️ FD exhaustion prod’da sık patlar." if usage > 80 else "✔ Normal"
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
    while True:
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
                    cached_wrapped_icon_lines = prepare_witr_content(lines, w - 4)
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

        curses.doupdate()

        # If any modal/action requested a full refresh, do the same sequence used for 'r'
        if TRIGGER_REFRESH:
            TRIGGER_REFRESH = False
            rows = parse_ss()  # force real parse
            # clear caches to avoid stale data after global changes
            _parse_cache.clear(); _witr_cache.clear(); _conn_cache.clear()
            _table_row_cache.clear()
            cache.clear()
            splash_screen(stdscr, rows, cache)
            if selected >= len(rows):
                selected = len(rows) - 1
            if selected < 0 and rows:
                selected = 0
            offset = min(max(selected - visible_rows // 2, 0), max(0, len(rows) - visible_rows))
            # after refresh, immediately redraw (continue to top of loop)
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
                    rows = parse_ss()
                    _parse_cache.clear(); _witr_cache.clear(); _conn_cache.clear()
                    _table_row_cache.clear()
                    cache.clear()
                    splash_screen(stdscr, rows, cache)
                    if selected >= len(rows):
                        selected = len(rows) - 1
            elif k == ord('a'):
                # open Action Center modal
                handle_action_center_input(stdscr, rows, selected, cache, firewall_status)
            elif k == KEY_FIREWALL and selected >= 0 and rows:
                port = rows[selected][0]
                toggle_firewall(port, stdscr, firewall_status)
            elif k == ord('c'):
                # Switch theme (Colorize)
                global CURRENT_THEME_INDEX
                CURRENT_THEME_INDEX = (CURRENT_THEME_INDEX + 1) % len(THEMES)
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


def cli_entry():
    """terminal command 'heimdall' entry point"""
    check_python_version()
    check_witr_exists()
    parse_args()
    curses.wrapper(main)


if __name__ == "__main__":
    # developer entry python heimdall.py
    cli_entry()