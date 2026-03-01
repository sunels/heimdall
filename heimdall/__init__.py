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
import pty
import importlib
from datetime import datetime, timedelta
import unicodedata
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
import signal
import socket
import select
from concurrent.futures import ThreadPoolExecutor
import platform
import queue
try:
    import yaml
except ImportError:
    yaml = None
try:
    import requests as _requests_lib
except ImportError:
    _requests_lib = None
import webbrowser
from pathlib import Path
import math
import queue
import threading
import select
import signal

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

def safe_open_url(url):
    """Open a URL in the browser, dropping root privileges if running under sudo."""
    try:
        # Check if running under sudo
        sudo_user = os.environ.get("SUDO_USER")
        if os.getuid() == 0 and sudo_user:
            # Try to run as the original user using sudo -u
            # We use xdg-open which is standard for Linux desktops
            subprocess.Popen(
                ["sudo", "-u", sudo_user, "xdg-open", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            # Normal or no sudo info, use webbrowser
            webbrowser.open(url)
    except Exception as e:
        debug_log(f"URL_OPEN_ERROR: {e}")

def get_matched_cves(target, prog_name=None):
    """Retrieve matched CVEs for a PID, Process Name, or Package Name."""
    if not target or target == "-":
        return []
    
    target_str = str(target).lower()
    prog_str = str(prog_name).lower() if prog_name else ""
    matches = []
    seen_cves = set()

    with VULN_LOCK:
        for alert in VULN_PENDING:
            cve_id = alert.get("cve_id")
            if cve_id in seen_cves: continue
            
            p_match = False
            # 1. Direct PID match (Highest confidence)
            alert_pid = alert.get("pid")
            if alert_pid and str(alert_pid) == target_str:
                p_match = True
            
            # 2. Package name match
            vuln_pkg = alert.get("pkg", "").lower()
            if vuln_pkg and (target_str == vuln_pkg or vuln_pkg == prog_str):
                p_match = True
                
            # 3. Fuzzy match (as fallback)
            if not p_match and vuln_pkg:
                if vuln_pkg in prog_str or (prog_str and prog_str in vuln_pkg):
                    p_match = True

            if p_match:
                matches.append(alert)
                seen_cves.add(cve_id)
                
    return matches

# ═══════════════════════════════════════════════════════════════
# Persistent config helpers – ignored CVE list
# ═══════════════════════════════════════════════════════════════
def _load_vuln_config():
    """Read or create the persistent config file (ignored CVEs and last check)."""
    global VULN_CONFIG_DATA
    try:
        if not VULN_CONFIG_PATH.parent.exists():
            VULN_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if VULN_CONFIG_PATH.is_file() and yaml:
            with open(VULN_CONFIG_PATH, "r") as f:
                VULN_CONFIG_DATA = yaml.safe_load(f) or {}
            
            # Ensure defaults
            if "ignored_cves" not in VULN_CONFIG_DATA:
                VULN_CONFIG_DATA["ignored_cves"] = []
            if "last_check_timestamp" not in VULN_CONFIG_DATA:
                VULN_CONFIG_DATA["last_check_timestamp"] = 0
            if "last_check_status" not in VULN_CONFIG_DATA:
                VULN_CONFIG_DATA["last_check_status"] = "none"
            if "pending_vulns" not in VULN_CONFIG_DATA:
                VULN_CONFIG_DATA["pending_vulns"] = []
            
            # Populate VULN_PENDING from persistent storage
            with VULN_LOCK:
                VULN_PENDING[:] = VULN_CONFIG_DATA["pending_vulns"]
        else:
            VULN_CONFIG_DATA = {
                "ignored_cves": [],
                "last_check_timestamp": 0,
                "last_check_status": "none",
                "pending_vulns": []
            }
            if yaml:
                _save_vuln_config()
    except Exception:
        VULN_CONFIG_DATA = {"ignored_cves": [], "last_check_timestamp": 0, "last_check_status": "none"}

def _save_vuln_config():
    """Write the in-memory config back to disk."""
    try:
        if yaml:
            with open(VULN_CONFIG_PATH, "w") as f:
                yaml.safe_dump(VULN_CONFIG_DATA, f)
    except Exception:
        pass

CONFIG = {
    "auto_update_services": True,
    "update_interval_minutes": 30,
    "auto_scan_interval": 3.0,
    "daemon_enabled": False,
    "alert_timeout": 30,
    "vuln_scan_interval_hours": 0.5,
    "outbound_refresh_interval": 10.0
}
SERVICES_DB = {}
SYSTEM_SERVICES_DB = {}
SENTINEL_RULES = []
CONFIG_LOCK = threading.Lock()
UPDATING_SERVICES_EVENT = threading.Event()
UPDATE_STATUS_MSG = ""
ACTION_STATUS_MSG = ""
ACTION_STATUS_EXP = 0.0
SCANNING_STATUS_EXP = 0.0
VULN_STATUS_MSG = ""
VULN_STATUS_COLOR = 0
VULN_NEXT_CHECK_TIME = 0.0
VULN_IS_FETCHING = False
VULN_LAST_NEW_COUNT = 0
SERVICE_SYNC_ERROR = False
CONFIG_DIR = os.path.expanduser("~/.config/heimdall")
PENDING_ALERTS = [] # Global queue for both Daemon IPC and Local TUI Alerts
PENDING_IPC_RESULT = {} # id -> (allow, kill_parent)

_script_managed_cache = {} # pid -> (is_managed: bool, timestamp: float)
SC_MANAGED_TTL = 30.0
TUI_PROTECTION_HANDLED = set() # (pid, create_time) -> Action Taken (timestamp)

# ═══════════════════════════════════════════════════════════════
# 🛡️ VULNERABILITY SCANNER — Background NVD checker globals
# ═══════════════════════════════════════════════════════════════
VULN_QUEUE = queue.Queue()           # alerts from background thread
OUTBOUND_QUEUE = queue.Queue()       # trigger modal refreshes if needed
VULN_LOCK = threading.Lock()         # protect VULN_PENDING list
VULN_PENDING = []                    # list of dicts {cve_id, desc, severity, pkg, link}
VULN_CONFIG_PATH = Path(os.path.expanduser("~/.config/heimdall")) / "vuln_settings.yaml"
VULN_CONFIG_DATA = {"ignored_cves": [], "pending_vulns": []}

# ═══════════════════════════════════════════════════════════════
# 📡 TRAFFIC POLLER — Background thread for per-port traffic
# ═══════════════════════════════════════════════════════════════
_traffic_lock = threading.Lock()
_traffic_data = {}  # port(int) -> {"conns": int, "rx_queue": int, "tx_queue": int, "rate": float, "bytes_rate": float}
_traffic_prev = {}  # previous snapshot for delta calculation
TRAFFIC_POLL_INTERVAL = 1.0

# --- Outbound Connections Modal Globals ---
OUTBOUND_DATA = []
OUTBOUND_LOCK = threading.Lock()
OUTBOUND_REFRESH_INTERVAL = 3.0
OUTBOUND_HISTORY = {} # (remote_ip, remote_port, pid) -> {"first_seen": timestamp, "last_seen": timestamp, "sent": bytes, "recv": bytes}

def _traffic_poller_thread():
    """Background thread: polls per-pid network activity using /proc/pid/io every TRAFFIC_POLL_INTERVAL seconds."""
    global _traffic_data, _traffic_prev
    while True:
        try:
            now = time.time()
            new_data = {}
            active_pids = set()
            
            for proc in psutil.process_iter(['pid', 'io_counters']):
                try:
                    pid = str(proc.info['pid'])
                    active_pids.add(pid)
                    io = proc.info.get('io_counters')
                    if io:
                        # rchar + wchar represents socket and disk IO combined (Network Heuristic)
                        total_bytes = io.read_chars + io.write_chars
                        prev_entry = _traffic_prev.get(pid)
                        
                        if prev_entry:
                            dt = now - prev_entry['ts']
                            if dt > 0:
                                rate = (total_bytes - prev_entry['bytes']) / dt
                                new_data[pid] = {
                                    "rate": max(0, rate),
                                    "activity": max(0, rate)
                                }
                        
                        _traffic_prev[pid] = {'bytes': total_bytes, 'ts': now}
                except:
                    pass
            
            # Cleanup dead pids to prevent memory leaks
            for p in list(_traffic_prev.keys()):
                if p not in active_pids:
                    _traffic_prev.pop(p, None)

            with _traffic_lock:
                _traffic_data = new_data

            
        except Exception as e:
            debug_log(f"TRAFFIC_POLLER: Error: {e}")
        
        time.sleep(TRAFFIC_POLL_INTERVAL)

def _outbound_poller_thread():
    """
    Background thread for Outbound Connections (Total: X).
    Hybrid: ss polling for snapshot + (placeholder) conntrack logic.
    """
    global OUTBOUND_DATA, OUTBOUND_HISTORY
    while True:
        try:
            now = time.time()
            # ss -ntuip -H: Numeric, TCP/UDP, internal info, process, No Header
            # We want only established / non-listening for "active outbound"
            cmd = ["ss", "-ntuipH"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            
            new_list = []
            active_keys = set()
            
            # Pattern to parse ss output (which can be multi-line with -i)
            # 127.0.0.1:1234 1.2.3.4:443  users:(("prog",pid=123,fd=4))
            # ... stats ...
            lines = result.stdout.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i]
                parts = line.split()
                if len(parts) < 5: 
                    i += 1
                    continue
                
                proto = parts[0].lower()
                local = parts[4]
                remote = parts[5] if len(parts) > 5 else "-"
                
                # Check if it's strictly outbound (dest not 0.0.0.0 or [::])
                if remote in ["0.0.0.0:*", "[::]:*", "*:*"]:
                    i += 1
                    continue
                    
                # Parse PID/PROG
                pid = "-"
                prog = "-"
                m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if m:
                    prog = m.group(1)
                    pid = m.group(2)
                
                # Remote components
                try:
                    r_host_port = remote.rsplit(':', 1)
                    r_ip = r_host_port[0]
                    r_port = r_host_port[1]
                except:
                    r_ip, r_port = remote, "-"
                
                if r_ip.startswith("[") and r_ip.endswith("]"):
                    r_ip = r_ip[1:-1]
                
                # Stats (from -i)
                sent = 0
                received = 0
                # ss -i stats appear on subsequent lines or same line
                # Look for "bytes_sent:X" "bytes_received:Y"
                # If they aren't on this line, they might be on the next
                search_text = line
                next_line_idx = i + 1
                while next_line_idx < len(lines) and "users:" not in lines[next_line_idx]:
                    search_text += " " + lines[next_line_idx]
                    next_line_idx += 1
                
                m_s = re.search(r'bytes_sent:(\d+)', search_text)
                m_r = re.search(r'bytes_received:(\d+)', search_text)
                if m_s: sent = int(m_s.group(1))
                if m_r: received = int(m_r.group(1))
                
                # History key
                key = (r_ip, r_port, pid)
                if key not in OUTBOUND_HISTORY:
                    OUTBOUND_HISTORY[key] = {
                        "first_seen": now, "last_seen": now, 
                        "sent": sent, "recv": received,
                        "prog": prog, "proto": proto.upper()
                    }
                else:
                    hist = OUTBOUND_HISTORY[key]
                    hist["last_seen"] = now
                    hist["prog"] = prog # update in case it changes (unlikely for same PID/port)
                    # ss -i stats are usually life-of-connection
                    if sent < hist["sent"]:
                         hist["first_seen"] = now
                    hist["sent"] = sent
                    hist["recv"] = received
                
                hist = OUTBOUND_HISTORY[key]
                duration_sec = int(now - hist["first_seen"])
                last_active_sec = int(now - hist["last_seen"])
                
                # Risk Heuristics
                # Re-use existing Heimdall logic
                user = get_process_user(pid)
                findings = perform_security_heuristics(pid, r_port, prog, user, is_outbound=True)
                risk_level = "CLEAN"
                if any(f['level'] == 'CRITICAL' for f in findings): risk_level = "CRITICAL"
                elif any(f['level'] == 'HIGH' for f in findings): risk_level = "HIGH"
                elif any(f['level'] == 'MEDIUM' for f in findings): risk_level = "MEDIUM"
                
                new_list.append({
                    "pid": pid,
                    "prog": prog,
                    "remote_ip": r_ip,
                    "remote_port": r_port,
                    "proto": proto.upper(),
                    "sent": sent,
                    "recv": received,
                    "duration": duration_sec,
                    "last_active": last_active_sec,
                    "risk": risk_level,
                    "findings": findings
                })
                
                active_keys.add(key)
                i = next_line_idx
            
            # Default sorting: Last Activity (descending)
            new_list.sort(key=lambda x: x['last_active'])
            
            with OUTBOUND_LOCK:
                # Merge current poll with recent history (Ghost connections)
                # This helps catch short-lived connections (like the user's POST loop)
                final_list = []
                seen_keys = set()
                
                # First add currently active ones
                for item in new_list:
                    key = (item["remote_ip"], item["remote_port"], item["pid"])
                    final_list.append(item)
                    seen_keys.add(key)
                
                # Then add recently closed ones (up to 20s ago)
                for k, hist in OUTBOUND_HISTORY.items():
                    if k not in seen_keys:
                        last_active_sec = int(now - hist["last_seen"])
                        if last_active_sec < 20: # Keep in list for 20s after closure
                            # Re-run sentinel once for ghost items? or keep last findings
                            user = get_process_user(k[2])
                            findings = perform_security_heuristics(k[2], k[1], hist.get("prog","-"), user, is_outbound=True)
                            
                            final_list.append({
                                "pid": k[2],
                                "prog": hist.get("prog", "-"),
                                "remote_ip": k[0],
                                "remote_port": k[1],
                                "proto": hist.get("proto", "TCP"),
                                "sent": hist["sent"],
                                "recv": hist["recv"],
                                "duration": int(hist["last_seen"] - hist["first_seen"]),
                                "last_active": last_active_sec,
                                "risk": "CLEAN",
                                "findings": findings,
                                "is_ghost": True
                            })

                final_list.sort(key=lambda x: x['last_active'])
                OUTBOUND_DATA = final_list
            
            # Prune old history
            for k in list(OUTBOUND_HISTORY.keys()):
                if now - OUTBOUND_HISTORY[k]["last_seen"] > 600: # 10 min
                    OUTBOUND_HISTORY.pop(k, None)
                    
        except Exception as e:
            debug_log(f"OUTBOUND_POLLER Error: {e}")
            
        time.sleep(globals().get("OUTBOUND_REFRESH_INTERVAL", 3.0))

def get_traffic_for_pid(pid):
    """Thread-safe getter for traffic data of a specific pid."""
    with _traffic_lock:
        return _traffic_data.get(str(pid))

def format_traffic_bar(traffic_info):
    """
    Format traffic data as a high-density throughput meter.
    Uses Logarithmic Scaling (Option C) to capture wide dynamic range (1B/s to 1GB/s).
    
    Why Logarithmic? Network traffic is bursty and exponential. Linear scales either 
    bottom out at 0 or saturate immediately. Log scale provides visual feedback 
    for tiny heartbeats while still showing the gravity of massive downloads.
    """
    if not traffic_info:
        return "▏         " + "    0 B/s", 0

    rate = float(traffic_info.get("rate", 0))
    if rate <= 0:
        return "▏         " + "    0 B/s", 0

    # 1. Scaling Strategy: Logarithmic (Option C)
    # Range: 1 B/s (0) to ~100MB/s (8.0 on log10 scale)
    # 10 chars * 8 sub-blocks = 80 units of resolution
    log_v = math.log10(rate) if rate >= 1 else 0
    max_log = 8.0  # 100 MB/s is "full" saturation
    
    percent = min(1.0, log_v / max_log)
    total_width = 10
    total_subblocks = total_width * 8
    num_subblocks = int(percent * total_subblocks)
    
    # 2. Build High-Density Bar
    full_blocks = num_subblocks // 8
    partial_idx = num_subblocks % 8
    
    # Unicode partial blocks
    partials = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"]
    
    bar = "█" * full_blocks
    if full_blocks < total_width:
        bar += partials[partial_idx]
        bar += " " * (total_width - full_blocks - 1)
        
    # 3. Formatted Rate Text
    if rate >= 1024**3:
        rate_text = f"{rate/(1024**3):.1f}G"
    elif rate >= 1024**2:
        rate_text = f"{rate/(1024**2):.1f}M"
    elif rate >= 1024:
        rate_text = f"{rate/1024:.1f}K"
    else:
        rate_text = f"{int(rate)}B"

    # 4. Optional Directionality Hint (Heuristic based on rchar vs wchar)
    # We use io_counters.read_chars as RX and write_chars as TX
    # Since we only get total 'rate' here, we'd need separate rates for better hint.
    # For now, we'll keep it simple: if rate > 0, show a stable activity indicator.
    hint = "▼" if rate > 0 else " " # Assuming download-heavy for most listening ports

    # Precise 18-char layout (10 bar + 1 space + 5 text + 2 suffix)
    display = f"{bar} {rate_text:>5s}/s{hint}"
    
    # Return numerical intensity (0-10) for coloring logic
    intensity = int(percent * 10)
    return display, intensity


# System Health cache (refreshed every 5 seconds)
_system_health_cache = None
_system_health_ts = 0.0
SYSTEM_HEALTH_TTL = 5.0

def get_system_health():
    """Get system health metrics from psutil. Cached for SYSTEM_HEALTH_TTL seconds."""
    global _system_health_cache, _system_health_ts
    now = time.time()
    if _system_health_cache and (now - _system_health_ts) < SYSTEM_HEALTH_TTL:
        return _system_health_cache
    
    health = {}
    try:
        # CPU
        health['cpu_pct'] = psutil.cpu_percent(interval=0)
        health['cpu_count'] = psutil.cpu_count(logical=True)
        
        # Memory
        mem = psutil.virtual_memory()
        health['mem_pct'] = mem.percent
        health['mem_used_gb'] = round(mem.used / (1024**3), 1)
        health['mem_total_gb'] = round(mem.total / (1024**3), 1)
        
        # Swap
        swap = psutil.swap_memory()
        health['swap_pct'] = swap.percent
        health['swap_used_gb'] = round(swap.used / (1024**3), 1)
        health['swap_total_gb'] = round(swap.total / (1024**3), 1)
        
        # Disk
        disk = psutil.disk_usage('/')
        health['disk_pct'] = disk.percent
        health['disk_used_gb'] = round(disk.used / (1024**3), 1)
        health['disk_total_gb'] = round(disk.total / (1024**3), 1)
        
        # Uptime
        try:
            with open('/proc/uptime') as f:
                up_secs = int(float(f.read().split()[0]))
            days = up_secs // 86400
            hours = (up_secs % 86400) // 3600
            mins = (up_secs % 3600) // 60
            if days > 0:
                health['uptime'] = f"{days}d {hours}h {mins}m"
            elif hours > 0:
                health['uptime'] = f"{hours}h {mins}m"
            else:
                health['uptime'] = f"{mins}m"
        except:
            health['uptime'] = "-"
        
        # Battery
        try:
            bat = psutil.sensors_battery()
            if bat:
                health['battery_pct'] = round(bat.percent)
                health['battery_plugged'] = bat.power_plugged
            else:
                health['battery_pct'] = None
        except:
            health['battery_pct'] = None
        
        # Local IP
        try:
            addrs = psutil.net_if_addrs()
            local_ip = "-"
            for iface, addr_list in addrs.items():
                if iface == 'lo': continue
                for addr in addr_list:
                    if addr.family.name == 'AF_INET' and not addr.address.startswith('127.'):
                        local_ip = f"{addr.address} ({iface})"
                        break
                if local_ip != "-": break
            health['local_ip'] = local_ip
        except:
            health['local_ip'] = "-"
        
        # Hostname
        try:
            health['hostname'] = socket.gethostname()
        except:
            health['hostname'] = "-"
        
        # Load Average
        try:
            load1, load5, load15 = os.getloadavg()
            health['load_avg'] = f"{load1:.1f} / {load5:.1f} / {load15:.1f}"
        except:
            health['load_avg'] = "-"
        
        # OS (from /etc/os-release)
        try:
            os_name = "-"
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        os_name = line.split('=', 1)[1].strip().strip('"')
                        break
            arch = platform.machine()
            health['os'] = f"{os_name} {arch}"
        except:
            health['os'] = "-"
        
        # Host (from DMI)
        try:
            product = "-"
            family = ""
            dmi_product = '/sys/devices/virtual/dmi/id/product_name'
            dmi_family = '/sys/devices/virtual/dmi/id/product_family'
            if os.path.exists(dmi_product):
                with open(dmi_product) as f:
                    product = f.read().strip()
            if os.path.exists(dmi_family):
                with open(dmi_family) as f:
                    family = f.read().strip()
            if family and family != product and family not in ('To be filled by O.E.M.', 'Default string', ''):
                health['host'] = f"{product} ({family})"
            else:
                health['host'] = product
        except:
            health['host'] = "-"
        
        # Kernel
        try:
            health['kernel'] = f"Linux {platform.release()}"
        except:
            health['kernel'] = "-"
        
        # Shell
        try:
            shell_path = os.environ.get('SHELL', '-')
            shell_name = os.path.basename(shell_path)
            # Try to get version
            try:
                shell_ver_raw = subprocess.check_output([shell_path, '--version'], stderr=subprocess.DEVNULL, timeout=1).decode().split('\n')[0]
                # Extract version number
                import re as _re
                ver_match = _re.search(r'(\d+\.\d+\.\d+)', shell_ver_raw)
                if ver_match:
                    health['shell'] = f"{shell_name} {ver_match.group(1)}"
                else:
                    health['shell'] = shell_name
            except:
                health['shell'] = shell_name
        except:
            health['shell'] = "-"
        
        # DE / WM
        try:
            de = os.environ.get('XDG_CURRENT_DESKTOP', os.environ.get('DESKTOP_SESSION', '-'))
            session_type = os.environ.get('XDG_SESSION_TYPE', '-')  # x11, wayland
            health['de'] = de
            health['wm_type'] = session_type.upper()
        except:
            health['de'] = "-"
            health['wm_type'] = "-"
        
        # Packages (fast file-based count)
        try:
            pkg_parts = []
            # dpkg
            dpkg_status = '/var/lib/dpkg/status'
            if os.path.exists(dpkg_status):
                with open(dpkg_status) as f:
                    dpkg_count = sum(1 for line in f if line.startswith('Package: '))
                pkg_parts.append(f"{dpkg_count} (dpkg)")
            # snap
            snap_dir = '/snap'
            if os.path.isdir(snap_dir):
                snap_count = sum(1 for d in os.listdir(snap_dir) if os.path.isdir(os.path.join(snap_dir, d)) and d not in ('bin', 'core', 'snapd'))
                if snap_count > 0:
                    pkg_parts.append(f"{snap_count} (snap)")
            health['packages'] = ', '.join(pkg_parts) if pkg_parts else "-"
        except:
            health['packages'] = "-"
    
    except Exception as e:
        debug_log(f"SYSTEM_HEALTH: Error: {e}")
    
    _system_health_cache = health
    _system_health_ts = now
    return health

def is_managed_by_script(pid):
    """Fast check if a PID is part of a script-managed hierarchy."""
    if not pid or not pid.isdigit() or pid == "-": return False
    now = time.time()
    if pid in _script_managed_cache:
        val, ts = _script_managed_cache[pid]
        if now - ts < SC_MANAGED_TTL: return val
    
    is_managed = False
    curr_p = pid
    try:
        # Check parent chain (up to 4 levels) for script command lines
        for _ in range(4):
            stat_path = f"/proc/{curr_p}/stat"
            if not os.path.exists(stat_path): break
            with open(stat_path, "r") as f:
                c = f.read()
            m_end = c.rfind(")")
            ppid = c[m_end+2:].split()[1]
            if not ppid or ppid in ("0", "1"): break
            
            p_cmd = get_full_cmdline(ppid)
            if any(ext in p_cmd for ext in (".sh", ".py", ".js", ".pl", ".rb", ".php", ".sh ")):
                is_managed = True
                break
            curr_p = ppid
    except: pass
    
    _script_managed_cache[pid] = (is_managed, now)
    return is_managed

def start_ipc_server():
    """Run a simple Unix Domain Socket server for Daemon alerting."""
    global PENDING_ALERTS
    if os.path.exists(IPC_SOCKET_PATH):
        try: os.remove(IPC_SOCKET_PATH)
        except: pass
        
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(IPC_SOCKET_PATH)
            server.listen(1)
            server.settimeout(1.0)
            while True:
                try:
                    conn, _ = server.accept()
                    with conn:
                        data_raw = conn.recv(2048)
                        if data_raw:
                            alert = json.loads(data_raw.decode('utf-8'))
                            if alert.get("type") == "ALERT":
                                alert_id = f"{alert.get('pid')}_{time.time()}"
                                with CONFIG_LOCK:
                                    PENDING_ALERTS.append({**alert, "id": alert_id})
                                request_list_refresh()
                                
                                # Wait for result from UI thread
                                timeout = CONFIG.get("alert_timeout", 30)
                                start_wait = time.time()
                                allow = False
                                while time.time() - start_wait < timeout:
                                    if alert_id in PENDING_IPC_RESULT:
                                        result = PENDING_IPC_RESULT.pop(alert_id)
                                        # result is (allow: bool, kill_parent: bool)
                                        resp = {"allow": result[0], "kill_parent": result[1]}
                                        conn.sendall(json.dumps(resp).encode('utf-8'))
                                        break
                                    time.sleep(0.1)
                except socket.timeout:
                    continue
                except:
                    time.sleep(1)
    except: pass

def draw_ipc_alert_modal(stdscr, alert):
    """Show an approval modal for an IPC alert."""
    h, w = stdscr.getmaxyx()
    bw = min(w - 4, 80)
    bh = 15
    y, x = (h - bh) // 2, (w - bw) // 2
    
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.box()
    
    title = "🚨 DAEMON SECURITY ALERT 🚨"
    if alert.get("local"):
        title = "🚨 ACTIVE TUI PROTECTION 🚨"
    win.addstr(1, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    
    win.addstr(3, 3, f"PID  : {alert['pid']}", curses.A_BOLD)
    win.addstr(4, 3, f"PROG : {alert['prog']}", curses.color_pair(CP_ACCENT))
    win.addstr(5, 3, f"USER : {alert['user']}")
    win.addstr(6, 3, f"DEST : {alert['remote']}", curses.color_pair(CP_WARN))
    
    cmd = alert.get('cmdline', '-')
    if len(cmd) > bw - 8: cmd = cmd[:bw-11] + "..."
    win.addstr(8, 3, f"COMMAND: {cmd}")
    
    msg = "This process is suspicious and attempting OUTBOUND connection."
    win.addstr(10, (bw - len(msg)) // 2, msg, curses.A_DIM)
    
    footer = "[y] ALLOW | [n] KILL PROCESS | [k] KILL PARENT TREE"
    win.addstr(12, (bw - len(footer)) // 2, footer, curses.color_pair(CP_ACCENT))
    win.addstr(13, (bw - 20) // 2, "Timeout 30s = KILL", curses.A_DIM)
    
    win.timeout(1000)
    start_t = time.time()
    allow = False
    kill_parent = False
    
    while True:
        elapsed = int(time.time() - start_t)
        remain = CONFIG.get("alert_timeout", 30) - elapsed
        if remain <= 0: break
        
        try:
            win.addstr(1, bw - 5, f"{remain:2d}s", curses.color_pair(CP_WARN))
            win.refresh()
        except: pass
        
        k = win.getch()
        if k == ord('y') or k == ord('Y'):
            allow = True
            break
        elif k == ord('k') or k == ord('K'):
            allow = False
            kill_parent = True
            break
        elif k == ord('n') or k == ord('N') or k == 27:
            allow = False
            kill_parent = False
            break
            
    return allow, kill_parent
SERVICES_URL = "https://raw.githubusercontent.com/sunels/heimdall/main/heimdall/services.json"
SHA_URL = "https://raw.githubusercontent.com/sunels/heimdall/main/heimdall/services.sha256"
SYSTEM_SERVICES_URL = "https://raw.githubusercontent.com/sunels/heimdall/main/heimdall/system-services.json"
SYSTEM_SERVICES_SHA_URL = "https://raw.githubusercontent.com/sunels/heimdall/main/heimdall/system-services.sha256"

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

# --------------------------------------------------
# 🛡️  Daemon Mode & IPC
# --------------------------------------------------
IPC_SOCKET_PATH = "/tmp/heimdall_tui.ipc"
PID_FILE_PATH = "/tmp/heimdall.pid"

def is_daemon_running():
    """Check if Heimdall Daemon is active by reading the PID file."""
    try:
        if os.path.exists(PID_FILE_PATH):
            with open(PID_FILE_PATH, 'r') as f:
                d_pid = int(f.read().strip())
                # Verify process still exists and is probably 'heimdall'
                if psutil.pid_exists(d_pid):
                    return True
    except: pass
    return False

def check_active_tui_protection(pid, port, prog, user, findings):
    """
    Active TUI Protection: Mimics daemon behavior if daemon is inactive.
    Detects suspicious activity, suspends process, and cues Modal.
    """
    global PENDING_ALERTS, TUI_PROTECTION_HANDLED
    
    if is_daemon_running():
        return # Daemon is in charge, we stay silent to avoid mess.

    if not pid or pid == "-" or not str(pid).isdigit(): return
    pid_int = int(pid)
    
    is_suspicious = any(f['level'] in ['HIGH', 'CRITICAL'] for f in findings)
    if not is_suspicious: return
    
    # Avoid duplicate handling for the same process instance
    try:
        p = psutil.Process(pid_int)
        ctime = p.create_time()
        handle_key = (pid_int, ctime)
        if handle_key in TUI_PROTECTION_HANDLED:
            return
    except: return

    # 🚨 SUSPEND IMMEDIATELY (Safety first)
    try:
        os.kill(pid_int, signal.SIGSTOP)
        debug_log(f"TUI-PROTECT: SUSPENDED {pid} ({prog}) for investigation.")
    except: return
    
    # Queue for TUI Main Loop to show Modal
    cmdline = " ".join(p.cmdline())
    remote_display = f"PORT {port}"
    alert_id = f"LOCAL_{pid}_{time.time()}"
    
    with CONFIG_LOCK:
        PENDING_ALERTS.append({
            "id": alert_id,
            "pid": pid,
            "prog": prog,
            "user": user,
            "remote": remote_display,
            "cmdline": cmdline,
            "local": True
        })
    TUI_PROTECTION_HANDLED.add(handle_key)

def apply_tui_protection_action(stdscr, alert, result):
    """Execute the user's decision from the Active TUI Protection modal."""
    allow, kill_parent = result
    pid = int(alert['pid'])
    prog = alert['prog']
    
    if allow:
        try:
            os.kill(pid, signal.SIGCONT)
            debug_log(f"TUI-PROTECT: ALLOWED {pid} ({prog}). Resumed.")
            show_message(stdscr, f"Allowed {prog} - Resumed")
        except: pass
    else:
        try:
            if kill_parent:
                debug_log(f"TUI-PROTECT: Executing tree strike for {pid} ({prog}).")
                perform_tree_strike(pid)
                show_message(stdscr, f"Struck Process Tree: {prog}", duration=5.0)
            else:
                os.kill(pid, signal.SIGKILL)
                debug_log(f"TUI-PROTECT: Killed suspicious process {pid} ({prog}).")
                show_message(stdscr, f"Killed Suspicious: {prog}")
        except: pass

class DaemonManager:
    def __init__(self):
        self.seen_connections = set() # (pid, ctime, status, addr)
        self.denied_history = {} # (prog, cmdline) -> expire_time
        self.running = True
        self.executor = ThreadPoolExecutor(max_workers=10)

    def stop(self):
        self.running = False
        self.executor.shutdown(wait=False)

    def send_notification(self, title, msg):
        try:
            subprocess.run(["notify-send", title, msg], stderr=subprocess.DEVNULL)
        except: pass
        try:
            subprocess.run(["wall", f"{title}: {msg}"], stderr=subprocess.DEVNULL)
        except: pass

    def request_approval(self, pid, prog, user, remote, cmdline):
        """Request approval for a suspicious outbound connection."""
        alert_msg = f"Suspected Outbound: PID {pid} ({prog}) -> {remote}"
        debug_log(f"DAEMON: {alert_msg}")

        # 1. Try to communicate with running TUI
        if os.path.exists(IPC_SOCKET_PATH):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(2.0)
                    client.connect(IPC_SOCKET_PATH)
                    data = {
                        "type": "ALERT",
                        "pid": pid,
                        "prog": prog,
                        "user": user,
                        "remote": remote,
                        "cmdline": cmdline
                    }
                    client.sendall(json.dumps(data).encode('utf-8'))
                    
                    # Wait for response
                    resp_raw = client.recv(1024)
                    if resp_raw:
                        resp = json.loads(resp_raw.decode('utf-8'))
                        return resp.get("allow", False), resp.get("kill_parent", False)
            except Exception as e:
                debug_log(f"DAEMON: IPC failed: {e}")

        # 2. Fallback to Zenity
        try:
            if os.environ.get("DISPLAY"):
                # Use --extra-button to allow killing the parent tree
                z_cmd = [
                    "zenity", "--question", "--title=🛡️ Heimdall Security Alert",
                    "--text=Process: " + prog + "\nPID: " + str(pid) + "\nAction: " + remote + "\n\nHeimdall has SUSPENDED this process. What should we do?",
                    "--ok-label=Allow", "--cancel-label=Kill Process",
                    "--extra-button=Kill Parent Tree",
                    "--timeout=" + str(CONFIG.get("alert_timeout", 30))
                ]
                res = subprocess.run(z_cmd, capture_output=True, text=True)
                
                # Check STDOUT first because extra-button might return 0 or 1 depending on Zenity version
                # and we should prioritize the label if it's there.
                stdout_norm = res.stdout.strip()
                if "Kill Parent Tree" in stdout_norm:
                    return False, True
                
                if res.returncode == 0:
                    return True, False # Allow
                
                return False, False # Killed/Cancelled
        except Exception as e:
            debug_log(f"DAEMON: Zenity failed: {e}")

        return False, False # Default to Kill Process only

    def process_suspicious_conn(self, pid, prog, user, remote_display, cmdline, p):
        """Handle a suspicious connection in a separate thread to avoid blocking the loop."""
        try:
            history_key = (prog, cmdline)
            if history_key in self.denied_history:
                if time.time() < self.denied_history[history_key]:
                    # 🚨 AUTO-KILL + TREE STRIKE (If we've seen this malicious loop, strike hard)
                    try:
                        perform_tree_strike(pid, port=None)
                        debug_log(f"DAEMON: AUTO-STRIKED known malicious loop tree at {pid} ({prog}).")
                    except:
                        try: os.kill(pid, signal.SIGKILL)
                        except: pass
                    return

            try:
                # Suspend process while waiting for user
                os.kill(pid, signal.SIGSTOP)
                debug_log(f"DAEMON: SUSPENDED {pid} ({prog}) for investigation.")
            except: return
            
            parent_info = ""
            parent_pid = None
            try:
                parent = p.parent()
                if parent: 
                    parent_info = f" (Parent: {parent.name()} PID {parent.pid})"
                    parent_pid = parent.pid
            except: pass

            # Request Approval
            allow, kill_parent = self.request_approval(pid, prog, user, remote_display, f"{cmdline}{parent_info}")
            
            if allow:
                os.kill(pid, signal.SIGCONT)
                debug_log(f"DAEMON: ALLOWED {pid} ({prog}). Resumed.")
            else:
                # ⚔️ KILL ACTION
                try:
                    debug_log(f"DAEMON: Killing suspicious process {pid} ({prog})...")
                    
                    if kill_parent and parent_pid:
                        try:
                            # Use precision tree logic BEFORE killing the leaf pid, 
                            # otherwise /proc/pid vanishes and we can't trace the parent tree.
                            perform_tree_strike(pid, port=None)
                            debug_log(f"DAEMON: Executed Precision Tree Strike starting at {pid}.")
                            self.send_notification("🛡️ Heimdall Action", f"Killed Process {prog} AND its associated script tree")
                        except Exception as e:
                            debug_log(f"DAEMON: Tree kill failed - {e}")
                    else:
                        os.kill(pid, signal.SIGKILL)
                        self.send_notification("🛡️ Heimdall Action", f"Killed suspicious process {prog} (PID {pid})")

                    # Remember this denial to auto-kill respawns
                    self.denied_history[history_key] = time.time() + 60
                except: pass
        except Exception as e:
            debug_log(f"DAEMON: Error handling process {pid}: {e}")

    def run_loop(self):
        debug_log("DAEMON: Monitoring loop started.")
        while self.running:
            try:
                conns = psutil.net_connections(kind='inet')
                for conn in conns:
                    try:
                        # Check for Outbound (ESTABLISHED) OR Suspicious Listeners (LISTEN)
                        is_established = (conn.status == 'ESTABLISHED' and conn.raddr)
                        is_listener = (conn.status == 'LISTEN')
                        
                        if not (is_established or is_listener):
                            continue

                        pid = conn.pid
                        if not pid: continue

                        # Use create_time to ensure we catch every unique process instance
                        try:
                            p = psutil.Process(pid)
                            ctime = p.create_time()
                        except: continue

                        # Unique key including create_time to handle PID recycling
                        conn_key = (pid, ctime, conn.status, f"{conn.laddr.ip}:{conn.laddr.port}")
                        if conn_key in self.seen_connections:
                            continue
                        
                        self.seen_connections.add(conn_key)

                        if is_established:
                            try:
                                r_ip = ipaddress.ip_address(conn.raddr.ip)
                                if r_ip.is_loopback: continue
                            except: continue

                        # Get more info for heuristics
                        try:
                            prog = p.name()
                            user = p.username()
                            cmdline = " ".join(p.cmdline())
                        except: continue

                        # Check heuristics
                        findings = perform_security_heuristics(str(pid), str(conn.laddr.port), prog, user, is_outbound=is_established)
                        is_suspicious = any(f['level'] in ['HIGH', 'CRITICAL'] for f in findings)
                        
                        if is_suspicious:
                            remote_display = f"{conn.raddr.ip}:{conn.raddr.port}" if is_established else f"LISTENING on {conn.laddr.port}"
                            # Submit to executor to avoid blocking the monitoring loop
                            self.executor.submit(self.process_suspicious_conn, pid, prog, user, remote_display, cmdline, p)
                            
                    except Exception as e:
                        debug_log(f"DAEMON: Connection proc error: {e}")

            except Exception as e:
                debug_log(f"DAEMON: Loop error: {e}")
            
            time.sleep(CONFIG.get("auto_scan_interval", 3.0))

def run_daemon():
    """Entry point for daemon mode."""
    print("🚀 Heimdall starting in DAEMON mode...")
    print(f"📄 Logging to: {DEBUG_LOG_PATH}")
    
    # Simple PID file for instance check
    try:
        if os.path.exists(PID_FILE_PATH):
            with open(PID_FILE_PATH, 'r') as f:
                old_pid = int(f.read().strip())
                if psutil.pid_exists(old_pid):
                    print(f"❌ Heimdall is already running (PID {old_pid})")
                    sys.exit(1)
        
        with open(PID_FILE_PATH, 'w') as f:
            f.write(str(os.getpid()))
    except: pass

    manager = DaemonManager()
    
    def handle_exit(sig, frame):
        manager.stop()
        try: os.remove(PID_FILE_PATH)
        except: pass
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    manager.run_loop()

def get_hash(data):
    return hashlib.sha256(data).hexdigest()

def update_services_bg():
    global SERVICES_DB, SYSTEM_SERVICES_DB, UPDATE_STATUS_MSG
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
        
        targets = [
            ("services.json", SERVICES_URL, SHA_URL, "SERVICES_DB"),
            ("system-services.json", SYSTEM_SERVICES_URL, SYSTEM_SERVICES_SHA_URL, "SYSTEM_SERVICES_DB")
        ]
        
        for filename, url, sha_url, db_name in targets:
            SERVICE_SYNC_ERROR = False
            UPDATE_STATUS_MSG = f"Syncing {filename}..."
            debug_log(f"UPDATER: Checking {filename}...")
            start_time = time.time()
            
            try:
                # Fetch remote SHA first
                with urllib.request.urlopen(sha_url, timeout=10) as response:
                    remote_sha = response.read().decode('utf-8').strip().split()[0]
                
                local_json_path = os.path.join(CONFIG_DIR, filename)
                local_sha_path = os.path.join(CONFIG_DIR, filename.replace(".json", ".sha256"))
                
                do_update = True
                if os.path.exists(local_sha_path):
                    with open(local_sha_path, 'r') as f:
                        local_sha = f.read().strip()
                    if local_sha == remote_sha:
                        do_update = False
                
                if do_update:
                    debug_log(f"UPDATER: New version for {filename} detected.")
                    with urllib.request.urlopen(url, timeout=10) as response:
                        raw_data = response.read()
                        computed_sha = get_hash(raw_data)
                        
                        if computed_sha == remote_sha:
                            data = json.loads(raw_data.decode('utf-8'))
                            with open(local_json_path, 'wb') as f:
                                f.write(raw_data)
                            with open(local_sha_path, 'w') as f:
                                f.write(remote_sha)
                            
                            if db_name == "SERVICES_DB":
                                SERVICES_DB = data
                            else:
                                SYSTEM_SERVICES_DB = data
                                
                            debug_log(f"UPDATER: Applied {len(data)} definitions to {db_name}.")
            except Exception as e:
                SERVICE_SYNC_ERROR = True
                debug_log(f"UPDATER: Error updating {filename}: {e}")
                
        UPDATE_STATUS_MSG = "Sync complete! ✅"
        time.sleep(4) # visibility
            
        UPDATING_SERVICES_EVENT.clear()
        UPDATE_STATUS_MSG = ""
        
        sleep_interval = max(1, interval_mins)
        time.sleep(sleep_interval * 60)

def start_services_updater():
    t = threading.Thread(target=update_services_bg, daemon=True)
    t.start()
    return t

def load_sentinel_rules():
    """Load Sentinel behavioral rules from JSON DSL."""
    global SENTINEL_RULES
    rules_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_rules.json"),
        os.path.join(CONFIG_DIR, "sentinel_rules.json")
    ]
    for p in rules_paths:
        if os.path.exists(p):
            try:
                with open(p, 'r') as f:
                    data = json.load(f)
                    SENTINEL_RULES = data.get("rules", [])
                    debug_log(f"SENTINEL: Loaded {len(SENTINEL_RULES)} rules from {p}")
                    return
            except Exception as e:
                debug_log(f"SENTINEL: Error loading rules from {p}: {e}")

def evaluate_sentinel_logic(logic, context):
    """Evaluates a single DSL logic block against the context."""
    field = logic.get('field')
    op = logic.get('op')
    val = logic.get('value')
    
    # Get raw context value
    ctx_raw = context.get(field)
    
    # Normalize for comparison
    if isinstance(ctx_raw, list):
        # For lists (like process tree), we check membership or join for string search
        haystack = [str(x).lower() for x in ctx_raw]
        haystack_str = " ".join(haystack)
    else:
        haystack = [str(ctx_raw).lower()]
        haystack_str = str(ctx_raw).lower()

    # Operator implementation
    if op == "equals":
        return str(val).lower() in haystack
    elif op == "contains":
        return str(val).lower() in haystack_str
    elif op == "contains_any":
        return any(str(v).lower() in haystack_str for v in val)
    elif op == "not_contains_any":
        return not any(str(v).lower() in haystack_str for v in val)
    elif op == "in":
        # Check if any element of ctx (haystack) matches any element of rule (val)
        val_list = val if isinstance(val, list) else [val]
        val_list = [str(v).lower() for v in val_list]
        return any(h in val_list for h in haystack)
    elif op == "is_true":
        return bool(ctx_raw) is True
    elif op == "is_false":
        return bool(ctx_raw) is False
    
    return False

def load_services_db():
    global SERVICES_DB, SYSTEM_SERVICES_DB
    
    # helper to load a specific JSON database
    def load_json(filename, target_db_name):
        paths = [
            os.path.join(CONFIG_DIR, filename),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        ]
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            paths.append(os.path.join(sys._MEIPASS, filename))
            
        for json_path in paths:
            try:
                if os.path.exists(json_path):
                    with open(json_path, 'r') as f:
                        data = json.load(f)
                        if target_db_name == "SERVICES_DB":
                            globals()["SERVICES_DB"] = data
                        elif target_db_name == "SYSTEM_SERVICES_DB":
                            globals()["SYSTEM_SERVICES_DB"] = data
                    debug_log(f"SERVICES: {filename} loaded from {json_path}")
                    return True
            except Exception as e:
                debug_log(f"SERVICES: Error loading {json_path}: {e}")
        return False

    load_json("services.json", "SERVICES_DB")
    load_json("system-services.json", "SYSTEM_SERVICES_DB")

init_config()
load_services_db()
load_sentinel_rules()
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
CP_TRAFFIC_LOW = 6
CP_TRAFFIC_MID = 7
CP_TRAFFIC_HIGH = 8
CP_TRAFFIC_BURST = 9

THEMES = [
    {
        "name": "🔵 VSCode Dark (Default)",
        # Standard fallback
        "colors": {
            CP_HEADER: (curses.COLOR_BLUE, -1),
            CP_ACCENT: (curses.COLOR_CYAN, -1),
            CP_TEXT: (curses.COLOR_WHITE, -1),
            CP_WARN: (curses.COLOR_YELLOW, -1),
            CP_BORDER: (curses.COLOR_BLUE, -1),
            CP_TRAFFIC_LOW: (curses.COLOR_CYAN, -1),
            CP_TRAFFIC_MID: (curses.COLOR_GREEN, -1),
            CP_TRAFFIC_HIGH: (curses.COLOR_YELLOW, -1),
            CP_TRAFFIC_BURST: (curses.COLOR_RED, -1)
        },
        # Precise 256-color map (FG, BG)
        "colors_256": {
            CP_HEADER: (33, 234),    # DodgerBlue1 on DarkGrey
            CP_ACCENT: (45, 234),    # Turquoise2
            CP_TEXT: (255, 234),     # White
            CP_WARN: (226, 234),     # Yellow
            CP_BORDER: (33, 234),    # Blue border
            CP_TRAFFIC_LOW: (244, 234),   # Dim Grey
            CP_TRAFFIC_MID: (76, 234),    # Green
            CP_TRAFFIC_HIGH: (214, 234),  # Orange
            CP_TRAFFIC_BURST: (196, 234)  # Red
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
            CP_BORDER: (curses.COLOR_YELLOW, -1),
            CP_TRAFFIC_LOW: (curses.COLOR_WHITE, -1),
            CP_TRAFFIC_MID: (curses.COLOR_GREEN, -1),
            CP_TRAFFIC_HIGH: (curses.COLOR_YELLOW, -1),
            CP_TRAFFIC_BURST: (curses.COLOR_RED, -1)
        },
        "colors_256": {
            CP_HEADER: (214, 235),   # Orange1 on Black/Grey (Gruvbox BG)
            CP_ACCENT: (167, 235),   # IndianRed
            CP_TEXT: (223, 235),     # Bisque/Cream
            CP_WARN: (208, 235),     # OrangeRed
            CP_BORDER: (246, 235),   # Grey border
            CP_TRAFFIC_LOW: (240, 235),
            CP_TRAFFIC_MID: (142, 235),
            CP_TRAFFIC_HIGH: (172, 235),
            CP_TRAFFIC_BURST: (167, 235)
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
            CP_BORDER: (curses.COLOR_BLUE, -1),
            CP_TRAFFIC_LOW: (curses.COLOR_WHITE, -1),
            CP_TRAFFIC_MID: (curses.COLOR_GREEN, -1),
            CP_TRAFFIC_HIGH: (curses.COLOR_YELLOW, -1),
            CP_TRAFFIC_BURST: (curses.COLOR_RED, -1)
        },
        "colors_256": {
            CP_HEADER: (135, 234),   # MediumPurple on DarkBG
            CP_ACCENT: (45, 234),    # Cyan
            CP_TEXT: (189, 234),     # Light Grey-Blue
            CP_WARN: (220, 234),     # Gold
            CP_BORDER: (63, 234),    # SlateBlue
            CP_TRAFFIC_LOW: (60, 234),
            CP_TRAFFIC_MID: (120, 234),
            CP_TRAFFIC_HIGH: (215, 234),
            CP_TRAFFIC_BURST: (203, 234)
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
            CP_BORDER: (curses.COLOR_CYAN, -1),
            CP_TRAFFIC_LOW: (curses.COLOR_WHITE, -1),
            CP_TRAFFIC_MID: (curses.COLOR_GREEN, -1),
            CP_TRAFFIC_HIGH: (curses.COLOR_YELLOW, -1),
            CP_TRAFFIC_BURST: (curses.COLOR_RED, -1)
        },
        "colors_256": {
            CP_HEADER: (117, 235),   # SkyBlue on DeepDark
            CP_ACCENT: (210, 235),   # Salmon/Flamingo
            CP_TEXT: (254, 235),     # White-ish
            CP_WARN: (228, 235),     # Yellow
            CP_BORDER: (103, 235),   # SlateGray
            CP_TRAFFIC_LOW: (242, 235),
            CP_TRAFFIC_MID: (114, 235),
            CP_TRAFFIC_HIGH: (216, 235),
            CP_TRAFFIC_BURST: (204, 235)
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
            CP_BORDER: (curses.COLOR_WHITE, -1),
            CP_TRAFFIC_LOW: (curses.COLOR_WHITE, -1),
            CP_TRAFFIC_MID: (curses.COLOR_GREEN, -1),
            CP_TRAFFIC_HIGH: (curses.COLOR_YELLOW, -1),
            CP_TRAFFIC_BURST: (curses.COLOR_RED, -1)
        },
        "colors_256": {
            CP_HEADER: (39, 236),    # DeepSkyBlue on DarkGreyBlue
            CP_ACCENT: (170, 236),   # Orchid
            CP_TEXT: (253, 236),     # Very Light Grey
            CP_WARN: (203, 236),     # IndianRed
            CP_BORDER: (59, 236),    # Grey59
            CP_TRAFFIC_LOW: (241, 236),
            CP_TRAFFIC_MID: (114, 236),
            CP_TRAFFIC_HIGH: (208, 236),
            CP_TRAFFIC_BURST: (197, 236)
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
            stdscr.bkgdset(' ', curses.color_pair(CP_TEXT))
            # stdscr.erase() removed to prevent background persistence issues
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

def _get_app_version():
    try:
        v_file = os.path.join(os.path.dirname(__file__), "VERSION")
        with open(v_file) as f:
            return f.read().strip()
    except:
        return "1.0.2"

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="version", version=f'heimdall {_get_app_version()}')
    parser.add_argument('--no-update', action='store_true', help='Disable background service updates')
    parser.add_argument('--port', type=int, help='Filter view by specific Port')
    parser.add_argument('--pid', type=str, help='Filter view by specific Process ID')
    parser.add_argument('--user', type=str, help='Filter view by Process Owner (User)')
    parser.add_argument('--daemon', '--background', action='store_true', help='Run in Daemon (background) monitoring mode')
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
                f_path = os.path.join(fd_dir, fd)
                path = os.readlink(f_path)
                f_size = 0; f_mtime = 0; f_ctime = 0
                try:
                    stats = os.stat(f_path)
                    f_size = stats.st_size
                    f_mtime = stats.st_mtime
                    f_ctime = stats.st_ctime
                except: pass
                files.append((fd, path, f_size, f_mtime, f_ctime))
            except PermissionError:
                files.append((fd, "Permission denied", 0, 0, 0))
            except OSError:
                continue
    except PermissionError:
        files.append(("-", "Permission denied (run as root to view)", 0, 0, 0))
    except (FileNotFoundError, ProcessLookupError):
        pass # Process exited while inspecting
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
_risk_level_cache = {}  # port -> risk keyword ("High", "Critical", etc.)
_security_audit_cache = {}  # port -> bool (has security warnings)

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
    
    # 🎨 Keep current screen content visible as a background
    try:
        stdscr.touchwin()
        stdscr.noutrefresh()
    except: pass

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

        # Progress bar logic
        pct = int((i / total) * 100)
        pct_str = f" {pct}%"
        draw_bar_w = bar_w - len(pct_str)
        filled = int(draw_bar_w * i / total)
        bar = "█" * filled + "░" * (draw_bar_w - filled)
        
        bar_x = (bw - bar_w) // 2
        win.addstr(progress_y + 3, bar_x, f"[{bar}]{pct_str}", curses.color_pair(CP_ACCENT) | curses.A_BOLD)

        # 🎨 Keep background visible on every update
        try: stdscr.noutrefresh()
        except: pass
        
        win.noutrefresh()
        curses.doupdate()

        # --- Preload data per port ---
        prog_name = row[3] if len(row) > 3 else "-"
        pid = row[4] if len(row) > 4 else "-"
        
        try:
            lines = get_witr_output(port)
            _witr_cache[str(port)] = (lines, time.time())
            user = extract_user_from_witr(lines)
            # Fallback: if witr didn't provide user, resolve from PID
            if user == "-":
                user = get_process_user(pid)
            process = extract_process_from_witr(lines)
            detail_width = w - 4
            wrapped_icon_lines = prepare_witr_content(lines, detail_width, prog=prog_name, port=port, pid=pid)
            cache[port] = {
                "user": user,
                "process": process,
                "lines": lines,
                "wrapped_icon_lines": wrapped_icon_lines,
                "prewrapped_width": detail_width
            }
        except Exception:
            detail_width = w - 4
            fallback_lines = prepare_witr_content(["No data"], detail_width, prog=prog_name, port=port, pid=pid)
            cache[port] = {"user": "-", "process": "-", "lines": ["No data"], "wrapped_icon_lines": fallback_lines}

        try:
            conn = get_connections_info(port)
            _conn_cache[str(port)] = (conn, time.time())
        except Exception:
            _conn_cache[str(port)] = ({"active_connections": 0, "top_ip": "-", "top_ip_count": 0, "all_ips": Counter()}, time.time())

        try:
            if pid and pid.isdigit():
                _proc_usage_cache[pid] = (get_process_usage(pid), time.time())
                _open_files_cache[pid] = (get_open_files(pid), time.time())
                _proc_chain_cache[pid] = get_process_parent_chain(pid)
                _fd_cache[pid] = get_fd_pressure(pid)
                _runtime_cache[pid] = detect_runtime_type(pid)
        except Exception:
            pass

        # Compute risk level from services.json
        risk_lvl = get_risk_level(prog_name, port)
        _risk_level_cache[str(port)] = risk_lvl

        # Security audit check (uses cached user from above)
        cached_user = cache.get(port, {}).get("user", "-")
        pid_val = row[4] if len(row) > 4 else "-"
        findings = perform_security_heuristics(pid_val, port, prog_name, cached_user)
        _security_audit_cache[str(port)] = findings
        
        # ACTIVE TUI PROTECTION Check (Mimic Daemon when needed)
        check_active_tui_protection(pid_val, port, prog_name, cached_user, findings)

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

def resolve_service_knowledge(prog, port, pid=None):
    """
    Unified resolver: merges system intelligence and curated DB.
    Priority:
    1. Curated Database (services.json) for Name/Desc/Risk/Rec (User-Friendly)
    2. System Discovery (systemctl, dpkg, rpm, snap) for Name/Desc/Version
    """
    # 1. Start with Curated Database
    # This is where the "User Friendly" names like "Very Secure FTP Daemon" live.
    info = get_service_info(prog, port)
    is_known = (info.get("name") != "Unknown")
    
    # 2. Get Live System Metadata
    system_info = get_local_package_info(prog, pid=pid) if (prog or pid) else None
    
    if system_info:
        # 3. If Curated DB has no info, use System Info as fallback for name/description
        if not is_known:
            if system_info.get("name"):
                info["name"] = system_info["name"]
            if system_info.get("description"):
                info["description"] = system_info["description"]
            is_known = (info.get("name") != "Unknown")
        
        # 4. BRIDGE: If still unknown or even if known by generic process name,
        # lookup curated DB by the PACKAGE name revealed by the system.
        if system_info.get("package"):
            pkg_curated = get_service_info(system_info["package"], None)
            if pkg_curated.get("name") != "Unknown":
                # We found knowledge by package name!
                # Prioritize this curated info as it's specifically written for Heimdall.
                for field in ["name", "description", "risk", "recommendation", "typical_user"]:
                    if pkg_curated.get(field):
                        info[field] = pkg_curated[field]
                is_known = True

        # 5. Add technical metadata from system (never overrides Identity/Scope)
        for f in ["version", "package", "homepage", "maintainer", "installed_size", "source"]:
            if system_info.get(f):
                info[f] = system_info[f]
    
    # 6. Special Case: 'master' is almost always Postfix
    if not is_known and prog == "master":
         postfix_info = get_service_info("postfix", None)
         if postfix_info.get("name") != "Unknown":
             info.update(postfix_info)
             is_known = True

    # 7. Final cosmetic fallback
    if info.get("name") == "Unknown" and prog:
        info["name"] = prog.replace("-", " ").title()
        
    return info, is_known

def prepare_witr_content(lines, width, prog=None, port=None, pid=None):
    """Wraps witr output lines, adds icons, and supplements with knowledge."""
    # Ensure lines is a list
    if not lines: lines = []
    
    # Resolve knowledge base info
    info, is_unknown = resolve_service_knowledge(prog, port, pid=pid)
    
    # If witr returned nothing, use full fallback
    if lines == ["No data"] or not lines:
        return _generate_service_fallback(prog, port, width, pid=pid)

    lines = annotate_warnings(lines)
    wrapped = []
    
    # Icon variants
    icons = {
        "Target": "🎯",
        "Container": "🐳",
        "Command": "🧠",
        "Started": "⏱ ",
        "Why It Exists": "🔍",
        "Why it Exists": "🔍",
        "Source": "📦",
        "Working Dir": "🗂 ",
        "Listening": "👂",
        "Socket": "🔌",
        "Warnings": "⚠️ ",
        "PID": "🆔",
        "User": "👤",
        "Process": "🧠"
    }

    # PRE-EXTRACT identity lines from witr for priority display
    identity_lines = []
    other_lines = []
    for line in lines:
        if any(x in line for x in ["Target", "Process", "User", "Command"]):
            identity_lines.append(line)
        else:
            other_lines.append(line)

    # 1. Identity Section
    for line in identity_lines:
        for key, icon in icons.items():
            if key in line and not line.strip().startswith(icon):
                line = line.replace(key, f"{icon} {key}", 1)
        wrapped.extend(textwrap.wrap(line, width=width) or [""])

    # 2. HEIMDALL INSIGHTS (Promoted to top for maximum visibility)
    wrapped.append("")
    wrapped.append(f"🔍 HEIMDALL INSIGHTS (Service Purpose):")
    desc = info.get("description", "Purpose not discovered in local package database or Heimdall knowledge base.")
    for line in textwrap.wrap(f"   {desc}", width=width):
        wrapped.append(line)
    
    if info.get("risk") and info["risk"] != "Unknown":
        wrapped.append(f"   🚩 Risk Level: {info['risk']}")

    wrapped.append("")

    # 3. All other witr details (Why it exists, connections, etc)
    for line in other_lines:
        for key, icon in icons.items():
            if key in line and not line.strip().startswith(icon):
                line = line.replace(key, f"{icon} {key}", 1)
        wrapped.extend(textwrap.wrap(line, width=width) or [""])

    return wrapped

def _generate_service_fallback(prog, port, width, pid=None):
    """Generate rich detail content when witr has no data."""
    wrapped = []
    info, is_unknown = resolve_service_knowledge(prog, port, pid=pid)
    
    wrapped.append(f"📦 Service: {info.get('name')}")
    wrapped.append(f"   Process: {prog or '-'}")
    wrapped.append(f"   Port: {port or '-'}")
    
    if info.get("version"):
        wrapped.append(f"   Version: {info['version']}")
    if info.get("package"):
        wrapped.append(f"   Package: {info['package']}")
    wrapped.append("")

    wrapped.append("🔍 What is this service?")
    desc = info.get("description", "No description available.")
    for line in textwrap.wrap(f"   {desc}", width=width):
        wrapped.append(line)
    wrapped.append("")

    # Typical user for curated services
    typical_user = info.get("typical_user", "-")
    if typical_user != "-":
        wrapped.append(f"👤 Typical User: {typical_user}")

    # Port info
    known_ports = info.get("ports", [])
    if known_ports:
        port_str = ", ".join(str(p) for p in known_ports)
        if info.get("dynamic_ports"):
            port_str += " + dynamic"
        wrapped.append(f"🔌 Known Ports: {port_str}")
        wrapped.append("")

    # Risk and Recommendation
    risk = info.get("risk", "Unknown")
    rec = info.get("recommendation", "No specific recommendation.")
    
    wrapped.append("⚠️  Risk Assessment:")
    for line in textwrap.wrap(f"   {risk}", width=width):
        wrapped.append(line)
    wrapped.append("")

    wrapped.append("🛡️ Recommendation:")
    for line in textwrap.wrap(f"   {rec}", width=width):
        wrapped.append(line)
    wrapped.append("")

    # Source Attribution
    source = info.get("source", "Heimdall service knowledge base")
    wrapped.append(f"ℹ️  Source: {source}")
    if is_unknown and not info.get("source"):
        wrapped.append("   Consider investigating manually.")

    return wrapped

# ── Layer 2: Local System Intelligence ──────────────────────────────
_pkg_info_cache = {}

def get_local_package_info(prog, pid=None):
    """
    Query the local package manager (dpkg/rpm) to discover information
    about a running process. Zero internet, zero API keys required.
    Results are cached for the session.
    """
    cache_key = f"{prog}_{pid}" if pid else prog
    if cache_key in _pkg_info_cache:
        return _pkg_info_cache[cache_key]

    info = None
    # Strategy 0: Try systemd description (fastest and most direct for services)
    info = _try_systemd(prog)

    # Strategy 1: Direct dpkg query by process name
    if not info:
        info = _try_dpkg(prog)

    # Strategy 2: Find binary path and reverse-lookup package
    if not info:
        binary_path = _find_binary_path(prog, pid=pid)
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

    _pkg_info_cache[cache_key] = info
    return info

def _try_systemd(prog):
    """Query systemd for unit description."""
    if not prog or prog == "-": return None
    try:
        # Try both unit name and service alias
        units = [f"{prog}.service", prog]
        for unit in units:
            # Check if unit exists first to avoid stderr noise
            res = subprocess.run(["systemctl", "show", unit, "-p", "Description", "--value"], 
                                 capture_output=True, text=True, timeout=1)
            desc = res.stdout.strip()
            # systemctl show returns "" if not found or no description
            if desc and desc != "" and not desc.startswith("Unit "):
                return {
                    "name": prog.replace("-", " ").title(),
                    "description": desc,
                    "source": "systemd (systemctl)"
                }
    except:
        pass
    return None

def _find_binary_path(prog, pid=None):
    """Find the actual binary path of a process via /proc or 'which'."""
    # Priority 1: /proc/[pid]/exe is the most reliable way to find the actual binary
    if pid:
        try:
            proc_exe = f"/proc/{pid}/exe"
            if os.path.exists(proc_exe):
                return os.path.realpath(proc_exe)
        except Exception:
            pass

    # Priority 2: Use psutil if available
    if psutil and pid:
        try:
            p = psutil.Process(int(pid))
            return os.path.realpath(p.exe())
        except Exception:
            pass

    # Priority 3: 'which' (only works if in PATH)
    try:
        res = subprocess.run(["which", prog], capture_output=True, text=True, timeout=1)
        path = res.stdout.strip()
        if path and os.path.exists(path):
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
        if is_managed_by_script(pid):
            choice = confirm_tree_kill_dialog(stdscr, pid, prog, "Stop (SIGTERM)")
            if choice == "tree":
                kill_process_group(pid, prog, None, stdscr)
                return
            elif choice == "cancel":
                return
        
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

    # Force kill can be dangerous
    try:
        if is_managed_by_script(pid):
            choice = confirm_tree_kill_dialog(stdscr, pid, prog, "Force Kill (SIGKILL)")
            if choice == "tree":
                kill_process_group(pid, prog, None, stdscr)
                return
            elif choice == "cancel":
                return

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

def perform_tree_strike(pid, port=None):
    """
    Safe, surgical tree strike that kills a script and all its children
    WITHOUT touching the user terminal or display session.

    Strategy:
    1. Walk UP the ancestor chain to find the topmost script root
    2. Stop at login shell / terminal boundary (never climb into it)
    3. Sweep DOWN from the identified root using recursive pgrep -P
    4. Kill only what we found in step 3
    5. NEVER use PGRP kill (too blunt, kills unrelated processes)
    """
    # Processes we NEVER touch under any circumstances
    HARD_PROTECT = {
        "gnome-shell", "gnome-session", "kwin", "kwin_x11", "kwin_wayland",
        "plasmashell", "Xorg", "Xwayland",
        "systemd", "systemd-user", "init",
        "lightdm", "gdm", "sddm", "xdm",
        "terminator", "gnome-terminal", "konsole", "xterm", "xfce4-terminal",
        "tmux", "screen", "byobu", "dtach",
        "sshd", "login", "su",
        "dbus-daemon", "dbus-broker",
        "pulseaudio", "pipewire",
        "NetworkManager", "wpa_supplicant",
    }

    our_pid = str(os.getpid())

    try:
        debug_log(f"TREE-KILL: Starting safe scan for PID {pid} (Port {port})")
        scripts_found = set()

        # PHASE 1: Walk UPWARD to locate the script root
        script_root = str(pid)
        curr_p = str(pid)

        for level in range(10):
            if not curr_p or curr_p in ("0", "1"):
                break

            stat_path = f"/proc/{curr_p}/stat"
            if not os.path.exists(stat_path):
                break

            try:
                with open(stat_path, "r") as f:
                    content = f.read()

                m_start = content.find("(")
                m_end   = content.rfind(")")
                if m_start == -1 or m_end == -1:
                    break

                name    = content[m_start+1:m_end]
                ppid    = content[m_end+2:].split()[1]
                cmdline = get_full_cmdline(curr_p)

                debug_log(f"TREE-KILL: Level {level} - PID {curr_p} ({name}) - Cmd: {cmdline}")

                if name in HARD_PROTECT:
                    debug_log(f"TREE-KILL: HARD_PROTECT boundary at {name}({curr_p}), stopping.")
                    break

                is_shell   = name in ("bash", "sh", "dash", "zsh", "fish")
                has_script = any(ext in cmdline for ext in (".sh", ".py", ".js", ".pl", ".rb", ".php"))

                if is_shell and not has_script:
                    debug_log(f"TREE-KILL: Bare shell boundary at {name}({curr_p}), stopping.")
                    break

                script_root = curr_p

                if has_script:
                    for part in cmdline.split():
                        for ext in (".sh", ".py", ".js", ".pl", ".rb", ".php"):
                            if part.endswith(ext):
                                scripts_found.add(os.path.basename(part))

                curr_p = ppid

            except Exception as e:
                debug_log(f"TREE-KILL: Ancestor scan error at {curr_p}: {e}")
                break

        # PHASE 2: Sweep DOWNWARD from script_root
        pids_to_strike = set()
        queue   = [script_root]
        visited = set()

        while queue:
            p = queue.pop(0)
            if not p or p in visited or p in ("0", "1"):
                continue
            visited.add(p)

            try:
                with open(f"/proc/{p}/stat", "r") as f:
                    c = f.read()
                n_start = c.find("(")
                n_end   = c.rfind(")")
                p_name  = c[n_start+1:n_end] if n_start != -1 and n_end != -1 else ""
                if p_name in HARD_PROTECT:
                    debug_log(f"TREE-KILL: Skipping protected child {p_name}({p})")
                    continue
            except:
                pass

            pids_to_strike.add(p)

            try:
                res = subprocess.run(["pgrep", "-P", p], capture_output=True, text=True)
                for child in res.stdout.split():
                    if child not in visited:
                        queue.append(child)
            except:
                pass

        # PHASE 3: Script Broadcast
        for script in scripts_found:
            if len(script) < 3:
                continue
            try:
                res = subprocess.run(["pgrep", "-f", script], capture_output=True, text=True)
                for p in res.stdout.split():
                    try:
                        with open(f"/proc/{p}/stat", "r") as f:
                            c = f.read()
                        n_start = c.find("(")
                        n_end   = c.rfind(")")
                        p_name  = c[n_start+1:n_end] if n_start != -1 else ""
                        if p_name not in HARD_PROTECT:
                            pids_to_strike.add(p)
                    except:
                        pids_to_strike.add(p)
            except:
                pass

        # ── PHASE 3.5: Port Orphan Sweep ──────────────────────────────────────
        # Scripts that died previously may have left orphan nc/socat processes
        # that got reparented to systemd. They still hold the port.
        # Use ss to find ALL pids on this port and add them.
        if port:
            try:
                res = subprocess.run(
                    ["ss", "-lntuHp"],
                    capture_output=True, text=True
                )
                for line in res.stdout.splitlines():
                    if f":{port}" not in line:
                        continue
                    m = re.search(r'pid=(\d+)', line)
                    if m:
                        orphan_pid = m.group(1)
                        try:
                            with open(f"/proc/{orphan_pid}/stat", "r") as f:
                                c = f.read()
                            n_start = c.find("("); n_end = c.rfind(")")
                            p_name = c[n_start+1:n_end] if n_start != -1 else ""
                            if p_name not in HARD_PROTECT:
                                pids_to_strike.add(orphan_pid)
                                debug_log(f"TREE-KILL: Port orphan found: {p_name}({orphan_pid}) on :{port}")
                        except:
                            pids_to_strike.add(orphan_pid)
            except Exception as e:
                debug_log(f"TREE-KILL: Port orphan sweep error: {e}")

        # PHASE 4: Execute Strike
        strike_list = [
            p for p in pids_to_strike
            if p and p != "0" and p != "1" and p != our_pid and p.isdigit()
        ]


        if not strike_list:
            return False, "No targetable PIDs found"

        debug_log(f"TREE-KILL: Final Strike List: {strike_list}")

        for p in strike_list:
            try: os.kill(int(p), signal.SIGSTOP)
            except: pass

        remaining = []
        for p in strike_list:
            try: os.kill(int(p), signal.SIGKILL)
            except PermissionError: remaining.append(p)
            except: pass

        if remaining:
            subprocess.run(["sudo", "kill", "-9"] + remaining, capture_output=True)

        if port:
            subprocess.run(["sudo", "fuser", "-k", "-9", "-n", "tcp", str(port)], capture_output=True)

        names = ", ".join(scripts_found) if scripts_found else "process tree"
        return True, f"Eliminated {len(strike_list)} PIDs ({names})"

    except Exception as e:
        debug_log(f"TREE-KILL: Exception - {str(e)}")
        return False, str(e)


def kill_process_group(pid, prog, port, stdscr):
    if not pid or not pid.isdigit():
        show_message(stdscr, "Invalid PID.")
        return

    # If port is not directly known, try to find it from the process
    actual_port = port
    if not actual_port:
        try:
            res = subprocess.run(["ss", "-lntuHp"],
                                 capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if f"pid={pid}," in line or f"pid={pid})" in line:
                    local = line.split()[4] if len(line.split()) > 4 else ""
                    actual_port = local.split(":")[-1]
                    break
        except: pass
    
    if stdscr:
        show_message(stdscr, f"🚀 Precision Tree Strike on port {actual_port or '?'}...", duration=1.0)
    
    success, msg = perform_tree_strike(pid, actual_port)
    
    if stdscr:
        if success:
            show_message(stdscr, f"✅ Clean Kill: {msg} (Terminal protected).")
        else:
            show_message(stdscr, f"Strike failed: {msg}")

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

def get_risk_level(process_name, port=None):
    """Extract the risk level keyword from service info (High, Critical, Medium, etc.)."""
    svc = get_service_info(process_name, port)
    risk_str = svc.get('risk', 'Unknown')
    # The risk string starts with the level keyword, e.g. "High - ..."
    level = risk_str.split(' ')[0].rstrip(' -') if risk_str else 'Unknown'
    return level

def is_high_risk(risk_level):
    """Return True if the risk level is considered dangerous (High or Critical)."""
    return risk_level in ('High', 'Critical')

def perform_security_heuristics(pid, port, prog, username, is_outbound=False):
    """
    Heimdall Sentinel: Behavioral Security Heuristics (Rule Engine version).
    Loads logic from external DSL (sentinel_rules.json).
    """
    findings = []
    
    # 1. Gather Context
    context = {
        "pid": pid,
        "port": port,
        "prog": prog,
        "user": username,
        "exe": "",
        "cmdline": "",
        "cwd": "",
        "tree": [],
        "is_public": False,
        "is_outbound": is_outbound
    }

    if psutil and pid and pid.isdigit():
        try:
            p = psutil.Process(int(pid))
            context["exe"] = p.exe()
            context["cmdline"] = p.cmdline()
            context["cwd"] = p.cwd()
            context["tree"] = get_process_parent_chain(pid)
            
            conns = p.connections(kind='inet')
            for c in conns:
                if c.status == 'LISTEN' and c.laddr.ip in ['0.0.0.0', '::', '0:0:0:0:0:0:0:0']:
                    context["is_public"] = True
                    break
        except: pass

    # 2. Run Rules
    for rule in SENTINEL_RULES:
        logic_blocks = rule.get("logic", [])
        if not logic_blocks: continue
        
        # All logic blocks in a rule must be TRUE (AND logic)
        match = True
        for logic in logic_blocks:
            if not evaluate_sentinel_logic(logic, context):
                match = False
                break
        
        if match:
            # Format message with context (e.g. {prog}, {cwd})
            try:
                msg = rule["message"].format(**context)
            except:
                msg = rule["message"]
                
            findings.append({
                "level": rule["level"],
                "msg": msg,
                "icon": rule["icon"]
            })
    
    return findings

def compute_risk_for_all_ports(rows, cache=None):
    """Compute and cache risk levels + security audit for all ports/processes."""
    global _risk_level_cache, _security_audit_cache
    _risk_level_cache.clear()
    _security_audit_cache.clear()
    for row in rows:
        port = row[0]
        prog = row[3] if len(row) > 3 else "-"
        pid = row[4] if len(row) > 4 else "-"
        
        # Use full resolver to get accurate risk (handles package-bridge lookups)
        info, _ = resolve_service_knowledge(prog, port, pid=pid)
        level = info.get("risk", "Unknown")
        _risk_level_cache[str(port)] = level
        
        # Security audit: use behavioral heuristics (Heimdall Sentinel)
        username = "-"
        if cache and port in cache:
            username = cache[port].get("user", "-")
        else:
            username = get_process_user(pid) if pid and pid.isdigit() else "-"
        
        # Store full findings list
        findings = perform_security_heuristics(pid, port, prog, username)
        _security_audit_cache[str(port)] = findings
        
        # ACTIVE TUI PROTECTION Check
        check_active_tui_protection(pid, port, prog, username, findings)

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
    
    # Unified resolver: System Intelligence -> Curated Database
    info, is_unknown = resolve_service_knowledge(prog, port, pid=pid)
    
    lines.append((f"  Identity    : {info.get('name')}", CP_TEXT))
    lines.append(("  Scope       :", CP_TEXT))
    
    desc = info.get("description", "No detailed description available.")
    desc_wrapped = textwrap.wrap(desc, 70)
    for d_line in desc_wrapped:
        lines.append((f"    {d_line}", CP_TEXT))
    
    risk_lvl = info.get('risk', 'Unknown')
    lines.append((f"  🚩 Risk Level: {risk_lvl}", CP_WARN if any(x in risk_lvl for x in ["High", "Danger", "Medium"]) else CP_TEXT))
    lines.append((f"  💡 Recommendation:", CP_ACCENT))
    rec = info.get('recommendation', 'No specific recommendation.')
    rec_wrapped = textwrap.wrap(rec, 70)
    for r_line in rec_wrapped:
        lines.append((f"    {r_line}", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 2. Security Audit (MOVED TO TOP)
    lines.append(("⚠️ SECURITY AUDIT (SENTINEL)", CP_ACCENT))
    
    findings = perform_security_heuristics(pid, port, prog, username)
        
    if not findings:
        lines.append(("  ✅ No critical security indicators detected.", CP_TEXT))
    else:
        for f in findings:
            color = CP_WARN if f['level'] in ['HIGH', 'CRITICAL'] else CP_TEXT
            lines.append((f"  {f['icon']} {f['level']}: {f['msg']}", color))

    lines.append(("", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 3. Vulnerability Status (CVE)
    lines.append(("🔓 VULNERABILITY ANALYSIS (NVD)", CP_ACCENT))
    pkg_name = info.get("package", "-")
    cves = get_matched_cves(pkg_name)
    if not cves:
        lines.append(("  ✅ No known NVD vulnerabilities for this package.", CP_TEXT))
    else:
        lines.append((f"  ❗ FOUND {len(cves)} MATCHING VULNERABILITIES:", CP_WARN))
        for cve in cves:
            lines.append((f"    ● {cve['cve_id']} [{cve['severity']}]", CP_WARN))
            # Just one line of desc for brevity
            lines.append((f"      {cve['desc'][:65]}...", CP_TEXT))
    
    lines.append(("", CP_TEXT))

    # 4. Runtime Classification
    lines.append(("🏷️ CLASSIFICATION", CP_ACCENT))
    runtime_info = detect_runtime_type_cached(pid)
    lines.append((f"  Runtime     : {runtime_info['type']}", CP_TEXT))
    lines.append((f"  Stack Mode  : {runtime_info['mode']}", CP_TEXT))
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

    lines.append(("", CP_TEXT))

    lines.append(("🛡️ SENTINEL ICON LEGEND", CP_ACCENT))
    lines.append(("  ☢️ Backdoor  🧪 Script Listener  🎭 Masquerade", CP_TEXT))
    lines.append(("  💀 Deleted Bin  📂 Suspicious Dir  🌐 Public IP", CP_TEXT))
    lines.append(("  🛡️ Root Privilege  🌲 Shell Lineage", CP_TEXT))
    
    lines.append(("", CP_TEXT))

    lines.append(("", CP_TEXT))

    # 10. Connection Visibility
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
        for f_item in f_list:
            lines.append((f"    {f_item}", CP_TEXT))

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
            except (FileNotFoundError, ProcessLookupError):
                pass
            except Exception as e:
                debug_log(f"LIFECYCLE error for pid {pid}: {e}")

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

    except Exception as e:
        debug_log(f"LIFECYCLE outer error for prog {prog} pid {pid}: {e}")
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


def show_full_inspection_preview(stdscr, report_lines):
    """Display the full system inspection report in a scrollable modal with save option."""
    h, w = stdscr.getmaxyx()
    bh, bw = h - 4, min(140, w - 4)
    y, x = (h - bh) // 2, (w - bw) // 2
    
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    
    scroll_pos = 0
    total_lines = len(report_lines)
    max_visible = bh - 4
    
    while True:
        win.erase()
        try: win.bkgd(' ', curses.color_pair(CP_TEXT))
        except: pass
        win.box()
        
        title = " 📊 FULL SYSTEM INSPECTION RESULTS "
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        for i in range(max_visible):
            idx = scroll_pos + i
            if idx < total_lines:
                line = report_lines[idx].rstrip('\n')
                # Basic color coding for preview
                color = CP_TEXT
                if any(x in line for x in ["🛑", "⚠️", "CRITICAL", "HIGH"]):
                    color = CP_WARN
                elif any(x in line for x in ["✅", "🔹", "🌐", "🧠"]):
                    color = CP_ACCENT
                
                try:
                    win.addstr(2 + i, 2, line[:bw-4], curses.color_pair(color))
                except: pass
        
        footer = " ↑↓ Scroll / PgUp/PgDn | [s] Save to File | [q/ESC] Close | Full Security Audit Active "
        win.addstr(bh-1, (bw - len(footer)) // 2, footer, curses.color_pair(CP_ACCENT))
        
        win.refresh()
        k = win.getch()
        
        if k in (ord('q'), 27):
            win.erase(); win.refresh(); del win
            return False # User closed without saving
        elif k in (ord('s'), ord('S')):
            win.erase(); win.refresh(); del win
            return True # User wants to save
        elif k == curses.KEY_UP and scroll_pos > 0:
            scroll_pos -= 1
        elif k == curses.KEY_DOWN and scroll_pos < total_lines - max_visible:
            scroll_pos += 1
        elif k == curses.KEY_PPAGE: # PageUp
            scroll_pos = max(0, scroll_pos - max_visible)
        elif k == curses.KEY_NPAGE: # PageDown
            scroll_pos = min(max(0, total_lines - max_visible), scroll_pos + max_visible)

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
    Heimdall 'Status Bar': Displays background activity and action feedback
    at the bottom-right corner with a progressing icon.
    """
    global ACTION_STATUS_MSG, ACTION_STATUS_EXP, UPDATE_STATUS_MSG, SCANNING_STATUS_EXP
    h, w = stdscr.getmaxyx()
    now = time.time()
    
    # 🌀 Progressing icon: Blue Braille Circle (mavi noktalar)
    spinner_frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    # Sync spinner speed (approx 8Hz) with loop timeout (120ms) for smoothness
    s_frame = spinner_frames[int(now * 8) % len(spinner_frames)]
    
    msg = ""
    is_active = False
    # CP_HEADER is blue in most themes (VSCode, Catppuccin, OneDark)
    spinner_attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
    status_attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD
    
    # Priority 1: Action Feedback (Killed, Blocked, etc.)
    if ACTION_STATUS_MSG and now < ACTION_STATUS_EXP:
        msg = ACTION_STATUS_MSG
        is_active = True
        is_error = any(kw in ACTION_STATUS_MSG.lower() for kw in ["failed", "error", "invalid"])
        if is_error: status_attr = curses.color_pair(CP_WARN) | curses.A_BOLD
    # Priority 2: Background Service Updates
    elif UPDATE_STATUS_MSG:
        msg = UPDATE_STATUS_MSG
        is_active = True
    # Priority 3: Vulnerability Intel Background Refresh (Part 3.2)
    elif VULN_IS_FETCHING or VULN_STATUS_MSG:
        # Show specific message if fetching, else show general status
        msg = VULN_STATUS_MSG if VULN_STATUS_MSG else "🛡️ Checking Vulnerability Intelligence..."
        is_active = True
        status_attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD

    # Priority 4: Auto-Scan Heartbeat
    elif now < SCANNING_STATUS_EXP:
        msg = "🛡️ HEIMDALL: Active System Scan..."
        is_active = True
        status_attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD
        
    if is_active:
        # Format: [ ⣾ ] Message...
        indicator = f" {s_frame} {msg} "
        try:
            # Position: Bottom-right corner (h-1), right-aligned
            # We use w - len - 1 to leave a tiny gap at the end
            start_x = max(0, w - len(indicator) - 1)
            
            # 1. Draw the text part
            stdscr.addstr(h - 1, start_x, indicator, status_attr)
            
            # 2. Overlay the spinner with the requested blue color
            stdscr.addstr(h - 1, start_x + 1, s_frame, spinner_attr)
            
            # 3. Ensure the update is sent to the buffer for doupdate()
            stdscr.noutrefresh()
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
    bh, bw = 10, 45
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
        win.addstr(4, 4, "[d] Daemon Mode (Background)", curses.color_pair(CP_TEXT))
        win.addstr(5, 4, "[v] Vulnerability Scanner (NVD API Key)", curses.color_pair(CP_TEXT))
        win.addstr(6, 4, "[i] Vuln. Scan Interval", curses.color_pair(CP_TEXT))
        win.addstr(7, 4, "[o] Outbound Refresh Interval", curses.color_pair(CP_TEXT))
        
        daemon_status = "ON" if CONFIG.get("daemon_enabled") else "OFF"
        win.addstr(4, bw - 10, f"[{daemon_status}]", curses.color_pair(CP_ACCENT) if daemon_status == "ON" else curses.A_DIM)
        
        api_key = CONFIG.get("nvd_api_key")
        key_status = "SET" if api_key else "MISSING"
        win.addstr(5, bw - 10, f"[{key_status}]", curses.color_pair(CP_ACCENT) if api_key else curses.color_pair(CP_WARN))

        vuln_interval = CONFIG.get("vuln_scan_interval_hours", 1.0)
        win.addstr(6, bw - 10, f"[{vuln_interval}h]", curses.color_pair(CP_TEXT) | curses.A_BOLD)

        outbound_interval = CONFIG.get("outbound_refresh_interval", 10.0)
        win.addstr(7, bw - 10, f"[{outbound_interval}s]", curses.color_pair(CP_TEXT) | curses.A_BOLD)

        footer = " [q/ESC] Close "
        win.addstr(bh-2, (bw - len(footer)) // 2, footer, curses.color_pair(CP_TEXT))
        
        win.refresh()
        k = win.getch()
        if k == ord('q') or k == 27: break
        elif k == ord('s'):
            draw_auto_update_settings_modal(stdscr)
        elif k == ord('r'):
            draw_auto_scan_settings_modal(stdscr)
        elif k == ord('d'):
            draw_daemon_settings_modal(stdscr)
        elif k == ord('v'):
            draw_vuln_settings_modal(stdscr)
        elif k == ord('i'):
            draw_vuln_interval_settings_modal(stdscr)
        elif k == ord('o'):
            draw_outbound_interval_settings_modal(stdscr)
            
    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_outbound_interval_settings_modal(stdscr):
    global OUTBOUND_REFRESH_INTERVAL
    h, w = stdscr.getmaxyx()
    bh, bw = 8, 50
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    title = " 🌐 Outbound Refresh Interval "
    
    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        curr = CONFIG.get("outbound_refresh_interval", 10.0)
        win.addstr(2, 4, f"Current Interval: {curr} seconds")
        win.addstr(4, 4, "[+] Increase (+5s)  [-] Decrease (-5s)")
        win.addstr(bh-2, 4, "[ESC/q] Save and Close")
        win.refresh()
        k = win.getch()
        if k == 27 or k == ord('q'): break
        elif k == ord('+'):
            CONFIG["outbound_refresh_interval"] = min(60, curr + 5)
            OUTBOUND_REFRESH_INTERVAL = CONFIG["outbound_refresh_interval"]
            save_config()
        elif k == ord('-'):
            CONFIG["outbound_refresh_interval"] = max(5, curr - 5)
            OUTBOUND_REFRESH_INTERVAL = CONFIG["outbound_refresh_interval"]
            save_config()
    win.erase(); win.refresh(); del win

def draw_vuln_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 12, 65
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    title = " 📩 Vulnerability Scanner Settings "
    editing = False
    input_buf = CONFIG.get("nvd_api_key", "") or ""

    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        win.addstr(2, 4, "Automated NVD background scanning is always active.")
        win.addstr(3, 4, "Use an API Key to increase rate limits (50 req / 30s).")
        
        win.addstr(5, 4, "NVD API Key: ")
        key_disp = input_buf if editing else (("*" * len(input_buf)) if input_buf else "(not set)")
        attr = curses.A_REVERSE | curses.A_BOLD if editing else curses.A_NORMAL
        color = curses.color_pair(CP_ACCENT) if editing else curses.color_pair(CP_TEXT)
        
        max_k = bw - 20
        win.addstr(5, 18, key_disp[-max_k:], color | attr)
        
        if editing:
            win.addstr(7, 4, "[ENTER] Save  [ESC] Cancel", curses.color_pair(CP_WARN) | curses.A_BOLD)
        else:
            win.addstr(7, 4, "[e] Edit Key  [c] Clear  [ENTER/q] Close", curses.A_DIM)
        
        win.refresh()
        k = win.getch()
        
        if editing:
            if k == 27: # ESC
                editing = False
                input_buf = CONFIG.get("nvd_api_key", "") or ""
            elif k in (10, 13, curses.KEY_ENTER):
                with CONFIG_LOCK:
                    CONFIG["nvd_api_key"] = input_buf if input_buf else None
                save_config()
                editing = False
                show_message(stdscr, "✅ NVD API Key saved.")
            elif k in (8, 127, curses.KEY_BACKSPACE, 263):
                input_buf = input_buf[:-1]
            elif 32 <= k <= 126:
                input_buf += chr(k)
        else:
            if k in (curses.KEY_ENTER, 10, 13, ord('q'), 27):
                break
            elif k == ord('e'):
                editing = True
            elif k == ord('c'):
                with CONFIG_LOCK:
                    CONFIG["nvd_api_key"] = None
                save_config()
                input_buf = ""
                show_message(stdscr, "🗑️ NVD API Key cleared.")

    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_daemon_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 10, 60
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    title = " 🛡️ Daemon Mode Settings "
    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        enabled = CONFIG.get("daemon_enabled", False)
        status_str = "ENABLED" if enabled else "DISABLED"
        
        win.addstr(2, 4, "Daemon mode monitors outbound connections in the background.")
        win.addstr(3, 4, "It is useful when the TUI is not running.")
        
        win.addstr(5, 4, f"Current Status: ")
        win.addstr(5, 20, status_str, curses.color_pair(CP_ACCENT) if enabled else curses.A_DIM)
        
        win.addstr(7, 4, "[SPACE] Toggle  |  [ENTER/q] Apply & Close", curses.A_DIM)
        
        win.refresh()
        k = win.getch()
        if k in (curses.KEY_ENTER, 10, 13, ord('q'), 27):
            break
        elif k == ord(' '):
            with CONFIG_LOCK:
                CONFIG["daemon_enabled"] = not enabled
            save_config()
            
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

def draw_vuln_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 12, 65
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    title = " 📩 Vulnerability Scanner Settings "
    editing = False
    input_buf = CONFIG.get("nvd_api_key", "") or ""

    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        win.addstr(2, 4, "Automated NVD background scanning is always active.")
        win.addstr(3, 4, "Use an API Key to increase rate limits (50 req / 30s).")
        
        win.addstr(5, 4, "NVD API Key: ")
        key_disp = input_buf if editing else (("*" * len(input_buf)) if input_buf else "(not set)")
        attr = curses.A_REVERSE | curses.A_BOLD if editing else curses.A_NORMAL
        color = curses.color_pair(CP_ACCENT) if editing else curses.color_pair(CP_TEXT)
        
        max_k = bw - 20
        win.addstr(5, 18, key_disp[-max_k:], color | attr)
        
        if editing:
            win.addstr(7, 4, "[ENTER] Save  [ESC] Cancel", curses.color_pair(CP_WARN) | curses.A_BOLD)
        else:
            win.addstr(7, 4, "[e] Edit Key  [c] Clear  [ENTER/q] Close", curses.A_DIM)
        
        win.refresh()
        k = win.getch()
        
        if editing:
            if k == 27: # ESC
                editing = False
                input_buf = CONFIG.get("nvd_api_key", "") or ""
            elif k in (10, 13, curses.KEY_ENTER):
                with CONFIG_LOCK:
                    CONFIG["nvd_api_key"] = input_buf if input_buf else None
                save_config()
                editing = False
                show_message(stdscr, "✅ NVD API Key saved.")
            elif k in (8, 127, curses.KEY_BACKSPACE, 263):
                input_buf = input_buf[:-1]
            elif 32 <= k <= 126:
                input_buf += chr(k)
        else:
            if k in (curses.KEY_ENTER, 10, 13, ord('q'), 27):
                break
            elif k == ord('e'):
                editing = True
            elif k == ord('c'):
                with CONFIG_LOCK:
                    CONFIG["nvd_api_key"] = None
                save_config()
                input_buf = ""
                show_message(stdscr, "🗑️ NVD API Key cleared.")

    win.erase(); win.refresh(); del win
    stdscr.touchwin()

def draw_vuln_interval_settings_modal(stdscr):
    h, w = stdscr.getmaxyx()
    bh, bw = 14, 55
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    options = [
        (0.08, "5 Minutes (Very Aggressive)"),
        (0.25, "15 Minutes (Aggressive)"),
        (0.5,  "30 Minutes (Standard)"),
        (1.0,  "1 Hour (Relaxed)"),
        (4.0,  "4 Hours (Very Relaxed)"),
        (24.0, "Daily (24 Hours)"),
        (168.0, "Weekly")
    ]
    
    idx = 0
    curr = CONFIG.get("vuln_scan_interval_hours", 1.0)
    for i, opt in enumerate(options):
        if opt[0] == curr:
            idx = i
            break
            
    title = " 🕓 Vuln. Scan Interval "
    while True:
        win.erase(); win.box()
        win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_WARN) | curses.A_BOLD)
        
        for i, (val, label) in enumerate(options):
            attr = curses.A_REVERSE | curses.A_BOLD if i == idx else curses.A_NORMAL
            win.addstr(2 + i, 4, f" {label:<45} ", attr)
            
        win.addstr(bh - 2, 4, "[ENTER] Select  [q/ESC] Cancel", curses.A_DIM)
        
        win.refresh()
        k = win.getch()
        if k == ord('q') or k == 27: break
        elif k == curses.KEY_UP:
            idx = (idx - 1) % len(options)
        elif k == curses.KEY_DOWN:
            idx = (idx + 1) % len(options)
        elif k in (curses.KEY_ENTER, 10, 13):
            with CONFIG_LOCK:
                CONFIG["vuln_scan_interval_hours"] = options[idx][0]
            save_config()
            show_message(stdscr, f"✅ Scan interval set to {options[idx][0]}h")
            break
            
def show_env_vars_modal(stdscr, pid, prog):
    """View process environment variables from /proc/[pid]/environ."""
    h, w = stdscr.getmaxyx()
    win_h, win_w = h - 6, w - 10
    win = curses.newwin(win_h, win_w, 3, 5)
    win.box()
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    envs = []
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            data = f.read()
            envs = [e.decode('utf-8', 'replace') for e in data.split(b'\x00') if e]
    except Exception as e:
        envs = [f"Error reading environ: {e}"]
    
    envs.sort()
    scroll = 0
    title = f" 🌍 Env Vars: {prog} (PID {pid}) "
    
    while True:
        win.erase(); win.box()
        win.addstr(0, (win_w - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        max_rows = win_h - 4
        for i in range(max_rows):
            idx = scroll + i
            if idx < len(envs):
                line = envs[idx]
                win.addstr(2 + i, 3, line[:win_w-6], curses.color_pair(CP_TEXT))
        
        hint = " [UP/DN] Scroll | [ESC/q/Enter] Close "
        win.addstr(win_h - 1, (win_w - len(hint)) // 2, hint, curses.color_pair(CP_ACCENT))
        win.refresh()
        
        k = win.getch()
        if k in (27, ord('q'), ord('Q'), 10, curses.KEY_ENTER): break
        elif k == curses.KEY_UP and scroll > 0: scroll -= 1
        elif k == curses.KEY_DOWN and scroll < len(envs) - max_rows: scroll += 1
    
    win.erase(); win.refresh(); del win

def show_redirections_modal(stdscr, pid, prog):
    """View process redirections (stdin, stdout, stderr) from /proc/[pid]/fd/."""
    h, w = stdscr.getmaxyx()
    win_h, win_w = 12, min(80, w - 10)
    win = curses.newwin(win_h, win_w, (h - win_h) // 2, (w - win_w) // 2)
    win.box()
    win.keypad(True)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    
    fds = [0, 1, 2]
    labels = ["STDIN (0)", "STDOUT (1)", "STDERR (2)"]
    targets = []
    for fd in fds:
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except:
            target = "unknown / closed"
        targets.append(target)
    
    sel = 1 # Default to stdout
    title = f" ⇄ Redirections: {prog} "
    
    while True:
        win.erase(); win.box()
        win.addstr(0, (win_w - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        win.addstr(2, 4, "Process Standard Streams:", curses.A_DIM)
        for i, (label, target) in enumerate(zip(labels, targets)):
            attr = curses.A_REVERSE | curses.A_BOLD if i == sel else curses.color_pair(CP_TEXT)
            icon = "➡️" if i == sel else "  "
            win.addstr(4 + i, 4, f"{icon} {label}: {target[:win_w-20]}", attr)
        
        hint = " [Enter/t] Tail File | [ESC/q] Close "
        win.addstr(win_h - 2, (win_w - len(hint)) // 2, hint, curses.color_pair(CP_ACCENT))
        win.refresh()
        
        k = win.getch()
        if k in (27, ord('q'), ord('Q')): break
        elif k == curses.KEY_UP and sel > 0: sel -= 1
        elif k == curses.KEY_DOWN and sel < 2: sel += 1
        elif k in (10, curses.KEY_ENTER, ord('t'), ord('T')):
            target = targets[sel]
            if target.startswith("/") and os.path.exists(target) and not os.path.isdir(target):
                draw_file_tail_window(stdscr, pid, prog, target_path=target)
            elif "socket:[" in target or "pipe:[" in target:
                show_message(stdscr, "Cannot tail a socket/pipe directly.")
            else:
                show_message(stdscr, "Selected stream is not a tail-able file.")
            # Refresh in case we returned from tail
            stdscr.touchwin(); curses.doupdate(); win.refresh()

    win.erase(); win.refresh(); del win

# --------------------------------------------------
# System Services Management
# --------------------------------------------------

def get_systemd_services():
    """Fetch all systemd services and capture legend info."""
    try:
        output = subprocess.check_output(['systemctl', 'list-units', '--type=service', '--no-pager', '--all'], stderr=subprocess.STDOUT).decode('utf-8', 'ignore')
        services = []
        legend = []
        for line in output.splitlines():
            orig_line = line
            line = line.strip()
            if not line: continue
            
            # Identify legend/explanation lines (LOAD=, ACTIVE=, SUB=, etc) 
            # or lines that aren't service units
            is_legend = any(line.startswith(s) for s in ('UNIT', 'LOAD', 'ACTIVE', 'SUB', 'LEGEND', 'Legend:', 'To ')) or 'loaded units listed' in line or 'Reflects' in line
            if is_legend:
                if not line.startswith('UNIT'): # Don't need the header twice
                    legend.append(line)
                continue

            # Handle lines starting with error/status markers
            if line.startswith('●'): line = line[1:].strip()
            
            parts = line.split(None, 4)
            if len(parts) >= 4 and parts[0].endswith('.service'):
                services.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else ""
                })
        return sorted(services, key=lambda x: x['unit']), legend
    except Exception as e:
        debug_log(f"SERVICES: Error fetching: {e}")
        return [], []

def get_systemd_unit_files():
    """Fetch all installed systemd unit files."""
    try:
        output = subprocess.check_output(['systemctl', 'list-unit-files', '--type=service', '--no-pager'], stderr=subprocess.STDOUT).decode('utf-8', 'ignore')
        files = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('UNIT FILE') or 'unit files listed' in line or line.startswith('STATE'):
                continue
            parts = line.split()
            if len(parts) >= 2:
                files.append({
                    "unit": parts[0],
                    "active": parts[1], # Map 'state' to 'active' for reused drawing logic
                    "sub": parts[2] if len(parts) > 2 else "-", # Map 'preset' to 'sub'
                    "description": "" # No description in list-unit-files
                })
        return sorted(files, key=lambda x: x['unit'])
    except Exception as e:
        debug_log(f"SERVICES: Error fetching unit files: {e}")
        return []

def draw_services_modal(stdscr, services, selected_idx, offset, mode=0):
    h, w = stdscr.getmaxyx()
    bw = min(w - 4, 140)
    bh = min(h - 4, 32)
    y = max(1, (h - bh) // 2)
    x = (w - bw) // 2
    
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.erase()
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    
    if mode == 0:
        title = " ⚙️  System Services: Units (Running/Active/Inactive) "
        headers = ["  UNIT", "IDENTITY", "STATE", "STATUS", "DESCRIPTION"]
        widths = [35, 25, 10, 12, max(10, bw - 87)]
    else:
        title = " 📂 System Services: All Unit Files (Installed/Enabled/Disabled) "
        headers = ["  UNIT FILE", "IDENTITY", "TYPE", "STATE", "PRESET"]
        widths = [35, 25, 12, 10, max(10, bw - 87)]

    try: win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except: pass
    
    hx = 2
    for head, wd in zip(headers, widths):
        try: win.addstr(1, hx, head.ljust(wd)[:wd], curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except: pass
        hx += wd
        
    try: win.hline(2, 1, curses.ACS_HLINE, bw - 2, curses.color_pair(CP_BORDER))
    except: pass
    
    visible_rows = bh - 6
    for i in range(visible_rows):
        idx = offset + i
        if idx >= len(services): break
        s = services[idx]
        is_selected = (idx == selected_idx)
        
        attr = curses.A_REVERSE | curses.A_BOLD if is_selected else curses.A_NORMAL
        # Flag risky services
        risk_level = get_risk_level(s['unit'].replace('.service', ''))
        is_risky = is_high_risk(risk_level)
        color = curses.color_pair(CP_ACCENT) if is_selected else (curses.color_pair(CP_WARN) if is_risky else curses.color_pair(CP_TEXT))
        
        # Define icon/prefix based on mode and status
        if mode == 0: # Units Mode
            prefix = "⚠️ " if is_risky or s['active'] != 'active' else "✅ "
            if s['active'] == 'failed': prefix = "💀 "
        else: # Unit Files Mode
            st = s['active'].lower()
            if st == 'enabled': prefix = "✅ "
            elif st == 'disabled': prefix = "🚫 "
            elif st == 'static': prefix = "⚙️  "
            elif st == 'alias': prefix = "🔗 "
            elif st in ('masked', 'bad', 'error'): prefix = "⚠️ "
            else: prefix = "📄 "
        
        # Get user friendly info
        info = SYSTEM_SERVICES_DB.get(s['unit'], {})
        friendly_name = info.get('name', '')
        srv_type = info.get('type', '-')

        try:
            # Draw the row with fixed column offsets
            win.addstr(3 + i, 1, " " * (bw - 2), color | attr) # Fill background
            win.addstr(3 + i, 1, prefix, color | attr)
            win.addstr(3 + i, 4, s['unit'][:32], color | attr)
            win.addstr(3 + i, 37, friendly_name[:24], color | attr)
            
            if mode == 0:
                win.addstr(3 + i, 62, s['active'][:9].ljust(9), color | attr)
                win.addstr(3 + i, 72, s['sub'][:11].ljust(11), color | attr)
                desc_w = bw - 87
                win.addstr(3 + i, 84, s['description'][:desc_w], color | attr)
            else:
                win.addstr(3 + i, 62, srv_type[:11].ljust(11), color | attr)
                win.addstr(3 + i, 74, s['active'][:9].ljust(9), color | attr)
                win.addstr(3 + i, 84, s['sub'][:12].ljust(12), color | attr)
        except: pass
        
    hints = " [↑↓] Nav  [Enter] Status  [i] Help/Info  [S] Start  [s] Stop  [r] Restart  [l] Reload  [e] Edit  [ESC] Exit"
    try: win.addstr(bh - 2, 2, hints[:bw-4], curses.color_pair(CP_TEXT) | curses.A_DIM)
    except: pass
    
    # Mode switch hint
    mode_hint = " [TAB] Unit Files " if mode == 0 else " [TAB] Running Units "
    try: win.addstr(bh - 2, bw - len(mode_hint) - 2, mode_hint, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except: pass

    win.refresh()
    return win

def handle_services_modal(stdscr):
    units, legend = get_systemd_services()
    unit_files = []
    mode = 0 # 0: Units, 1: Unit Files
    
    if not units:
        show_message(stdscr, "No systemd services found.")
        return
        
    services = units
    selected = 0
    offset = 0
    h, w = stdscr.getmaxyx()
    visible_rows = min(h - 4, 32) - 6
    if visible_rows <= 0: visible_rows = 1
    
    while True:
        win = draw_services_modal(stdscr, services, selected, offset, mode=mode)
        win.timeout(-1)
        k = win.getch()
        if k == 27: break
        elif k == curses.KEY_UP and selected > 0:
            selected -= 1
            if selected < offset: offset = selected
        elif k == curses.KEY_DOWN and selected < len(services) - 1:
            selected += 1
            if selected >= offset + visible_rows: offset = selected - visible_rows + 1
        elif k == 9: # TAB: Switch mode
            mode = 1 - mode
            if mode == 1:
                if not unit_files:
                    show_modal_message(stdscr, "Loading unit files...", duration=0.2)
                    unit_files = get_systemd_unit_files()
                services = unit_files
            else:
                services = units
            # Reset view status
            selected = 0
            offset = 0
        elif k in (ord('s'), ord('S'), ord('r'), ord('l')):
            unit = services[selected]['unit']
            action_map = {ord('s'):'stop', ord('S'):'start', ord('r'):'restart', ord('l'):'reload'}
            action = action_map[k]
            if action != 'start' and not confirm_dialog(stdscr, f"{action.capitalize()} {unit}?"):
                continue
            execute_service_action(unit, action, stdscr)
            # Refresh list after action
            if mode == 0:
                units, legend = get_systemd_services()
                services = units
            else:
                unit_files = get_systemd_unit_files()
                services = unit_files
        elif k in (10, 13, curses.KEY_ENTER):
            show_service_details_modal(stdscr, services[selected]['unit'])
        elif k == ord('i'):
            show_service_help_modal(stdscr, services[selected], legend)
        elif k == ord('e'):
            edit_service_unit(stdscr, services[selected]['unit'])
            services, legend = get_systemd_services()
            
    stdscr.touchwin()
    curses.doupdate()

def show_service_help_modal(stdscr, service_entry, legend):
    """Show a combined Help and Info modal for Systemd terms and the selected service."""
    h, w = stdscr.getmaxyx()
    bw = min(w - 2, 90)
    bh = min(h - 2, 28)
    y, x = (h - bh) // 2, (w - bw) // 2

    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.erase()
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()

    title = " ℹ️  Systemd Service Info & Legend "
    try: win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except: pass

    content = [
        "UNIT: The systemd service unit name.",
        "─────────────────────────────────────────────────────────────────",
        "💡 WHICH MODE AM I IN?",
        " • Units Mode (Default): Shows what is currently in memory (Running/Failed).",
        " • Unit Files Mode (TAB): Shows what is installed on disk (Enabled/Disabled).",
        "─────────────────────────────────────────────────────────────────",
    ]
    
    # Use the captured legend lines if available, otherwise use defaults
    if legend:
        content.extend(legend)
    else:
        content.extend([
            "LOADED: Reflects whether the unit definition was properly loaded.",
            "ACTIVE: The high-level unit activation state (generalization of SUB).",
            "SUB: The low-level unit activation state, values depend on unit type.",
        ])

    content.append("─────────────────────────────────────────────────────────────────")
    # Identify friendly info
    info = SYSTEM_SERVICES_DB.get(service_entry['unit'], {})
    if info:
        content.append(f"🆔 IDENTITY: {info.get('name', 'N/A')}")
        content.append(f"🏷️  TYPE:     {info.get('type', 'N/A')}")
        desc = info.get('description', '')
        if desc:
            content.append("📝 DESCRIPTION:")
            # Wrap description to fit the modal width
            wrapped = textwrap.wrap(desc, width=bw-8)
            for w_line in wrapped:
                content.append(f"   {w_line}")
        content.append("─────────────────────────────────────────────────────────────────")

    content.append(f"CURRENT SELECTION: {service_entry['unit']}")
    if 'load' in service_entry:
        content.append(f"  ● Load State: {service_entry['load']}")
        content.append(f"  ● High-Level (Active): {service_entry['active']}")
        content.append(f"  ● Low-Level (Sub): {service_entry['sub']}")
    else:
        # Mode: Unit Files
        content.append(f"  ● Enable State: {service_entry['active']}")
        content.append(f"  ● Vendor Preset: {service_entry['sub']}")
    
    content.append("")
    content.append("💡 QUICK TIPS:")
    content.append(" - 'dead/inactive' is often normal for one-shot services.")
    content.append(" - 'exited' in Sub-state usually means the service finished successfully.")
    content.append(" - 'alias' (🔗) means the unit is a symbolic link to another service.")
    content.append(" - Use 'systemctl list-unit-files' to see all installed units.")

    for i, line in enumerate(content):
        if i >= bh - 4: break
        try: win.addstr(2 + i, 2, line[:bw-4], curses.color_pair(CP_TEXT))
        except: pass

    try: win.addstr(bh-2, 2, " [Any Key] Close Info ", curses.color_pair(CP_TEXT) | curses.A_DIM)
    except: pass
    
    win.refresh()
    win.getch()
    del win

def execute_service_action(unit, action, stdscr):
    try:
        curses.def_prog_mode()
        curses.endwin()
        # Use sudo for actions
        res = subprocess.run(["sudo", "systemctl", action, unit], capture_output=True, text=True)
        stdscr.refresh()
        if res.returncode == 0:
            show_message(stdscr, f"Service {unit} {action}ed.")
        else:
            show_modal_message(stdscr, f"Error: {res.stderr.strip()}", duration=3.0)
    except Exception as e:
        show_modal_message(stdscr, f"Exception: {e}")

def show_service_details_modal(stdscr, unit):
    h, w = stdscr.getmaxyx()
    bw, bh = min(w - 2, 140), min(h - 2, 42)
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    
    def get_content():
        try:
            # Check if it's an alias and find the real target
            real_id_raw = subprocess.check_output(['systemctl', 'show', unit, '--property=Id', '--value'], stderr=subprocess.STDOUT).decode('utf-8', 'ignore').strip()
            
            status = subprocess.check_output(['systemctl', 'status', unit, '--no-pager'], stderr=subprocess.STDOUT).decode('utf-8', 'ignore').splitlines()
            logs = subprocess.check_output(['journalctl', '-u', unit, '-n', '50', '--no-pager'], stderr=subprocess.STDOUT).decode('utf-8', 'ignore').splitlines()
            
            header_info = []
            if real_id_raw and real_id_raw != unit:
                header_info = [f"🔗 ALIAS POINTER: {unit} -> {real_id_raw}", "─────────────────────────────────────────────────────────────────", ""]
            
            return header_info + status + ["", "📜 RECENT LOGS:", "━"*(bw-4)] + logs
        except Exception as e: return [f"Error: {e}"]

    content = get_content()
    scroll = 0
    while True:
        win.erase(); win.box()
        try: win.bkgd(' ', curses.color_pair(CP_TEXT))
        except: pass
        try: win.addstr(0, (bw - len(unit) - 12)//2, f" ⚙️  Details: {unit} ", curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except: pass
        for i in range(bh - 4):
            idx = scroll + i
            if idx >= len(content): break
            try: win.addstr(i+2, 2, content[idx][:bw-4], curses.color_pair(CP_TEXT))
            except: pass
        try: win.addstr(bh-2, 2, " [↑↓] Scroll  [r] Refresh  [q/ESC] Back", curses.color_pair(CP_TEXT) | curses.A_DIM)
        except: pass
        win.refresh()
        k = win.getch()
        if k in (27, ord('q')): break
        elif k == curses.KEY_UP and scroll > 0: scroll -= 1
        elif k == curses.KEY_DOWN and scroll < len(content) - (bh - 4): scroll += 1
        elif k == ord('r'): content = get_content(); scroll = 0
    del win

def edit_service_unit(stdscr, unit):
    try:
        path = subprocess.check_output(['systemctl', 'show', '-p', 'FragmentPath', '--value', unit], text=True).strip()
        if not path or not os.path.exists(path):
            show_message(stdscr, f"No unit file found for {unit}")
            return
        editor = os.environ.get('EDITOR', 'nano')
        curses.def_prog_mode(); curses.endwin()
        subprocess.call(['sudo', editor, path])
        # Auto daemon-reload
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
        stdscr.refresh()
    except Exception as e:
        show_message(stdscr, f"Edit error: {e}")

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

def confirm_tree_kill_dialog(stdscr, pid, prog, action_name):
    """Specific dialog for script-managed processes."""
    h, w = stdscr.getmaxyx()
    win_h, win_w = 8, min(70, w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h) // 2, (w - win_w) // 2)
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()
    win.addstr(1, 2, "⚠️ SCRIPT LOOP DETECTED", curses.color_pair(CP_WARN) | curses.A_BOLD)
    win.addstr(2, 2, f"Target: {prog} (PID {pid})", curses.color_pair(CP_TEXT))
    win.addstr(3, 2, "This process is managed by a script. If killed alone,", curses.color_pair(CP_TEXT))
    win.addstr(4, 2, "it will likely RESPAWN immediately.", curses.color_pair(CP_TEXT))
    win.addstr(6, 2, "[t] Kill Entire Tree (Safe)  [9] Only Process  [ESC] Cancel", curses.color_pair(CP_ACCENT) | curses.A_BOLD)
    win.refresh()
    while True:
        k = win.getch()
        if k in (ord('t'), ord('T')): return "tree"
        if k == ord('9'): return "process"
        if k == 27: return "cancel"

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
    Post a non-blocking notification to the 'Status Bar' (bottom-right).
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
    
    # 🚩 Risk level flag from services.json (High/Critical)
    risk_lvl = _risk_level_cache.get(key, None)
    if risk_lvl is None:
        risk_lvl = get_risk_level(prog, port)
        _risk_level_cache[key] = risk_lvl
    risk_flag = " 🚩" if is_high_risk(risk_lvl) else ""
    
    # 🛡️ Security audit warning (Heimdall Sentinel)
    findings = _security_audit_cache.get(key, None)
    if findings is None:
        findings = perform_security_heuristics(pid, port, prog, user)
        _security_audit_cache[key] = findings
    
    sec_warn = ""
    if findings:
        # Show most critical icon first
        findings_sorted = sorted(findings, key=lambda x: {"CRITICAL":0, "HIGH":1, "MEDIUM":2}.get(x['level'], 9))
        best_finding = findings_sorted[0]
        
        # Avoid twin icons: if it's just the root shield and we already have proc_icon='👑', hide it
        if proc_icon == "👑" and best_finding['icon'] == "🛡️" and len(findings) == 1:
            sec_warn = ""
        else:
            sec_warn = f" {best_finding['icon']}"
    
    # 🔓 Vulnerability matching icon (Pulsing potential in future, static for now)
    vulns = get_matched_cves(pid, prog_name=prog)
    vuln_icon = " 🔓" if any(v.get('severity') in ('CRITICAL', 'HIGH') for v in vulns) else ""
    
    # Combine icons after process name
    managed_icon = " 🌲" if is_managed_by_script(str(pid)) else ""
    alert_icons = f"{managed_icon}{risk_flag}{sec_warn}{vuln_icon}"
    
    # Preformat with widths (adjust to table widths)
    # PORT(10) + TRAFFIC(20) + PROTO(8) + USAGE(18) + PROCESS(28) + USER(rest)
    traffic_w = 20
    widths = [10, traffic_w, 8, 18, 28, w - 68 - traffic_w]  # added TRAFFIC column
    
    # Get traffic data for this process
    traffic_info = get_traffic_for_pid(pid)
    traffic_display, traffic_level = format_traffic_bar(traffic_info)
    
    data = [f"{fw_icon} {port}", traffic_display, proto.upper(), usage, f"{status_tag}{proc_icon} {prog}{alert_icons}", f"👤 {user}"]
    
    def pad_visual(text, width):
        """Pad string accounting for double-width characters/emojis."""
        vis_len = 0
        for char in text:
            # Zero-width check first (Marks, Enclosing marks, Format characters like ZWJ/VS)
            if unicodedata.category(char) in ('Mn', 'Me', 'Cf'):
                continue
            # Double-width check
            # Added more sentinel icons to the double-width list
            if (unicodedata.east_asian_width(char) in ('W', 'F') or 
                char in ('⚡', '⛔', '👑', '🧑', '🚩', '⚠️', '⏸', '🔗', '💀', '☢️', '🧪', '🎭', '🌲', '🌐', '🛡️', '📝', '🎨', '⚙️', '🔍', '📂', '🎯', '🔓')):
                vis_len += 2
            else:
                vis_len += 1
        return text + " " * max(0, width - vis_len)

    row_str = ""
    for val, wd in zip(data, widths):
        row_str += pad_visual(val, wd)
    _table_row_cache[key] = (row_str, now)
    return row_str

def draw_table(win, rows, selected, offset, cache, firewall_status, is_active=False):
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    h, w = win.getmaxyx()
    
    # Border with theme color
    b_color = curses.color_pair(CP_ACCENT) | curses.A_BOLD if is_active else curses.color_pair(CP_BORDER)
    try:
        win.attron(b_color)
        win.box()
        win.attroff(b_color)
    except:
        pass

    # Header
    headers = ["🌐 PORT", "📡 TRAFFIC", "PROTO", "📊 USAGE [Mem/CPU]", "  🧠 PROCESS", "   👤 USER"]
    # Calculate widths dynamically
    traffic_w = 20
    widths = [10, traffic_w, 8, 18, 28, max(10, w - 66 - traffic_w)]
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
        
        # 🛡️ SECURITY RISK AUDIT (Part 4.2)
        pid_val = rows[idx][4]
        port_val = rows[idx][0]
        vulns = get_matched_cves(pid_val, prog_name=rows[idx][3])
        is_high_risk = any(v.get('severity') in ('CRITICAL', 'HIGH') for v in vulns)
        
        # Check for BLINK: high traffic + CRIT sentinel finding
        blink = False
        traffic_info = get_traffic_for_pid(pid_val)
        if traffic_info and traffic_info.get('activity', 0) > 1048576: # > 1MB/s
            findings = _security_audit_cache.get(str(port_val), [])
            if findings and any(f['level'] == 'CRITICAL' for f in findings):
                blink = True
        
        if blink and not is_selected:
            attr = attr | curses.A_BLINK
        
        try:
            max_len = max(1, w - 4)
            win.addstr(i+3, 1, pre_row_str[:max_len].ljust(max_len), attr)
            
            # Sub-highlight risky ports (Part 4.2)
            if is_high_risk and not is_selected:
                port_str = pre_row_str[:10]
                win.addstr(i+3, 1, port_str, curses.color_pair(CP_WARN) | curses.A_BOLD)
            
            # 📡 Color the TRAFFIC column separately based on intensity (semantic mapping)
            traffic_display, traffic_intensity = format_traffic_bar(traffic_info)
            traffic_x = 11  # After PORT column (width 10 + 1 border)
            
            if traffic_intensity >= 8:
                t_attr = curses.color_pair(CP_TRAFFIC_BURST) | curses.A_BOLD
            elif traffic_intensity >= 5:
                t_attr = curses.color_pair(CP_TRAFFIC_HIGH)
            elif traffic_intensity >= 2:
                t_attr = curses.color_pair(CP_TRAFFIC_MID)
            elif traffic_intensity > 0:
                t_attr = curses.color_pair(CP_TRAFFIC_LOW)
            else:
                t_attr = curses.color_pair(CP_TEXT) | curses.A_DIM

            if is_selected:
                t_attr = curses.color_pair(CP_ACCENT) | curses.A_REVERSE
            
            try:
                win.addstr(i+3, traffic_x, traffic_display[:traffic_w], t_attr)
            except curses.error:
                pass
            
            # 🔧 REPAIR BORDERS
            win.addch(i+3, 0, curses.ACS_VLINE, b_color)
            win.addch(i+3, w-1, curses.ACS_VLINE, b_color)
        except:
            pass
            
    win.noutrefresh()


def draw_detail(win, wrapped_icon_lines, scroll=0, conn_info=None, is_active=False):
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass

    h, w = win.getmaxyx()
    
    # Border
    b_color = curses.color_pair(CP_ACCENT) | curses.A_BOLD if is_active else curses.color_pair(CP_BORDER)
    try:
        win.attron(b_color)
        win.box()
        win.attroff(b_color)
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
        # ═══════════════════════════════════════════════════════════════
        # Build right-panel (Column 2) content as virtual lines,
        # then render with scroll support.
        # ═══════════════════════════════════════════════════════════════
        rp_lines = []  # list of tuples: (type, ...) 
        T = curses.color_pair(CP_TEXT)
        A = curses.color_pair(CP_ACCENT)
        W = curses.color_pair(CP_WARN)
        H_ATTR = curses.A_BOLD | curses.A_UNDERLINE

        def rp(txt, attr=None):
            rp_lines.append(("TEXT", txt, attr if attr else T))
        def rp_blank():
            rp_lines.append(("TEXT", "", T))

        # ── 🔴 Connection Visibility ──
        rp("🔴 Connection Visibility", H_ATTR)
        rp_blank()
        rp(f"Active Connections : {conn_info['active_connections']}")
        rp(f"Top IP : {conn_info['top_ip']} ({conn_info['top_ip_count']})")
        rp("IPs:")
        for ip, cnt in conn_info["all_ips"].most_common(5):
            rp(f"  {ip} : {cnt}")
        rp_blank()

        # ── 🔥 Process Reality Check ──
        rp("🔥 Process Reality Check (DEBUG)", H_ATTR)
        pid = conn_info.get("pid")
        if pid and pid.isdigit():
            nice_val = get_process_nice(pid)
            nice_text = f"{nice_val} (Normal)" if nice_val == "0" else (f"{nice_val} (High)" if int(nice_val) < 0 else f"{nice_val} (Low)")
            rp(f"Priority (Nice)    : {nice_text}")
            oom_val = get_oom_score_adj(pid)
            oom_text = f"{oom_val} (Neutral)" if oom_val == "0" else (f"{oom_val} (Protected)" if int(oom_val) < 0 else f"{oom_val} (Vulnerable)")
            rp(f"OOM Score Adj      : {oom_text}")
            cmdline = get_full_cmdline(pid)
            rp("📜 Command Line:")
            wrapped_cmd = textwrap.wrap(cmdline, conn_panel_w // 2 - 4)
            for l in wrapped_cmd[:3]:
                rp(f"  {l}")
            rp_blank()

            # Process Tree
            chain = get_process_parent_chain_cached(pid)
            tree = format_process_tree(chain)
            for line in tree:
                rp(line)
            rp_blank()

            # File Descriptor Pressure
            rp("🔥 RESOURCE PRESSURE (OPS)", H_ATTR)
            rp("🔥 4. File Descriptor Pressure")
            rp("📂 File Descriptors :")
            fd_info = get_fd_pressure_cached(pid)
            for key in ["open", "limit", "usage"]:
                rp(f"  {key.capitalize()} : {fd_info[key]}")
            rp(f"  Risk  : {fd_info.get('risk','-')}")
            rp_blank()

            # Runtime Classification
            runtime = detect_runtime_type_cached(pid)
            rp("6️⃣ RUNTIME CLASSIFICATION (SMART)", H_ATTR)
            rp(f"🧩 Runtime :")
            rp(f"  Type : {runtime['type']}")
            rp(f"  Mode : {runtime['mode']}")
            rp(f"  GC   : {runtime['gc']}")
        else:
            rp("<no pid>")

        # ═══════════════════════════════════════════════════════════════
        # RENDER Column 2 (Connection/Process info) with scroll
        # ═══════════════════════════════════════════════════════════════
        visible_rows = h - 4  # rows 3..h-2
        total_rp = len(rp_lines)
        rp_scroll = scroll
        # Column 2 takes left half of the right panel area
        col2_max_w = conn_panel_w // 2

        for vi in range(visible_rows):
            ri = rp_scroll + vi
            if ri >= total_rp:
                break
            draw_y = 3 + vi
            if draw_y >= h - 1:
                break

            entry = rp_lines[ri]
            if entry[0] == "TEXT":
                _, txt, attr = entry
                try:
                    win.addstr(draw_y, conn_panel_x, txt[:col2_max_w], attr)
                except curses.error:
                    pass

        # ═══════════════════════════════════════════════════════════════
        # 🖥️ COLUMN 3: SYSTEM HEALTH (Live) — Independent, top-right
        # Positioned to the right of Connection Visibility, near shortcuts bar
        # ═══════════════════════════════════════════════════════════════
        health_panel_x = conn_panel_x + col2_max_w + 1
        health_avail_w = w - health_panel_x - 1
        
        if health_avail_w >= 20:  # Only render if enough space
            # Draw vertical separator line between Column 2 and Column 3
            sep_x = health_panel_x - 1
            for sy in range(3, h - 1):
                try:
                    win.addch(sy, sep_x, curses.ACS_VLINE, curses.color_pair(CP_BORDER))
                except curses.error:
                    pass
            
            health = get_system_health()
            if health:
                hy = 1  # Same level as "❓ Why It Exists" header
                
                def health_add(y, txt, attr=None, x_offset=0):
                    if attr is None:
                        attr = T
                    if y < h - 1:
                        try:
                            win.addstr(y, health_panel_x + x_offset, txt[:max(0, health_avail_w - x_offset)], attr)
                        except curses.error:
                            pass
                
                def health_bar(y, icon, label, pct, detail=""):
                    if y >= h - 1: return
                    bar_width = min(10, health_avail_w - 30)
                    if bar_width < 4: bar_width = 4
                    pct_clamped = max(0, min(100, int(pct)))
                    filled = int(bar_width * pct_clamped / 100)
                    bar = "█" * filled + "░" * (bar_width - filled)
                    if pct_clamped >= 90:
                        bar_color = W | curses.A_BOLD
                    elif pct_clamped >= 70:
                        bar_color = W
                    else:
                        bar_color = A
                    
                    lbl = f" {icon} {label:<7s}"
                    pct_text = f" {pct_clamped:3d}%"
                    try:
                        win.addstr(y, health_panel_x, lbl, T)
                        cx = health_panel_x + len(lbl)
                        win.addstr(y, cx, bar, bar_color)
                        cx += bar_width
                        win.addstr(y, cx, pct_text, T)
                        if detail:
                            cx += len(pct_text)
                            win.addstr(y, cx, f" {detail}", T | curses.A_DIM)
                    except curses.error:
                        pass
                
                health_add(hy, "🖥️ System Health (Live)", curses.color_pair(CP_HEADER) | curses.A_BOLD)
                hy = 3  # Bars start below the hline separator
                
                health_bar(hy, "🔥", "CPU", health.get('cpu_pct', 0), f"({health.get('cpu_count', '?')} cores)")
                hy += 1
                health_bar(hy, "🧠", "Memory", health.get('mem_pct', 0), f"({health.get('mem_used_gb', '?')}/{health.get('mem_total_gb', '?')}G)")
                hy += 1
                health_bar(hy, "💾", "Swap", health.get('swap_pct', 0), f"({health.get('swap_used_gb', '?')}/{health.get('swap_total_gb', '?')}G)")
                hy += 1
                health_bar(hy, "💿", "Disk /", health.get('disk_pct', 0), f"({health.get('disk_used_gb', '?')}/{health.get('disk_total_gb', '?')}G)")
                hy += 1
                
                bat_pct = health.get('battery_pct')
                if bat_pct is not None:
                    plugged = health.get('battery_plugged', False)
                    bat_icon = "⚡Chg" if plugged else "🔋Dis"
                    health_bar(hy, "🔋", "Battery", bat_pct, bat_icon)
                    hy += 1
                
                hy += 1
                health_add(hy, f" ⏱  Uptime : {health.get('uptime', '-')}")
                hy += 1
                health_add(hy, f" 🌐 IP     : {health.get('local_ip', '-')}")
                hy += 1
                health_add(hy, f" 📊 Load   : {health.get('load_avg', '-')}")
                hy += 1
                health_add(hy, f" 🏠 Host   : {health.get('hostname', '-')}")
                hy += 2
                
                # ── System Info ──
                health_add(hy, "📋 System Info", curses.A_BOLD | curses.A_UNDERLINE)
                hy += 1
                health_add(hy, f" 🐧 OS     : {health.get('os', '-')}")
                hy += 1
                health_add(hy, f" 💻 Host   : {health.get('host', '-')}")
                hy += 1
                health_add(hy, f" 🔩 Kernel : {health.get('kernel', '-')}")
                hy += 1
                health_add(hy, f" 📦 Pkgs   : {health.get('packages', '-')}")
                hy += 1
                
                health_add(hy, f" 🐚 Shell  : {health.get('shell', '-')}")
                hy += 1
                health_add(hy, f" 🖥️  DE     : {health.get('de', '-')} ({health.get('wm_type', '-')})")
                hy += 2
                
                # ── Vulnerability Scan Status (Bottom) ──
                v_title = "🛡️ NVD Check Status"
                if VULN_IS_FETCHING:
                    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][int(time.time() * 10) % 10]
                    v_title += f" [ {spinner} PULLING... ]"
                health_add(hy, v_title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
                hy += 1
                
                last_ts = VULN_CONFIG_DATA.get("last_check_timestamp", 0)
                last_status = VULN_CONFIG_DATA.get("last_check_status", "none")
                if last_ts > 0:
                    dt_str = time.strftime("%H:%M:%S", time.localtime(last_ts))
                    new_str = f" (+{VULN_LAST_NEW_COUNT} new)" if VULN_LAST_NEW_COUNT > 0 else ""
                    health_add(hy, f"  Last: {dt_str} ({last_status}){new_str}", curses.color_pair(CP_ACCENT))
                    hy += 1
                
                now_t = time.time()
                if VULN_NEXT_CHECK_TIME > now_t:
                    diff = int(VULN_NEXT_CHECK_TIME - now_t)
                    m, s = divmod(diff, 60)
                    health_add(hy, f"  Next: {m:02d}:{s:02d}", curses.A_DIM)
                    hy += 1
                
                # 🔥 Actionable Alerts (High Urgency)
                if len(VULN_PENDING) > 0:
                    v_count = len(VULN_PENDING)
                    icon = "🔥"
                    # Pulse ONLY the icon (True blink: appear/disappear)
                    icon_attr = curses.color_pair(CP_WARN) | curses.A_BOLD
                    
                    # Blink at 2Hz for high visibility
                    if int(time.time() * 2) % 2 == 0:
                        health_add(hy, f"  {icon}", icon_attr)
                    
                    health_add(hy, f" {v_count} Active Security Advisories", curses.color_pair(CP_WARN) | curses.A_BOLD, x_offset=4)
                    hy += 1
                
                if SERVICE_SYNC_ERROR:
                    health_add(hy, "  ⚠ Sync Error: services.json", curses.color_pair(CP_WARN))
                    hy += 1
                
                if VULN_STATUS_MSG and "miss" in VULN_STATUS_MSG.lower():
                    health_add(hy, "  ⚠ API Key Missing!", curses.color_pair(CP_WARN) | curses.A_BOLD)
                    hy += 1

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

def draw_open_files(win, pid, prog, files, selected_idx=-1, scroll=0, is_active=False, sort_key='fd', query="", hide_footer=False):
    win.erase()
    try:
        win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    h, w = win.getmaxyx()
    if h < 4 or w < 10: return # Too small
    
    # 1. Processing (Filter)
    display_files = []
    for f in files:
        fd, path, size, mtime, ctime = f
        is_special = any(x in path for x in ["socket:[", "pipe:[", "anon_inode:", "[pidfd]", "dmabuf:"])
        is_binary = False
        if not is_special:
            binary_ext = ('.so', '.bin', '.exe', '.db', '.dat', '.png', '.jpg', '.zip', '.gz', '.tar', '.o', '.pyc', '.pak', '.bdic')
            if path.lower().endswith(binary_ext) or path.startswith("/dev/") or "/leveldb/" in path.lower() or "/gpcache/" in path.lower() or "/gpucache/" in path.lower():
                is_binary = True
        
        f_type = "Special" if is_special else ("Binary" if is_binary else "Text")
        
        if query:
            q = query.lower()
            # Match path OR type name
            if q not in path.lower() and q not in f_type.lower():
                continue
        
        display_files.append((fd, path, size, mtime, ctime, f_type))
    
    # 2. Sorting
    reverse = True if sort_key in ['size', 'mtime', 'ctime'] else False
    if sort_key == 'size': display_files.sort(key=lambda x: x[2], reverse=reverse)
    elif sort_key == 'mtime': display_files.sort(key=lambda x: x[3], reverse=reverse)
    elif sort_key == 'ctime': display_files.sort(key=lambda x: x[4], reverse=reverse)
    elif sort_key == 'type': display_files.sort(key=lambda x: x[5])
    elif sort_key == 'path': display_files.sort(key=lambda x: x[1].lower())
    else: display_files.sort(key=lambda x: int(x[0]) if (len(x) > 0 and str(x[0]).isdigit()) else 9999)

    # Border
    b_color = curses.color_pair(CP_ACCENT) | curses.A_BOLD if is_active else curses.color_pair(CP_BORDER)
    try:
        win.attron(b_color)
        win.box()
        # Top internal border for 📂 line
        win.hline(2, 1, curses.ACS_HLINE, w - 2)
        win.attroff(b_color)
    except:
        win.box()

    # Dynamic Column definitions based on width
    # (Name, SortKey, Width)
    cols = [("FD", "fd", 3)]
    if w >= 40: cols.append(("Size", "size", 6))
    if w >= 55: cols.append(("Type", "type", 7))
    if w >= 75: cols.append(("Created", "ctime", 12))
    if w >= 95: cols.append(("Modified", "mtime", 12))
    cols.append(("Path", "path", 0))
    
    # Header drawing
    try:
        win.addstr(1, 2, f"📂 PID {pid} ({len(display_files)})", curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        col_header_y = 3
        curr_x = 2
        for name, sk, width in cols:
            if width == 0: name_str = f" {name}"
            else: name_str = f" {name:<{width-1}}"
            
            if sort_key == sk:
                indicator = " ↓" if reverse else " ↑"
                name_str = name_str.rstrip() + indicator
                if width > 0: name_str = f"{name_str:<{width}}"
            
            attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD if sort_key == sk else curses.color_pair(CP_HEADER)
            try: win.addstr(col_header_y, curr_x, name_str[:w-curr_x-1], attr)
            except: pass
            
            if width > 0: curr_x += width + 2
            else: break
            
        # USER REQUEST: Use ~ for header line
        try:
            for x in range(1, w-1):
                win.addch(col_header_y + 1, x, '~', curses.color_pair(CP_BORDER))
        except: pass
    except: pass
        
    start_y = 5
    max_rows = h - 7
    for i in range(max_rows):
        idx = scroll + i
        if idx >= len(display_files): break
        
        f_data = display_files[idx]
        fd, path, size, mtime, ctime, f_type = f_data
        icon = "⚙️ " if f_type == "Special" else ("💾" if f_type == "Binary" else "📄")
        
        # Formatting Values
        if size < 1024: s_val = f"{size}B"
        elif size < 1024*1024: s_val = f"{size/1024:.1f}K"
        else: s_val = f"{size/(1024*1024):.1f}M"
        
        def fmt_t(t):
            if t <= 0: return "-"
            try: return datetime.fromtimestamp(t).strftime("%m-%d %H:%M")
            except: return "-"

        try:
            attr = curses.A_REVERSE if (is_active and idx == selected_idx) else curses.color_pair(CP_TEXT)
            if not is_active and idx == selected_idx: attr |= curses.A_DIM 
            if f_type == "Special" and not (is_active and idx == selected_idx): attr |= curses.A_DIM

            curr_x = 2
            # FD (always)
            win.addstr(start_y + i, curr_x, f"{fd:>2}", attr)
            curr_x += 5
            
            # Size
            if w >= 40:
                win.addstr(start_y + i, curr_x, f"{s_val:>6}", attr)
                curr_x += 8
                
            # Type (with Icon)
            if w >= 55:
                win.addstr(start_y + i, curr_x, f"{icon}{f_type:7}", attr)
                curr_x += 10
                
            # Created
            if w >= 75:
                win.addstr(start_y + i, curr_x, f"{fmt_t(ctime):12}", attr)
                curr_x += 14
                
            # Modified
            if w >= 95:
                win.addstr(start_y + i, curr_x, f"{fmt_t(mtime):12}", attr)
                curr_x += 14
            
            # Path
            win.addstr(start_y + i, curr_x, f" {path[:w-curr_x-2]}", attr)
        except: pass
    
    # 3. Footer
    footer_y = h - 2
    if is_active and not hide_footer:
        help_hint = " [S] Sort [F] Filter [t] Tail 🦊 "
        if query:
            filter_msg = f" 🔍 FILTER: {query} (Press F to clear/edit) "
            try: 
                win.attron(curses.color_pair(CP_WARN) | curses.A_BOLD)
                win.addstr(footer_y - 1, (w - len(filter_msg)) // 2, filter_msg)
                win.attroff(curses.color_pair(CP_WARN) | curses.A_BOLD)
            except: pass
        try: win.addstr(footer_y, (w - len(help_hint)) // 2, help_hint, curses.color_pair(CP_ACCENT) | curses.A_BOLD)
        except: pass
    win.noutrefresh()

def draw_help_bar(stdscr, active_pane=0):
    h, w = stdscr.getmaxyx()
    # Fixed width for the vertical help bar
    bar_w = 22
    bar_x = w - bar_w
    
    try:
        bar_win = stdscr.derwin(h - 1, bar_w, 1, bar_x)
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

        # Branding / Title at the top
        title = " 🛡️ HEIMDALL "
        try:
            bar_win.addstr(0, max(1, (bar_w - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except: pass

        # Short labels for vertical fit
        snap = " 🔄 [r Refresh]" if SNAPSHOT_MODE else ""
        vuln_count = len(VULN_PENDING)
        vuln_label = f" 📩 [n Vulns] ({vuln_count})" if vuln_count > 0 else " 📩 [n Vulns]"
        
        shortcuts = [
            (" ⇱⇲ [Ret Maximize]", curses.color_pair(CP_ACCENT)),
            (" ♻️  [Tab Cycles]", curses.color_pair(CP_ACCENT)),
            (" 🔍 [i Inspect]", curses.color_pair(CP_ACCENT)),
            (" 📋 [d Full Inspect]", curses.color_pair(CP_ACCENT)),
            (" 🎨 [c Color]", curses.color_pair(CP_ACCENT)),
            (" 🌐 [o Outbound]", curses.color_pair(CP_ACCENT)),
            (" ⚙️  [p Settings]", curses.color_pair(CP_ACCENT)),
            (" 🔍 [F Filter]", curses.color_pair(CP_ACCENT)),
            (" 🌍 [e Env Vars]", curses.color_pair(CP_ACCENT)),
            (" ⇄  [u Redirect]", curses.color_pair(CP_ACCENT)),
            (" ⛔ [s Stop]", curses.color_pair(CP_ACCENT)),
            (" 🔥 [f Firewall]", curses.color_pair(CP_ACCENT)),
            (" 🛠  [a Actions]", curses.color_pair(CP_ACCENT)),
            (" ⚙️  [z Services]", curses.color_pair(CP_ACCENT)),
            (" ↕️  [+/- Resize]", curses.color_pair(CP_ACCENT)),
            (" 🧭 [↑↓ Select]", curses.color_pair(CP_ACCENT)),
            (f"{vuln_label}", curses.color_pair(CP_WARN) if vuln_count > 0 else curses.color_pair(CP_ACCENT)),
            (" ❌ [q Quit]", curses.color_pair(CP_ACCENT)),
        ]
        if SNAPSHOT_MODE:
            shortcuts.insert(0, (snap, curses.color_pair(CP_ACCENT)))

        y = 2
        for text, attr in shortcuts:
            if y >= h - 1: break
            if text == "": 
                y += 1
                continue
            
            try:
                bar_win.addstr(y, 1, text[:bar_w-2], attr if attr else curses.color_pair(CP_TEXT))
            except: pass
            y += 1

        # 🛡️ SENTINEL ICON LEGEND (Bottom Section)
        # Check if we have enough space for the legend
        if h - y >= 8:
            try:
                # Separator
                y += 1
                bar_win.attron(curses.color_pair(CP_BORDER))
                bar_win.hline(y, 1, curses.ACS_HLINE, bar_w - 2)
                bar_win.attroff(curses.color_pair(CP_BORDER))
                y += 1
                
                # Legend Title
                legend_title = " SENTINEL LEGEND "
                bar_win.addstr(y, max(1, (bar_w - len(legend_title)) // 2), legend_title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
                y += 2  # Leaving a blank line here
                
                legend_items = [
                    (" 🚩 Risk (DB)", CP_WARN),
                    (" ☢️  Backdoor", CP_WARN),
                    (" 🎭 Masquerade", CP_WARN),
                    (" 💀 Deleted", CP_WARN),
                    (" 🧪 Script Ln", CP_ACCENT),
                    (" 📂 /tmp Path", CP_ACCENT),
                    (" 🌐 Public Int", CP_ACCENT),
                    (" 🛡️  Root Priv", CP_ACCENT),
                    (" 🌲 Shell Prnt", CP_ACCENT)
                ]
                
                for item_text, pair_id in legend_items:
                    if y >= h - 1: break
                    bar_win.addstr(y, 1, item_text[:bar_w-2], curses.color_pair(pair_id))
                    y += 1
            except: pass

        bar_win.noutrefresh()
    except curses.error:
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
        ("  🔍  [d] Full Inspection", 'd'),
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
        elif ch == 'd':
            # Generate Full System Dump (also accessible from main screen)
            try:
                win.erase()
                win.refresh()
                del win
            except: pass
            generate_full_system_dump(stdscr, rows, cache)
            stdscr.touchwin()
            curses.doupdate()
            return
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
    Checks cmdline, environment, and library dependencies if possible.
    """
    runtime = {"type": "Native / Binary", "mode": "Direct", "gc": "Manual"}
    if not pid or not pid.isdigit():
        return runtime
    try:
        pid_int = int(pid)
        p = None
        cmdline = ""
        if psutil:
            try:
                p = psutil.Process(pid_int)
                cmdline = " ".join(p.cmdline()).lower()
            except: pass
        
        if not cmdline:
            with open(f"/proc/{pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\0", " ").lower()

        # 1. Environment variables (Internal)
        env = {}
        try:
            with open(f"/proc/{pid}/environ", "r") as f:
                for e in f.read().split("\0"):
                    if "=" in e:
                        k, v = e.split("=", 1)
                        env[k] = v
        except: pass

        # 2. Container Detection
        if os.path.exists(f"/proc/{pid}/cgroup"):
            with open(f"/proc/{pid}/cgroup", "r") as f:
                cg = f.read()
                if "/docker/" in cg or "/kube" in cg:
                    runtime["mode"] = "Containerized"

        # 3. Stack Detection
        # java
        if "java" in cmdline or "jvm" in cmdline:
            runtime["type"] = "Java"
            runtime["gc"] = "JVM Management"
            if "spring-boot" in cmdline or "springboot" in cmdline:
                runtime["mode"] = "Spring Boot / Microservice"
            else:
                runtime["mode"] = "Server" if "-jar" in cmdline else "Standard App"
        
        # node
        elif "node" in cmdline:
            runtime["type"] = "Node.js"
            runtime["gc"] = "V8 Scavenger/Mark-Sweep"
            runtime["mode"] = "Event-driven Server"
            if "electron" in cmdline:
                runtime["type"] = "Electron (Node + Chromium)"
                runtime["mode"] = "Desktop App"

        # python
        elif "python" in cmdline:
            runtime["type"] = "Python"
            runtime["gc"] = "Ref Counting + Cycle GC"
            runtime["mode"] = "Interpreted Script"
            if "gunicorn" in cmdline or "uvicorn" in cmdline or "flask" in cmdline:
                runtime["mode"] = "WSGI/ASGI Web Server"

        # go
        elif "go-" in cmdline or (p and "go" in p.name().lower()):
            runtime["type"] = "Go (Golang)"
            runtime["gc"] = "Tcmalloc-based / Concurrent"
            runtime["mode"] = "Statically Linked Binary"

        # php
        elif "php" in cmdline:
            runtime["type"] = "PHP"
            runtime["mode"] = "FastCGI / CLI"

        # nginx
        elif "nginx" in cmdline:
            runtime["type"] = "Nginx"
            runtime["mode"] = "Reverse Proxy / Web Server"

    except Exception as e:
        debug_log(f"DETECT_RUNTIME ERROR (PID {pid}): {e}")

    _runtime_cache[str(pid)] = runtime
    return runtime


def generate_full_system_dump(stdscr, rows, cache):
    """
    Generate a comprehensive inspection report for ALL active ports/processes.
    Saves the report to a timestamped file.
    Includes a progress splash screen to avoid UI blocking.
    """
    # Ask user preference first
    include_services = confirm_dialog(stdscr, "Include System Services & Unit Files in Inspection?")
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"heimdall_dump_{timestamp}.txt"
    
    h, w = stdscr.getmaxyx()
    bh = 16
    bw = min(70, w - 4)
    win_y, win_x = (h - bh) // 2, (w - bw) // 2
    
    # Background persistence
    try:
        stdscr.touchwin()
        stdscr.noutrefresh()
    except: pass
    
    try:
        win = curses.newwin(bh, bw, win_y, win_x)
        try: win.bkgd(' ', curses.color_pair(CP_TEXT))
        except: pass
        win.box()
    except:
        win = None
        show_message(stdscr, "⏳ Generating Inspection... Please wait.")
        curses.doupdate()

    report_lines = []
    def add_line(text=""):
        report_lines.append(text)

    try:
        add_line("╔" + "═" * 78 + "╗")
        add_line("║                 HEIMDALL FULL SYSTEM INSPECTION REPORT                       ║")
        add_line(f"║ Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<55}  ║")
        add_line("╚" + "═" * 78 + "╝\n")

        # 1. NVD Vulnerability Summary (Global)
        add_line("🔓  NVD VULNERABILITY EXECUTIVE SUMMARY")
        add_line("=" * 48)
        with VULN_LOCK:
            if not VULN_PENDING:
                add_line("  ✅ No high-risk vulnerabilities detected (Score > 7.0).")
            else:
                add_line(f"  ❗ {len(VULN_PENDING)} RISKY VULNERABILITIES DETECTED:")
                for v in sorted(VULN_PENDING, key=lambda x: x.get('score', 0), reverse=True):
                    kev = " [KEV]" if v.get('is_kev') else ""
                    add_line(f"     - {v['cve_id']} [{v['severity']} / {float(v.get('score',0.0)):.1f}]{kev}: {v['pkg']} v{v.get('version','?')}")
        add_line("-" * 48)
        add_line()

        # 2. Sentinel Behavioral Summary
        add_line("🛡️  HEIMDALL SENTINEL: BEHAVIORAL AUDIT SUMMARY")
        add_line("=" * 48)
        add_line("Legend: ☢️ Backdoor | 🧪 Interpreter | 🎭 Masquerade | 💀 Deleted")
        add_line("-" * 48)
        
        all_findings = []
        for row in rows:
            p, _, _, prog_name, p_id = row
            p_user = get_process_user(p_id) if (p_id and p_id.isdigit()) else "-"
            findings = perform_security_heuristics(p_id, p, prog_name, p_user)
            if findings:
                for find in findings:
                    all_findings.append((p, prog_name, find))
        
        if not all_findings:
            add_line("  ✅ No high-priority security threats detected across active services.")
        else:
            threats = [x for x in all_findings if x[2]['level'] in ['HIGH', 'CRITICAL']]
            if threats:
                crit = [x for x in threats if x[2]['level'] == 'CRITICAL']
                if crit:
                    add_line(f"  🛑 {len(crit)} CRITICAL THREATS FOUND:")
                    for p, pr, fi in crit: add_line(f"     - [Port {p}] {pr}: {fi['msg']}")
                hi = [x for x in threats if x[2]['level'] == 'HIGH']
                if hi:
                    add_line(f"  ☢️  {len(hi)} HIGH RISKS DETECTED:")
                    for p, pr, fi in hi: add_line(f"     - [Port {p}] {pr}: {fi['msg']}")
            else:
                add_line("  ✅ No critical threats found (Warnings exist in details).")
        
        add_line()
        add_line(f"Total Active Ports/Services: {len(rows)}")
        add_line("=" * 80 + "\n")

        total = len(rows)
        start_time = time.time()

        for idx, row in enumerate(rows):
            port, proto, pidprog, prog, pid = row
            
            # ... UPDATE UI ...
            if win:
                try:
                    win.erase()
                    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
                    except: pass
                    win.box()
                    
                    # Title
                    title = "🔍 FULL SYSTEM INSPECTION"
                    win.addstr(2, max(1, (bw - len(title))//2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
                    
                    # Service Info
                    info = f"Archiving: {prog} ({port}/{proto})"
                    win.addstr(5, 4, info[:bw-6], curses.color_pair(CP_ACCENT))
                    
                    # Progress Bar
                    pct = int(((idx + 1) / total) * 100)
                    pct_str = f" {pct}%"
                    avail_w = bw - 10 
                    bar_len = avail_w - len(pct_str)
                    
                    if bar_len > 0:
                        filled = int(bar_len * (idx + 1) / total)
                        bar = "█" * filled + "░" * (bar_len - filled)
                        win.addstr(8, 5, f"[{bar}]{pct_str}", curses.color_pair(CP_TEXT))
                    
                    # Stats
                    elapsed = time.time() - start_time
                    win.addstr(10, 5, f"Processed: {idx + 1}/{total} services", curses.A_DIM)
                    win.addstr(11, 5, f"Time: {elapsed:.1f}s", curses.A_DIM)
                    
                    try: stdscr.noutrefresh()
                    except: pass

                    win.noutrefresh()
                    curses.doupdate()
                except:
                    pass
            
            # --- COLLECT LOGIC ---
            user = cache.get(port, {}).get("user") or get_process_user(pid)
            
            add_line(f"🔹 [{idx+1}/{len(rows)}] SERVICE: {prog} (PID: {pid})")
            add_line(f"   Port: {port}/{proto} | User: {user}")
                
                # ── Service Intelligence (Heimdall & Package) ──
            info, _ = resolve_service_knowledge(prog, port, pid=pid)
            
            add_line(f"   Identity: {info.get('name', prog)}")
            add_line(f"   Scope: {info.get('description', 'No description available.')}")
            
            if info.get('package'):
                add_line(f"   Package: {info.get('package', '-')}")
                add_line(f"   Version: {info.get('version', '-')}")
            
            add_line(f"   Risk: {info.get('risk', 'Unknown')}")
            add_line(f"   Recommendation: {info.get('recommendation', '-')}\n")

            # ── WITR Deep Analysis ──
            add_line("   🔍 Analysis:")
            try:
                w_lines = get_witr_output(port)
                if not w_lines or w_lines == ["No data"]:
                    # If witr failed, show our fallback content in text form
                    for l in _generate_service_fallback(prog, port, 80):
                        add_line(f"     {l}")
                else:
                    for l in w_lines:
                         if l.strip():
                             add_line(f"     {l}")
            except:
                add_line("     (Analysis unavailable)")
            add_line()

            # ── Process Reality Check ──
            if pid and pid.isdigit():
                add_line("   🔥 Process Reality Check:")
                findings = perform_security_heuristics(pid, port, prog, user)
                
                # ── Vulnerability Audit (High Confidence PID Matching) ──
                cves = get_matched_cves(pid)
                if cves:
                    add_line(f"     🔓 VULNERABILITY AUDIT: {len(cves)} HIGH-RISK MATCHES")
                    for cve in sorted(cves, key=lambda x: x.get('score', 0), reverse=True):
                        kev = " (KNOWN EXPLOITED)" if cve.get('is_kev') else ""
                        add_line(f"       - {cve['cve_id']} [{cve['severity']} / {float(cve.get('score',0.0)):.1f}]{kev}")
                        add_line(f"         Impact: {cve['desc'][:120]}...")
                
                add_line("     🛡️ SENTINEL AUDIT:")
                for find in findings:
                    add_line(f"       [{find['level']}] {find['msg']}")
                cmd = get_full_cmdline(pid)
                add_line(f"     Command: {cmd}")
                
                chain = get_process_parent_chain(pid)
                tree = format_process_tree(chain)
                if tree:
                    add_line("     Process Tree:")
                    for l in tree:
                        add_line(f"       {l}")
                
                runtime = detect_runtime_type_cached(pid)
                if runtime.get("type") != "Native":
                     add_line(f"     Runtime: {runtime['type']} ({runtime['mode']})")

                fd_info = get_fd_pressure_cached(pid)
                add_line(f"     File Descriptors: {fd_info['open']} / {fd_info['limit']} ({fd_info['usage']})")
                add_line(f"     OOM Score: {get_oom_score_adj(pid)}\n")
            
            # ── Activity History ──
            history = get_service_activity_history(prog, pid, port, max_entries=100)
            add_line(f"   📜 Recent Activity ({len(history)} events):")
            if history:
                for ts, msg, _ in history:
                    add_line(f"     [{ts}] {msg}")
            else:
                add_line("     (No logs found)")
            
            # ── Connection Stats ──
            conn = get_connections_info(port)
            add_line(f"\n   🔴 Network Visibility:")
            add_line(f"     Active Connections: {conn['active_connections']}")
            if conn['top_ip'] != "-":
                 add_line(f"     Top IP: {conn['top_ip']} ({conn['top_ip_count']})")

            # ── Open Files ──
            files = get_open_files_cached(pid)
            add_line(f"\n   📂 Open Files ({len(files)}):")
            for i, file_entry in enumerate(files):
                add_line(f"     - {file_entry}")
            
            add_line("\n" + "=" * 80 + "\n")

        if include_services:
            add_line("\n" + "═" * 80)
            add_line("      ⚙️  SYSTEM SERVICES & UNIT FILES ANALYSIS (With Identity Info)")
            add_line("═" * 80 + "\n")
            
            add_line("── ACTIVE SYSTEMD UNITS ──")
            add_line(f"{'UNIT':<50} {'IDENTITY':<30} {'ACTIVE':<12} {'SUB':<12} {'DESCRIPTION'}")
            add_line("-" * 140)
            units_list, _ = get_systemd_services()
            for u_item in units_list:
                info_itm = SYSTEM_SERVICES_DB.get(u_item['unit'], {})
                id_itm = info_itm.get('name', '-')
                add_line(f"{u_item['unit']:<50} {id_itm:<30} {u_item['active']:<12} {u_item['sub']:<12} {u_item['description']}")
            
            add_line("\n\n── INSTALLED UNIT FILES ──")
            add_line(f"{'UNIT FILE':<50} {'IDENTITY':<30} {'TYPE':<15} {'STATE':<12} {'PRESET'}")
            add_line("-" * 140)
            ufiles = get_systemd_unit_files()
            for uf in ufiles:
                info_uf = SYSTEM_SERVICES_DB.get(uf['unit'], {})
                id_uf = info_uf.get('name', '-')
                stype_uf = info_uf.get('type', '-')
                add_line(f"{uf['unit']:<50} {id_uf:<30} {stype_uf:<15} {uf['active']:<12} {uf['sub']}")
            
            add_line("\n" + "═" * 80 + "\n")

        # Cleanup splash
        if win:
            win.erase(); win.refresh(); del win
        
        # --- SHOW PREVIEW MODAL ---
        if show_full_inspection_preview(stdscr, report_lines):
            try:
                with open(filename, "w", encoding="utf-8") as fsav:
                    for rl in report_lines:
                        fsav.write(rl + "\n")
                show_message(stdscr, f"✅ Full inspection saved to: {filename}")
            except Exception as e_sav:
                 show_message(stdscr, f"❌ Save failed: {str(e_sav)}")
        else:
            show_message(stdscr, "Inspection closed without saving.")
        
        time.sleep(1.5)

    except Exception as e:
        show_message(stdscr, f"❌ Inspection failed: {str(e)}")
        time.sleep(2)
# --------------------------------------------------
# User Details Overlay
# --------------------------------------------------
_user_info_cache = {}  # username -> (data_dict, timestamp)
_user_info_lock = threading.Lock()
USER_INFO_TTL = 30.0

def _fetch_user_info_worker(username):
    try:
        data = {"_loading": False, "username": username}
        
        # 1. Properties
        try:
            import pwd
            pw = pwd.getpwnam(username)
            data["uid"] = str(pw.pw_uid)
            data["home"] = pw.pw_dir
            data["shell"] = pw.pw_shell
        except:
            data["uid"] = "?"
            data["home"] = "?"
            data["shell"] = "?"

        # 2. Last Login
        try:
            last_out = subprocess.check_output(["last", "-n", "1", username], text=True, stderr=subprocess.DEVNULL)
            last_line = last_out.splitlines()[0] if last_out.strip() else ""
            if last_line and not last_line.startswith("wtmp begins"):
                parts = last_line.split()
                if len(parts) >= 4:
                    data["last_login"] = " ".join(parts[3:])
                else:
                    data["last_login"] = last_line
            else:
                data["last_login"] = "No recent login"
        except:
            data["last_login"] = "Unknown"

        # 3. CPU sum
        try:
            ps_out = subprocess.check_output(["ps", "-u", username, "-o", "%cpu="], text=True, stderr=subprocess.DEVNULL)
            cpu_pct = sum(float(l.strip()) for l in ps_out.splitlines() if l.strip())
            core_count = psutil.cpu_count() or 1
            data["cpu"] = cpu_pct / core_count
            data["cores"] = core_count
        except:
            data["cpu"] = 0.0
            data["cores"] = 1

        # 4. Recent commands (try bash_history or journal)
        cmds = []
        try:
            hist_file = os.path.join(data.get("home", ""), ".bash_history")
            if os.path.exists(hist_file) and os.access(hist_file, os.R_OK):
                with open(hist_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                cmds = [l.strip() for l in lines if l.strip()]
            else:
                if data["uid"] != "?":
                    j_out = subprocess.check_output(
                        ["journalctl", f"_UID={data['uid']}", "-n", "10", "--no-pager", "-o", "cat"],
                        text=True, stderr=subprocess.DEVNULL
                    )
                    cmds = [l.strip() for l in j_out.splitlines() if l.strip()]
        except:
            pass
        
        data["commands"] = cmds[-10:] if cmds else []

        with _user_info_lock:
            _user_info_cache[username] = (data, time.time())
    except Exception as e:
        debug_log(f"USER_INFO_ERROR: {e}")
        with _user_info_lock:
            _user_info_cache[username] = ({"_loading": False, "error": str(e)}, time.time())

def get_user_info_cached(username):
    if not username or username == "-":
        return None
    now = time.time()
    with _user_info_lock:
        entry = _user_info_cache.get(username)
        if entry:
            data, ts = entry
            if now - ts < USER_INFO_TTL:
                return data
            if data.get("_loading"):
                return data
        
        _user_info_cache[username] = ({"_loading": True, "username": username}, now)
    
    threading.Thread(target=_fetch_user_info_worker, args=(username,), daemon=True).start()
    return {"_loading": True, "username": username}

def draw_user_subpane(win, user_data, is_active=False):
    win.erase()
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    h, w = win.getmaxyx()
    if h < 2 or w < 10: return

    b_color = curses.color_pair(CP_ACCENT) | curses.A_BOLD if is_active else curses.color_pair(CP_BORDER)
    try:
        win.attron(b_color)
        win.box()
        win.attroff(b_color)
    except: pass

    is_root = user_data.get("username", "") == "root"
    title_icon = "🔴" if is_root else "👤"
    title_attr = curses.color_pair(CP_WARN) | curses.A_BOLD if is_root else curses.color_pair(CP_HEADER) | curses.A_BOLD
    title = f" User Profile: {title_icon} {user_data.get('username', '?')} "
    try: win.addstr(0, max(1, (w - len(title)) // 2), title[:w-2], title_attr)
    except: pass

    if user_data.get("_loading"):
        try: win.addstr(h//2, max(1, (w - 10)//2), "Loading...", curses.color_pair(CP_ACCENT) | curses.A_BLINK)
        except: pass
        win.noutrefresh()
        return

    pad = 2
    y = 1
    
    # Header info
    info_str = f"UID: {user_data.get('uid', '?')} | {user_data.get('home', '?')}"
    shell_str = f"🐚 {os.path.basename(user_data.get('shell', ''))}"
    try: 
        win.addstr(y, pad, info_str[:max(1, w-pad-len(shell_str)-2)], curses.color_pair(CP_TEXT) | curses.A_BOLD)
        win.addstr(y, max(pad, w-len(shell_str)-pad), shell_str, curses.color_pair(CP_ACCENT))
    except: pass
    y += 1
    
    try: win.addstr(y, pad, f"Last: {user_data.get('last_login', '?')[:w-pad-10]}", curses.color_pair(CP_TEXT) | curses.A_DIM)
    except: pass
    y += 1
    
    # CPU
    cpu = user_data.get('cpu', 0.0)
    cores = user_data.get('cores', 1)
    cpu_str = f"🔥 Total CPU: {cpu:.1f}% ({cores} cores)"
    cpu_attr = curses.color_pair(CP_WARN) | curses.A_BLINK if cpu > 50.0 else curses.color_pair(CP_TEXT)
    try: win.addstr(y, pad, cpu_str[:w-pad-1], cpu_attr)
    except: pass
    y += 1
    
    try: win.hline(y, 1, curses.ACS_HLINE, w-2, curses.color_pair(CP_BORDER))
    except: pass
    y += 1
    
    try: win.addstr(y, pad, "⌨️  Recent Commands:", curses.color_pair(CP_HEADER))
    except: pass
    y += 1

    cmds = user_data.get("commands", [])
    if not cmds:
        try: win.addstr(y, pad, "No history available", curses.color_pair(CP_TEXT) | curses.A_DIM)
        except: pass
    else:
        for cmd in cmds:
            if y >= h - 1: break
            try: win.addstr(y, pad, f"> {cmd}"[:w-pad-1], curses.color_pair(CP_TEXT))
            except: pass
            y += 1

    win.noutrefresh()


# --------------------------------------------------
# Main Loop
# --------------------------------------------------
def get_filter_status_str(filters):
    active = []
    if filters.get("port"): active.append(f"Port:{filters['port']}")
    if filters.get("pid"): active.append(f"PID:{filters['pid']}")
    if filters.get("user"): active.append(f"User:{filters['user']}")
    return " | ".join(active) if active else ""

def matches_filter(row, filters, cache):
    port, proto, pidprog, prog, pid = row

    f_port = filters.get("port") if isinstance(filters, dict) else (filters.port if hasattr(filters, "port") else None)
    f_pid = filters.get("pid") if isinstance(filters, dict) else (filters.pid if hasattr(filters, "pid") else None)
    f_user = filters.get("user") if isinstance(filters, dict) else (filters.user if hasattr(filters, "user") else None)

    if f_port and str(port) != str(f_port): return False
    if f_pid and str(pid) != str(f_pid): return False
    if f_user:
         user = cache.get(port, {}).get("user") or get_process_user(pid)
         if port not in cache: cache[port] = {}
         cache[port]["user"] = user
         if str(user) != str(f_user): return False
    return True

def draw_filter_modal(stdscr, filters):
    h, w = stdscr.getmaxyx()
    pad = 2
    bw = min(w - 4, 60)
    bh = 12
    y = (h - bh) // 2
    x = (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.erase()
    try: win.bkgd(' ', curses.color_pair(CP_TEXT))
    except: pass
    win.box()

    title = " 🔍 System Filter "
    try: win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    except: pass

    fields = [
        ("p", "Port", "port"),
        ("i", "PID", "pid"),
        ("u", "User", "user")
    ]

    editing = None
    input_buf = ""

    while True:
        win.erase()
        win.box()
        try: win.addstr(0, (bw - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except: pass

        for idx, (key, label, field) in enumerate(fields):
            val = filters.get(field) or "(all)"
            attr = curses.A_REVERSE | curses.A_BOLD if editing == field else curses.A_NORMAL
            color = curses.color_pair(CP_ACCENT) if editing == field else curses.color_pair(CP_TEXT)

            try:
                win.addstr(2 + idx*2, pad, f"[{key}] {label}: ", curses.color_pair(CP_TEXT))
                display_val = input_buf if editing == field else str(val)
                max_disp = bw - pad*2 - 15
                display_val = display_val[-max_disp:]
                win.addstr(2 + idx*2, pad + 12, display_val, color | attr)
            except: pass

        try:
            win.addstr(bh - 3, pad, "[c] Clear Filters  [ESC] Apply", curses.color_pair(CP_TEXT) | curses.A_DIM)
            if editing:
                win.addstr(bh - 2, pad, "Typing... Press ENTER to save", curses.color_pair(CP_WARN) | curses.A_BOLD)
        except: pass

        win.refresh()
        k = win.getch()

        if editing:
            if k == 27: # ESC cancels edit
                editing = None
                input_buf = ""
            elif k in (10, 13, curses.KEY_ENTER):
                filters[editing] = input_buf if input_buf else None
                editing = None
                input_buf = ""
            elif k in (8, 127, curses.KEY_BACKSPACE, 263):
                input_buf = input_buf[:-1]
            elif 32 <= k <= 126:
                input_buf += chr(k)
        else:
            if k == 27: break
            try: ch = chr(k).lower()
            except: ch = None
            if ch == 'p':
                editing = "port"
                input_buf = str(filters.get("port") or "")
            elif ch == 'i':
                editing = "pid"
                input_buf = str(filters.get("pid") or "")
            elif ch == 'u':
                editing = "user"
                input_buf = str(filters.get("user") or "")
            elif ch == 'c':
                filters["port"] = None
                filters["pid"] = None
                filters["user"] = None
                show_message(stdscr, "Filters cleared.")
                break

    del win
    return True

# --------------------------------------------------
# 🔌 Plugin System
# --------------------------------------------------
LOADED_PLUGINS = []

def load_plugins(heimdall_instance=None):
    global LOADED_PLUGINS
    LOADED_PLUGINS = []
    plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
    if not os.path.exists(plugins_dir):
        return
    for filename in os.listdir(plugins_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            mod_name = f"heimdall.plugins.{filename[:-3]}"
            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, "Plugin"):
                    plugin_instance = mod.Plugin(heimdall_instance)
                    
                    import shutil
                    tc = getattr(plugin_instance, "tool_command", None)
                    if tc:
                        cmd_path = shutil.which(tc)
                        if not cmd_path:
                            sudo_user = os.environ.get('SUDO_USER')
                            if sudo_user:
                                local_bin = os.path.expanduser(f"~{sudo_user}/.local/bin/{tc}")
                                if os.path.exists(local_bin):
                                    cmd_path = local_bin
                        if not cmd_path:
                            debug_log(f"Plugin {filename} skipped: tool '{tc}' not installed.")
                            continue
                            
                    LOADED_PLUGINS.append(plugin_instance)
            except Exception as e:
                debug_log(f"Failed to load plugin {filename}: {e}")

class HeimdallDummyInstance:
    # Small dummy instance if plugins need simple callbacks, could be enriched later.
    pass

def draw_outbound_modal(stdscr):
    global OUTBOUND_DATA, OUTBOUND_LOCK
    h, w = stdscr.getmaxyx()
    bw = min(w - 4, 140)
    bh = min(h - 4, 35)
    y = (h - bh) // 2
    x = (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    win.keypad(True)
    win.timeout(500) # Fast refresh for activity timers

    filters = {"proc": "", "remote": "", "min_sent": 0, "min_dur": 0, "risk": "", "user": ""}
    sort_key = "last_active"
    sort_desc = False # For last_active, ascending means "most recent" in my poller (0s ago < 10s ago)
    
    selected = 0
    offset = 0
    paused = False
    current_rows = []
    
    def get_filtered_data():
        with OUTBOUND_LOCK:
            data = list(OUTBOUND_DATA)
        
        filtered = []
        for d in data:
            if filters["proc"] and filters["proc"].lower() not in d["prog"].lower(): continue
            if filters["remote"] and filters["remote"].lower() not in d["remote_ip"].lower() and filters["remote"] not in str(d["remote_port"]): continue
            if filters["min_sent"] and d["sent"] < filters["min_sent"] * 1024: continue
            if filters["min_dur"] and d["duration"] < filters["min_dur"] * 60: continue
            if filters["risk"] and filters["risk"].upper() not in d["risk"]: continue
            # User filter would need process lookup if not in d
            filtered.append(d)
        
        # Apply sorting
        if sort_key == "sent": filtered.sort(key=lambda x: x["sent"], reverse=True)
        elif sort_key == "duration": filtered.sort(key=lambda x: x["duration"], reverse=True)
        elif sort_key == "prog": filtered.sort(key=lambda x: x["prog"].lower())
        elif sort_key == "last_active": filtered.sort(key=lambda x: x["last_active"])
        else: filtered.sort(key=lambda x: x["last_active"])
        
        return filtered

    while True:
        if not paused:
            current_rows = get_filtered_data()
        
        rows = current_rows
        bh_actual, bw_actual = win.getmaxyx()
        visible_rows = bh_actual - 6
        
        if selected >= len(rows): selected = max(0, len(rows) - 1)
        if selected < offset: offset = selected
        if selected >= offset + visible_rows: offset = selected - visible_rows + 1

        win.erase()
        win.box()
        try:
            title = f" 🌐 Outbound Connections (Total: {len(rows)}) "
            win.addstr(0, (bw_actual - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
            
            # Header
            header = f"{'Process+PID':<25} {'Remote IP:Port':<30} {'Proto':<6} {'Sent':<10} {'Recv':<10} {'Dur':<8} {'Active':<10} {'Risk':<10}"
            win.addstr(2, 2, header[:bw_actual-4], curses.color_pair(CP_ACCENT) | curses.A_BOLD | curses.A_UNDERLINE)
        except: pass

        for i in range(visible_rows):
            idx = i + offset
            if idx >= len(rows): break
            d = rows[idx]
            attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
            
            risk_color = CP_TEXT
            if d["risk"] == "CRITICAL": risk_color = CP_WARN
            elif d["risk"] == "HIGH": risk_color = CP_WARN
            
            line_proc = f"{d['prog'][:18]+'('+d['pid']+')':<25}"
            
            line = f"{line_proc} {d['remote_ip']+':'+str(d['remote_port']):<30} {d['proto']:<6} {format_bytes(d['sent']):<10} {format_bytes(d['recv']):<10} {format_duration(d['duration']):<8} {d['last_active']}s ago"
            try:
                l_attr = attr
                if d.get("is_ghost"): l_attr |= curses.A_DIM
                
                win.addstr(3 + i, 2, line, curses.color_pair(CP_TEXT) | l_attr)
                
                # Risk column with CLOSED status
                if d.get("is_ghost"):
                    win.addstr(3 + i, 108, f"⏹️  CLOSED", curses.color_pair(CP_TEXT) | curses.A_DIM | attr)
                else:
                    icon = "🛡️ " if d["risk"] == "CLEAN" else "💀 "
                    win.addstr(3 + i, 108, f"{icon}{d['risk']:<8}", curses.color_pair(risk_color) | l_attr)
            except: pass

        # Footer
        try:
            p_status = "[FROZEN]" if paused else ""
            footer = f" [f] Filter  [Space] {p_status or 'Freeze'}  [r] Refresh  [t] Tail Traffic  [S] HTTP Summary  [ESC] Close"
            win.addstr(bh_actual - 2, 2, footer[:bw_actual-4], curses.color_pair(CP_ACCENT) | curses.A_DIM)
        except: pass

        win.refresh()
        k = win.getch()
        if k == -1: continue # refresh timeout
        if k == ord(' '): 
            paused = not paused
            continue
        if k == 27: break
        
        if k == curses.KEY_UP:
            if selected > 0: selected -= 1
        elif k == curses.KEY_DOWN:
            if selected < len(rows) - 1: selected += 1
        elif k == ord('r'):
            OUTBOUND_QUEUE.put("refresh") # optional trigger
        elif k == ord('f'):
            # Simple Filter Dialog
            filters["proc"] = get_input_modal(stdscr, "Filter Process Name:", filters["proc"])
            filters["remote"] = get_input_modal(stdscr, "Filter Remote IP/Port:", filters["remote"])
        elif k == ord('S') and rows: # Capital S for Summary
            d = rows[selected]
            draw_http_summary_modal(stdscr, d)
        elif k == ord('s'):
            # Sort choice
            sort_opts = [("l", "Last Activity", "last_active"), ("s", "Sent Bytes", "sent"), ("d", "Duration", "duration"), ("p", "Process Name", "prog")]
            msg = "Sort by: " + " ".join([f"[{k}] {l}" for k, l, f in sort_opts])
            show_message(stdscr, msg)
            sk = stdscr.getch()
            for key_char, label, field in sort_opts:
                if sk == ord(key_char):
                    sort_key = field
                    break
        elif k == ord('k') and rows:
            d = rows[selected]
            if confirm_dialog(stdscr, f"Kill connection to {d['remote_ip']}?"):
                if kill_connection(d['remote_ip'], d['remote_port']):
                    show_message(stdscr, "Connection killed (ss -K)")
                else:
                    show_message(stdscr, "Failed to kill connection (Check sudo)")
        elif k == ord('K') and rows:
            d = rows[selected]
            if confirm_dialog(stdscr, f"Kill process {d['prog']} (PID {d['pid']})?"):
                stop_process_or_service(d['pid'], d['prog'], stdscr)
        elif k in [ord('s'), ord('r')] and rows:
            # Re-use existing suspend/resume if possible, or direct
            d = rows[selected]
            action = "STOP" if k == ord('s') else "CONT"
            try: subprocess.run(["sudo", "kill", f"-{action}", d["pid"]])
            except: pass
        elif k == ord('b') and rows:
            d = rows[selected]
            if confirm_dialog(stdscr, f"Block IP {d['remote_ip']} via iptables?"):
                subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", d["remote_ip"], "-j", "DROP"])
                show_message(stdscr, f"IP {d['remote_ip']} blocked.")
        elif k == ord('B') and rows:
            d = rows[selected]
            if confirm_dialog(stdscr, f"Block Remote Port {d['remote_port']}?"):
                subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-p", d["proto"].lower(), "--dport", str(d["remote_port"]), "-j", "DROP"])
                show_message(stdscr, f"Port {d['remote_port']} blocked.")
        elif k == ord('e'):
            export_outbound_data(rows)
            show_message(stdscr, "Data exported to ~/heimdall_outbound_export.json")
        elif k == ord('t') and rows:
            d = rows[selected]
            draw_traffic_tail_window(stdscr, d)
        elif k == ord('f') and rows:
            d = rows[selected]
            draw_file_tail_window(stdscr, d["pid"], d["prog"])
        elif k == 10 or k == curses.KEY_ENTER:
            if rows:
                d = rows[selected]
                user = get_process_user(d["pid"])
                show_inspect_modal(stdscr, "-", d["prog"], d["pid"], user)

    del win
    return

def format_bytes(b):
    if b < 1024: return f"{b} B"
    if b < 1024*1024: return f"{b/1024:.1f} KB"
    return f"{b/(1024*1024):.1f} MB"

def format_duration(s):
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m {s%60}s"
    return f"{s//3600}h {(s%3600)//60}m"

def get_input_modal(stdscr, prompt, current=""):
    h, w = stdscr.getmaxyx()
    win_h, win_w = 6, 60
    win = curses.newwin(win_h, win_w, (h-win_h)//2, (w-win_w)//2)
    win.box()
    win.keypad(True)
    curses.curs_set(1)
    
    buf = list(current)
    pos = len(buf)
    
    while True:
        win.erase()
        win.box()
        win.addstr(1, 2, f" {prompt} ", curses.color_pair(CP_HEADER) | curses.A_BOLD)
        win.addstr(2, 2, " [ESC] Cancel | [Enter] Confirm ", curses.A_DIM)
        
        # Draw input field
        win.addstr(3, 2, "> ")
        field_w = win_w - 6
        display_str = "".join(buf)
        win.addstr(3, 4, display_str[:field_w])
        
        win.move(3, 4 + pos)
        win.refresh()
        
        k = win.getch()
        if k == 27: # ESC
            curses.curs_set(0)
            return None
        elif k in (10, curses.KEY_ENTER):
            curses.curs_set(0)
            return "".join(buf)
        elif k in (curses.KEY_BACKSPACE, 127, 8):
            if pos > 0:
                buf.pop(pos-1)
                pos -= 1
        elif k == curses.KEY_LEFT:
            if pos > 0: pos -= 1
        elif k == curses.KEY_RIGHT:
            if pos < len(buf): pos += 1
        elif k == curses.KEY_DC: # Delete
            if pos < len(buf): buf.pop(pos)
        elif 32 <= k <= 126: # Printable
            if len(buf) < field_w:
                buf.insert(pos, chr(k))
                pos += 1
    
    curses.curs_set(0)
    return "".join(buf)

def kill_connection(remote_ip, remote_port):
    try:
        subprocess.run(["sudo", "ss", "-K", "dst", remote_ip, "dport", str(remote_port)], check=True, capture_output=True)
        return True
    except: return False

def export_outbound_data(rows):
    path = os.path.expanduser("~/heimdall_outbound_export.json")
    with open(path, "w") as f:
        json.dump(rows, f, indent=4)

def draw_traffic_tail_window(stdscr, conn_info):
    h, w = stdscr.getmaxyx()
    win = curses.newwin(h-6, w-10, 3, 5)
    win.box()
    win.keypad(True)
    win.timeout(100)
    title = f" 🕵️ Tail Traffic: {conn_info['prog']} -> {conn_info['remote_ip']} "
    
    log_path = os.path.expanduser(f"~/heimdall_tail_{conn_info['pid']}_{int(time.time())}.log")
    # Write directly to file to use OS-level buffering
    cmd = f"sudo tcpdump -U -nn -A -i any host {conn_info['remote_ip']} and port {conn_info['remote_port']} > {log_path} 2>/dev/null"
    
    try:
        # Start tcpdump in background writing to file
        proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        # Ensure file exists
        open(log_path, 'a').close()
    except Exception as e:
        show_message(stdscr, f"Error starting capture: {e}")
        return

    lines = []
    is_waiting = True
    
    while True:
        try:
            # Read last 32KB of the file for tailing
            if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
                is_waiting = False
                with open(log_path, "r", errors='ignore') as f:
                    f.seek(0, 2)
                    f_size = f.tell()
                    # Read last 32k to ensure we have enough context
                    read_size = min(f_size, 32768)
                    f.seek(f_size - read_size)
                    chunk = f.read()
                    lines = chunk.splitlines()
        except: pass

        win.erase()
        win.box()
        win.addstr(0, (w-10-len(title))//2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        
        y_off = 1
        if conn_info['remote_port'] == '443':
            hint = "⚠️  HTTPS (Port 443) ENCRYPTED Content."
            win.addstr(y_off, 2, hint, curses.color_pair(CP_WARN) | curses.A_DIM)
            y_off += 1

        if is_waiting:
            msg = "📡  Capture Active. Waiting for data..."
            win.addstr(h//2 - 3, (w-10-len(msg))//2, msg, curses.color_pair(CP_ACCENT) | curses.A_BOLD)
        else:
            visible_h = h - 8 - y_off
            display_slice = lines[-visible_h:] if len(lines) > visible_h else lines
            for i, l in enumerate(display_slice):
                disp = "".join([c if (ord(c) >= 32 and ord(c) < 127) or c == '\t' else "." for c in l])
                try: win.addstr(y_off + i, 2, disp[:w-14], curses.color_pair(CP_TEXT))
                except: pass
        
        th, tw = win.getmaxyx()
        win.addstr(th - 2, 2, f" [ESC] Stop   Log: {log_path}", curses.color_pair(CP_ACCENT) | curses.A_DIM)
        win.refresh()
        
        k = win.getch()
        if k == 27: break

    # Clean up
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except: pass
    del win

def draw_http_summary_modal(stdscr, conn_info):
    h, w = stdscr.getmaxyx()
    # Compact sizing: max 15 lines height, max 85 columns width
    win_h = min(h - 4, 15)
    win_w = min(w - 4, 85)
    # Perfectly centered
    start_y = (h - win_h) // 2
    start_x = (w - win_w) // 2
    win = curses.newwin(win_h, win_w, start_y, start_x)
    win.box()
    win.keypad(True)
    win.timeout(100)
    
    start_time = datetime.now().strftime("%H:%M:%S")
    title = f" 📊 HTTP Accurate Monitor: {conn_info['prog']} "
    target_pid = conn_info['pid']
    
    def get_current_ips(pid):
        ips = {conn_info['remote_ip']}
        try:
            import psutil
            p = psutil.Process(pid)
            for c in p.connections(kind='inet'):
                if c.raddr: ips.add(c.raddr.ip)
        except: pass
        return ips

    # Initial capture IPs
    active_ips = get_current_ips(target_pid)
    ip_filter = " or ".join([f"host {ip}" for ip in active_ips])
    is_encrypted = str(conn_info['remote_port']) == "443"

    import queue
    data_queue = queue.Queue()
    stop_event = threading.Event()
    
    # CRITICAL: Added single quotes around the filter to prevent shell expansion of ()
    cmd = f"sudo tcpdump -U -l -nn -A -s 2048 -i any '{ip_filter}' 2>/dev/null"
    
    def reader_thread(proc, q, ev):
        try:
            while not ev.is_set():
                r, _, _ = select.select([proc.stdout], [], [], 0.1)
                if r:
                    chunk = proc.stdout.read(4096)
                    if not chunk: break
                    q.put(chunk)
        except: pass

    proc = None
    if not is_encrypted:
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, preexec_fn=os.setsid)
            t = threading.Thread(target=reader_thread, args=(proc, data_queue, stop_event), daemon=True)
            t.start()
        except Exception as e:
            show_message(stdscr, f"Error: {e}")
            return

    stats = {}
    session_host = ""
    overlap_buffer = ""
    total_bytes = 0
    
    METHOD_ICONS = {
        "GET": "📥 GET", "POST": "📤 POST", "PUT": "📝 PUT", 
        "PATCH": "🔧 PATCH", "DELETE": "❌ DELETE", "HEAD": "🔍 HEAD", "OPTIONS": "⚙️  OPTS"
    }

    last_ip_update = time.time()

    while True:
        # Periodically refresh IPs to catch new load-test connections
        if time.time() - last_ip_update > 5:
            new_ips = get_current_ips(target_pid)
            if new_ips != active_ips:
                # We show the delta in UI
                active_ips = new_ips
            last_ip_update = time.time()

        while not data_queue.empty():
            chunk = data_queue.get_nowait()
            total_bytes += len(chunk)
            # Combine with overlap to catch patterns split across chunks
            text = overlap_buffer + chunk
            overlap_len = len(overlap_buffer)
            overlap_buffer = text[-1024:] 
            
            # 1. Update Host (with deduplication)
            hosts = re.finditer(r'Host:\s+(\S+)', text, re.I)
            for h_match in hosts:
                if h_match.end() > overlap_len:
                    new_host = h_match.group(1).strip()
                    if new_host and new_host != session_host:
                        to_migrate = [k for k in stats.keys() if not k[1].startswith(new_host) and k[1].startswith("/")]
                        for m_key in stats.copy(): # Safely iterate over keys to pop
                            if m_key in to_migrate:
                                new_key = (m_key[0], f"{new_host}{m_key[1]}")
                                stats[new_key] = stats.get(new_key, 0) + stats.pop(m_key)
                        session_host = new_host

            # 2. Match Method + Path (with deduplication)
            matches = re.finditer(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s\r\n]+)', text, re.I)
            for m in matches:
                if m.end() > overlap_len:
                    method = m.group(1).upper()
                    path = m.group(2).split('?')[0].split('#')[0]
                    path = path.replace("http://", "").replace("https://", "")
                    
                    full_endpoint = path
                    if path.startswith("/") and session_host:
                        full_endpoint = f"{session_host}{path}"
                    
                    key = (method, full_endpoint)
                    stats[key] = stats.get(key, 0) + 1

        win.erase()
        win.box()
        # Full centering within the compact window
        win.addstr(0, (win_w-len(title))//2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        win.addstr(1, 2, f"⏱️  {start_time}", curses.A_DIM)
        win.addstr(1, win_w-15, f"📡  Nodes: {len(active_ips)}", curses.color_pair(CP_ACCENT))
        
        if is_encrypted:
            win.addstr(win_h//2, (win_w-20)//2, "🔒  HTTPS Encrypted", curses.color_pair(CP_WARN) | curses.A_BOLD)
        elif not stats:
            msg = f"📡  Listening ({total_bytes//1024} KB rcvd)..."
            win.addstr(win_h//2, (win_w-len(msg))//2, msg, curses.color_pair(CP_ACCENT) | curses.A_BOLD)
        else:
            # Table Header for win_w=85
            header = f"  {'Method':<10} {'Full Endpoint (Host/Path)':<55} {'Count':>10}"
            win.addstr(2, 1, header, curses.color_pair(CP_ACCENT) | curses.A_BOLD | curses.A_UNDERLINE)
            
            sorted_items = sorted(stats.items(), key=lambda x: x[1], reverse=True)
            # Display rows (max win_h-6 to fit headers and footer)
            for i, ((method, endpoint), count) in enumerate(sorted_items[:win_h-6]):
                icon = METHOD_ICONS.get(method, method)
                try:
                    win.addstr(3 + i, 3, f"{icon:<10}", curses.color_pair(CP_TEXT))
                    win.addstr(3 + i, 14, f"{endpoint[:54]:<55}", curses.color_pair(CP_TEXT))
                    win.addstr(3 + i, 70, f"{count:>10}", curses.color_pair(CP_ACCENT) | curses.A_BOLD)
                except: pass

        stats_total = sum(stats.values())
        footer = f" [ESC] Close   Hits: {stats_total}   Data: {total_bytes/1024:.1f} KB"
        win.addstr(win_h - 2, 2, footer, curses.A_DIM)
        win.refresh()
        if win.getch() == 27: break

    stop_event.set()
    if proc:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except: pass
    del win


def draw_file_tail_window(stdscr, pid, prog, target_path=None):
    if not target_path:
        files = get_open_files(pid)
        if not files:
            show_message(stdscr, "No open files found.")
            return
            
        # Selection sub-modal for files
        h, w = stdscr.getmaxyx()
        f_h = min(20, h-10)
        f_w = min(100, w-10)
        fwin = curses.newwin(f_h, f_w, (h-f_h)//2, (w-f_w)//2)
        fwin.box()
        fwin.keypad(True)
        fsel = 0
        while True:
            fwin.erase()
            fwin.box()
            title = f" Select file to tail ({prog}) "
            fwin.addstr(0, (f_w - len(title)) // 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
            
            # Show visible files in the selection window
            max_sel_rows = f_h - 4
            sel_scroll = max(0, fsel - max_sel_rows + 1)
            
            for i in range(min(max_sel_rows, len(files))):
                idx = sel_scroll + i
                if idx < len(files):
                    # Icons consistent with Open Files pane
                    is_special = any(x in path for x in ["socket:[", "pipe:[", "anon_inode:", "pidfd"])
                    
                    # Heuristic for binary in selection list too
                    is_binary = False
                    if not is_special:
                        binary_ext = ('.so', '.bin', '.exe', '.db', '.dat', '.png', '.zip', '.gz')
                        if path.lower().endswith(binary_ext) or path.startswith("/dev/"):
                            is_binary = True
                    
                    if is_special: icon = "⚙️  "
                    elif is_binary: icon = "💾 "
                    else: icon = "📄 "
                    
                    attr = curses.A_REVERSE if idx == fsel else curses.A_NORMAL
                    if is_special:
                        attr |= curses.A_DIM
                    
                    fwin.addstr(2+i, 2, f"{fd:>3} | {icon}{path[:f_w-18]}", curses.color_pair(CP_TEXT) | attr)
            
            help_footer = " [Enter/T] Tail Selected 🦊 | [ESC/Q] Cancel "
            fwin.addstr(f_h-1, max(1, (f_w - len(help_footer)) // 2), help_footer, curses.color_pair(CP_ACCENT) | curses.A_BOLD)
            
            fwin.refresh()
            k = fwin.getch()
            if k in (ord('q'), 27): del fwin; return
            if k == curses.KEY_UP and fsel > 0: fsel -= 1
            elif k == curses.KEY_DOWN and fsel < len(files)-1: fsel += 1
            elif k in (10, curses.KEY_ENTER, ord('t'), ord('T')):
                path = files[fsel][1]
                break
        del fwin
    else:
        path = target_path

    # Filter out sockets, pipes, etc. before tailing
    if any(x in path for x in ["socket:[", "pipe:[", "anon_inode:", "pidfd"]):
        show_message(stdscr, "Cannot tail non-file descriptor (socket/pipe/internal).")
        return

    if not os.path.exists(path) or os.path.isdir(path):
        # Maybe it's a character device like /dev/pts/X
        if not os.path.exists(path) or (not path.startswith("/dev/")):
             show_message(stdscr, "Access denied or file does not exist.")
             return

    # Check if file is likely binary (more robust heuristic)
    try:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            # First, check common text-like extensions to bail out early
            text_exts = ('.log', '.txt', '.py', '.sh', '.json', '.xml', '.yaml', '.yml', '.md', '.conf', '.cfg')
            if not path.lower().endswith(text_exts):
                with open(path, 'rb') as f:
                    chunk = f.read(1024)
                    if not chunk: return
                    # Count null bytes and non-printable chars
                    null_count = chunk.count(b'\x00')
                    # A small number of nulls might be okay in some text encodings, 
                    # but usually 1 is enough to be suspicious. 
                    # Let's check the ratio of non-ascii/non-printable
                    printable = bytes(range(32, 127)) + b'\n\r\t'
                    non_printable = sum(1 for b in chunk if b not in printable)
                    
                    if null_count > 0 or (non_printable / len(chunk) > 0.3):
                        if not confirm_dialog(stdscr, "File appears to be binary. Tail anyway?"):
                            return
    except: pass

    h, w = stdscr.getmaxyx()
    twin = curses.newwin(h-6, w-10, 3, 5)
    twin.box()
    twin.timeout(200)
    twin.keypad(True)
    
    # We'll use tail -f via subprocess
    try:
        tproc = subprocess.Popen(["tail", "-f", "-n", str(h-10), path], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.STDOUT, 
                                 text=False) # bufsize=1 not supported in binary mode
    except Exception as e:
        show_message(stdscr, f"Tail error: {e}")
        return
    
    # Set non-blocking read
    import fcntl
    fd = tproc.stdout.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    
    tlines = []
    title = f" 📄 Tail: {os.path.basename(path)} "
    help_text = " [q/ESC] Close | [s] Stop Stream "
    
    while True:
        try:
            line_bytes = tproc.stdout.readline()
            if line_bytes:
                line = line_bytes.decode('utf-8', 'replace').rstrip('\n')
                tlines.append(line)
                if len(tlines) > h - 10:
                    tlines.pop(0)
        except (IOError, TypeError):
            pass
            
        twin.erase()
        twin.box()
        try:
            twin.addstr(0, (w-10-len(title))//2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
            twin.addstr(h-7, (w-10-len(help_text))//2, help_text, curses.color_pair(CP_ACCENT))
            
            for i, l in enumerate(tlines):
                # Sanitize line (remove non-printable)
                clean_l = "".join(c for c in l if c.isprintable())
                twin.addstr(1+i, 2, clean_l[:w-14], curses.color_pair(CP_TEXT))
        except: pass
        
        twin.refresh()
        k = twin.getch()
        if k in (ord('q'), ord('Q'), 27): break
        if k in (ord('s'), ord('S')):
            # Pause/Stop stream toggle (simulated by stop reading)
            confirm_dialog(stdscr, "Tailing paused. Press enter to close.")
            break
            
    tproc.terminate()
    try: tproc.wait(timeout=0.5)
    except: pass
    del twin

def draw_top_tabs(stdscr, active_tab_index):
    global LOADED_PLUGINS
    h, w = stdscr.getmaxyx()
    tabs = ["Heimdall"] + [p.name for p in LOADED_PLUGINS]
    
    x = 2
    for i, tab in enumerate(tabs):
        attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD | curses.A_REVERSE if i == active_tab_index else curses.color_pair(CP_TEXT) | curses.A_DIM
        try:
            stdscr.addstr(0, x, f" [{i+1}] {tab} ", attr)
        except:
            pass
        x += len(tab) + 7
    stdscr.chgat(0, 0, w, curses.color_pair(CP_HEADER) | curses.A_REVERSE)


def exit_animation(stdscr):
    """Melting effect: characters fall to the bottom of the screen."""
    import random
    import time
    try:
        h, w = stdscr.getmaxyx()
        chars = []
        # Capture screen content
        for y in range(h):
            for x in range(w):
                try:
                    ch = stdscr.inch(y, x)
                    char = ch & 0xFF
                    if char != ord(' '):
                        attr = ch & ~0xFF
                        chars.append({
                            'y': float(y), 
                            'x': x, 
                            'char': char, 
                            'attr': attr, 
                            'v': 0.0, # Velocity
                            'delay': random.uniform(0, 0.8) # Staggered start
                        })
                except: continue
        
        curses.curs_set(0)
        start_time = time.time()
        
        while True:
            elapsed = time.time() - start_time
            still_falling = False
            stdscr.erase()
            
            for c in chars:
                if elapsed > c['delay']:
                    if c['y'] < h - 1:
                        c['v'] += 0.15 # Gravity
                        c['y'] += c['v']
                        if c['y'] >= h - 1:
                            c['y'] = h - 1
                        else:
                            still_falling = True
                else:
                    still_falling = True
                
                try:
                    # Draw character at calculated integer position
                    stdscr.addch(int(c['y']), c['x'], c['char'], c['attr'])
                except: pass
            
            stdscr.refresh()
            if not still_falling or elapsed > 3.0:
                break
            time.sleep(0.02)
            
        time.sleep(0.1)
    except:
        pass

def main(stdscr, args=None):
    global TRIGGER_REFRESH, TRIGGER_LIST_ONLY, SCANNING_STATUS_EXP, SNAPSHOT_MODE
    global PENDING_IPC_ALERT, CURRENT_THEME_INDEX
    
    curses.curs_set(0)
    stdscr.keypad(True)
    # make input non-blocking with short timeout so we can debounce selection and let caches serve during fast scroll
    stdscr.timeout(120)  # ms

    # Initialize theme
    apply_current_theme(stdscr)

    # Load Plugins
    load_plugins(HeimdallDummyInstance())
    active_tab = 0 # 0 = Heimdall, 1+ = Plugins
    
    # Start the background services updater
    start_services_updater()

    # use cached parse initially to reduce startup churn
    # Start IPC Server for Daemon alerts
    ipc_thread = threading.Thread(target=start_ipc_server, daemon=True)
    ipc_thread.start()

    # Start Traffic Poller thread
    traffic_thread = threading.Thread(target=_traffic_poller_thread, daemon=True)
    traffic_thread.start()
    debug_log("TRAFFIC_POLLER: Background thread started.")

    # Start Outbound Poller thread
    outbound_thread = threading.Thread(target=_outbound_poller_thread, daemon=True)
    outbound_thread.start()
    debug_log("OUTBOUND_POLLER: Background thread started.")

    rows = parse_ss_cached()
    cache = {}
    firewall_status = {}

    runtime_filters = {
        "port": args.port if args else None,
        "pid": args.pid if args else None,
        "user": args.user if args else None
    }

    if any(runtime_filters.values()):
        rows = [r for r in rows if matches_filter(r, runtime_filters, cache)]

    splash_screen(stdscr, rows, cache)

    selected = 0 if rows else -1
    offset = 0
    table_h = max(6, curses.LINES//2)
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

    last_auto_scan_time = time.time()
    
    # Runtime state variables
    open_files_scroll = 0
    h, w = stdscr.getmaxyx()
    table_h = h // 2
    offset = 0
    selected = 0
    
    # 0: Table, 1: Open Files, 2: User Profile, 3: Detail Info
    active_pane = 0 
    maximized_pane = None
    open_files_selected_idx = 0
    open_files_sort_mode = 0 # 0:fd, 1:size, 2:ctime, 3:mtime, 4:type, 5:path
    open_files_query = ""
    
    while True:
        # ------------------------------------------------------------------
        # Pull vulnerability alerts from background thread (non-blocking)
        # ------------------------------------------------------------------
        while not VULN_QUEUE.empty():
            try:
                _vuln_alert = VULN_QUEUE.get_nowait()
                with VULN_LOCK:
                    # Check if already exists
                    if any(a["cve_id"] == _vuln_alert["cve_id"] for a in VULN_PENDING):
                        continue
                    if _vuln_alert["cve_id"] in VULN_CONFIG_DATA.get("ignored_cves", []):
                        continue
                    
                    VULN_PENDING.append(_vuln_alert)
                    # Persist immediately
                    VULN_CONFIG_DATA["pending_vulns"] = list(VULN_PENDING)
                    _save_vuln_config()
            except queue.Empty:
                break

        h, w = stdscr.getmaxyx()
        
        draw_top_tabs(stdscr, active_tab)
        
        if active_tab > 0:
            plugin_idx = active_tab - 1
            if plugin_idx < len(LOADED_PLUGINS):
                plugin = LOADED_PLUGINS[plugin_idx]
                # draw shortcuts bar if needed
                plugin_win = stdscr.derwin(h-1, w, 1, 0)
                plugin.render(plugin_win)
                
                curses.doupdate()
                k = stdscr.getch()
                if k == -1: continue
                
                if 49 <= k <= 57: # 1-9
                    idx = k - 49
                    if idx < len(LOADED_PLUGINS) + 1 and idx != active_tab:
                        LOADED_PLUGINS[active_tab-1].stop()
                        active_tab = idx
                        if active_tab > 0: LOADED_PLUGINS[active_tab-1].start()
                        stdscr.erase()
                    continue
                
                # Tab keys
                if k == 9 or k == curses.KEY_BTAB:
                    pass # plugin panes if complex

                if k == ord('q'):
                    pass # pass to plugin, or quit main? user said q quits tool in plugin
                    
                plugin.on_key(k)
                continue

        # Periodic background refresh (Auto-scan)
        if not show_detail:
            auto_interval = CONFIG.get("auto_scan_interval", 3.0)
            if auto_interval > 0 and time.time() - last_auto_scan_time > auto_interval:
                SCANNING_STATUS_EXP = time.time() + 1.5
                request_list_refresh()

        visible_rows = table_h-4

        # refresh rows from cached parser (fast)
        rows = parse_ss_cached()
        if any(runtime_filters.values()):
            rows = [r for r in rows if matches_filter(r, runtime_filters, cache)]

        if rows:
            bar_w = 22
            main_w = w - bar_w
            
            # Sub-pane sizes
            of_w = min(60, max(45, main_w // 3))
            if main_w < 100:
                of_w = 35
            table_w = main_w - of_w
            user = cache.get(rows[selected][0] if selected>=0 and selected<len(rows) else "-", {}).get("user", "-")
            req_user_pane_h = 10
            
            # debounce heavy detail fetch: only update cached_wrapped_lines / conn_info when selection stable
            now = time.time()
            selection_changed = (selected != last_selected)
            if selection_changed:
                last_selected_change_time = now
                last_selected = selected
                # Reset open files view on selection change
                open_files_selected_idx = 0
                open_files_scroll = 0

            selection_stable = (now - last_selected_change_time) >= SELECT_STABLE_TTL
            
            pid = rows[selected][4] if selected>=0 and selected < len(rows) else "-"
            prog = rows[selected][3] if selected>=0 and selected < len(rows) else "-"

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
                        cached_conn_info["pid"] = pid
                    else:
                        # show quick placeholder until stable or until preloaded
                        placeholder = ["Waiting for selection to stabilize..."]
                        cached_wrapped_icon_lines = placeholder
                        cached_total_lines = len(placeholder)
                        from collections import Counter
                        cached_conn_info = {"active_connections": 0, "top_ip": "-", "top_ip_count": 0, "all_ips": Counter(), "port": port, "pid": pid}
                
                port_cache = cache.get(port, {})
                # Check if window resized significantly, rewrap if needed
                prewrapped_width = port_cache.get("prewrapped_width", 0)
                if abs(main_w - prewrapped_width) > 10:  # Threshold for rewrap
                    lines = port_cache.get("lines", [])
                    cached_wrapped_icon_lines = prepare_witr_content(lines, main_w - 4, prog=prog, port=port, pid=pid)
                    if port in cache:
                        cache[port]["wrapped_icon_lines"] = cached_wrapped_icon_lines
                        cache[port]["prewrapped_width"] = main_w
                    cached_total_lines = len(cached_wrapped_icon_lines)
            else:
                cached_wrapped_icon_lines = []
                cached_conn_info = None

            # Render maximized logic
            if maximized_pane is not None:
                max_win = stdscr.derwin(h - 1, main_w, 1, 0) # Maximize to main_w to preserve right panel
                try: max_win.bkgd(' ', curses.color_pair(CP_TEXT))
                except: pass
                
                if maximized_pane == 0:
                    draw_table(max_win, rows, selected, offset, cache, firewall_status, is_active=True)
                elif maximized_pane == 1:
                    pid = rows[selected][4] if selected>=0 and selected < len(rows) else "-"
                    prog = rows[selected][3] if selected>=0 and selected < len(rows) else "-"
                    files = get_open_files_cached(pid)
                    sk = ["fd", "size", "type", "ctime", "mtime", "path"][open_files_sort_mode]
                    draw_open_files(max_win, pid, prog, files, selected_idx=open_files_selected_idx, scroll=open_files_scroll, is_active=True, sort_key=sk, query=open_files_query, hide_footer=True)
                elif maximized_pane == 2:
                    if user != "-":
                        user_data = get_user_info_cached(user)
                        if user_data:
                            draw_user_subpane(max_win, user_data, is_active=True)
                elif maximized_pane == 3:
                    # fetch logic for detail
                    draw_detail(max_win, cached_wrapped_icon_lines, scroll=detail_scroll, conn_info=cached_conn_info, is_active=True)
                
                # Add ESC to exit maximize hint
                try:
                    if maximized_pane == 1:
                        esc_msg = " [ESC/Enter] Restore | [s] Sort [f] Filter [t] Tail 🦊 "
                    else:
                        esc_msg = " [ESC/Enter] Restore | [t] Tail 🦊 "
                    max_win.addstr(h - 2, max(1, (main_w - len(esc_msg)) // 2), esc_msg, curses.color_pair(CP_TEXT) | curses.A_BOLD | curses.A_REVERSE)
                    max_win.noutrefresh()
                except:
                    pass
                
            else:
                # Normal Layout
                table_win = stdscr.derwin(table_h, table_w, 1, 0)
                draw_table(table_win, rows, selected, offset, cache, firewall_status, is_active=(active_pane == 0))

                if table_h >= 15 and user != "-":
                    files_h = table_h - req_user_pane_h
                    open_files_win = stdscr.derwin(files_h, of_w, 1, table_w)
                    user_win = stdscr.derwin(req_user_pane_h, of_w, 1 + files_h, table_w)
                elif user != "-":
                    files_h = table_h
                    open_files_win = stdscr.derwin(files_h, of_w, 1, table_w)
                    user_win = stdscr.derwin(min(req_user_pane_h, files_h), of_w, 1 + files_h - min(req_user_pane_h, files_h), table_w)
                else:
                    files_h = table_h
                    open_files_win = stdscr.derwin(files_h, of_w, 1, table_w)
                    user_win = None

                try: open_files_win.bkgd(' ', curses.color_pair(CP_TEXT))
                except: pass
                
                files = get_open_files_cached(pid)
                sk = ["fd", "size", "type", "ctime", "mtime", "path"][open_files_sort_mode]
                draw_open_files(open_files_win, pid, prog, files, selected_idx=open_files_selected_idx, scroll=open_files_scroll, is_active=(active_pane == 1), sort_key=sk, query=open_files_query)

                if user_win:
                    user_data = get_user_info_cached(user)
                    if user_data:
                        draw_user_subpane(user_win, user_data, is_active=(active_pane == 2))

                detail_win = stdscr.derwin(h - table_h - 1, main_w, table_h + 1, 0)
                try: detail_win.bkgd(' ', curses.color_pair(CP_TEXT))
                except: pass
                draw_detail(detail_win, cached_wrapped_icon_lines, scroll=detail_scroll, conn_info=cached_conn_info, is_active=(active_pane == 3))
            
            draw_help_bar(stdscr, active_pane)

        # Vulnerability alerts are now handled inside draw_detail (System Health)

        draw_status_indicator(stdscr)

        # 🚨 Handle Pending Alerts (Daemon IPC or Local TUI Protection)
        while PENDING_ALERTS:
            with CONFIG_LOCK:
                alert = PENDING_ALERTS.pop(0)
            
            result = draw_ipc_alert_modal(stdscr, alert)
            
            if alert.get("local"):
                # Handle local TUI protection action
                apply_tui_protection_action(stdscr, alert, result)
            else:
                # Fallback to normal Daemon IPC result routing
                PENDING_IPC_RESULT[alert["id"]] = result
            
            # Force redraw after modal
            stdscr.touchwin()
            stdscr.noutrefresh()
            curses.doupdate()

        # Show active filters if any
        if any(runtime_filters.values()):
            f_str = f"🔍 Filter: {get_filter_status_str(runtime_filters)} "
            try:
                stdscr.addstr(h-2, 2, f_str, curses.color_pair(CP_HEADER) | curses.A_BOLD)
            except: pass
        curses.doupdate()

        # If any modal/action requested a full refresh, do the same sequence used for 'r'
        if TRIGGER_REFRESH or TRIGGER_LIST_ONLY:
            is_full = TRIGGER_REFRESH
            TRIGGER_REFRESH = False
            TRIGGER_LIST_ONLY = False
            
            # IMPORTANT: Disable snapshot mode temporarily to allow fresh scan
            old_mode = SNAPSHOT_MODE
            SNAPSHOT_MODE = False
            
            # For list-only, we skip clearing service metadata caches (witr, conn)
            if is_full:
                _witr_cache.clear()
                _conn_cache.clear()
                cache.clear()
                _risk_level_cache.clear()
                _security_audit_cache.clear()
                _script_managed_cache.clear()
            
            _parse_cache.clear()
            _table_row_cache.clear()
            
            # Force a real, non-cached parse
            rows = parse_ss() 
            if is_full:
                splash_screen(stdscr, rows, cache)
                # risk levels are re-populated inside splash_screen per-port
            else:
                # For list-only refresh, recompute risk levels without full splash
                compute_risk_for_all_ports(rows, cache)
            
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

        if k == 27: # ESC
            stdscr.nodelay(True)
            next_k = stdscr.getch()
            stdscr.nodelay(False)
            if next_k == -1:
                if maximized_pane is not None:
                    maximized_pane = None
                continue
            elif next_k == ord('c'):
                CURRENT_THEME_INDEX = (CURRENT_THEME_INDEX + 1) % len(THEMES)
                save_theme_preference(CURRENT_THEME_INDEX)
                apply_current_theme(stdscr)
                rows = parse_ss_cached()
                splash_screen(stdscr, rows, cache)
                continue
            else:
                k = next_k

        if k == ord('q'):
            # Play exit animation
            exit_animation(stdscr)
            # Cleanup IPC
            try:
                if os.path.exists(IPC_SOCKET_PATH):
                    os.remove(IPC_SOCKET_PATH)
            except: pass
            break
            
        if 49 <= k <= 57: # 1-9
            idx = k - 49
            if idx < len(LOADED_PLUGINS) + 1 and idx != active_tab:
                if active_tab > 0: LOADED_PLUGINS[active_tab-1].stop()
                active_tab = idx
                if active_tab > 0: LOADED_PLUGINS[active_tab-1].start()
                stdscr.erase()
            continue

        elif k == ord('v') or k == ord('n'):
            _open_vuln_modal(stdscr)
            continue
            
        if k == 9 or k == KEY_TAB:
            active_pane = (active_pane + 1) % 4
        elif k == curses.KEY_BTAB:
            active_pane = (active_pane - 1) % 4
            
        elif k == 10 or k == curses.KEY_ENTER:
            if maximized_pane is None:
                maximized_pane = active_pane
            else:
                maximized_pane = None
                
        elif k == curses.KEY_UP:
            if active_pane == 0 and selected > 0:
                selected -= 1
            elif active_pane == 1 and open_files_selected_idx > 0:
                open_files_selected_idx -= 1
                if open_files_selected_idx < open_files_scroll:
                    open_files_scroll = open_files_selected_idx
            elif active_pane == 3 and detail_scroll > 0:
                detail_scroll -= 1
                
        elif k == curses.KEY_DOWN:
            if active_pane == 0 and selected < len(rows) - 1:
                selected += 1
            elif active_pane == 1:
                files = get_open_files_cached(pid)
                # We MUST count filtered files for correct boundary
                filtered_count = 0
                for f in files:
                    p = f[1]
                    is_spec = any(x in p for x in ["socket:[", "pipe:[", "anon_inode:", "[pidfd]", "dmabuf:"])
                    is_bin = False
                    if not is_spec:
                        binary_ext = ('.so', '.bin', '.exe', '.db', '.dat', '.png', '.jpg', '.zip', '.gz', '.tar', '.o', '.pyc', '.pak', '.bdic')
                        if p.lower().endswith(binary_ext) or p.startswith("/dev/") or "/leveldb/" in p.lower() or "/gpcache/" in p.lower() or "/gpucache/" in p.lower():
                            is_bin = True
                    f_tp = "Special" if is_spec else ("Binary" if is_bin else "Text")
                    if open_files_query:
                        q = open_files_query.lower()
                        if q not in p.lower() and q not in f_tp.lower(): continue
                    filtered_count += 1

                if open_files_selected_idx < filtered_count - 1:
                    open_files_selected_idx += 1
                    of_h, _ = (open_files_win.getmaxyx() if maximized_pane is None else max_win.getmaxyx())
                    if open_files_selected_idx >= open_files_scroll + (of_h - 7): # Use 7 due to header lines
                        open_files_scroll += 1
            elif active_pane == 3 and detail_scroll < max(0, cached_total_lines - (h - 3)):
                detail_scroll += 1
                
        # Open Files Pane Specific Commands
        if active_pane == 1:
            if k in (ord('s'), ord('S')):
                open_files_sort_mode = (open_files_sort_mode + 1) % 6
                continue
            elif k in (ord('f'), ord('F')):
                new_q = get_input_modal(stdscr, "Filter path/type:", open_files_query)
                if new_q is not None:
                    open_files_query = new_q
                    open_files_selected_idx = 0
                    open_files_scroll = 0
                continue
            elif k in (ord('t'), ord('T')): # Handle 't' for tail specifically when active
                files = get_open_files_cached(pid)
                display_files = []
                for f in files:
                    fd, path, size, mtime, ctime = f
                    is_special = any(x in path for x in ["socket:[", "pipe:[", "anon_inode:", "[pidfd]", "dmabuf:"])
                    is_binary = False
                    if not is_special:
                        binary_ext = ('.so', '.bin', '.exe', '.db', '.dat', '.png', '.jpg', '.zip', '.gz', '.tar', '.o', '.pyc', '.pak', '.bdic')
                        if path.lower().endswith(binary_ext) or path.startswith("/dev/") or "/leveldb/" in path.lower() or "/gpcache/" in path.lower() or "/gpucache/" in path.lower(): 
                            is_binary = True
                    f_type = "Special" if is_special else ("Binary" if is_binary else "Text")
                    if open_files_query:
                        q = open_files_query.lower()
                        if q not in path.lower() and q not in f_type.lower(): continue
                    display_files.append((fd, path, size, mtime, ctime, f_type))
                
                sk_name = ["fd", "size", "type", "ctime", "mtime", "path"][open_files_sort_mode]
                reverse = True if sk_name in ['size', 'mtime', 'ctime'] else False
                if sk_name == 'size': display_files.sort(key=lambda x: x[2], reverse=reverse)
                elif sk_name == 'mtime': display_files.sort(key=lambda x: x[3], reverse=reverse)
                elif sk_name == 'ctime': display_files.sort(key=lambda x: x[4], reverse=reverse)
                elif sk_name == 'type': display_files.sort(key=lambda x: x[5])
                elif sk_name == 'path': display_files.sort(key=lambda x: x[1].lower())
                else: display_files.sort(key=lambda x: int(x[0]) if (len(x) > 0 and str(x[0]).isdigit()) else 9999)
                
                if display_files and 0 <= open_files_selected_idx < len(display_files):
                    target_path = display_files[open_files_selected_idx][1]
                    draw_file_tail_window(stdscr, pid, prog, target_path=target_path)
                
                stdscr.touchwin()
                curses.doupdate()
                continue
            elif k == ord('e'):
                show_env_vars_modal(stdscr, pid, prog)
                stdscr.touchwin(); curses.doupdate(); continue
            elif k == ord('u'):
                show_redirections_modal(stdscr, pid, prog)
                stdscr.touchwin(); curses.doupdate(); continue
            
        # Main Table commands are restricted to when active_pane == 0
        if active_pane == 0:
            if k == KEY_SEP_UP and table_h < max(6, h - 2):
                table_h += 1
            elif k == KEY_SEP_DOWN and table_h > 6:
                table_h -= 1
            elif k == ord('s') and selected >= 0 and rows:
                port, proto, pidprog, prog, pid = rows[selected]
                confirm = confirm_dialog(stdscr, f"{pidprog} ({port}) stop?")
                if confirm:
                    stop_process_or_service(pid, prog, stdscr)
                    request_list_refresh()
            elif k == ord('a'):
                handle_action_center_input(stdscr, rows, selected, cache, firewall_status)
            elif k == ord('z'):
                handle_services_modal(stdscr)
                request_list_refresh()
            elif k == ord('i') and selected >= 0 and rows:
                port, proto, pidprog, prog, pid = rows[selected]
                user = cache.get(port, {}).get("user", "unknown")
                show_inspect_modal(stdscr, port, prog, pid, user)
            elif k == KEY_FIREWALL and selected >= 0 and rows:
                port = rows[selected][0]
                toggle_firewall(port, stdscr, firewall_status)
            elif k == ord('e') and selected >= 0 and rows:
                pid = rows[selected][4]
                prog = rows[selected][3]
                show_env_vars_modal(stdscr, pid, prog)
            elif k == ord('u') and selected >= 0 and rows:
                pid = rows[selected][4]
                prog = rows[selected][3]
                show_redirections_modal(stdscr, pid, prog)
                
        # Global hotkeys
        if k == ord('r'):
            # force real refresh and clear caches
            SCANNING_STATUS_EXP = time.time() + 1.5
            rows = parse_ss()
            _parse_cache.clear(); _witr_cache.clear(); _conn_cache.clear()
            _table_row_cache.clear(); _risk_level_cache.clear(); _security_audit_cache.clear()
            cache.clear()
            splash_screen(stdscr, rows, cache)
            if selected >= len(rows):
                selected = len(rows) - 1
            offset = 0
            
        elif k == ord('F'):
            draw_filter_modal(stdscr, runtime_filters)
            request_list_refresh()
            
        elif k == ord('d'):
            generate_full_system_dump(stdscr, rows, cache)
            
        elif k == ord('p'):
            draw_settings_modal(stdscr)
            
        elif k == ord('o'):
            draw_outbound_modal(stdscr)
            
        elif k == ord('c'):
            CURRENT_THEME_INDEX = (CURRENT_THEME_INDEX + 1) % len(THEMES)
            save_theme_preference(CURRENT_THEME_INDEX)
            apply_current_theme(stdscr)
            t_name = THEMES[CURRENT_THEME_INDEX]['name']
            try:
                h, w = stdscr.getmaxyx()
                msg = f" Theme: {t_name} "
                stdscr.addstr(h//2, (w-len(msg))//2, msg, curses.A_REVERSE | curses.A_BOLD)
                stdscr.refresh()
                time.sleep(0.5)
            except: pass
            rows = parse_ss_cached()
            splash_screen(stdscr, rows, cache)
        elif k in (ord('t'), ord('T')):
            if active_pane == 1:
                # Tail the currently selected file in the pane
                files = get_open_files_cached(pid)
                if files and 0 <= open_files_selected_idx < len(files):
                    path = files[open_files_selected_idx][1]
                    draw_file_tail_window(stdscr, pid, prog, target_path=path)
                else:
                    show_message(stdscr, "No file selected to tail.")
            else:
                # Fallback to selection modal
                if selected >= 0:
                    port, proto, pidprog, prog, pid = rows[selected]
                    draw_file_tail_window(stdscr, pid, prog)
            
            stdscr.touchwin()
            curses.doupdate()
            continue

        offset = min(max(selected - visible_rows // 2, 0), max(0, len(rows) - visible_rows))


# ═══════════════════════════════════════════════════════════════
# 🛡️ VULNERABILITY INTELLIGENCE ENGINE (Part 1-3)
# ═══════════════════════════════════════════════════════════════

class ServiceFingerprint:
    """Represents a detected service, its version, and detection confidence."""
    def __init__(self, product, version, confidence, method):
        self.product = product
        self.version = version  # Normalized string
        self.confidence = confidence # 0.0 - 1.0
        self.method = method # 'dpkg', 'rpm', 'cmdline', 'probe'

    def __repr__(self):
        return f"<SF: {self.product} v{self.version} ({self.confidence*100:.0f}%) via {self.method}>"

class VersionDetector:
    """Modular version detection using multiple providers."""
    def __init__(self):
        self._pkg_cache = {}

    @staticmethod
    def normalize_version(v: str) -> str:
        """Strip distro suffixes and normalize to semver-like format."""
        if not v: return "0.0.0"
        # Strip leading v/V
        v = v.lstrip('vV')
        # Take everything before first '-', '+', or '~'
        for sep in ['-', '+', '~', ':']: # Added ':' for epoch
            if sep in v:
                v = v.split(sep)[-1] if sep == ':' else v.split(sep)[0]
        # Keep only numbers and dots
        v = re.sub(r'[^0-9.]', '', v)
        return v.strip('.') or "0.0.0"

    def detect(self, pid: int) -> ServiceFingerprint:
        """Entry point for detecting version of a running process."""
        try:
            # We use global psutil or try to import it if missing
            p = psutil.Process(pid)
            name = p.name().lower()
            try:
                exe = p.exe()
                cmdline = p.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ""
                cmdline = []
        except:
            return None

        # 1. Package Manager (High Confidence)
        fp = self._detect_via_pkg(name, exe=exe)
        if fp and fp.confidence >= 0.8:
            return fp

        # 2. Cmdline Inspection
        fp_cmd = self._detect_via_cmdline(name, cmdline)
        if fp_cmd and (not fp or fp_cmd.confidence > fp.confidence):
            fp = fp_cmd

        # 3. Binary Probing (Internal safe list only)
        if not fp or fp.confidence < 0.5:
            fp_probe = self._detect_via_probe(exe, name)
            if fp_probe and (not fp or fp_probe.confidence > fp.confidence):
                fp = fp_probe

        return fp

    def _detect_via_pkg(self, name, exe=""):
        cache_key = f"{name}:{exe}"
        if cache_key in self._pkg_cache:
            return self._pkg_cache[cache_key]

        res = None
        # Try dpkg-query first (fast)
        try:
            out = subprocess.check_output(["dpkg-query", "-W", "-f", "${Package}|${Version}", name], 
                                          text=True, stderr=subprocess.DEVNULL)
            if "|" in out:
                pkg, ver = out.strip().split("|", 1)
                res = ServiceFingerprint(pkg, self.normalize_version(ver), 0.95, "dpkg")
        except: pass
        
        # Binary Path Ownership (Deep lookup)
        if not res and exe and os.path.exists(exe):
            try:
                # dpkg -S /path/to/exe
                out = subprocess.check_output(["dpkg", "-S", exe], text=True, stderr=subprocess.DEVNULL)
                if ":" in out:
                    pkg = out.split(":")[0].strip()
                    # Found the owning package, now get its version
                    ver_out = subprocess.check_output(["dpkg-query", "-W", "-f", "${Version}", pkg], 
                                                     text=True, stderr=subprocess.DEVNULL)
                    res = ServiceFingerprint(pkg, self.normalize_version(ver_out), 0.98, "dpkg-path")
            except: pass

        if not res:
            try:
                # RPM fallback
                cmd = ["rpm", "-qf", "--queryformat", "%{NAME}|%{VERSION}", exe] if exe else ["rpm", "-q", "--queryformat", "%{NAME}|%{VERSION}", name]
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
                if "|" in out:
                    pkg, ver = out.strip().split("|", 1)
                    res = ServiceFingerprint(pkg, self.normalize_version(ver), 0.95, "rpm")
            except: pass
        
        self._pkg_cache[cache_key] = res
        return res

    def _detect_via_cmdline(self, name, cmdline):
        text = " ".join(cmdline)
        # Regex for common version patterns
        patterns = [
            (r'/([0-9]+\.[0-9.]*[0-9])', 0.7),
            (r'version[:\s]+([0-9]+\.[0-9.]*[0-9])', 0.7),
            (r'([0-9]+\.[0-9]+\.[0-9]+)', 0.5), # generic triplet
        ]
        for pat, conf in patterns:
            m = re.search(pat, text, re.I)
            if m:
                return ServiceFingerprint(name, self.normalize_version(m.group(1)), conf, "cmdline")
        return None

    def _detect_via_probe(self, exe, name):
        if not exe or not os.path.exists(exe):
            return None
        
        # Only probe known server binaries to minimize noise/risk
        safe_list = ["nginx", "httpd", "apache2", "ssh", "sshd", "vsftpd", "mysql", "mysqld", "postgres", "redis-server"]
        if name not in safe_list:
            return None

        try:
            # Try -v or --version with tight timeout
            for flag in ["-v", "--version", "-V"]:
                try:
                    out = subprocess.check_output([exe, flag], text=True, stderr=subprocess.STDOUT, timeout=0.8)
                    m = re.search(r'([0-9]+\.[0-9.]*[0-9])', out)
                    if m:
                        return ServiceFingerprint(name, self.normalize_version(m.group(1)), 0.85, f"probe:{flag}")
                except: continue
        except: pass
        return None

class CPEMatcher:
    """Fuzzy matcher for ServiceFingerprint -> NVD CPEs."""
    def __init__(self):
        # Maps common process names to (Vendor, Product)
        self._map = {
            "nginx": ("nginx", "nginx"),
            "sshd": ("openbsd", "openssh"),
            "vsftpd": ("vsftpd_project", "vsftpd"),
            "apache2": ("apache", "http_server"),
            "httpd": ("apache", "http_server"),
            "mysql": ("oracle", "mysql"),
            "postgres": ("postgresql", "postgresql"),
            "redis-server": ("redislabs", "redis"),
            "node": ("nodejs", "node.js"),
            "python": ("python", "python"),
            "cups-daemon": ("apple", "cups"),
            "cups": ("apple", "cups"),
            "ssh": ("openbsd", "openssh"),
            "sshd": ("openbsd", "openssh"),
            "apache2": ("apache", "http_server"),
            "ntp": ("ntp", "ntp"),
        }

    def match(self, fp: ServiceFingerprint) -> list:
        if not fp or fp.confidence < 0.4:
            return []
        
        vendor, product = self._map.get(fp.product, (fp.product, fp.product))
        # Generate CPE 2.3 string
        # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        return [f"cpe:2.3:a:{vendor}:{product}:{fp.version}"]

class NVDCache:
    """Persistent local cache for NVD queries to avoid rate limits."""
    def __init__(self, ttl_hours=24):
        self.path = Path(os.path.expanduser("~/.cache/heimdall/vuln_cache.json"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_hours * 3600
        self._data = self._load()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    return json.load(f)
            except: return {}
        return {}

    def save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._data, f)
        except: pass

    def get(self, key):
        entry = self._data.get(key)
        if entry:
            if time.time() - entry.get("ts", 0) < self.ttl:
                return entry.get("val")
            else:
                del self._data[key]
                self.save()
        return None

    def set(self, key, value):
        self._data[key] = {"ts": time.time(), "val": value}
        self.save()

class ThreatIntelEnricher:
    """Enriches CVEs with KEV/EPSS data (Pluggable logic)."""
    def __init__(self):
        self.kev_ids = set() # Stub for now
        self._updated = 0

    def enrich(self, cve_id):
        # FUTURE: Fetch actual EPSS/KEV feeds here
        return {
            "is_kev": cve_id in self.kev_ids,
            "epss": 0.0,
            "score_mod": 1.2 if cve_id in self.kev_ids else 1.0
        }

# ═══════════════════════════════════════════════════════════════
# 🛡️ VULNERABILITY SCANNER — Background NVD checker thread
# ═══════════════════════════════════════════════════════════════
class VulnerabilityChecker(threading.Thread):
    """Background daemon: polls NVD, matches active services, pushes alerts."""
    def __init__(self, api_key=None):
        super().__init__(daemon=True, name="VulnChecker")
        self.api_key = api_key
        # High-confidence intelligence engine
        self.detector = VersionDetector()
        self.matcher = CPEMatcher()
        self.cache = NVDCache()
        self.enricher = ThreatIntelEnricher()

    def _fetch_for_cpe(self, cpe):
        """Query NVD for a specific CPE with rate-limiting and caching."""
        global VULN_STATUS_MSG
        cached = self.cache.get(cpe)
        if cached:
            return cached, "success"

        if not _requests_lib:
            return [], "error"

        api_key = CONFIG.get("nvd_api_key")
        base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "virtualformat": "cpe",
            "cpeName": cpe,
            "resultsPerPage": 20
        }
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        try:
            r = _requests_lib.get(base, params=params, headers=headers, timeout=15)
            if r.status_code == 404:
                # 404 means the CPE doesn't exist in NVD (very common for custom/local processes)
                # Cache as empty so we don't hammer the API for missing products
                self.cache.set(cpe, [])
                return [], "success"
            
            if r.status_code == 403 or r.status_code == 429:
                return [], "rate_limit"
            r.raise_for_status()
            
            vulns = r.json().get("vulnerabilities", [])
            self.cache.set(cpe, vulns)
            
            # Rate limit protection: 6s delay if no API key (NVD recommendation)
            if not api_key:
                time.sleep(6)
            return vulns, "success"
        except Exception as e:
            # Distinguish between network errors and missing CPEs
            if not isinstance(e, _requests_lib.HTTPError) or e.response.status_code != 404:
                debug_log(f"VULN_CHECKER: NVD Error for {cpe}: {e}")
            return [], "error"

    def run(self):
        global VULN_STATUS_MSG, VULN_NEXT_CHECK_TIME, VULN_IS_FETCHING, VULN_LAST_NEW_COUNT
        # Delay to let TUI settle
        time.sleep(6)
        
        while True:
            try:
                now = time.time()
                last_check = VULN_CONFIG_DATA.get("last_check_timestamp", 0)
                interval_hours = CONFIG.get("vuln_scan_interval_hours", 0.5)
                interval_sec = max(600, int(interval_hours * 3600))
                
                VULN_NEXT_CHECK_TIME = last_check + interval_sec

                # 1. Skip if too recent
                if last_check > 0 and (now - last_check) < interval_sec and len(VULN_PENDING) > 0:
                    time.sleep(10)
                    continue

                VULN_IS_FETCHING = True
                VULN_STATUS_MSG = "🔍 Fingerprinting services..."
                
                # 2. Part 1: Service & Version Intelligence (High Confidence)
                targets = []
                try:
                    # Scan active processes with listening sockets 
                    for p in psutil.process_iter(['pid', 'name']):
                        try:
                            # Only scan processes with listening sockets to minimize noise
                            conns = p.connections(kind='inet')
                            if any(c.status == 'LISTEN' for c in conns):
                                fp = self.detector.detect(p.pid)
                                if fp and fp.product not in ["antigravity", "sh", "bash"]:
                                    targets.append((p.pid, fp))
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            continue
                except Exception as e:
                    debug_log(f"VULN_CHECKER: Error during process scan: {e}")

                if not targets:
                    VULN_IS_FETCHING = False
                    VULN_CONFIG_DATA["last_check_timestamp"] = int(time.time())
                    _save_vuln_config()
                    time.sleep(300)
                    continue

                VULN_LAST_NEW_COUNT = 0
                fetch_status = "success"

                # 3. Part 2 & 3: Match, Fetch, and Prioritize
                # NVD Access Optimization: Querying specific CPEs is more efficient and accurate
                for pid, fp in targets:
                    VULN_STATUS_MSG = f"📡 Checking {fp.product} v{fp.version}..."
                    cpes = self.matcher.match(fp)
                    
                    for cpe in cpes:
                        vulns, status = self._fetch_for_cpe(cpe)
                        if status == "rate_limit":
                            fetch_status = "rate_limit"
                            break
                        
                        for entry in vulns:
                            c = entry.get("cve", {})
                            cve_id = c.get("id")
                            if not cve_id or cve_id in VULN_CONFIG_DATA.get("ignored_cves", []):
                                continue

                            # Thread-safe duplicate check
                            # Ensure we don't spam duplicate CVE IDs across different products
                            with VULN_LOCK:
                                if any(a["cve_id"] == cve_id for a in VULN_PENDING):
                                    continue

                            # Severity Filtering & Robust Scoring (Part 2.1)
                            metrics = c.get("metrics", {})
                            severity = "UNKNOWN"
                            score = 0.0
                            
                            for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                                for m in metrics.get(mkey, []):
                                    data = m.get("cvssData", {})
                                    # V3.x has it in cvssData, V2.0 has it as sibling to cvssData
                                    severity = (data.get("baseSeverity") or m.get("baseSeverity") or "UNKNOWN").upper()
                                    score = data.get("baseScore", 0.0)
                                    if severity != "UNKNOWN": break
                                if severity != "UNKNOWN": break
                            
                            # Final fallback: if score is >= 7.0 but severity still UNKNOWN, it's HIGH
                            if severity == "UNKNOWN" and score >= 7.0:
                                severity = "HIGH"
                            
                            if severity not in ("HIGH", "CRITICAL"):
                                continue

                            # Risk Priority & Enrichment (Part 2.2, 2.3)
                            intel = self.enricher.enrich(cve_id)
                            desc = ""
                            for d in c.get("descriptions", []):
                                if d.get("lang") == "en":
                                    desc = d.get("value", "")[:400]
                                    break

                            alert = {
                                "cve_id": cve_id,
                                "desc": desc,
                                "severity": severity,
                                "pkg": fp.product,
                                "version": fp.version if fp.version not in ("Unknown", "0.0.0") else "Version Undetected",
                                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                "score": score,
                                "confidence": fp.confidence,
                                "is_kev": intel["is_kev"],
                                "epss": intel["epss"],
                                "method": fp.method,
                                "ts": int(time.time()),
                                "pid": pid
                            }
                            VULN_QUEUE.put(alert)
                            VULN_LAST_NEW_COUNT += 1
                        
                        if fetch_status == "rate_limit": break
                    if fetch_status == "rate_limit": break

                VULN_IS_FETCHING = False
                VULN_CONFIG_DATA["last_check_timestamp"] = int(time.time())
                VULN_CONFIG_DATA["last_check_status"] = fetch_status
                _save_vuln_config()

                if fetch_status == "rate_limit":
                    VULN_STATUS_MSG = "⚠ NVD Rate limit reached – Scanning paused."
                    time.sleep(1800) # Wait 30 mins
                else:
                    VULN_STATUS_MSG = ""
                    time.sleep(interval_sec)

            except Exception as e:
                debug_log(f"VULN_CHECKER Error: {e}")
                VULN_IS_FETCHING = False
                time.sleep(60)



def _open_vuln_modal(stdscr):
    """Top-level modal: lists pending HIGH/CRITICAL CVEs with severity badges."""
    # Consume queue first
    while not VULN_QUEUE.empty():
        try:
            item = VULN_QUEUE.get_nowait()
            with VULN_LOCK:
                if not any(a["cve_id"] == item["cve_id"] for a in VULN_PENDING):
                    VULN_PENDING.append(item)
        except: break

    if not VULN_PENDING:
        h, w = stdscr.getmaxyx()
        last_ts = VULN_CONFIG_DATA.get("last_check_timestamp", 0)
        dt_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_ts)) if last_ts > 0 else "Never"
        msg = f" ✅ SECURITY AUDIT: No high-risk vulnerabilities found (Last Scan: {dt_str}) "
        try:
            stdscr.addstr(h // 2, (w - len(msg)) // 2, msg, curses.color_pair(CP_ACCENT) | curses.A_BOLD | curses.A_REVERSE)
            stdscr.refresh()
            time.sleep(1.8)
        except: pass
        return

    sel = 0
    scroll = 0
    while True:
        h, w = stdscr.getmaxyx()
        # Sort pending by score descending
        with VULN_LOCK:
            sorted_vulns = sorted(VULN_PENDING, key=lambda x: x.get('score', 0), reverse=True)
        
        if not sorted_vulns: break
        if sel >= len(sorted_vulns): sel = len(sorted_vulns) - 1

        win_h = min(len(sorted_vulns) + 6, h - 4)
        win_w = min(w - 4, 130)
        start_y = max(1, (h - win_h) // 2)
        start_x = max(1, (w - win_w) // 2)

        try:
            win = curses.newwin(win_h, win_w, start_y, start_x)
            win.bkgd(' ', curses.color_pair(CP_TEXT))
            win.box()
            
            # Legend Header explaining Origin (Part 4.4)
            legend = "[SYSTEM]: Package is installed  |  [PID:X]: Risk detected in running service"
            win.addstr(1, (win_w - len(legend)) // 2, legend, curses.A_DIM | curses.A_ITALIC)
        except: break

        title = " 🛡️  SECURITY ADVISORY — HIGH-RISK VULNERABILITIES "
        footer = " [↑↓] Navigate  [Enter] CVE Details  [i] Ignore  [Esc] Close "
        try:
            win.addstr(0, max(1, (win_w - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
            win.addstr(win_h - 1, max(1, (win_w - len(footer)) // 2), footer, curses.color_pair(CP_TEXT) | curses.A_DIM)
        except: pass

        visible_rows = win_h - 4
        for vi in range(visible_rows):
            idx = scroll + vi
            if idx >= len(sorted_vulns): break
            a = sorted_vulns[idx]
            
            # Severity Badge (Part 4.1) - Show actual severity instead of hardcoded HIGH
            sev = a.get("severity", "UNKNOWN")
            badge = f"[{sev:^10}]"
            if sev == "CRITICAL":
                b_attr = curses.color_pair(CP_WARN) | curses.A_BOLD
            elif sev == "HIGH":
                b_attr = curses.color_pair(CP_WARN)
            else:
                b_attr = curses.color_pair(CP_TEXT) | curses.A_DIM

            kev_flag = "💥" if a.get("is_kev") else "  "
            origin = "[SYSTEM]" if not a.get("pid") else f"[PID:{a.get('pid')}]"
            line_start = f" {kev_flag} {badge} {origin:<10} {a['cve_id']:<15} {a.get('pkg', ''):<15} v{a.get('version', '?.?'):<10} "
            v_score = a.get('score', 0.0)
            score_str = f"Score: {float(v_score):.1f} " if v_score > 0 else "Unrated "
            
            avail_desc = win_w - len(line_start) - len(score_str) - 5
            desc = a.get("desc", "")[:max(0, avail_desc)] + "..."
            
            full_line = f"{line_start}{score_str} {desc}"
            attr = curses.color_pair(CP_ACCENT) | curses.A_REVERSE if idx == sel else curses.color_pair(CP_TEXT)
            
            try:
                win.addstr(vi + 2, 1, full_line[:win_w - 2].ljust(win_w - 2), attr)
                # Apply color to badge if not selected (for contrast)
                if idx != sel:
                    win.addstr(vi + 2, 4, badge, b_attr)
            except: pass

        win.refresh()
        key = stdscr.getch()
        if key in (27, ord('q')): break
        elif key == curses.KEY_UP:
            if sel > 0:
                sel -= 1
                if sel < scroll: scroll = sel
        elif key == curses.KEY_DOWN:
            if sel < len(sorted_vulns) - 1:
                sel += 1
                if sel >= scroll + visible_rows: scroll = sel - visible_rows + 1
        elif key == ord('i'):
            # Ignore
            cve_id = sorted_vulns[sel]["cve_id"]
            VULN_CONFIG_DATA.setdefault("ignored_cves", []).append(cve_id)
            with VULN_LOCK:
                VULN_PENDING[:] = [v for v in VULN_PENDING if v["cve_id"] != cve_id]
            VULN_CONFIG_DATA["pending_vulns"] = list(VULN_PENDING)
            _save_vuln_config()
        elif key in (10, 13, curses.KEY_ENTER):
            _open_vuln_detail(stdscr, sorted_vulns[sel])
            # Check if alert was ignored inside detail
            with VULN_LOCK:
                VULN_PENDING[:] = [v for v in VULN_PENDING if v["cve_id"] not in VULN_CONFIG_DATA.get("ignored_cves", [])]
            if not VULN_PENDING: break

    stdscr.touchwin()
    stdscr.refresh()

def _open_vuln_detail(stdscr, alert):
    """Deep-dive CVE Panel with KEV and EPSS data."""
    while True:
        h, w = stdscr.getmaxyx()
        win_h = 24
        win_w = min(w - 2, 100)
        start_y = (h - win_h) // 2
        start_x = (w - win_w) // 2

        try:
            win = curses.newwin(win_h, win_w, start_y, start_x)
            win.bkgd(' ', curses.color_pair(CP_TEXT))
            win.box()
        except: break

        title = f" 🔍  VULNERABILITY DETAIL: {alert['cve_id']} "
        try:
            win.addstr(0, max(1, (win_w - len(title)) // 2), title, curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except: pass

        y = 2
        def add_field(label, value, attr=None, val_attr=None):
            nonlocal y
            try:
                win.addstr(y, 2, f"{label:<18}: ", attr or curses.color_pair(CP_ACCENT))
                win.addstr(y, 20, str(value), val_attr or curses.color_pair(CP_TEXT))
                y += 1
            except: pass

        add_field("PRODUCT", alert.get("pkg", "Unknown"))
        # Use a more accurate fallback than "Scan Failed"
        v_disp = alert.get("version", "Version Undetected")
        add_field("DETECTED VERSION", v_disp if v_disp != "Unknown" else "Not Detected")
        
        sev = alert.get("severity", "UNKNOWN")
        s_attr = curses.color_pair(CP_WARN) | curses.A_BOLD if sev in ("HIGH", "CRITICAL") else curses.color_pair(CP_TEXT)
        add_field("SEVERITY", sev, val_attr=s_attr)
        
        score = alert.get('score', 0.0)
        score_disp = f"{score:.1f}" if score > 0 else "Awaiting Analysis (New CVE)"
        add_field("BASE SCORE", score_disp)
        
        # Threat Intel enrichment placeholders (Part 2.3)
        is_kev = alert.get("is_kev")
        epss = alert.get("epss", 0.0)
        
        if is_kev:
            add_field("KNOWN EXPLOITED", "⚠️ YES (CISA KEV List)", val_attr=curses.color_pair(CP_WARN) | curses.A_BOLD)
        
        if epss > 0.01: # Only show if statistically significant
            add_field("EPSS SCORE", f"{epss:.4f} (Likelihood of Exploit)")
        
        method = alert.get('method', 'pattern')
        method_map = {
            "dpkg": "System Package", 
            "rpm": "System Package", 
            "dpkg-path": "Package Ownership lookup",
            "cmdline": "Command Line Inspection", 
            "probe": "Direct Binary Probe",
            "pattern": "Heuristic Pattern Match"
        }
        method_disp = method_map.get(method, f"Match: {method}")
        conf = alert.get('confidence', 0.5) * 100
        add_field("MATCH METHOD", f"{method_disp} ({conf:.0f}% confidence)")
        y += 1
        
        # Description
        try:
            win.addstr(y, 2, "DESCRIPTION:", curses.color_pair(CP_ACCENT) | curses.A_BOLD)
            y += 2
            desc_text = alert.get("desc", "No description available.")
            desc_lines = textwrap.wrap(desc_text, win_w - 6)
            for line in desc_lines[:10]:
                win.addstr(y, 3, line)
                y += 1
        except: pass

        footer = " [o] Open in Browser  [i] Ignore  [Esc/q] Back "
        try:
            win.addstr(win_h - 1, (win_w - len(footer)) // 2, footer, curses.color_pair(CP_TEXT) | curses.A_DIM)
        except: pass

        win.refresh()
        key = stdscr.getch()
        if key in (27, ord('q')): break
        elif key == ord('o'):
            safe_open_url(alert.get("link", f"https://nvd.nist.gov/vuln/detail/{alert['cve_id']}"))
        elif key == ord('i'):
            VULN_CONFIG_DATA.setdefault("ignored_cves", []).append(alert["cve_id"])
            _save_vuln_config()
            break

    stdscr.touchwin()
    stdscr.refresh()


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
    check_python_version()
    init_config()
    args = parse_args()

    # Daemon mode logic
    if args.daemon or (CONFIG.get("daemon_enabled") and not sys.stdin.isatty()):
        check_witr_exists()
        run_daemon()
        return

    # Check terminal size after args so --help works in small terminals
    check_and_show_terminal_size_then_exit()
    check_witr_exists()
    
    if args.no_update:
        CONFIG["auto_update_services"] = False

    # Load persistent ignored-CVE config
    _load_vuln_config()
    
    # We no longer purge items automatically to avoid "disappearing" findings.
    # The scanner will simply filter for HIGH/CRITICAL for NEW detections.
    # Existing findings stay until ignored by the user.

    # Start background vulnerability scanner (optional API key from CONFIG)
    _vuln_api_key = CONFIG.get("nvd_api_key")
    _vuln_thread = VulnerabilityChecker(api_key=_vuln_api_key)
    _vuln_thread.start()
    debug_log("VULN_CHECKER: Background vulnerability scanner started.")

    curses.wrapper(main, args)


if __name__ == "__main__":
    # developer entry python heimdall.py
    cli_entry()