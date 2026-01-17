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

KEY_SEP_UP = ord('+')
KEY_SEP_DOWN = ord('-')
KEY_TAB = 9
KEY_FIREWALL = ord('f')

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
    parser.add_argument('--version', action='version', version='portwitr-interactive 2.0')
    return parser.parse_args()

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
    """Return CPU%/MEM formatted as MB or GB"""
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

# --------------------------------------------------
# Splash Screen
# --------------------------------------------------
def splash_screen(stdscr, rows, cache):
    h, w = stdscr.getmaxyx()
    bh, bw = 9, min(72, w - 4)
    y, x = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y, x)
    total = len(rows)
    for i, row in enumerate(rows, 1):
        port = row[0]
        win.erase()
        win.box()
        title = " Initializing Port / Process Viewer "
        win.addstr(0, (bw - len(title)) // 2, title, curses.A_BOLD)
        win.addstr(2, 3, "Collecting data...")
        win.addstr(4, 3, f"Port: {port}")
        bar_w = bw - 10
        filled = int(bar_w * i / total)
        bar = "█" * filled + " " * (bar_w - filled)
        win.addstr(6, 4, f"[{bar}]")
        win.addstr(7, bw - 12, f"{i}/{total}")
        win.refresh()
        lines = get_witr_output(port)
        cache[port] = {
            "user": extract_user_from_witr(lines),
            "process": extract_process_from_witr(lines),
            "lines": lines,
            "wrapped": []
        }
    win.erase()
    win.box()
    done = " Initialization Complete "
    win.addstr(bh // 2, (bw - len(done)) // 2, done, curses.A_BOLD)
    win.refresh()
    time.sleep(0.8)
    stdscr.clear()
    stdscr.refresh()

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
    win.box()
    win.addstr(1, 2, question, curses.A_BOLD)
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
    h, w = stdscr.getmaxyx()
    win_h, win_w = 3, min(60, w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h)//2, (w - win_w)//2)
    win.box()
    win.addstr(1, 2, msg)
    win.refresh()
    stdscr.timeout(int(duration*1000))
    stdscr.getch()
    stdscr.timeout(-1)

# --------------------------------------------------
# UI Draw
# --------------------------------------------------
# --------------------------------------------------
# UI Draw (Güncellenmiş)
# --------------------------------------------------
# --------------------------------------------------
# UI Draw (Düzeltilmiş)
# --------------------------------------------------
def draw_table(win, rows, selected, offset, cache, firewall_status):
    win.erase()
    h, w = win.getmaxyx()
    # Header
    headers = ["🌐 PORT", "PROTO", "📊 USAGE [Mem/CPU]", "🧠 PROCESS", "👤 USER"]
    widths = [10, 8, 18, 28, w - 68]  # PORT-PROTO arası boşluk artırıldı, PROCESS-USER arası azaltıldı
    x = 1
    for htxt, wd in zip(headers, widths):
        win.addstr(1, x, htxt.ljust(wd), curses.A_BOLD)
        x += wd
    win.hline(2, 1, curses.ACS_HLINE, w - 2)

    for i in range(h - 4):
        idx = offset + i
        if idx >= len(rows):
            break
        attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
        port, proto, pidprog, prog, pid = rows[idx]
        usage = get_process_usage(pid)
        user = cache.get(port, {}).get("user", "-")
        # Process ikon seçimi: root vs normal
        proc_icon = "👑" if user=="root" else "🧑"
        # TCP/UDP ikon sadece PROTO header altında
        fw_icon = "⚡" if firewall_status.get(port, True) else "⛔"
        data = [f"{fw_icon} {port}", proto.upper(), usage, f"{proc_icon} {prog}", f"👤 {user}"]
        x = 1
        for val, wd in zip(data, widths):
            win.addstr(i+3, x, val[:wd].ljust(wd), attr)
            x += wd
    win.box()
    win.noutrefresh()

def draw_detail(win, lines, scroll=0):
    win.erase()
    h, w = win.getmaxyx()
    header = f"📝 Detail View — {len(lines)} lines"
    win.addstr(1, 2, header, curses.A_BOLD)
    win.hline(2, 1, curses.ACS_HLINE, w - 2)
    max_rows = h - 4

    # ikon eşlemesi
    icons = {
        "Target": "🎯",
        "Container": "🐳",
        "Command": "🧠",
        "Started": "⏱ ",
        "Why it Exists": "🧠",
        "Source": "📦",
        "Working Dir": "🗂 ",
        "Listening": "👂",
        "Socket": "🔌",
        "Warnings": "⚠️ ",
        "PID": "🆔",
        "User": "👤",
        "Process": "🧠"
    }

    for i in range(max_rows):
        idx = scroll + i
        if idx >= len(lines):
            continue
        line = lines[idx]
        # Her satır türüne ikon ekle
        for key, icon in icons.items():
            if key in line:
                line = line.replace(key, f"{icon} {key}")
        win.addstr(i+3, 2, line[:w-4])
    win.box()
    win.noutrefresh()


def draw_open_files(win, pid, prog, files, scroll=0):
    win.erase()
    h, w = win.getmaxyx()
    header = f"📂 Open Files — PID {pid}/{prog} ({len(files)})"
    win.addstr(1, 2, header, curses.A_BOLD)
    win.hline(2, 1, curses.ACS_HLINE, w - 2)
    max_rows = h - 4
    for i in range(max_rows):
        idx = scroll + i
        if idx >= len(files):
            continue
        fd, path = files[idx]
        win.addstr(i+3, 2, f"{idx+1:3d}. [{fd}] {path}")
    win.box()
    win.noutrefresh()

def draw_help_bar(stdscr, show_detail):
    h, w = stdscr.getmaxyx()
    if show_detail:
        help_text = " 🧭 ↑/↓ Scroll   [Tab] Maximize/Restore Witr Pane   ❌ Quit "
    else:
        help_text = (" 🧭 ↑/↓ Select   ↕️ +/- Resize   🔄 r Refresh   "
                     "📂 ←/→ Open Files Scroll   ⛔ s Stop Proc/Service   🔥 f Toggle Firewall   ❌ q Quit ")
    bar_win = curses.newwin(3, w, h-3, 0)
    bar_win.erase()
    bar_win.box()
    x = max(1, (w - len(help_text)) // 2)
    try:
        bar_win.addstr(1, x, help_text, curses.A_BOLD)
    except:
        bar_win.addstr(1, x, help_text)
    bar_win.noutrefresh()

# --------------------------------------------------
# Main Loop
# --------------------------------------------------
def main(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)

    rows = parse_ss()
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
    cached_wrapped_lines = []
    cached_total_lines = 0

    while True:
        h, w = stdscr.getmaxyx()
        max_h = h-3-2
        min_h = 6
        visible_rows = table_h-4

        if not show_detail and rows:
            table_win = curses.newwin(table_h, w//2, 0, 0)
            draw_table(table_win, rows, selected, offset, cache, firewall_status)

            open_files_win = curses.newwin(table_h, w-w//2, 0, w//2)
            pid = rows[selected][4] if selected>=0 else "-"
            prog = rows[selected][3] if selected>=0 else "-"
            files = get_open_files(pid)
            draw_open_files(open_files_win, pid, prog, files, scroll=open_files_scroll)

            detail_win = curses.newwin(h-table_h-3, w, table_h, 0)
            if selected>=0 and rows:
                port = rows[selected][0]
                if cached_port != port:
                    cached_port = port
                    lines = get_witr_output(port)
                    lines = annotate_warnings(lines)
                    wrapped = []
                    for l in lines:
                        wrapped += textwrap.wrap(l, width=w-4) or [""]
                    cached_wrapped_lines = wrapped
                    cached_total_lines = len(wrapped)
                draw_detail(detail_win, cached_wrapped_lines, scroll=detail_scroll)
            else:
                draw_detail(detail_win, [], scroll=0)

            draw_help_bar(stdscr, show_detail)
            total_detail_lines = cached_total_lines

        elif show_detail:
            detail_win = curses.newwin(h-3, w, 0, 0)
            draw_detail(detail_win, cached_wrapped_lines, scroll=detail_scroll)
            draw_help_bar(stdscr, show_detail)
            total_detail_lines = cached_total_lines

        curses.doupdate()
        k = stdscr.getch()

        if k == ord('q'):
            break
        if show_detail:
            if k == curses.KEY_UP and detail_scroll>0:
                detail_scroll -= 1
            elif k == curses.KEY_DOWN and detail_scroll < max(0,total_detail_lines-(h-3)):
                detail_scroll += 1
            elif k == KEY_TAB:
                show_detail = False
                detail_scroll = 0
        else:
            if k == curses.KEY_UP and selected>0:
                selected -=1
            elif k == curses.KEY_DOWN and selected<len(rows)-1:
                selected +=1
            elif k == KEY_SEP_UP and table_h<max_h:
                table_h +=1
            elif k == KEY_SEP_DOWN and table_h>min_h:
                table_h -=1
            elif k == ord('r'):
                rows = parse_ss()
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
                    cache.clear()
                    splash_screen(stdscr, rows, cache)
                    if selected >= len(rows):
                        selected = len(rows) - 1
            elif k == KEY_FIREWALL and selected >= 0 and rows:
                port = rows[selected][0]
                toggle_firewall(port, stdscr, firewall_status)

            if selected >= len(rows):
                selected = len(rows) - 1
            if selected < 0 and rows:
                selected = 0
            offset = min(max(selected - visible_rows // 2, 0), max(0, len(rows) - visible_rows))

if __name__ == "__main__":
    check_python_version()
    check_witr_exists()
    parse_args()
    curses.wrapper(main)
