"""
_command_viewer.py
------------------
Generic base class for "read-only command output" plugins.
Used by: zfs.py, smartctl.py, fail2ban.py, firewall.py

These are NOT interactive TUIs (like btop/lazydocker).
Instead they run a shell command and display the output in a
scrollable curses pane inside Heimdall, with auto-refresh.

Plugin authors inherit this class and set class-level attributes:
    name             -- display name
    description      -- short description
    tabTitle         -- tab bar label (can differ from name)
    tool_command     -- used by load_plugins() to check if tool is installed
                        (set to None to skip the availability check)
    shell_command    -- the full shell command string to run
    refresh_interval -- seconds between auto-refreshes (default 60)
    mode             -- must be "command_viewer" (used by main loop)
"""

import subprocess
import time
import curses


class CommandViewerPlugin:
    # ── Override in subclasses ────────────────────────────────────────────────
    name             = "Command Output"
    description      = "Runs a command and shows its output"
    tabTitle         = "Output"
    tool_command     = None          # Set to first word of command for availability check
    shell_command    = "echo hello"  # Full shell command
    refresh_interval = 60            # Seconds between auto-refresh
    mode             = "command_viewer"
    # ─────────────────────────────────────────────────────────────────────────

    def __init__(self, heimdall_instance):
        self.h            = heimdall_instance
        self._lines       = ["Loading…"]
        self._last_run    = 0.0
        self._scroll      = 0
        self._running     = False

    # ── Public interface (called by main loop) ────────────────────────────────

    def start(self):
        self._running  = True
        self._scroll   = 0
        self._last_run = 0.0   # force immediate refresh on first render

    def stop(self):
        self._running = False

    def render(self, tab_win):
        """Draw the command output inside *tab_win* (a curses sub-window)."""
        now = time.time()
        if now - self._last_run >= self.refresh_interval:
            self._refresh_output()

        h, w = tab_win.getmaxyx()
        tab_win.erase()

        max_scroll = max(0, len(self._lines) - (h - 3))
        self._scroll = max(0, min(self._scroll, max_scroll))

        # ── Header bar ────────────────────────────────────────────────────
        try:
            elapsed = int(now - self._last_run)
            next_in  = max(0, self.refresh_interval - elapsed)
            header   = f" {self.tabTitle}  │  Lines: {len(self._lines)}  │  Refresh in {next_in}s  │  [↑↓/PgUp/PgDn] scroll  [r] refresh "
            tab_win.addstr(0, 0, header[:w - 1], curses.A_REVERSE)
        except Exception:
            pass

        # ── Content ────────────────────────────────────────────────────────
        visible = h - 3
        for idx in range(visible):
            line_no = self._scroll + idx
            if line_no >= len(self._lines):
                break
            try:
                tab_win.addstr(1 + idx, 0, self._lines[line_no][:w - 1])
            except Exception:
                pass

        # ── Footer / scrollbar indicator ───────────────────────────────────
        try:
            pct     = int(100 * self._scroll / max(1, len(self._lines) - visible))
            footer  = f" {pct:3d}%  line {self._scroll + 1}/{len(self._lines)} "
            tab_win.addstr(h - 2, 0, footer[:w - 1], curses.A_DIM)
        except Exception:
            pass

        tab_win.noutrefresh()

    def on_key(self, key):
        """Handle navigation keys forwarded from the main loop."""
        page = 20
        if key in (curses.KEY_UP, ord('k')):
            self._scroll = max(0, self._scroll - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            self._scroll += 1          # clamped in render()
        elif key in (curses.KEY_PPAGE, ord('b')):
            self._scroll = max(0, self._scroll - page)
        elif key in (curses.KEY_NPAGE, ord('f'), ord(' ')):
            self._scroll += page       # clamped in render()
        elif key in (curses.KEY_HOME, ord('g')):
            self._scroll = 0
        elif key in (curses.KEY_END, ord('G')):
            self._scroll = max(0, len(self._lines) - 1)
        elif key == ord('r'):
            self._last_run = 0.0       # force refresh

    # ── Internal ──────────────────────────────────────────────────────────────

    def _refresh_output(self):
        try:
            result = subprocess.run(
                self.shell_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + (result.stderr if result.returncode != 0 else "")
            if not output.strip():
                output = f"(No output from command)\n{self.shell_command}"
            self._lines    = output.splitlines()
            self._last_run = time.time()
        except subprocess.TimeoutExpired:
            self._lines    = ["⚠️  Command timed out (30s)", f"  Command: {self.shell_command}"]
            self._last_run = time.time()
        except Exception as e:
            self._lines    = [f"⚠️  Error running command: {e}", f"  Command: {self.shell_command}"]
            self._last_run = time.time()
