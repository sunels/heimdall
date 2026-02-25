import os
import pty
import subprocess
import threading
import select
import curses
import fcntl
import termios
import struct
import pyte

class Plugin:
    name = "Lazydocker"
    description = "Lazydocker container management tool embed it"
    tool_command = "lazydocker"
    shortcuts = {"q": "Quit tool", "r": "Refresh"}
    panes = [
        {"name": "Main Tool Pane", "type": "embed", "position": "full", "width": 1.0, "height": 0.9},
        {"name": "Shortcuts/Help", "type": "list", "position": "bottom", "height": 0.1}
    ]

    def __init__(self, heimdall_instance):
        self.h = heimdall_instance
        self.process = None
        self.master_fd = None
        self.slave_fd = None
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
        self.max_r = 24
        self.max_c = 80
        self.screen = pyte.Screen(self.max_c, self.max_r)
        self.stream = pyte.Stream(self.screen)

    def start(self):
        if self.running: return
        self.running = True
        self.master_fd, self.slave_fd = pty.openpty()
        
        env = os.environ.copy()
        env['TERM'] = 'vt100'  # basic term to avoid complex escape chars if possible
        
        import shutil
        cmd_path = shutil.which(self.tool_command)
        if not cmd_path:
            # If running via sudo, PATH is often restricted. Check the original user's local bin.
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                local_bin = os.path.expanduser(f"~{sudo_user}/.local/bin/{self.tool_command}")
                if os.path.exists(local_bin):
                    cmd_path = local_bin
            if not cmd_path:
                cmd_path = self.tool_command # fallback
        
        def set_ctty():
            os.setsid()
            try:
                fcntl.ioctl(self.slave_fd, termios.TIOCSCTTY, 0)
            except Exception:
                pass

        try:
            self.process = subprocess.Popen(
                [cmd_path],
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                env=env,
                preexec_fn=set_ctty
            )
        except Exception as e:
            with self.lock:
                self.stream.feed(f"Error starting {self.tool_command}: {e}\n")
            return

        self.thread = threading.Thread(target=self._read_output, daemon=True)
        self.thread.start()

    def _set_pty_size(self, lines, cols):
        if self.master_fd is not None:
            if lines != self.max_r or cols != self.max_c:
                self.max_r = lines
                self.max_c = cols
                with self.lock:
                    self.screen.resize(lines, cols)
            try:
                winsize = struct.pack("HHHH", lines, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), 15)
                self.process.wait(timeout=1)
            except:
                pass
            self.process = None
        
        if self.master_fd is not None:
            try: os.close(self.master_fd)
            except: pass
            self.master_fd = None
            
        if self.slave_fd is not None:
            try: os.close(self.slave_fd)
            except: pass
            self.slave_fd = None

    def _read_output(self):
        while self.running and self.master_fd is not None:
            r, _, _ = select.select([self.master_fd], [], [], 0.5)
            if self.master_fd in r:
                try:
                    data = os.read(self.master_fd, 4096)
                    if not data:
                        break
                    
                    text = data.decode('utf-8', errors='ignore')
                    with self.lock:
                        self.stream.feed(text)
                except OSError:
                    break
            else:
                pass

    def render(self, tab_win):
        h, w = tab_win.getmaxyx()
        pty_h = max(24, h)
        pty_w = max(80, w)
        self._set_pty_size(pty_h, pty_w)
        
        tab_win.erase()
        
        with self.lock:
            for i in range(h):
                if i < self.max_r:
                    line = self.screen.display[i]
                    try:
                        tab_win.addstr(i, 0, line[:w-1])
                    except:
                        pass
                        
        tab_win.noutrefresh()

    def on_key(self, key):
        if self.master_fd is not None:
            try:
                # To pty, we write strings of the char
                os.write(self.master_fd, chr(key).encode('utf-8'))
            except Exception:
                pass

    def on_maximize_pane(self, pane_name):
        pass
