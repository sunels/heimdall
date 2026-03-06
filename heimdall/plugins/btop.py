import os
import subprocess
import shutil
import curses

class Plugin:
    name = "Btop"
    description = "Btop sistem monitörünü tam ekran çalıştır"
    tool_command = "btop"
    # fullscreen mode: curses is suspended, tool runs natively
    mode = "fullscreen"

    def __init__(self, heimdall_instance):
        self.h = heimdall_instance

    def _find_command(self):
        """Resolve the full path to the tool command."""
        cmd_path = shutil.which(self.tool_command)
        if cmd_path:
            return cmd_path
        # If running via sudo, check the original user's local bin
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user:
            local_bin = os.path.expanduser(f"~{sudo_user}/.local/bin/{self.tool_command}")
            if os.path.exists(local_bin):
                return local_bin
        return self.tool_command  # fallback

    def run_fullscreen(self, stdscr):
        """
        Temporarily suspend curses and run the tool with FULL native
        terminal access. Colors, mouse, scrollbars - everything works
        exactly like running the tool standalone.
        """
        cmd_path = self._find_command()

        # Suspend curses - gives terminal back to the tool
        curses.endwin()

        try:
            env = os.environ.copy()
            env['TERM'] = os.environ.get('TERM', 'xterm-256color')
            subprocess.call([cmd_path], env=env)
        except FileNotFoundError:
            from heimdall.plugins._command_viewer import CommandViewerPlugin
            hint = CommandViewerPlugin._install_hint(self.tool_command)
            print(f"\n  ⚠️  '{self.tool_command}' bulunamadı. Kurulum: {hint}")
            print("  Devam etmek için Enter'a basın...")
            input()
        except Exception as e:
            print(f"\n  ⚠️  Hata: {e}")
            print("  Devam etmek için Enter'a basın...")
            input()
        finally:
            # Restore curses
            stdscr.refresh()

    # Legacy stubs (kept for compatibility, not used in fullscreen mode)
    def start(self):
        pass

    def stop(self):
        pass

    def render(self, tab_win):
        pass

    def on_key(self, key):
        pass
