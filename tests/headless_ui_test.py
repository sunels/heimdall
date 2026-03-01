import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import datetime

# Mock curses before importing heimdall
sys.modules['curses'] = MagicMock()
sys.modules['curses.textpad'] = MagicMock()

# Import heimdall
from heimdall import draw_http_summary_modal

class TestHeadlessUI(unittest.TestCase):
    def test_http_summary_modal_rendering(self):
        """Mocks the entire curses UI to catch NameError/AttributeError in modal logic."""
        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (24, 80)
        
        # Mock window and its methods
        win = MagicMock()
        win.getmaxyx.return_value = (18, 70)
        # Mock getch to return ESC after first render to break loop
        win.getch.side_effect = [27] 
        
        with patch('curses.newwin', return_value=win):
            with patch('subprocess.Popen') as mock_popen:
                # Mock a running process
                mock_proc = MagicMock()
                mock_proc.stdout.read.return_value = ""
                mock_popen.return_value = mock_proc
                
                conn_info = {
                    'prog': 'test_proc',
                    'pid': 1234,
                    'remote_ip': '1.1.1.1',
                    'remote_port': 80
                }
                
                print("Testing draw_http_summary_modal for NameErrors...")
                try:
                    draw_http_summary_modal(stdscr, conn_info)
                    print("✅ No NameError or basic render errors found in draw_http_summary_modal.")
                except Exception as e:
                    self.fail(f"❌ Modal crashed with error: {e}")

if __name__ == "__main__":
    unittest.main()
