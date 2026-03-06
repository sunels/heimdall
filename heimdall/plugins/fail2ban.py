from heimdall.plugins._command_viewer import CommandViewerPlugin


class Plugin(CommandViewerPlugin):
    name             = "Fail2Ban"
    description      = "Banned IPs and jail status (via fail2ban-client)"
    tabTitle         = "Fail2Ban"
    tool_command     = "fail2ban-client"   # skip if fail2ban not installed
    refresh_interval = 60

    def __init__(self, heimdall_instance):
        hint = self._install_hint("fail2ban")
        self.shell_command = (
            "fail2ban-client status 2>/dev/null && echo '' && "
            "echo '── Active Bans ──' && "
            "fail2ban-client banned 2>/dev/null || "
            f"echo 'Fail2Ban not installed  →  {hint}'"
        )
        super().__init__(heimdall_instance)
