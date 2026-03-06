from heimdall.plugins._command_viewer import CommandViewerPlugin


class Plugin(CommandViewerPlugin):
    name             = "Disk Health"
    description      = "SMART values and health status for all disks (via smartctl)"
    tabTitle         = "SMART Health"
    tool_command     = "smartctl"       # skip if smartctl not installed
    refresh_interval = 300              # 5 minutes — disk queries are slow

    def __init__(self, heimdall_instance):
        hint = self._install_hint("smartmontools")
        self.shell_command = (
            "smartctl --scan-open 2>/dev/null | awk '{print $1}' | "
            "xargs -I {} sh -c 'echo \"══════════════════════════════\"; "
            "echo \"Disk: {}\"; echo \"══════════════════════════════\"; "
            "smartctl -a {} 2>/dev/null; echo' "
            f"|| echo 'smartctl not installed  →  {hint}'"
        )
        super().__init__(heimdall_instance)
