from heimdall.plugins._command_viewer import CommandViewerPlugin


class Plugin(CommandViewerPlugin):
    name             = "ZFS"
    description      = "ZFS pool status, scrub progress and ARC cache stats"
    tabTitle         = "ZFS Pools"
    tool_command     = "zpool"          # skip if zpool not installed
    refresh_interval = 60
    shell_command    = (
        "zpool status && echo '' && echo '── ARC Summary ──' && "
        "arc_summary 2>/dev/null || echo 'ZFS not installed or no pools configured'"
    )
