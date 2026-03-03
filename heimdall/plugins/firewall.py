from heimdall.plugins._command_viewer import CommandViewerPlugin


class Plugin(CommandViewerPlugin):
    name             = "Firewall"
    description      = "Active iptables / nftables rules"
    tabTitle         = "Firewall Rules"
    tool_command     = None             # both iptables and nft checked at runtime
    refresh_interval = 60
    shell_command    = (
        "if command -v iptables >/dev/null 2>&1; then "
        "  echo '── iptables ──'; iptables -L -v -n --line-numbers 2>/dev/null; "
        "  echo ''; echo '── iptables NAT ──'; iptables -t nat -L -v -n 2>/dev/null; "
        "fi; "
        "if command -v nft >/dev/null 2>&1; then "
        "  echo ''; echo '── nftables ──'; nft list ruleset 2>/dev/null; "
        "fi; "
        "command -v iptables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1 || "
        "echo 'No firewall tools found (iptables / nft)'"
    )
