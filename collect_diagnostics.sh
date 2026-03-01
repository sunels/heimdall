#!/bin/bash

# Diagnostic script for Heimdall crash and logout investigation
# This script collects system logs and state around the time of the incident.

LOG_FILE="heimdall_diagnostic_$(date +%Y%m%d_%H%M%S).log"
echo "--- HEIMDALL DIAGNOSTIC REPORT ---" > "$LOG_FILE"
echo "Generated at: $(date)" >> "$LOG_FILE"
echo "----------------------------------" >> "$LOG_FILE"

echo -e "\n[1] System Information" >> "$LOG_FILE"
uname -a >> "$LOG_FILE"
uptime >> "$LOG_FILE"

echo -e "\n[2] Last Login/Logout Events" >> "$LOG_FILE"
last -n 20 >> "$LOG_FILE"

echo -e "\n[3] Heimdall Debug Logs (Last 100 lines)" >> "$LOG_FILE"
tail -n 100 ~/.config/heimdall/debug.log >> "$LOG_FILE" 2>/dev/null || echo "No debug.log found" >> "$LOG_FILE"

echo -e "\n[4] System Logs (Journalctl - Last 200 lines)" >> "$LOG_FILE"
journalctl -n 200 >> "$LOG_FILE"

echo -e "\n[5] Xorg/Display Server Logs (Potential logout reason)" >> "$LOG_FILE"
grep -i "error" /var/log/Xorg.0.log >> "$LOG_FILE" 2>/dev/null || echo "No Xorg logs found or accessible" >> "$LOG_FILE"

echo -e "\n[6] Dmesg (Kernel Errors)" >> "$LOG_FILE"
dmesg | tail -n 100 >> "$LOG_FILE"

echo -e "\n[7] Resource Usage around crash" >> "$LOG_FILE"
free -h >> "$LOG_FILE"
df -h >> "$LOG_FILE"

echo -e "\nDiagnostic collection complete: $LOG_FILE"
echo "Please provide this file to the diagnostic agent."
