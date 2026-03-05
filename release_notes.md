## 📋 Log Explorer & Unified Log Auditing (v1.8.0)

This release introduces the **Log Explorer Modal**, a unified interface for system-wide log auditing that aggregates everything from Systemd Journals to raw `/var/log` files into a single, highly interactive workspace.

### **✨ New Features (v1.8.0)**
- **Unified Log Explorer (`l` / `j`)**: A comprehensive multi-tabbed interface for system logs.
  - **Tab 1: Systemd Journal**: Failed services and critical unit logs.
  - **Tab 2: rsyslog**: Syslog service state and tailing of `/var/log/syslog`.
  - **Tab 3: /var/log Directory**: Browse, inspect, and tail any log file by size and modification date.
  - **Tab 4: journalctl Deep Dive**: Pre-filtered urgent errors (`-p err`) across all boot namespaces and vacuuming ops.
  - **Tab 5: dmesg (Kernel Logs)**: Human-readable ring buffer output and real-time buffer trailing.
  - **Tab 6: logrotate Management**: View rotation status and trigger forced rotations instantly.
- **Background Intelligence**: All log fetches and streams run non-blocking via threaded workers, ensuring instant UI responsiveness.
- **Export & Filtering**: Native capability to run `grep`-like real-time filtering and save outputs to `$HOME` for deep forensic analysis.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-40.png" alt="heimdall log explorer" width="100%"/>

## 📔 Systemd Journal Auditing & Real-time Logs (v1.7.0)

This release introduces native support for auditing system-wide events and service failures directly within the Heimdall interface.

### **✨ New Features (v1.7.0)**
- **Systemd Journal Logs (l/j)**: New high-priority modal for real-time log auditing.
- **Fail-Fast Service Monitoring**: Automatically identifies and lists failing systemd units with one-click inspection.
- **Sentinel Log Integration**: Behavioral engine now monitors journal logs for failure patterns (Killed, OOM, Auth Denied) and flags them with high urgency.
- **Contextual Live Tail**: Real-time `journalctl -f` integration with smart filtering and semantic syntax highlighting.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-39.png" alt="heimdall journal logs" width="100%"/>

## 🐋 Docker Testing & Security Hardening (v1.6.0)

This release focuses on easing the adoption of Heimdall with Docker and hardening the project's security via GitHub Advanced Security.

### **✨ New Features (v1.6.0)**
- **Quick Testing in Docker**: Added a one-liner Alpine-based Docker command for isolated testing without host contamination.
- **GitHub Advanced Security**: Fully integrated CodeQL (SAST), Dependabot (SCA), and Secret Scanning into the project core.

### **🔧 CI/CD & Documentation**
- **Enhanced Release Script**: Improved extraction of release notes for cleaner GitHub Releases.
- **Standalone Binary Fixes**: Resolved path issues in PyInstaller build process for the Steam Deck/Atomic Linux package.

## �🛡️ Guardian Mode & Multi-layered Protection (v1.5.0)

This major release introduces **Guardian Mode**, a high-performance autonomous mitigation engine, along with a re-architected multi-layered security stack.

### **✨ New Features (v1.5.0)**
- **Guardian Mode (g)**: Autonomous threat response for zero-latency mitigation.
- **Forensics Vault**: Automatically captures deep forensic evidence (Env Vars, Open Files, Connections, Ancestry) into a JSON report before process termination.
- **Autonomous Tree Strikes**: Instant nuclear termination for high-risk script-managed threats.
- **SMTP Security Alerts**: Real-time email notifications with threat metadata and forensic links.
- **Secure Credential Storage**: Password obfuscation (Base64) and hardened file permissions (600) for SMTP settings.
- **Multi-layered Security Stack**: Consolidated documentation and logic for Daemon Mode, Active TUI Protection, and Guardian Mode.
- **Enhanced Journal Logging**: Detailed audit trail for all mitigation and forensic operations.
- **Visual Status Bar**: Matrix-style "Robotic Typist" status animation during active Guardian oversight.

### **🔧 Improvements & Security**
- **KeyError Fix**: Resolved a critical dictionary key mismatch in the Guardian interception logic.
- **Enhanced Settings Modal**: Dedicated, masked password field for improved UX and privacy.
- **SMTP Diagnostics**: Improved logging for troubleshooting email configuration issues (Gmail App Passwords).

## 📜 User Intelligence & history Tail (v1.3.3)

This release significantly expands user-level diagnostics with deep command history tracking and real-time history tailing.

### **✨ New Features (v1.3.3)**
- **User History Tail (`t`)**: Press 't' while the User Profile pane is active to instantly tail the owner's `.bash_history`.
- **Deep History Buffer**: Command history capture increased to 1000 lines for a more comprehensive "Allah ne verdiyse" view.
- **Improved Header**: The "Open Files" pane now explicitly shows the program name and PID for better navigation.
- **Expanded User Pane**: Increased default height and improved layout for better command visibility.
- **Optimized Layout**: Adjusted startup layout to give 3 additional lines to the main process table, reducing the initial detail pane height.
- **Context-Aware Tail**: The 't' shortcut now intelligently handles different panes (Open Files, User Profile, or Main Table) even when maximized.

### **🔧 Bug Fixes**
- **Tail Selection Crash**: Fixed a `NameError: path` in the file selection modal that caused Heimdall to crash when choosing a file to tail.
- **Inspection Export Fix**: Resolved a bug where exporting data in the System Inspection modal provided no visual feedback and fixed the auto-closing behavior.
- **Outbound Export Fix**: Resolved a bug where exporting data in the Outbound Connections modal provided no visual feedback and fixed conflicting shortcuts (Filter vs File Tail).
- **Binary Detection**: Improved heuristic handling in the file selection list to correctly identify and iconize binary files.

## 🌍 Deep Context & Stream Redirections (v1.0.9)

This release introduces deeper process introspection with Environment Variables and I/O Redirection tracking, along with a high-density Open Files pane.

### **✨ New Features (v1.0.9)**
- **Process Environment Variables (`e`)**: View the full `environ` block for any running process directly in the TUI.
- **Process Redirections (`u`)**: Track process standard streams (`stdin`, `stdout`, `stderr`) and their targets (files, pipes, sockets).
- **Live Stream Tail**: Launch a live tail directly from the Redirections modal if stdout/stderr points to a file.
- **Enhanced Open Files Pane**: 
  - **Type Column**: Categorization with icons (📄 Text, 💾 Binary, ⚙️ Special).
  - **Dynamic Columns**: Auto-hiding columns based on window width to prevent layout overflow.
  - **Smart Binary Detection**: Improved heuristics using entropy analysis and extension matching.
- **Improved Tiling & Navigation**: 
  - **ESC Support**: Unified back/restore behavior for all modals and maximized panes.
  - **Input Modals**: Enhanced input fields with full backspace, cursor movement, and ESC cancel support.

### **🔧 Bug Fixes**
- **Unicode Stability**: Fixed `UnicodeDecodeError` in the Tail window when encountering binary data in text streams.
- **Layout Integrity**: Fixed a boundary error in the Open Files pane that caused UI corruption on down-scroll.
- **Tail Performance**: Removed illegal buffering flags in binary mode for better compatibility and performance.

## 📊 HTTP Accurate Monitor & Outbound Intelligence (v1.0.8)

This release introduces deep packet inspection for HTTP traffic and UI refinements for the Outbound Connections Modal.

### **✨ New Features (v1.0.8)**
- **HTTP Accurate Monitor (`S`)**: New sub-modal inside the Outbound Connections view that provides real-time, per-process HTTP endpoint analysis.
  - Automatically targets selected processes.
  - Shows Method, Host, and Path distribution.
  - Real-time hit counting and data volume tracking.
- **Enhanced Outbound Modal**: UI refinements to the footer and key bindings for better navigation.

### **🔧 Maintenance**
- Refactored internal signal handling for packet capture subprocesses.
- Optimized cleanup logic in modal windows to prevent memory leaks.

## 🛡️ Vulnerability Guard & NVD Stability (v1.0.7)

This patch focuses on the stability and accuracy of the background vulnerability scanner.

### **✨ Major Fixes (v1.0.7)**
- **NVD 404 Silence**: Resolved "NVD Error 404" noise in debug logs by gracefully handling missing CPE entries (common for local or custom processes). These are now silently cached as empty results to avoid API overhead.
- **Improved Service Fingerprinting**: Added high-confidence CPE mapping for common Linux services:
  - **CUPS** (cups-daemon)
  - **SSH/SSHD** (OpenSSH)
  - **Apache2** (HTTP Server)
  - **NTP**
- **Noise Reduction**: Automatically excludes internal and generic processes like `antigravity`, `sh`, and `bash` from vulnerability scans.

### **🚀 Core Recap (v1.0.6)**
- **Zero-Loss Traffic Tail**: High-performance OS-level file buffering for real-time traffic monitoring.
- **Smart Data Truncation**: UI-optimized 32KB tail reading for high-speed packet analysis.
- **UI Freeze (Space)**: Instantly lock lists for stable inspection.
