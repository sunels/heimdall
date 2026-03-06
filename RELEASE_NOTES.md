## 🎨 Visual UI Refinements & Layout Optimization (v1.11.2)

This maintenance release focuses on "pixel-perfect" UI adjustments to ensure a flawless visual experience across different terminal sizes.

### **✨ Visual Improvements (v1.11.2)**
- **Sidebar Layout Optimization**: Re-architected the vertical spacing in the help sidebar. The **Sentinel Legend** now fits perfectly without overflowing or touching the borders, even on smaller terminal windows.
- **ZFS Asset Alignment**: Fixed a minor icon alignment issue in the Dashboard's ZFS/Storage health status section for better visual symmetry.
- **Improved Sidebar Density**: Removed unnecessary gaps at the top of the shortcuts list, providing 3-4 lines of extra space for diagnostic data.

### **🔧 Bug Fixes**
- **Indentation Recovery**: Fixed a potential indentation error in the UI rendering loop that could affect sidebar stability.
- **Border Collision**: Implemented strict boundary checks for the Sentinel Legend to prevent icon clipping at the bottom of the screen.

## 🛡️ Expanded Security Guidance & Full Hotkey Ledger (v1.11.1)

This patch release significantly expands the **Integrated Help System** with deep architectural insights and a full ledger of all system hotkeys for better user sovereignty.

### **✨ New Features (v1.11.1)**
- **Security Architecture Blueprint**: The `[h]` Help modal now details Heimdall's 3-tier defense strategy: **Daemon Mode** (Background), **TUI Level Protection** (Active), and **Guardian Mode** (Autonomous).
- **Full Hotkey Ledger**: Comprehensive breakdown of every single key available in the TUI, ensuring no feature is hidden.
- **Scrollable Help Interface**: The Help window now supports full vertical scrolling to accommodate the expanded knowledge base.
- **Improved Feedback**: Action confirmations and background scan notifications are now more tightly integrated into the global status bar.

### **🔧 Bug Fixes**
- **Help Content Accuracy**: Corrected several shortcut descriptions in the Help UI to align with current keyboard mappings.
- **Release Documentation**: Updated internal release notes to include the "Security Architecture" section.

## 💁 Integrated Help System & User Guidance (v1.11.0)

This release introduces a comprehensive **Integrated Help System**, making Heimdall more accessible to new users and providing deep insights into your system's configuration.

### **✨ New Features (v1.11.0)**
- **Unified Help Modal (`h`)**: A new scrollable help window that explains every hotkey, panel, and hidden feature. No more guessing what keys do!
- **Plugin Environment Audit**: The Help system now actively reports which plugins are active and which were skipped due to missing system tools (e.g., `btop`, `zpool`), with hints on how to enable them.
- **Log & Diagnostic Tracking**: Quick reference for all log locations (`debug.log`, `forensic vault`, `system journals`) directly within the TUI.
- **Community & Feedback**: New easy-access contact information for feature requests (`serkan.sunel@gmail.com`) and project contributions.

### **🔧 Bug Fixes**
- **Help Bar UI**: Integrated the `[h] Help` shortcut into the global shortcuts bar for better visibility.
- **Plugin Loading**: Improved tracking of skipped plugins during the startup sequence to provide better user feedback.

## 🌀 Interactive Integrity Feedback & Plugin UI Stability (v1.10.0)

This minor release focuses on refining the **Verifiable Integrity** user experience with real-time audio-visual feedback and critical UI stability fixes for the plugin ecosystem.

### **✨ New Features (v1.10.0)**
- **Real-time Action Feedback**: Pressing keys like `v` (Baseline) or `r` (Remeasure) now triggers instant status bar notifications and high-visibility modal confirmation windows.
- **Improved UI Stability**: Plugin windows are now correctly dimensioned to leave space for the global status bar, preventing UI overlaps and ensuring active scan notifications remain visible.
- **Rock-Solid PCR Alignment**: Implemented a new "pixel-perfect" grid system for the PCR table that accounts for emoji visual width, ensuring consistent alignment on all terminal types.
- **Enhanced Plugin API**: Added new UI bridge methods to the internal plugin system, allowing plugins to directly trigger Heimdall's native notification and modal components.

### 🧩 **Optional Dependencies for Advanced Features**
Heimdall gracefully falls back if these are missing:
- **TPM2 support**: `pip install tpm2-pytss` and system package `tpm2-tools`.
- **IMA appraisal**: `apt install ima-evm-utils` (or equivalent). Kernel must have `CONFIG_INTEGRITY=y`.
- **Systemd Integration**: `dbus-python` for deeper unit tracking.

### **🔧 Bug Fixes**
- **Plugin Overlay Issue**: Fixed a bug where plugin drawing windows would overwrite the global status notification area.
- **PCR Table Drift**: Resolved an alignment issue in the Boot Integrity panel where long hash values would cause column headers to drift.
- **AttributeError**: Fixed a crash in the `show_modal_message` bridge when called from a plugin context with a `None` screen reference.

## 🔏 Verifiable Integrity & Distro-Agnostic Intelligence (v1.9.0)

This major release introduces the **Verifiable Integrity Dashboard**, providing deep visibility into boot and runtime integrity using TPM2, PCR measurements, and systemd measured boot. It also makes Heimdall truly distro-agnostic with intelligent package manager detection and cross-distro support.

### **✨ New Features (v1.9.0)**
- **Verifiable Integrity Dashboard (`4`)**: A dedicated three-panel panel for hardware and runtime trust.
  - **Tab 1: Boot Integrity**: TPM2 status, Secure Boot validation, Measured UKI detection, and live PCR table auditing.
  - **Tab 2: IMA/Runtime**: Integrity Measurement Architecture tracking for critical system files.
  - **Tab 3: Anomalies**: Real-time detection of baseline mismatches in system targets.
- **TPM Hardware Discovery**: Detailed reporting of TPM version, manufacturer, firmware, and PCR hash banks (SHA1/SHA256).
- **Distro-Agnostic Intelligence**: 
  - Dynamic discovery of package managers (`apt`, `dnf`, `zypper`, `pacman`, `apk`).
  - Distro-aware installation hints for required tools (e.g., `tpm2-tools`, `btop`, `smartctl`).
  - Cross-distro package metadata retrieval and reverse file-to-package lookups.
- **System Health & Security Summary**: TPM and ZFS status integrated directly into the main Dashboard View.
- **UX Refinements**: 
  - Fixed keyboard navigation: All global shortcuts are now accessible while inside plugin tabs.
  - Case-insensitive panel navigation (Support for `B`, `I`, `A` keys).

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-41.png" alt="heimdall integrity dashboard" width="100%"/>
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-42.png" alt="heimdall tpm discovery" width="100%"/>
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-43.png" alt="heimdall system health integrity" width="100%"/>

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
