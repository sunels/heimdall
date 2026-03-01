## 📜 User Intelligence & history Tail (v1.3.1)

This release significantly expands user-level diagnostics with deep command history tracking and real-time history tailing.

### **✨ New Features (v1.3.1)**
- **User History Tail (`t`)**: Press 't' while the User Profile pane is active to instantly tail the owner's `.bash_history`.
- **Deep History Buffer**: Command history capture increased to 1000 lines for a more comprehensive "Allah ne verdiyse" view.
- **Improved Header**: The "Open Files" pane now explicitly shows the program name and PID for better navigation.
- **Expanded User Pane**: Increased default height and improved layout for better command visibility.
- **Optimized Layout**: Adjusted startup layout to give 3 additional lines to the main process table, reducing the initial detail pane height.
- **Context-Aware Tail**: The 't' shortcut now intelligently handles different panes (Open Files, User Profile, or Main Table) even when maximized.

### **🔧 Bug Fixes**
- **Tail Selection Crash**: Fixed a `NameError: path` in the file selection modal that caused Heimdall to crash when choosing a file to tail.
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
